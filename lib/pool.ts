// Bounded keep-alive pool for reused HTTP/2 connections.
//
// Every request otherwise opens a fresh TLS connection and closes it when the response
// completes — tens of milliseconds of TCP + handshake re-paid per call. This pool keeps a
// small number of live h2 sessions per origin and multiplexes later streams onto them, the
// same shape Chrome uses (one connection per origin, many concurrent streams).
//
// The pool is deliberately bounded and short-lived: runtimes like Cloudflare Workers cap the
// sockets an isolate may hold open (single digits), so pooled sockets must never accumulate.
// Defaults: one socket per origin, sixteen across the process, idle sockets closed after
// fifteen seconds. Callers opt in per request (`keepAlive: true`) and may lower the caps via
// `pool: { maxSockets, maxPerOrigin, idleMs }`. A request that finds no capacity opens a
// one-shot connection exactly as before — the pool never blocks or queues.
//
// Only healthy, non-GOAWAYed h2 sessions are ever handed out. Any stream-level teardown path
// that closes the connection evicts its pool entry, so a poisoned socket cannot be reused.

import * as frame from './h2/frame.ts'

import type { Connection } from './connect.ts'
import type { H2Session } from './h2/session.ts'

export interface PoolConfig {
	maxSockets: number
	maxPerOrigin: number
	idleMs: number
}

interface Entry {
	key: string
	conn: Connection
	config: PoolConfig
	active: number
	dead: boolean
	idleTimer: ReturnType<typeof setTimeout> | null
}

const DEFAULT_CONFIG: PoolConfig = { maxSockets: 16, maxPerOrigin: 1, idleMs: 15_000 }

const entries = new Map<string, Entry[]>()
const byConn = new WeakMap<Connection, Entry>()

function poolKey(
	host: string,
	port: number,
	profile: unknown,
	proxy: string | null | undefined,
	verifyTLS: boolean,
	proxyAuth: string | null | undefined = ''
): string {
	const profileName = typeof profile === 'string' ? profile : profile ? 'inline' : 'default'
	return `${host}:${port}|${profileName}|${proxy ?? ''}|${verifyTLS ? 1 : 0}|${proxyAuth ?? ''}`
}

function sessionOf(conn: Connection): H2Session | null {
	return conn.alpn === 'h2' ? conn.h2Session : null
}

/** A pooled socket is hand-out-able while its session lives and has stream headroom. */
function usable(entry: Entry): boolean {
	if (entry.dead || entry.conn.closed) return false
	const session = sessionOf(entry.conn)
	if (!session || session.closed || session.destroyed) return false
	const cap = session.peerSettings[frame.SETTING.MAX_CONCURRENT_STREAMS] ?? Infinity
	return entry.active < cap
}

function remove(entry: Entry): void {
	if (entry.dead) return
	entry.dead = true
	if (entry.idleTimer) {
		clearTimeout(entry.idleTimer)
		entry.idleTimer = null
	}
	byConn.delete(entry.conn)
	const bucket = entries.get(entry.key)
	if (bucket) {
		const at = bucket.indexOf(entry)
		if (at !== -1) bucket.splice(at, 1)
		if (bucket.length === 0) entries.delete(entry.key)
	}
}

/**
 * Take a live socket for `key`, or null. The returned entry counts the caller's stream as
 * active; the request path must call release() when the stream completes or poolEvict() when
 * it tears the connection down.
 */
function take(key: string): Connection | null {
	const bucket = entries.get(key)
	if (!bucket) return null
	for (const entry of bucket) {
		if (!usable(entry)) continue
		entry.active += 1
		if (entry.idleTimer) {
			clearTimeout(entry.idleTimer)
			entry.idleTimer = null
		}
		return entry.conn
	}
	return null
}

function pooledCount(): number {
	let n = 0
	for (const bucket of entries.values()) n += bucket.length
	return n
}

/**
 * Register a freshly handshaken connection under `key` when the pool has budget. The creating
 * request already holds a stream slot, so the entry starts at active=1. Returns whether the
 * connection joined the pool; unregistered connections keep the historic one-shot behavior.
 */
function register(conn: Connection, key: string, config: PoolConfig): boolean {
	if (conn.alpn !== 'h2' || !conn.h2Session) return false
	const bucket = entries.get(key) ?? []
	if (bucket.length >= config.maxPerOrigin || pooledCount() >= config.maxSockets) return false

	const entry: Entry = { key, conn, config, active: 1, dead: false, idleTimer: null }
	bucket.push(entry)
	entries.set(key, bucket)
	byConn.set(conn, entry)

	const session = conn.h2Session
	// GOAWAY means the peer is winding the session down: stop handing out new streams but let
	// in-flight ones finish. Session close/teardown evicts immediately.
	session.on?.('goaway', () => remove(entry))
	session.once?.('close', () => remove(entry))
	conn.onClosed = () => remove(entry)
	return true
}

/**
 * Return a connection's stream slot after a completed exchange. True means the socket stays
 * pooled (idle-closed after the entry's configured lifetime if nothing else takes it); false
 * means the caller must close the connection itself.
 */
function release(conn: Connection): boolean {
	const entry = byConn.get(conn)
	if (!entry) return false
	entry.active = Math.max(0, entry.active - 1)
	if (entry.active > 0 || entry.dead || conn.closed) return entry.active > 0 && !entry.dead && !conn.closed
	if (!usable(entry)) {
		remove(entry)
		return false
	}
	entry.idleTimer = setTimeout(() => {
		entry.idleTimer = null
		remove(entry)
		conn.close('pool-idle-expired')
	}, entry.config.idleMs)
	entry.idleTimer.unref?.()
	return true
}

/** Drop a pooled entry whose connection is being torn down by the request path. */
function poolEvict(conn: Connection): void {
	const entry = byConn.get(conn)
	if (entry) remove(entry)
}

/** Test/shutdown helper: close every pooled socket and empty the bookkeeping. */
function clearPool(reason = 'pool-cleared'): void {
	// Snapshot first: remove() mutates `entries` while we walk it.
	const buckets = [...entries.values()]
	for (const bucket of buckets) {
		for (const entry of bucket) {
			remove(entry)
			entry.conn.close(reason)
		}
	}
	entries.clear()
}

export { DEFAULT_CONFIG, poolKey, take, register, release, poolEvict, clearPool, pooledCount }
export type { Entry }
