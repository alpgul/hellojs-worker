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
// fifteen seconds. The caps are process-wide, set once with `setPoolConfig()`; individual
// requests only opt in with `keepalive: true`. A request that finds no capacity opens a
// one-shot connection exactly as before — the pool never blocks or queues.
//
// Only healthy, non-GOAWAYed h2 sessions are ever handed out. Any stream-level teardown path
// that closes the connection evicts its pool entry, so a poisoned socket cannot be reused.

import { createHash } from 'node:crypto'

import { HellojsError } from './errors.ts'
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
	active: number
	dead: boolean
	idleTimer: ReturnType<typeof setTimeout> | null
}

const DEFAULT_CONFIG: PoolConfig = { maxSockets: 16, maxPerOrigin: 1, idleMs: 15_000 }

// The pool owns sockets process-wide, so its caps live here rather than on any request.
let config: PoolConfig = { ...DEFAULT_CONFIG }

/** Set the process-wide pool caps. Each call starts from the defaults, then applies `partial`. */
function setPoolConfig(partial: Partial<PoolConfig> = {}): void {
	const next = { ...DEFAULT_CONFIG, ...partial }
	if (!Number.isInteger(next.maxSockets) || next.maxSockets < 1) {
		throw new HellojsError(`pool.maxSockets must be a positive integer`, 'EBADOPTS')
	}
	if (!Number.isInteger(next.maxPerOrigin) || next.maxPerOrigin < 1) {
		throw new HellojsError(`pool.maxPerOrigin must be a positive integer`, 'EBADOPTS')
	}
	if (!Number.isInteger(next.idleMs) || next.idleMs < 0) {
		throw new HellojsError(`pool.idleMs must be a non-negative integer`, 'EBADOPTS')
	}
	config = next
}

/** Internal: shared with the proxy-hop pool so both honor the same caps. */
function getPoolConfig(): PoolConfig {
	return config
}

const entries = new Map<string, Entry[]>()
const byConn = new WeakMap<Connection, Entry>()

// Structural shape of the proxy option — kept local so this module does not depend on client.ts.
interface ProxyLike {
	url?: string | null
	authorization?: string | null
	headers?: Record<string, string> | null
}

// The proxy segment is a digest, never the raw material: a proxy URL can carry `user:pass` and
// `authorization` can be a bearer token, and this key lives in a process-wide Map for as long
// as its socket stays pooled. Digesting also partitions by CONNECT shape — a tunnel opened with one
// header set must not answer for a request configured with another, whose hop-by-hop headers would
// then never be sent. Shared with lib/proxy-pool.ts so a proxy hop and the h2 session tunneled
// through it agree on the same identity.
export function proxySegment(proxy: ProxyLike | null | undefined): string {
	// Lowercased and sorted, so an equivalent header map — different order, different casing —
	// reaches the same bucket.
	const headers = proxy?.headers
		? Object.entries(proxy.headers)
				.map(([name, value]) => `${name.toLowerCase()}\u0000${String(value)}`)
				.sort()
				.join('&')
		: ''
	const url = proxy?.url ?? ''
	const auth = proxy?.authorization ?? ''
	if (!url && !auth && !headers) return ''
	return createHash('sha256').update(`${url}\u0000${auth}\u0000${headers}`).digest('base64url')
}

function poolKey(
	host: string,
	port: number,
	profile: unknown,
	proxy: ProxyLike | null | undefined,
	verifyTLS: boolean
): string {
	const profileName = typeof profile === 'string' ? profile : profile ? 'inline' : 'default'
	return `${host}:${port}|${profileName}|${verifyTLS ? 1 : 0}|${proxySegment(proxy)}`
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
function register(conn: Connection, key: string): boolean {
	if (conn.alpn !== 'h2' || !conn.h2Session) return false
	const bucket = entries.get(key) ?? []
	if (bucket.length >= config.maxPerOrigin || pooledCount() >= config.maxSockets) return false

	const entry: Entry = { key, conn, active: 1, dead: false, idleTimer: null }
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
 * pooled (idle-closed after the configured lifetime if nothing else takes it); false means
 * the caller must close the connection itself.
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
	}, config.idleMs)
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

export { setPoolConfig, getPoolConfig, poolKey, take, register, release, poolEvict, clearPool, pooledCount }
export type { Entry }
