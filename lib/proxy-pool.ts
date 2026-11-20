// Bounded pool of reusable connections to an HTTP(S) proxy.
//
// `proxy.keepAlive` opts a request into keeping the connection to the proxy open after the
// destination's h2 session is torn down. A later request takes the idle hop and issues a fresh
// CONNECT over the same socket (possibly to a different destination). One hop is never shared by
// two live requests: a taken hop is removed from the pool until its connection closes.
//
// Both proxy flavours are pooled: http/ws keeps its raw TCP socket, https/wss keeps the outer TLS
// session plus the plaintext Duplex its CONNECT exchange runs over. SOCKS5 has no CONNECT phase
// here and is never pooled.

import { getPoolConfig, proxySegment } from './pool.ts'

import type { ProxyHop } from './tls/tls.ts'

interface ProxyLike {
	url?: string | null
	authorization?: string | null
	headers?: Record<string, string> | null
}

interface Entry {
	key: string
	hop: ProxyHop
	idleTimer: ReturnType<typeof setTimeout> | null
	onClose: () => void
}

const entries = new Map<string, Entry[]>()
const byHop = new WeakMap<ProxyHop, Entry>()

function destroyed(hop: ProxyHop): boolean {
	return (hop.transport as unknown as { destroyed?: boolean }).destroyed === true
}

/** Partition by the proxy identity plus whether we validate its certificate. */
function key(proxy: ProxyLike, verifyTLS: boolean): string {
	return `${proxySegment(proxy)}|${verifyTLS ? 1 : 0}`
}

function count(): number {
	let n = 0
	for (const bucket of entries.values()) n += bucket.length
	return n
}

function remove(entry: Entry): void {
	if (entry.idleTimer) {
		clearTimeout(entry.idleTimer)
		entry.idleTimer = null
	}
	try {
		entry.hop.transport.removeListener('close', entry.onClose)
	} catch {}
	byHop.delete(entry.hop)
	const bucket = entries.get(entry.key)
	if (!bucket) return
	const at = bucket.indexOf(entry)
	if (at !== -1) bucket.splice(at, 1)
	if (bucket.length === 0) entries.delete(entry.key)
}

/** Take an idle hop. The caller owns it until release()/evict(). */
function take(key: string): ProxyHop | null {
	const bucket = entries.get(key)
	if (!bucket) return null
	for (const entry of bucket) {
		if (destroyed(entry.hop)) {
			remove(entry)
			continue
		}
		remove(entry)
		return entry.hop
	}
	return null
}

/**
 * Hand a hop back after its connection closes. Returns it to the idle bucket when there is
 * capacity; otherwise closes it. An idle hop is closed after the configured idleMs or on
 * socket close. Caps come from the process-wide pool config.
 */
function release(hop: ProxyHop, key: string): void {
	if (!hop) return
	const config = getPoolConfig()
	if (destroyed(hop) || byHop.has(hop)) {
		close(hop)
		return
	}
	const bucket = entries.get(key) ?? []
	if (bucket.length >= config.maxPerOrigin || count() >= config.maxSockets) {
		close(hop)
		return
	}

	const entry: Entry = { key, hop, idleTimer: null, onClose: () => remove(entry) }
	bucket.push(entry)
	entries.set(key, bucket)
	byHop.set(hop, entry)
	try {
		hop.transport.on('close', entry.onClose)
	} catch {}

	entry.idleTimer = setTimeout(() => {
		if (byHop.get(hop) !== entry) return
		remove(entry)
		close(hop)
	}, config.idleMs)
	entry.idleTimer.unref?.()
}

/** Drop a hop that failed mid-CONNECT. Never puts it back into circulation. */
function evict(hop: ProxyHop | null): void {
	if (!hop) return
	const entry = byHop.get(hop)
	if (entry) remove(entry)
	close(hop)
}

function close(hop: ProxyHop): void {
	try {
		hop.close()
	} catch {}
}

/** Test/shutdown helper: close every idle hop and empty the bookkeeping. */
function clearProxyPool(): void {
	const buckets = [...entries.values()]
	for (const bucket of buckets) {
		for (const entry of bucket) {
			remove(entry)
			close(entry.hop)
		}
	}
	entries.clear()
}

function pooledCount(): number {
	return count()
}

export { key, take, release, evict, clearProxyPool, pooledCount }
export type { ProxyHop }
