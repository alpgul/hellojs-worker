// The proxy pool: process-wide, in memory, and deliberately not persisted.
//
// A host behind Cloudflare cannot be reached by a direct socket from this runtime, so the request
// has to leave through something else. The pool is that "something else" and nothing more — this
// module holds a list and a success/fail tally, picks one, and records the outcome. Lifetime,
// persistence, health checks and rotation are the caller's policy, not this module's.
//
// Scope is the runtime, not the request: `setProxyPool()` at module scope is the portable way to
// populate it. On Node that is one process-wide list. On Workers the module scope is per-isolate,
// so each isolate builds its own — fine for a list that comes from configuration, surprising for
// one mutated per request. Applications that need a single shared pool manage it themselves
// (for example inside a Durable Object) and call `setProxyPool()` there.
//
// Two counters and a set are the entire state. `deniedHosts` exists because a 403 is evidence
// about one origin, not about the proxy: a proxy blocked by a single geopicky site should lose
// that host only, not its standing everywhere.

import { HellojsError } from './errors.ts'
import { pickWeighted, selectionWeight, wilsonLower } from './proxy-score.ts'

import type { ProxyOptions } from './client.ts'

interface ProxyEntry {
	proxy: ProxyOptions
	/** Normalised URL — the pool's identity for this proxy. */
	url: string
	success: number
	fail: number
	lastOutcome: 'ok' | 'fail' | null
	/** Hosts that answered 403 through this proxy; cleared as soon as one succeeds. */
	deniedHosts: Set<string>
	generation: number
}

/** Returned by selection so callers can book outcomes against the exact slot they used. */
interface SelectedProxy {
	url: string
	proxy: ProxyOptions
	generation: number
}

/** Public, read-only view of one pool slot. */
interface ProxyPoolEntry {
	url: string
	success: number
	fail: number
	/** Wilson lower bound in `0..1`; `0.5` while the slot has no history. */
	score: number
	lastOutcome: 'ok' | 'fail' | null
	/** Derived, never probed: a slot is live until its most recent request failed. */
	live: boolean
}

type ProxyOutcome = 'ok' | 'fail' | 'blocked'

let entries: ProxyEntry[] = []
let generationSeq = 1

/**
 * Canonical identity for a proxy URL: lowercase scheme and host, no trailing slash, no default
 * port. Credentials in the URL are rejected — every CONNECT detail belongs in `proxy`.
 */
function proxyKeyOf(proxy: ProxyOptions | null | undefined): string {
	const raw = proxy?.url
	if (typeof raw !== 'string' || !raw.trim()) {
		throw new HellojsError('proxy.url must be a non-empty string', 'EBADOPTS')
	}

	let url: URL
	try {
		url = new URL(raw.trim())
	} catch {
		throw new HellojsError(`proxy.url is not a valid URL: ${raw}`, 'EBADOPTS')
	}

	const scheme = url.protocol.toLowerCase()
	const allowsUrlCreds = scheme === 'socks5:' || scheme === 'socks5h:'
	if ((url.username || url.password) && !allowsUrlCreds) {
		throw new HellojsError('proxy credentials belong in proxy.authorization, not the URL', 'EBADOPTS')
	}

	const path = url.pathname === '/' ? '' : url.pathname
	// Credentials are part of identity for formats that authenticate through the URL.
	const auth = url.username || url.password ? `${url.username}:${url.password}@` : ''
	return `${scheme}//${auth}${url.host.toLowerCase()}${path}${url.search}`
}

function entryFrom(proxy: ProxyOptions, previous?: ProxyEntry): ProxyEntry {
	const url = proxyKeyOf(proxy)
	const keep = previous?.url === url
	return {
		proxy: { ...proxy },
		url,
		success: keep ? previous.success : 0,
		fail: keep ? previous.fail : 0,
		lastOutcome: keep ? previous.lastOutcome : null,
		deniedHosts: keep ? new Set(previous.deniedHosts) : new Set(),
		generation: keep ? previous.generation : generationSeq++
	}
}

function toPoolEntry(entry: ProxyEntry): ProxyPoolEntry {
	return {
		url: entry.url,
		success: entry.success,
		fail: entry.fail,
		score: wilsonLower(entry.success, entry.fail),
		lastOutcome: entry.lastOutcome,
		live: entry.lastOutcome !== 'fail'
	}
}

/**
 * Replace the whole pool. Every entry is validated before anything is swapped in, so a bad URL
 * leaves the previous pool intact. Statistics are not carried over: the new list starts clean.
 */
function setProxyPool(proxies: ProxyOptions[] = []): void {
	const next: ProxyEntry[] = []
	const seen = new Map<string, ProxyEntry>()
	for (const proxy of proxies) {
		const entry = entryFrom(proxy)
		const existing = seen.get(entry.url)
		if (existing) {
			// Last definition wins, in the first position it occupied. Different config means
			// a different slot even when the URL is reused.
			existing.proxy = entry.proxy
			existing.generation = generationSeq++
			continue
		}
		seen.set(entry.url, entry)
		next.push(entry)
	}
	entries = next
}

/**
 * Add a proxy, or update the URL's connection details while keeping its tally. A proxy the caller
 * has already added is not reset by a repeated `addProxy()`.
 */
function sameProxyConfig(a: ProxyOptions, b: ProxyOptions): boolean {
	const aHeaders = a.headers ?? null
	const bHeaders = b.headers ?? null
	const headersEqual =
		aHeaders === bHeaders ||
		(!!aHeaders &&
			!!bHeaders &&
			Object.keys(aHeaders).length === Object.keys(bHeaders).length &&
			Object.keys(aHeaders).every((k) => aHeaders[k] === bHeaders[k]))
	return (
		proxyKeyOf(a) === proxyKeyOf(b) &&
		(a.authorization ?? null) === (b.authorization ?? null) &&
		(a.keepAlive ?? true) === (b.keepAlive ?? true) &&
		headersEqual
	)
}

function addProxy(proxy: ProxyOptions): void {
	const entry = entryFrom(proxy)
	const existing = entries.find((candidate) => candidate.url === entry.url)
	if (existing) {
		const changed = !sameProxyConfig(existing.proxy, entry.proxy)
		existing.proxy = entry.proxy
		if (changed) existing.generation = generationSeq++
		return
	}
	entries.push(entry)
}

/** Remove a proxy by URL. Returns whether anything was removed. */
function removeProxy(url: string): boolean {
	const key = proxyKeyOf({ url })
	const at = entries.findIndex((entry) => entry.url === key)
	if (at === -1) return false
	entries.splice(at, 1)
	return true
}

/** The pool as the caller sees it, best score first. */
function getProxyList(): ProxyPoolEntry[] {
	return entries.map(toPoolEntry).sort((a, b) => b.score - a.score)
}

/**
 * Weighted pick for one request. Higher scores are chosen more often, never exclusively, so a
 * single good proxy does not absorb the whole pool's traffic and get rate-limited for it.
 * `exclude` lets a retry avoid the proxy that just failed.
 */
function selectProxy(host: string, exclude?: ReadonlySet<string>): SelectedProxy | null {
	const candidates: ProxyEntry[] = []
	const weights: number[] = []
	for (const entry of entries) {
		if (exclude?.has(entry.url)) continue
		if (entry.deniedHosts.has(host)) continue
		candidates.push(entry)
		weights.push(selectionWeight(entry.success, entry.fail))
	}
	const picked = pickWeighted(candidates, weights)
	return picked ? { url: picked.url, proxy: picked.proxy, generation: picked.generation } : null
}

/**
 * Record what a request through this proxy did.
 *
 * `blocked` is an origin rejection (403/challenge), which counts against this host only.
 * `fail` is the proxy's own fault — refused, timed out, or truncated mid-response.
 *
 * Returns false when the proxy is not in the pool (a caller-supplied proxy of its own), so an
 * explicit proxy never picks up statistics it was never added with.
 */
function recordProxyOutcome(proxy: ProxyOptions, host: string, outcome: ProxyOutcome, generation?: number): boolean {
	let key: string
	try {
		key = proxyKeyOf(proxy)
	} catch {
		return false
	}
	const entry = entries.find((candidate) => candidate.url === key)
	if (!entry) return false
	if (generation !== undefined && entry.generation !== generation) return false

	if (outcome === 'ok') {
		entry.success++
		entry.lastOutcome = 'ok'
		entry.deniedHosts.delete(host)
		return true
	}
	if (outcome === 'blocked') {
		// An origin rejection is host-specific: it must not poison the proxy globally.
		entry.deniedHosts.add(host)
		return true
	}
	entry.fail++
	entry.lastOutcome = 'fail'
	return true
}

/** Whether the pool holds anything at all. */
function hasProxies(): boolean {
	return entries.length > 0
}

/** Test hook: empty the pool. */
function clearProxyPool(): void {
	entries = []
}

export {
	proxyKeyOf,
	setProxyPool,
	addProxy,
	removeProxy,
	getProxyList,
	selectProxy,
	recordProxyOutcome,
	hasProxies,
	clearProxyPool
}
export type { ProxyEntry, ProxyPoolEntry, ProxyOutcome, SelectedProxy }
