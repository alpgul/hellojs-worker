// TTL-bounded getaddrinfo cache.
//
// libuv does not cache dns.lookup(): every fresh connection resolves the host again, and on a
// real network that is tens of milliseconds per request (33–38 ms to www.cloudflare.com on the
// development machine). The cache is deliberately small and short-lived — it amortises repeated
// connections inside one process without pinning an IP for longer than DNS-based load balancing
// can tolerate. Failures are never cached.
//
// node:dns is resolved lazily: on workerd it is absent, dnsCacheAvailable() answers false, and
// the TLS/QUIC layers keep connecting by hostname exactly as before.

import * as net from 'node:net'

import type { LookupAddress, LookupOptions } from 'node:dns'

export type ResolvedAddress = LookupAddress
export type ResolvedLookup = (hostname: string) => Promise<ResolvedAddress[]>
type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void
// Error-first callbacks legally omit the address; Node's LookupFunction type still requires it.
type LookupFail = (err: NodeJS.ErrnoException) => void

const DEFAULT_TTL_MS = 30_000
const DEFAULT_MAX_ENTRIES = 256

let ttlMs = DEFAULT_TTL_MS
let maxEntries = DEFAULT_MAX_ENTRIES
const cache = new Map<string, { addresses: ResolvedAddress[]; expiresAt: number }>()
const inflight = new Map<string, Promise<ResolvedAddress[]>>()
let resolver: ResolvedLookup | null | undefined
let override: ResolvedLookup | null = null

function builtinResolver(): ResolvedLookup | null {
	try {
		const proc = process as unknown as { getBuiltinModule?: (id: string) => unknown }
		const dns = proc.getBuiltinModule?.('node:dns') as
			| {
					lookup?: (
						hostname: string,
						options: { all: true },
						cb: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void
					) => void
			  }
			| undefined
		if (!dns || typeof dns.lookup !== 'function') return null
		return (hostname) =>
			new Promise<ResolvedAddress[]>((resolve, reject) => {
				dns.lookup!(hostname, { all: true }, (err, addresses) => {
					if (err) reject(err)
					else resolve(addresses)
				})
			})
	} catch {
		return null
	}
}

// True when this runtime has a usable node:dns. Callers pass cachedLookup to net only then.
function dnsCacheAvailable(): boolean {
	if (resolver === undefined) resolver = builtinResolver()
	return override !== null || resolver !== null
}

function lookupError(hostname: string): NodeJS.ErrnoException {
	const err = new Error(`getaddrinfo ENOTFOUND ${hostname}`) as NodeJS.ErrnoException & { hostname: string }
	err.code = 'ENOTFOUND'
	err.hostname = hostname
	return err
}

// Resolve once per (host, TTL); concurrent callers share the in-flight query.
async function resolveHost(hostname: string): Promise<ResolvedAddress[]> {
	const literal = net.isIP(hostname)
	if (literal) return [{ address: hostname, family: literal === 6 ? 6 : 4 }]

	const now = Date.now()
	const entry = cache.get(hostname)
	if (entry && now < entry.expiresAt) {
		cache.delete(hostname)
		cache.set(hostname, entry)
		return entry.addresses
	}
	if (entry) cache.delete(hostname)

	const pending = inflight.get(hostname)
	if (pending) return pending

	const promise = (async () => {
		if (resolver === undefined) resolver = builtinResolver()
		const fn = override ?? resolver
		if (!fn) throw lookupError(hostname)
		const addresses = await fn(hostname)
		if (!addresses.length) throw lookupError(hostname)
		cache.set(hostname, { addresses, expiresAt: Date.now() + ttlMs })
		while (cache.size > maxEntries) {
			const oldest = cache.keys().next().value
			if (oldest === undefined) break
			cache.delete(oldest)
		}
		return addresses
	})()
	inflight.set(hostname, promise)
	try {
		return await promise
	} finally {
		inflight.delete(hostname)
	}
}

// net.createConnection({ lookup }) seam. Mirrors dns.lookup's callback contract, including the
// `all` form Node uses for Happy Eyeballs.
function cachedLookup(hostname: string, options: LookupOptions, callback: LookupCallback): void {
	const opts = typeof options === 'number' ? { family: options } : options || {}
	const family = opts.family === 'IPv4' ? 4 : opts.family === 'IPv6' ? 6 : Number(opts.family) || 0
	const all = opts.all === true
	const fail = callback as LookupFail
	resolveHost(hostname).then(
		(addresses) => {
			const usable = family === 4 || family === 6 ? addresses.filter((a) => a.family === family) : addresses
			if (usable.length === 0) {
				fail(lookupError(hostname))
				return
			}
			if (all) callback(null, usable)
			else callback(null, usable[0].address, usable[0].family)
		},
		(err: unknown) => fail(err instanceof Error ? (err as NodeJS.ErrnoException) : lookupError(hostname))
	)
}

function clearDnsCache(): void {
	cache.clear()
	inflight.clear()
}

// Internal knobs for tests and for applications that need a different trust window.
function configureDnsCache(config: { ttlMs?: number; maxEntries?: number }): void {
	if (config.ttlMs !== undefined) ttlMs = config.ttlMs
	if (config.maxEntries !== undefined) maxEntries = config.maxEntries
	clearDnsCache()
}

function setResolverForTests(fn: ResolvedLookup | null): void {
	override = fn
	clearDnsCache()
}

export { dnsCacheAvailable, cachedLookup, resolveHost, clearDnsCache, configureDnsCache, setResolverForTests }
