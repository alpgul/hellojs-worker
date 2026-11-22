// RFC 7838 Alternative Services cache, driven entirely by protocol state — no public option.
//
// Alt-Svc values arrive either as an HTTP response header or as an HTTP/2 ALTSVC frame. Entries
// are keyed by origin (scheme://host:port), carry the RFC's `ma` freshness lifetime (24h default)
// and `clear` invalidation, and are dropped on HTTP 421. A failed QUIC handshake marks the h3
// entry broken so the next request goes straight to TCP instead of retrying a dead endpoint.
//
// SNI, Host and certificate verification always stay on the ORIGIN authority; only the dial
// target moves to the advertised host/port. Proxy requests never learn or use Alt-Svc.

import type { TransportHint } from './transport-race.ts'

const DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000

interface AltEntry {
	protocol: string
	host: string
	port: number
	expiresAt: number
	persist: boolean
	broken: boolean
}

const cache = new Map<string, AltEntry[]>()

/** Normalized origin key. Default ports are made explicit so `:443` forms compare equal. */
export function originKey(input: string | URL): string {
	const url = typeof input === 'string' ? new URL(input) : input
	const port = url.port || (url.protocol === 'https:' ? '443' : url.protocol === 'http:' ? '80' : '')
	return `${url.protocol}//${url.hostname.toLowerCase()}:${port}`
}

/**
 * Resolve the origin an ALTSVC frame is allowed to affect (RFC 7838 §4).
 * Stream 0 must name the connection's own origin; stream-level frames must leave Origin empty
 * and inherit the origin of the request that opened the stream. `null` means invalid.
 */
export function authorizedAltsvcOrigin(
	frameOrigin: string | null,
	connectionOrigin: string | URL,
	streamId: number
): string | null {
	if (frameOrigin === null) return null
	const normalize = (input: string | URL): string | null => {
		try {
			return originKey(input)
		} catch {
			return null
		}
	}
	const own = normalize(connectionOrigin)
	if (!own) return null
	if (streamId === 0) {
		if (!frameOrigin) return null
		const claimed = normalize(frameOrigin)
		return claimed === own ? own : null
	}
	return frameOrigin ? null : own
}

/** Split on a delimiter while respecting RFC 7838 quoted-strings. */
function splitOutsideQuotes(input: string, delimiter: string): string[] {
	const out: string[] = []
	let current = ''
	let quoted = false
	for (let i = 0; i < input.length; i++) {
		const ch = input[i]
		if (ch === '\\' && quoted && i + 1 < input.length) {
			current += ch + input[++i]
			continue
		}
		if (ch === '"') {
			quoted = !quoted
			current += ch
			continue
		}
		if (ch === delimiter && !quoted) {
			out.push(current)
			current = ''
			continue
		}
		current += ch
	}
	out.push(current)
	return out
}

function parseAuthority(authority: string, origin: URL): { host: string; port: number } | null {
	const raw = authority.trim().replace(/^"|"$/g, '')
	let host: string
	let portText: string
	if (raw.startsWith(':')) {
		// `:port` means "same host as the origin" (RFC 7838 §3).
		host = origin.hostname.replace(/^\[|\]$/g, '')
		portText = raw.slice(1)
	} else {
		const match = /^\[([^\]]+)\]:(\d{1,5})$|^([^:\]]+):(\d{1,5})$/.exec(raw)
		if (!match) return null
		host = (match[1] ?? match[3]).toLowerCase()
		portText = match[2] ?? match[4]
	}
	const port = Number(portText)
	if (!Number.isInteger(port) || port < 1 || port > 65535) return null
	return { host, port }
}

function parseAltSvc(value: string, origin: URL): AltEntry[] {
	const entries: AltEntry[] = []
	for (const field of splitOutsideQuotes(value, ',')) {
		const trimmed = field.trim()
		if (!trimmed) continue
		const eq = trimmed.indexOf('=')
		if (eq < 1) continue
		const protocol = trimmed.slice(0, eq).trim().toLowerCase()
		if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(protocol) || protocol === 'clear') continue
		const parts = splitOutsideQuotes(trimmed.slice(eq + 1), ';')
		const authority = parseAuthority(parts[0], origin)
		if (!authority) continue
		let maxAgeMs = DEFAULT_MAX_AGE_MS
		let persist = false
		for (const param of parts.slice(1)) {
			const sep = param.indexOf('=')
			if (sep < 1) continue
			const name = param.slice(0, sep).trim().toLowerCase()
			const raw = param
				.slice(sep + 1)
				.trim()
				.replace(/^"|"$/g, '')
			if (name === 'ma') {
				const seconds = Number(raw)
				if (Number.isFinite(seconds) && seconds >= 0) maxAgeMs = seconds * 1000
			} else if (name === 'persist') {
				persist = raw === '1'
			}
		}
		entries.push({
			protocol,
			host: authority.host,
			port: authority.port,
			expiresAt: Date.now() + maxAgeMs,
			persist,
			broken: false
		})
	}
	return entries
}

/**
 * Learn an Alt-Svc field value for `origin`. RFC 7838 §3/§4 replace ALL alternatives for the
 * origin with the freshly received set; `clear` empties it and malformed values are ignored.
 */
export function rememberAltSvc(value: string | string[] | undefined, origin: string | URL): void {
	if (value == null) return
	const key = originKey(origin)
	let originUrl: URL
	try {
		originUrl = new URL(key)
	} catch {
		return
	}
	const values = Array.isArray(value) ? value : [value]
	const fresh: AltEntry[] = []
	let cleared = false
	for (const raw of values) {
		if (raw.trim().toLowerCase() === 'clear') {
			cleared = true
			continue
		}
		fresh.push(...parseAltSvc(raw, originUrl))
	}
	if (cleared) {
		cache.delete(key)
		return
	}
	// An all-malformed field value is not a received replacement set (RFC 7838 §3.1):
	// keep the last valid alternatives rather than wiping the cache on one bad header.
	if (fresh.length === 0) return
	cache.set(key, fresh)
}

/** A cached alternative service on 421 is stale — RFC 7838 §5 requires dropping it. */
export function forgetAltSvc(origin: string | URL): void {
	cache.delete(originKey(origin))
}

/** Mark one protocol unusable after a failed handshake so the next request skips it. */
export function markAltSvcBroken(origin: string | URL, protocol: string): void {
	const entries = cache.get(originKey(origin))
	if (!entries) return
	const entry = entries.find((e) => e.protocol === protocol)
	if (entry) entry.broken = true
}

export interface AltSvcSelection {
	hint: TransportHint
	/** Dial target; SNI/Host/certificate checks still use the origin authority. */
	host: string
	port: number
	/** Authority to advertise in `Alt-Used` when the request uses a cached alternative. */
	altUsed: string | null
}

function liveEntries(origin: string): AltEntry[] {
	const entries = cache.get(origin)
	if (!entries) return []
	const now = Date.now()
	const live = entries.filter((e) => !e.broken && e.expiresAt > now)
	if (live.length === entries.length) return entries
	if (live.length) cache.set(origin, live)
	else cache.delete(origin)
	return live
}

/** Pick the best cached transport for an origin. Returns a no-op selection on a miss. */
export function selectAltSvc(origin: string | URL, defaultHost: string, defaultPort: number): AltSvcSelection {
	const none: AltSvcSelection = { hint: null, host: defaultHost, port: defaultPort, altUsed: null }
	const key = originKey(origin)
	const entries = liveEntries(key)
	if (!entries.length) return none
	// h3 first, then h2; "h1" needs no hint because it is the fallback path anyway.
	const chosen =
		entries.find((e) => e.protocol === 'h3') ??
		entries.find((e) => e.protocol === 'h2') ??
		entries.find((e) => e.protocol === 'h1')
	if (!chosen) return none
	return {
		hint: chosen.protocol as TransportHint,
		host: chosen.host,
		port: chosen.port,
		altUsed: `${chosen.host}:${chosen.port}`
	}
}

/** Test-only: clear the whole cache. */
export function clearAltSvcCache(): void {
	cache.clear()
}
