// Profile-driven request header builders. HTTP/2 sends headers in the order keys are
// inserted into the JS object, so order is controllable from JS. Each profile owns its
// header set (see lib/profiles/*); this file only merges and emits it.
//
// POLICY: a profile pins both the TLS/H2 fingerprint and the request header set. When a
// profile is resolved, its `.headers` block is injected in the profile's declared order.
// Caller headers may override non-identity values in place (keeping the profile's position);
// headers that are not in the profile append after the profile block. Identity headers
// (user-agent and the sec-ch-ua client hints) are fixed by the profile: passing a different
// value is a usage error instead of silently changing the browser fingerprint.
//
// A profile can extend the fixed set with a `fixedHeaders` array of lowercase names.

import { HellojsError } from './errors.ts'

import type { Profile } from './profiles/types.ts'

export type HeaderValue = string | string[] | number | boolean | null | undefined
export type HeaderMap = Record<string, HeaderValue>

const DEFAULT_FIXED_HEADERS = ['user-agent', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform']

const DEFAULT_PSEUDO_ORDER = [':method', ':authority', ':scheme', ':path']

function pseudoOrderFromProfile(profile?: Profile | null): string[] {
	const o = profile?.http2?.pseudoHeaderOrder
	return Array.isArray(o) && o.length ? o : DEFAULT_PSEUDO_ORDER
}

function fixedHeadersFor(profile?: Profile | null): Set<string> {
	const names = profile && Array.isArray(profile.fixedHeaders) ? profile.fixedHeaders : DEFAULT_FIXED_HEADERS
	return new Set(names.map((n) => String(n).toLowerCase()))
}

// Merge caller headers into the profile's header block. Profile headers keep their declared
// order; overriding an existing name updates its value in place. Names the profile does not
// define append in caller order, except Cookie, which Chrome emits just before `priority`.
function mergeProfileHeaders(userHeaders: HeaderMap | null | undefined, profile?: Profile | null): HeaderMap {
	const defaults = (profile && profile.headers) || {}
	const fixed = fixedHeadersFor(profile)
	const out: HeaderMap = {}
	const index = new Map<string, string>()
	for (const [k, v] of Object.entries<HeaderValue>(defaults)) {
		out[k] = v
		index.set(k.toLowerCase(), k)
	}
	for (const [k, v] of Object.entries<HeaderValue>(userHeaders || {})) {
		const lk = k.toLowerCase()
		if (lk === 'host') continue
		const existing = index.get(lk)
		if (existing != null) {
			if (fixed.has(lk) && String(v) !== String(out[existing])) {
				throw new HellojsError(
					`header "${k}" is fixed by profile ${(profile && profile.name) || 'unknown'}: ${JSON.stringify(out[existing])}`,
					'EHEADERFIXED')
			}
			out[existing] = v
			continue
		}
		const priorityKey = index.get('priority')
		if (lk === 'cookie' && priorityKey != null) {
			const entries = Object.entries(out)
			for (const key of Object.keys(out)) delete out[key]
			for (const [ek, ev] of entries) {
				if (ek === priorityKey) out[k] = v
				out[ek] = ev
			}
		} else {
			out[k] = v
		}
		index.set(lk, k)
	}
	return out
}

// Build the H/2 headers map for an outgoing request. Pseudo-headers come first in the
// profile-defined order, then the profile header block (caller overrides applied in place),
// then caller-only headers. Connection-specific headers are illegal in H2 (RFC 7540 §8.1.2.2)
// and are dropped even if the caller passes them.
export interface H2HeaderInput {
	method: string
	host: string
	path: string
	userHeaders?: HeaderMap | null
	profile?: Profile | null
}

function buildH2Headers({ method, host, path, userHeaders, profile }: H2HeaderInput): HeaderMap {
	const order = pseudoOrderFromProfile(profile)
	// A caller-supplied Host header overrides :authority and is NEVER emitted as a regular h2
	// header — Chrome carries the origin only in :authority, so a stray `host` header is a tell.
	let hostOverride: HeaderValue
	if (userHeaders) for (const k of Object.keys(userHeaders)) if (k.toLowerCase() === 'host') hostOverride = userHeaders[k]
	const pseudoVals: Record<string, HeaderValue> = { ':method': method, ':authority': hostOverride ?? host, ':scheme': 'https', ':path': path }
	const h: HeaderMap = {}
	for (const k of order) {
		if (pseudoVals[k] != null) h[k] = pseudoVals[k]
	}
	// Any pseudo we know about but isn't in the profile's order — append for safety.
	for (const [k, v] of Object.entries(pseudoVals)) {
		if (h[k] == null) h[k] = v
	}
	const FORBIDDEN_H2 = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'proxy-connection'])
	for (const [k, v] of Object.entries(mergeProfileHeaders(userHeaders, profile))) {
		const lk = k.toLowerCase()
		if (FORBIDDEN_H2.has(lk)) continue
		h[lk] = v
	}
	return h
}

// HTTP/1.1 header block builder. Returns a CRLF-joined header section (no leading request line).
// Host is builder-managed (RFC 7230 §5.4 — exactly one Host, first) so a caller-supplied Host
// overrides the URL-derived value rather than producing a duplicate line.
export interface H1HeaderInput {
	host: string
	userHeaders?: HeaderMap | null
	profile?: Profile | null
}

function buildH1Headers({ host, userHeaders, profile }: H1HeaderInput): string {
	let hostOverride: HeaderValue
	if (userHeaders) for (const [k, v] of Object.entries<HeaderValue>(userHeaders)) {
		if (k.toLowerCase() === 'host') { hostOverride = v; break }
	}
	const hostValue = hostOverride ?? host
	const lines = [`Host: ${hostValue}`]
	for (const [k, v] of Object.entries(mergeProfileHeaders(userHeaders, profile))) {
		lines.push(`${k}: ${v}`)
	}
	return lines.join('\r\n')
}

export { buildH2Headers, buildH1Headers, mergeProfileHeaders }
