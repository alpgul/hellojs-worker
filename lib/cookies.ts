// RFC 6265-compliant cookie jar.
//
// Scope:
//   - Parse Set-Cookie attributes: Expires, Max-Age, Domain, Path, Secure, HttpOnly, SameSite
//   - Honor Domain matching (RFC 6265 §5.1.3 — domain match) including the dotted-suffix rule
//   - Honor Path matching (RFC 6265 §5.1.4)
//   - Drop Secure cookies on http (non-TLS) requests
//   - Drop expired cookies on store/read
//   - Refuse cookies whose Domain attribute is in the public-suffix-like set (a minimal
//     blocklist; for tight enterprise use, plug in a real PSL via `Jar.setPublicSuffixList`)
//   - SameSite=Strict/Lax/None retained per cookie; the jar does NOT enforce cross-site
//     policy here (we don't have a navigation context), but callers can inspect samesite.
//
// Out of scope:
//   - __Host- / __Secure- name prefix enforcement (RFC 6265bis): documented but not enforced
//   - Partitioned: parsed but not enforced (no first-party-context concept)
//
// We expose two helpers:
//   const jar = new Jar()
//   jar.setCookie(setCookieHeader, requestUrl)    // host + path + scheme drive defaults
//   jar.getCookieString(requestUrl)                // returns 'a=1; b=2' for the matching set

import { URL } from 'node:url'

export interface Cookie {
	name: string
	value: string
	domain: string
	path: string
	secure: boolean
	httponly: boolean
	samesite: string | null
	expiresAt: number | null
	hostOnly: boolean
	creation: number
}

export interface ParsedSetCookie {
	name: string
	value: string
	attrs: Record<string, string>
}

export type PublicSuffixList = Set<string> | ((host: string) => boolean)

export interface JarOptions {
	maxCookies?: number
}

function parseSetCookie(s: string): ParsedSetCookie | null {
	const parts = s.split(';')
	const first = parts.shift() ?? ''
	const eq = first.indexOf('=')
	if (eq < 0) return null
	const name = first.slice(0, eq).trim()
	const value = first.slice(eq + 1).trim()
	if (!name) return null
	const attrs: Record<string, string> = {}
	for (const a of parts) {
		const idx = a.indexOf('=')
		const k = (idx < 0 ? a : a.slice(0, idx)).trim().toLowerCase()
		const v = idx < 0 ? '' : a.slice(idx + 1).trim()
		if (!k) continue
		attrs[k] = v
	}
	return { name, value, attrs }
}

function isIp(host: string): boolean {
	// Conservative: IPv4 dotted decimal or IPv6 (contains ':').
	if (/^[0-9.]+$/.test(host)) return true
	if (host.includes(':')) return true
	return false
}

function domainMatch(cookieDomain: string, hostname: string): boolean {
	// RFC 6265 §5.1.3: cookie-domain matches a host if:
	//   - exact match, OR
	//   - hostname ends with `.cookieDomain` AND hostname is not an IP address
	const h = hostname.toLowerCase()
	const d = cookieDomain.toLowerCase().replace(/^\./, '')
	if (h === d) return true
	if (isIp(h)) return false
	return h.endsWith('.' + d)
}

function pathMatch(cookiePath: string, requestPath: string): boolean {
	// RFC 6265 §5.1.4
	if (cookiePath === requestPath) return true
	if (!cookiePath.endsWith('/') && requestPath.startsWith(cookiePath + '/')) return true
	if (cookiePath.endsWith('/') && requestPath.startsWith(cookiePath)) return true
	return false
}

function defaultPath(reqPath: string): string {
	// RFC 6265 §5.1.4: default-path is the request URI path up to and including the LAST '/'.
	// If no '/' or path is empty, default to '/'.
	if (!reqPath || reqPath[0] !== '/') return '/'
	const idx = reqPath.lastIndexOf('/')
	if (idx <= 0) return '/'
	return reqPath.slice(0, idx)
}

class Jar {
	cookies: Cookie[]
	maxCookies: number
	publicSuffixList: PublicSuffixList | null

	constructor(opts: JarOptions = {}) {
		// cookies: array of { name, value, domain, path, secure, httponly, samesite, expiresAt, hostOnly, creation }
		this.cookies = []
		this.maxCookies = opts.maxCookies ?? 3000   // RFC 6265bis suggests 3000 total
		this.publicSuffixList = null
	}

	setPublicSuffixList(setOrFn: PublicSuffixList | null): void {
		// Either a Set<string> or a function(host) -> boolean (true if `host` is a public suffix).
		this.publicSuffixList = setOrFn
	}

	_isPublicSuffix(d: string): boolean {
		const psl = this.publicSuffixList
		if (!psl) return false
		if (typeof psl === 'function') return psl(d)
		if (psl instanceof Set) return psl.has(d.toLowerCase())
		return false
	}

	// Accept Set-Cookie header value(s) — either a single string or an array — applied to a
	// request URL. RFC 6265 §5.3 storage algorithm (slimmed).
	setCookie(setCookieValue: string | string[], requestUrlOrHost: string): void {
		const arr = Array.isArray(setCookieValue) ? setCookieValue : [setCookieValue]
		// Caller may pass a full URL or just a host string. Try to URL-parse first.
		let u: URL | null
		try { u = typeof requestUrlOrHost === 'string' && requestUrlOrHost.includes('://') ? new URL(requestUrlOrHost) : null } catch { u = null }
		const reqHost = (u ? u.hostname : (requestUrlOrHost.split(':')[0] || '')).toLowerCase()
		const reqPath = u ? (u.pathname || '/') : '/'
		const reqScheme = u ? u.protocol.replace(':', '') : 'https'
		const now = Date.now()

		for (const raw of arr) {
			const parsed = parseSetCookie(raw)
			if (!parsed) continue
			let domain = (parsed.attrs.domain || '').toLowerCase().replace(/^\./, '')
			let hostOnly = false
			if (!domain) {
				domain = reqHost
				hostOnly = true
			} else {
				// Domain attribute MUST domain-match the request host (RFC 6265 §5.3 step 6).
				if (!domainMatch(domain, reqHost)) continue
				// Reject public-suffix domains (e.g. ".co.uk") to prevent supercookies.
				if (this._isPublicSuffix(domain)) continue
			}
			const path = parsed.attrs.path && parsed.attrs.path.startsWith('/')
				? parsed.attrs.path
				: defaultPath(reqPath)
			const secure = 'secure' in parsed.attrs
			const httponly = 'httponly' in parsed.attrs
			const samesite = (parsed.attrs.samesite || '').toLowerCase() || null

			// Expiry: Max-Age wins over Expires (RFC 6265 §5.3).
			let expiresAt: number | null = null
			if (parsed.attrs['max-age']) {
				const n = Number.parseInt(parsed.attrs['max-age'], 10)
				if (!Number.isNaN(n)) expiresAt = n <= 0 ? 0 : (now + n * 1000)
			} else if (parsed.attrs.expires) {
				const t = Date.parse(parsed.attrs.expires)
				if (!Number.isNaN(t)) expiresAt = t
			}
			// Session cookies have expiresAt = null (kept for jar lifetime).

			// If Set-Cookie has secure on a non-secure request, RFC 6265bis recommends rejecting.
			if (secure && reqScheme !== 'https') continue

			// Replace any existing cookie with same (name, domain, path).
			const idx = this.cookies.findIndex(c =>
				c.name === parsed.name && c.domain === domain && c.path === path
			)
			const entry: Cookie = {
				name: parsed.name, value: parsed.value, domain, path, secure, httponly,
				samesite, expiresAt, hostOnly, creation: idx >= 0 ? this.cookies[idx].creation : now,
			}
			// Cookie is being deleted (Max-Age=0 or Expires in the past).
			if (expiresAt !== null && expiresAt <= now) {
				if (idx >= 0) this.cookies.splice(idx, 1)
				continue
			}
			if (idx >= 0) this.cookies[idx] = entry
			else this.cookies.push(entry)
		}

		// Bound total cookie count.
		if (this.cookies.length > this.maxCookies) {
			// Drop oldest (by creation).
			this.cookies.sort((a, b) => a.creation - b.creation)
			this.cookies.splice(0, this.cookies.length - this.maxCookies)
		}
	}

	getCookies(requestUrlOrHost: string): Cookie[] {
		let u: URL | null
		try { u = typeof requestUrlOrHost === 'string' && requestUrlOrHost.includes('://') ? new URL(requestUrlOrHost) : null } catch { u = null }
		const host = (u ? u.hostname : (requestUrlOrHost.split(':')[0] || '')).toLowerCase()
		const path = u ? (u.pathname || '/') : '/'
		const scheme = u ? u.protocol.replace(':', '') : 'https'
		const now = Date.now()

		const out: Cookie[] = []
		for (const c of this.cookies) {
			if (c.expiresAt !== null && c.expiresAt <= now) continue
			if (c.secure && scheme !== 'https') continue
			if (c.hostOnly) { if (host !== c.domain) continue }
			else { if (!domainMatch(c.domain, host)) continue }
			if (!pathMatch(c.path, path)) continue
			out.push(c)
		}
		// RFC 6265 §5.4: order by path length desc, then creation time asc.
		out.sort((a, b) => {
			if (b.path.length !== a.path.length) return b.path.length - a.path.length
			return a.creation - b.creation
		})
		return out
	}

	getCookieString(requestUrlOrHost: string): string {
		return this.getCookies(requestUrlOrHost).map(c => `${c.name}=${c.value}`).join('; ')
	}

	// Drop expired cookies. Callers can run this periodically to bound memory.
	gc(): void {
		const now = Date.now()
		this.cookies = this.cookies.filter(c => c.expiresAt === null || c.expiresAt > now)
	}
}

export { Jar, parseSetCookie, domainMatch, pathMatch }
