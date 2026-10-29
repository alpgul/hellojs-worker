// RFC 6265 cookie jar tests.

import { expect, it } from 'vitest'

import { Jar, parseSetCookie, domainMatch, pathMatch } from '../../lib/cookies.ts'

it('parseSetCookie: name/value + attributes', () => {
	const r = parseSetCookie('SID=abc; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600')!
	expect(r.name).toBe('SID')
	expect(r.value).toBe('abc')
	expect(r.attrs.domain).toBe('example.com')
	expect(r.attrs.path).toBe('/')
	expect(r.attrs.secure).toBe('')
	expect(r.attrs.httponly).toBe('')
	expect(r.attrs.samesite).toBe('Lax')
	expect(r.attrs['max-age']).toBe('3600')
})

it('domainMatch: exact + dotted-suffix + IP rejection', () => {
	expect(domainMatch('example.com', 'example.com')).toBe(true)
	expect(domainMatch('example.com', 'sub.example.com')).toBe(true)
	expect(domainMatch('example.com', 'evil.com')).toBe(false)
	expect(domainMatch('example.com', 'badexample.com')).toBe(false)
	expect(domainMatch('1.2.3.4', '1.2.3.4')).toBe(true)
	expect(domainMatch('1.2.3', '1.1.2.3')).toBe(false) // IP host can't match a "domain"
})

it('pathMatch: RFC 6265 rules', () => {
	expect(pathMatch('/', '/')).toBe(true)
	expect(pathMatch('/', '/foo')).toBe(true)
	expect(pathMatch('/foo', '/foo')).toBe(true)
	expect(pathMatch('/foo', '/foo/bar')).toBe(true)
	expect(pathMatch('/foo', '/foobar')).toBe(false)
	expect(pathMatch('/foo/', '/foo/bar')).toBe(true)
})

it('Jar: setCookie + getCookieString round-trip', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Path=/', 'https://example.com/')
	expect(j.getCookieString('https://example.com/')).toBe('SID=abc')
})

it('Jar: Secure cookies blocked on http', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Path=/; Secure', 'https://example.com/')
	expect(j.getCookieString('https://example.com/')).toBe('SID=abc')
	expect(j.getCookieString('http://example.com/')).toBe('')
})

it('Jar: Max-Age=0 deletes the cookie', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Path=/', 'https://example.com/')
	expect(j.getCookieString('https://example.com/')).toBe('SID=abc')
	j.setCookie('SID=abc; Path=/; Max-Age=0', 'https://example.com/')
	expect(j.getCookieString('https://example.com/')).toBe('')
})

it('Jar: Domain attribute applies to subdomains', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Domain=example.com', 'https://api.example.com/')
	expect(j.getCookieString('https://www.example.com/')).toBe('SID=abc')
	expect(j.getCookieString('https://example.com/')).toBe('SID=abc')
	expect(j.getCookieString('https://example.org/')).toBe('')
})

it('Jar: hostOnly cookie does NOT cross subdomains', () => {
	const j = new Jar()
	j.setCookie('SID=abc; Path=/', 'https://api.example.com/')
	expect(j.getCookieString('https://api.example.com/')).toBe('SID=abc')
	expect(j.getCookieString('https://www.example.com/')).toBe('')
})

it('Jar: Domain MUST domain-match the request host (cross-site rejection)', () => {
	const j = new Jar()
	// Setting a cookie for evil.com from example.com is rejected.
	j.setCookie('SID=evil; Domain=evil.com', 'https://example.com/')
	expect(j.getCookieString('https://evil.com/')).toBe('')
})

it('Jar: Path defaulting follows RFC 6265 §5.1.4', () => {
	const j = new Jar()
	j.setCookie('A=1', 'https://example.com/foo/bar')
	// Default-path = '/foo'. Cookie should appear on /foo and /foo/anything, not /.
	expect(j.getCookieString('https://example.com/foo/')).toBe('A=1')
	expect(j.getCookieString('https://example.com/foo/x')).toBe('A=1')
	expect(j.getCookieString('https://example.com/bar')).toBe('')
})

it('Jar: Path attribute when set is honored', () => {
	const j = new Jar()
	j.setCookie('A=1; Path=/admin', 'https://example.com/')
	expect(j.getCookieString('https://example.com/admin')).toBe('A=1')
	expect(j.getCookieString('https://example.com/')).toBe('')
})

it('Jar: longer path is sent first (RFC 6265 §5.4)', () => {
	const j = new Jar()
	j.setCookie('A=root; Path=/', 'https://example.com/')
	j.setCookie('B=deep; Path=/api', 'https://example.com/')
	expect(j.getCookieString('https://example.com/api/x')).toMatch(/^B=deep; A=root$/)
})

it('Jar: expired Expires drops cookie', () => {
	const j = new Jar()
	j.setCookie('A=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT', 'https://example.com/')
	expect(j.getCookieString('https://example.com/')).toBe('')
})

it('Jar: public suffix list blocks Domain=co.uk', () => {
	const j = new Jar()
	j.setPublicSuffixList(new Set(['co.uk']))
	j.setCookie('SID=evil; Domain=co.uk', 'https://example.co.uk/')
	expect(j.getCookieString('https://example.co.uk/')).toBe('')
})

it('Jar: gc() removes expired cookies', () => {
	const j = new Jar()
	j.setCookie('A=1; Max-Age=1', 'https://example.com/')
	expect(j.cookies.length).toBe(1)
	// Force-expire
	j.cookies[0].expiresAt = Date.now() - 1
	j.gc()
	expect(j.cookies.length).toBe(0)
})
