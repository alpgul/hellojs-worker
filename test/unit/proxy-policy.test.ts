// The /proxy guard is pure policy: no Worker, no sockets, no DO. These cases pin down the
// difference between "an example that forwards requests" and "an open relay".

import { describe, expect, it } from 'vitest'

import { resolveProxyTarget } from '../../examples/proxy-policy.ts'

const ALLOWED = 'httpbingo.org, TLS.PEET.WS ,'

describe('resolveProxyTarget', () => {
	it('accepts an allowlisted https origin and keeps its path/query', () => {
		const result = resolveProxyTarget('https://httpbingo.org/get?a=1', ALLOWED)
		expect(result.ok).toBe(true)
		if (result.ok) expect(result.url.toString()).toBe('https://httpbingo.org/get?a=1')
	})

	it('matches hostnames case-insensitively', () => {
		expect(resolveProxyTarget('https://tls.peet.ws/api/all', ALLOWED).ok).toBe(true)
	})

	it('rejects a host outside ALLOWED_HOSTS', () => {
		const result = resolveProxyTarget('https://example.com/', ALLOWED)
		expect(result).toMatchObject({ ok: false, status: 403 })
	})

	it('denies everything when the variable is missing or empty', () => {
		expect(resolveProxyTarget('https://httpbingo.org/', undefined)).toMatchObject({ ok: false, status: 403 })
		expect(resolveProxyTarget('https://httpbingo.org/', ' , ')).toMatchObject({ ok: false, status: 403 })
	})

	it('rejects a missing or malformed url', () => {
		expect(resolveProxyTarget(null, ALLOWED)).toMatchObject({ ok: false, status: 400 })
		expect(resolveProxyTarget('not a url', ALLOWED)).toMatchObject({ ok: false, status: 400 })
	})

	it('rejects non-http schemes even for an allowlisted host', () => {
		for (const raw of ['file:///etc/passwd', 'ws://httpbingo.org', 'javascript:alert(1)']) {
			expect(resolveProxyTarget(raw, ALLOWED)).toMatchObject({ ok: false, status: 403 })
		}
	})

	it('rejects credentials embedded in the target', () => {
		expect(resolveProxyTarget('https://user:pass@httpbingo.org/', ALLOWED)).toMatchObject({
			ok: false,
			status: 403
		})
	})

	it('rejects loopback and private addresses even if allowlisted', () => {
		const wideOpen = 'localhost,127.0.0.1,10.0.0.5,192.168.1.1,[::1]'
		for (const raw of [
			'http://localhost:8787/admin',
			'http://127.0.0.1:8787/admin',
			'http://10.0.0.5/',
			'http://192.168.1.1/',
			'http://[::1]/'
		]) {
			expect(resolveProxyTarget(raw, wideOpen)).toMatchObject({ ok: false, status: 403 })
		}
	})
})
