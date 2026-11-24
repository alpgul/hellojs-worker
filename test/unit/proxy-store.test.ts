// The proxy pool: identity, tally and selection. In memory on purpose — persistence and rotation
// are the caller's policy — so these cases cover exactly what this module owns.

import { describe, expect, it, beforeEach } from 'vitest'

import { HellojsError } from '../../lib/errors.ts'
import {
	addProxy,
	clearProxyPool,
	getProxyList,
	proxyKeyOf,
	recordProxyOutcome,
	removeProxy,
	selectProxy,
	setProxyPool
} from '../../lib/proxy-store.ts'

const A = { url: 'http://127.0.0.1:8080' }
const B = { url: 'http://127.0.0.1:8081' }

function urlOf(url: string) {
	const entry = getProxyList().find((candidate) => candidate.url === url)
	if (!entry) throw new Error(`expected ${url} in the pool`)
	return entry
}

describe('proxyKeyOf', () => {
	it('canonicalises scheme, host and trailing slash', () => {
		expect(proxyKeyOf({ url: 'HTTP://Example.COM:80/' })).toBe('http://example.com')
		expect(proxyKeyOf({ url: 'http://example.com' })).toBe('http://example.com')
		expect(proxyKeyOf({ url: '  https://proxy.example:8443/  ' })).toBe('https://proxy.example:8443')
	})

	it('rejects credentials in unsupported proxy URLs', () => {
		expect(() => proxyKeyOf({ url: 'http://user:pass@127.0.0.1:8080' })).toThrow(HellojsError)
	})

	it('allows credentials in SOCKS5 proxy URLs and keeps them in identity', () => {
		expect(proxyKeyOf({ url: 'socks5://user:pass@127.0.0.1:1080' })).toBe('socks5://user:pass@127.0.0.1:1080')
		expect(proxyKeyOf({ url: 'socks5://other:pass@127.0.0.1:1080' })).not.toBe(
			proxyKeyOf({ url: 'socks5://user:pass@127.0.0.1:1080' })
		)
	})

	it('rejects a missing or unparseable URL', () => {
		expect(() => proxyKeyOf({ url: '' })).toThrow(HellojsError)
		expect(() => proxyKeyOf({ url: 'not a url' })).toThrow(HellojsError)
		expect(() => proxyKeyOf(null)).toThrow(HellojsError)
	})
})

describe('pool membership', () => {
	beforeEach(() => clearProxyPool())

	it('starts empty', () => {
		expect(getProxyList()).toEqual([])
		expect(selectProxy('example.com')).toBeNull()
	})

	it('adds, lists and removes', () => {
		addProxy(A)
		addProxy(B)
		expect(getProxyList().map((entry) => entry.url)).toEqual(['http://127.0.0.1:8080', 'http://127.0.0.1:8081'])
		expect(removeProxy('http://127.0.0.1:8080')).toBe(true)
		expect(removeProxy('http://127.0.0.1:8080')).toBe(false)
		expect(getProxyList()).toHaveLength(1)
	})

	it('dedupes by normalised URL and keeps the tally on re-add', () => {
		addProxy(A)
		recordProxyOutcome(A, 'example.com', 'ok')
		addProxy({ url: 'HTTP://127.0.0.1:8080/' })
		const [entry] = getProxyList()
		expect(getProxyList()).toHaveLength(1)
		expect(entry?.success).toBe(1)
	})

	it('preserves generation when identical proxy is re-added', () => {
		setProxyPool([A])
		const selected = selectProxy('example.com')
		expect(selected?.url).toBe(A.url)
		addProxy({ url: 'HTTP://127.0.0.1:8080/' })
		expect(recordProxyOutcome(A, 'example.com', 'ok', selected?.generation)).toBe(true)
		expect(urlOf(A.url).success).toBe(1)
	})

	it('bumps generation when proxy config changes', () => {
		setProxyPool([A])
		const selected = selectProxy('example.com')
		addProxy({ url: A.url, authorization: 'Basic abc' })
		expect(recordProxyOutcome(A, 'example.com', 'ok', selected?.generation)).toBe(false)
		expect(urlOf(A.url).success).toBe(0)
	})

	it('setProxyPool replaces the pool and resets statistics', () => {
		addProxy(A)
		recordProxyOutcome(A, 'example.com', 'ok')
		setProxyPool([B])
		expect(getProxyList()).toHaveLength(1)
		expect(urlOf('http://127.0.0.1:8081').success).toBe(0)
	})

	it('leaves the previous pool intact when one entry is invalid', () => {
		addProxy(A)
		expect(() => setProxyPool([B, { url: 'not a url' }])).toThrow(HellojsError)
		expect(getProxyList().map((entry) => entry.url)).toEqual(['http://127.0.0.1:8080'])
	})
})

describe('outcomes', () => {
	beforeEach(() => {
		clearProxyPool()
		addProxy(A)
		addProxy(B)
	})

	it('counts success and marks the proxy live', () => {
		expect(urlOf(A.url)).toMatchObject({ success: 0, fail: 0, live: true, lastOutcome: null })
		recordProxyOutcome(A, 'example.com', 'ok')
		expect(urlOf(A.url)).toMatchObject({ success: 1, fail: 0, live: true, lastOutcome: 'ok' })
	})

	it('counts a failure and marks the proxy not live', () => {
		recordProxyOutcome(A, 'example.com', 'fail')
		expect(urlOf(A.url)).toMatchObject({ success: 0, fail: 1, live: false, lastOutcome: 'fail' })
	})

	it('counts an origin rejection as host-only denial without global failure', () => {
		setProxyPool([A])
		recordProxyOutcome(A, 'blocked.example', 'blocked')
		expect(urlOf(A.url)).toMatchObject({ fail: 0, live: true, lastOutcome: null })

		// The proxy is out for this host, still in the running everywhere else.
		expect(selectProxy('blocked.example')).toBeNull()
		expect(selectProxy('other.example')?.url).toBe(A.url)
	})

	it('clears the host denial once that host succeeds', () => {
		setProxyPool([A])
		recordProxyOutcome(A, 'example.com', 'blocked')
		expect(selectProxy('example.com')).toBeNull()
		recordProxyOutcome(A, 'example.com', 'ok')
		expect(selectProxy('example.com')?.url).toBe(A.url)
	})

	it('ignores a proxy that is not in the pool', () => {
		expect(recordProxyOutcome({ url: 'http://127.0.0.1:9999' }, 'example.com', 'ok')).toBe(false)
		expect(recordProxyOutcome({ url: 'not a url' }, 'example.com', 'ok')).toBe(false)
	})

	it('ranks a proven proxy above an untried one', () => {
		for (let i = 0; i < 5; i++) recordProxyOutcome(B, 'example.com', 'ok')
		expect(getProxyList()[0]?.url).toBe(B.url)
		expect(urlOf(A.url).score).toBe(0.5)
	})
})
