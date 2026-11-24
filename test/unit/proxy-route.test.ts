// Automatic routing. The decision is DNS + CIDR + pool, all three injectable, so these cases pin
// the policy without a socket: which hosts get a proxy, when the pool's absence stays silent, and
// which error a Cloudflare-owned target surfaces when nothing can serve it.

import { describe, expect, it, beforeEach, afterEach } from 'vitest'

import { getCfRanges, resetCfRanges } from '../../lib/cf-ranges.ts'
import { setResolverForTests } from '../../lib/dns-cache.ts'
import { HellojsError } from '../../lib/errors.ts'
import { blockedTargetError, isDisallowedTarget, rerouteProxy, resolveAutoProxy } from '../../lib/proxy-route.ts'
import { clearProxyPool, recordProxyOutcome, setProxyPool } from '../../lib/proxy-store.ts'

const A = { url: 'http://127.0.0.1:8080' }
const B = { url: 'http://127.0.0.1:8081' }
const CF_FEED_V4 = `104.16.0.0/13
172.64.0.0/13
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18`

/** Prime the shared range cache so routing never touches the network in a test. */
async function primeRanges() {
	await getCfRanges({
		fetchImpl: (async (input: string | URL | Request) =>
			new Response(String(input).endsWith('ips-v4') ? CF_FEED_V4 : '2606:4700::/32')) as unknown as typeof fetch
	})
}

function resolveTo(...addresses: string[]) {
	setResolverForTests(async () => addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })))
}

describe('resolveAutoProxy', () => {
	beforeEach(async () => {
		clearProxyPool()
		resetCfRanges()
		setResolverForTests(null)
		await primeRanges()
	})

	afterEach(() => {
		clearProxyPool()
		setResolverForTests(null)
	})

	it('routes a Cloudflare-owned host through the pool', async () => {
		setProxyPool([A])
		resolveTo('104.16.1.1')
		await expect(resolveAutoProxy('cf.example')).resolves.toMatchObject({ proxy: A, url: A.url })
	})

	it('leaves a host outside the ranges direct', async () => {
		setProxyPool([A])
		resolveTo('93.184.216.34')
		await expect(resolveAutoProxy('direct.example')).resolves.toBeNull()
	})

	it('stays direct when any address escapes the ranges', async () => {
		setProxyPool([A])
		resolveTo('104.16.1.1', '93.184.216.34')
		await expect(resolveAutoProxy('mixed.example')).resolves.toBeNull()
	})

	it('does no work at all with an empty pool', async () => {
		resolveTo('104.16.1.1')
		await expect(resolveAutoProxy('cf.example')).resolves.toBeNull()
	})

	it('keeps the direct path when the name cannot be resolved', async () => {
		setProxyPool([A])
		setResolverForTests(async () => {
			throw new Error('ENOTFOUND')
		})
		await expect(resolveAutoProxy('nowhere.example')).resolves.toBeNull()
	})

	it('fails loudly when the pool cannot serve a Cloudflare-owned host', async () => {
		setProxyPool([A])
		resolveTo('104.16.1.1')
		recordProxyOutcome(A, 'cf.example', 'blocked')
		await expect(resolveAutoProxy('cf.example')).rejects.toMatchObject({ code: 'ENOPROXY' })
	})
})

describe('rerouteProxy', () => {
	beforeEach(() => {
		clearProxyPool()
		setProxyPool([A, B])
	})
	afterEach(() => clearProxyPool())

	it('skips the proxy that just failed', async () => {
		const next = rerouteProxy('example.com', new Set(['http://127.0.0.1:8080']))
		expect(next).toMatchObject({ proxy: B, url: B.url })
	})

	it('returns null when everything was already tried', () => {
		expect(rerouteProxy('example.com', new Set(['http://127.0.0.1:8080', 'http://127.0.0.1:8081']))).toBeNull()
	})
})

describe('Cloudflare block detection', () => {
	it('recognises the runtime refusal, including when it arrives as a cause', () => {
		expect(isDisallowedTarget(new Error('proxy request failed, cannot connect to the specified address'))).toBe(
			true
		)
		expect(
			isDisallowedTarget(
				new Error('connect failed', { cause: new Error('cannot connect to the specified address') })
			)
		).toBe(true)
	})

	it('ignores unrelated failures', () => {
		expect(isDisallowedTarget(new Error('ECONNRESET'))).toBe(false)
		expect(isDisallowedTarget('not an error')).toBe(false)
	})

	it('reports ENOPROXY for an empty pool and ECFIPBLOCKED when proxies exist but none worked', () => {
		clearProxyPool()
		expect(blockedTargetError('cf.example', null)).toMatchObject({ code: 'ENOPROXY' })
		setProxyPool([A])
		expect(blockedTargetError('cf.example', null)).toMatchObject({ code: 'ECFIPBLOCKED' })
		clearProxyPool()
	})

	it('keeps the original error as the cause', () => {
		const cause = new Error('boom')
		const err = blockedTargetError('cf.example', cause)
		expect(err).toBeInstanceOf(HellojsError)
		expect(err.cause).toBe(cause)
	})
})
