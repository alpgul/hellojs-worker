// DNS cache: caching, TTL, in-flight dedupe, failure handling, lookup callback shapes.

import { beforeEach, expect, it } from 'vitest'

import {
	cachedLookup,
	clearDnsCache,
	configureDnsCache,
	dnsCacheAvailable,
	resolveHost,
	setResolverForTests
} from '../../lib/dns-cache.ts'

beforeEach(() => {
	configureDnsCache({ ttlMs: 30_000, maxEntries: 256 })
	setResolverForTests(null)
	clearDnsCache()
})

it('resolves once per host inside the TTL', async () => {
	let calls = 0
	setResolverForTests(async () => {
		calls++
		return [{ address: '192.0.2.1', family: 4 }]
	})
	const first = await resolveHost('cache.test')
	const second = await resolveHost('cache.test')
	expect(second).toStrictEqual(first)
	expect(calls).toBe(1)
})

it('shares one in-flight lookup between concurrent callers', async () => {
	let calls = 0
	setResolverForTests(async () => {
		calls++
		await new Promise((resolve) => setTimeout(resolve, 10))
		return [{ address: '192.0.2.2', family: 4 }]
	})
	const [a, b] = await Promise.all([resolveHost('inflight.test'), resolveHost('inflight.test')])
	expect(a).toStrictEqual(b)
	expect(calls).toBe(1)
})

it('re-resolves after the TTL', async () => {
	configureDnsCache({ ttlMs: 10 })
	let calls = 0
	setResolverForTests(async () => {
		calls++
		return [{ address: `192.0.2.${calls}`, family: 4 }]
	})
	await resolveHost('ttl.test')
	await resolveHost('ttl.test')
	expect(calls).toBe(1)
	await new Promise((resolve) => setTimeout(resolve, 25))
	await resolveHost('ttl.test')
	expect(calls).toBe(2)
})

it('does not cache failures', async () => {
	let calls = 0
	setResolverForTests(async () => {
		calls++
		if (calls === 1) {
			const err = new Error('temporary failure') as NodeJS.ErrnoException
			err.code = 'EAI_AGAIN'
			throw err
		}
		return [{ address: '192.0.2.3', family: 4 }]
	})
	await expect(resolveHost('failure.test')).rejects.toThrow(/temporary failure/)
	const addresses = await resolveHost('failure.test')
	expect(addresses).toHaveLength(1)
	expect(calls).toBe(2)
})

it('returns IP literals without consulting the resolver', async () => {
	let calls = 0
	setResolverForTests(async () => {
		calls++
		return []
	})
	expect(await resolveHost('127.0.0.1')).toStrictEqual([{ address: '127.0.0.1', family: 4 }])
	expect(await resolveHost('::1')).toStrictEqual([{ address: '::1', family: 6 }])
	expect(calls).toBe(0)
})

it('cachedLookup mirrors the dns.lookup callback shapes', async () => {
	setResolverForTests(async () => [
		{ address: '192.0.2.7', family: 4 },
		{ address: '2001:db8::7', family: 6 }
	])
	const lookup = (options: { all?: boolean; family?: number }): Promise<unknown> =>
		new Promise((resolve, reject) => {
			cachedLookup('shapes.test', options, (err, address, family) => {
				if (err) reject(err)
				else resolve({ address, family })
			})
		})
	expect(await lookup({ all: true })).toStrictEqual({
		address: [
			{ address: '192.0.2.7', family: 4 },
			{ address: '2001:db8::7', family: 6 }
		],
		family: undefined
	})
	expect(await lookup({ family: 4 })).toStrictEqual({ address: '192.0.2.7', family: 4 })
	expect(await lookup({ family: 6 })).toStrictEqual({ address: '2001:db8::7', family: 6 })
})

it('reports dns cache availability on Node', () => {
	expect(dnsCacheAvailable()).toBe(true)
})
