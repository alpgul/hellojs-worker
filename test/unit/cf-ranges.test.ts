// Cloudflare's published ranges. The feed is remote, so every case here injects a fetch: the point
// is that routing always gets a usable list, never a throw and never an empty set.

import { describe, expect, it, beforeEach } from 'vitest'

import { getCfRanges, getCfRangesSnapshot, parseCfRanges, resetCfRanges } from '../../lib/cf-ranges.ts'
import { ipInAny } from '../../lib/cidr.ts'

// Ten prefixes, matching the real feed's shape closely enough to clear the plausibility guard.
const V4 = `104.16.0.0/13
172.64.0.0/13
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18`
const V6 = `2606:4700::/32
2400:cb00::/32`
const TOTAL = 10

function feed(v4: string, v6: string, status = 200) {
	const calls: string[] = []
	const fetchImpl = (async (input: string | URL | Request) => {
		const url = String(input)
		calls.push(url)
		const body = url.endsWith('ips-v4') ? v4 : v6
		return new Response(status === 200 ? body : 'nope', { status })
	}) as unknown as typeof fetch
	return { fetchImpl, calls }
}

describe('parseCfRanges', () => {
	it('merges both families and keeps them apart', () => {
		const ranges = parseCfRanges(V4, V6)
		expect(ranges.filter((entry) => entry.family === 4)).toHaveLength(8)
		expect(ranges.filter((entry) => entry.family === 6)).toHaveLength(2)
		expect(ipInAny('104.16.1.1', ranges)).toBe(true)
		expect(ipInAny('2606:4700::1', ranges)).toBe(true)
		expect(ipInAny('93.184.216.34', ranges)).toBe(false)
	})

	it('drops a feed entry of the wrong family', () => {
		// v4 feed carrying v6 prefixes and vice versa: nothing survives the filter.
		expect(parseCfRanges(V6, V4)).toEqual([])
	})
})

describe('getCfRanges', () => {
	beforeEach(() => resetCfRanges())

	it('fetches both feeds once and caches the result', async () => {
		const { fetchImpl, calls } = feed(V4, V6)
		const first = await getCfRanges({ fetchImpl })
		const second = await getCfRanges({ fetchImpl })
		expect(first).toBe(second)
		expect(first).toHaveLength(TOTAL)
		expect(calls).toHaveLength(2)
	})

	it('refetches once the TTL expires', async () => {
		const { fetchImpl, calls } = feed(V4, V6)
		await getCfRanges({ fetchImpl, ttlMs: 0 })
		await getCfRanges({ fetchImpl, ttlMs: 0 })
		expect(calls).toHaveLength(4)
	})

	it('falls back to the snapshot on a non-200', async () => {
		const { fetchImpl } = feed(V4, V6, 503)
		const ranges = await getCfRanges({ fetchImpl })
		expect(ranges.length).toBe(getCfRangesSnapshot().length)
		expect(ipInAny('104.16.1.1', ranges)).toBe(true)
	})

	it('falls back to the snapshot when the feed parses to almost nothing', async () => {
		const { fetchImpl } = feed('<html>blocked</html>', '<html>blocked</html>')
		const ranges = await getCfRanges({ fetchImpl })
		expect(ranges.length).toBe(getCfRangesSnapshot().length)
	})

	it('keeps serving the last good list after a later failure', async () => {
		await getCfRanges({ fetchImpl: feed(V4, V6).fetchImpl })
		const broken = feed(V4, V6, 500).fetchImpl
		await expect(getCfRanges({ fetchImpl: broken, force: true })).resolves.toHaveLength(TOTAL)
	})

	it('never throws', async () => {
		const fetchImpl = (async () => {
			throw new Error('network down')
		}) as unknown as typeof fetch
		await expect(getCfRanges({ fetchImpl })).resolves.toHaveLength(getCfRangesSnapshot().length)
	})
})

describe('snapshot', () => {
	it('is bundled, non-empty and covers both families', () => {
		const ranges = getCfRangesSnapshot()
		expect(ranges.filter((entry) => entry.family === 4).length).toBeGreaterThan(10)
		expect(ranges.filter((entry) => entry.family === 6).length).toBeGreaterThan(3)
		expect(ipInAny('104.16.1.1', ranges)).toBe(true)
		expect(ipInAny('2606:4700::1', ranges)).toBe(true)
		expect(ipInAny('8.8.8.8', ranges)).toBe(false)
	})
})
