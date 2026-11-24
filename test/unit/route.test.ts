// Route policy: a host is either directly dialable or Cloudflare-owned. No DNS here — the caller
// supplies the addresses — so these cases pin the rule itself.

import { describe, expect, it } from 'vitest'

import { parseCidrList } from '../../lib/cidr.ts'
import { planRoute } from '../../lib/route.ts'

const RANGES = parseCidrList('104.16.0.0/13\n172.64.0.0/13\n2606:4700::/32')
const CF_V4 = { address: '104.16.1.1' }
const CF_V6 = { address: '2606:4700::1' }
const OTHER_V4 = { address: '93.184.216.34' }

describe('planRoute', () => {
	it('routes to a proxy when every address is Cloudflare-owned', () => {
		expect(planRoute([CF_V4], RANGES)).toBe('proxy')
		expect(planRoute([CF_V4, CF_V6], RANGES)).toBe('proxy')
	})

	it('stays direct when a single address escapes the ranges', () => {
		expect(planRoute([OTHER_V4], RANGES)).toBe('direct')
		expect(planRoute([CF_V4, OTHER_V4], RANGES)).toBe('direct')
	})

	it('stays direct on no evidence', () => {
		expect(planRoute([], RANGES)).toBe('direct')
	})

	it('treats an unusable address as not Cloudflare-owned', () => {
		expect(planRoute([{ address: 'example.com' }], RANGES)).toBe('direct')
	})
})
