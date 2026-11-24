// CIDR parsing and membership. Pure functions over strings — no DNS, no sockets, no runtime.

import { describe, expect, it } from 'vitest'

import { ipInAny, ipInCidr, parseCidr, parseCidrList } from '../../lib/cidr.ts'

function cidr(text: string) {
	const parsed = parseCidr(text)
	if (!parsed) throw new Error(`expected ${text} to parse`)
	return parsed
}

describe('parseCidr', () => {
	it('parses IPv4 prefixes and masks host bits off the base', () => {
		const net = cidr('10.1.2.3/24')
		expect(net.family).toBe(4)
		expect(net.bits).toBe(24)
		expect(net.base).toBe(0x0a010200n)
	})

	it('treats a bare address as a single-host prefix', () => {
		expect(cidr('104.16.0.1')).toMatchObject({ family: 4, bits: 32 })
		expect(cidr('2606:4700::1')).toMatchObject({ family: 6, bits: 128 })
	})

	it('rejects malformed input instead of throwing', () => {
		for (const bad of [
			'',
			'not-an-ip',
			'10.0.0.256',
			'10.0.0',
			'10.0.0.0/33',
			'10.0.0.0/',
			'10.0.0.0/abc',
			'::1::2',
			'1.2.3.4.5',
			'fe80::1%eth0'
		]) {
			expect(parseCidr(bad), bad).toBeNull()
		}
	})

	it('parses IPv6 with and without compression', () => {
		expect(cidr('2606:4700::/32').base).toBe(0x2606_4700n << 96n)
		expect(cidr('::1/128').base).toBe(1n)
		expect(cidr('2400:cb00:0000:0000:0000:0000:0000:0000/32').bits).toBe(32)
	})
})

describe('ipInCidr', () => {
	it('matches the network and its edges but not the neighbour', () => {
		const net = cidr('10.0.0.0/24')
		expect(ipInCidr('10.0.0.0', net)).toBe(true)
		expect(ipInCidr('10.0.0.255', net)).toBe(true)
		expect(ipInCidr('10.0.1.0', net)).toBe(false)
	})

	it('handles the degenerate prefixes', () => {
		expect(ipInCidr('8.8.8.8', cidr('0.0.0.0/0'))).toBe(true)
		expect(ipInCidr('104.16.0.1', cidr('104.16.0.1/32'))).toBe(true)
		expect(ipInCidr('104.16.0.2', cidr('104.16.0.1/32'))).toBe(false)
	})

	it('never crosses families', () => {
		expect(ipInCidr('104.16.0.1', cidr('2606:4700::/32'))).toBe(false)
		expect(ipInCidr('2606:4700::1', cidr('104.16.0.0/13'))).toBe(false)
	})

	it('normalises IPv4-mapped IPv6 to IPv4', () => {
		expect(ipInCidr('::ffff:104.16.0.1', cidr('104.16.0.0/13'))).toBe(true)
		expect(ipInCidr('::ffff:8.8.8.8', cidr('104.16.0.0/13'))).toBe(false)
	})

	it('returns false for a hostname rather than guessing', () => {
		expect(ipInCidr('example.com', cidr('0.0.0.0/0'))).toBe(false)
	})
})

describe('parseCidrList', () => {
	it('accepts newline, comma and space separated feeds and drops junk lines', () => {
		const list = parseCidrList('104.16.0.0/13\n# comment\n172.64.0.0/13, 2606:4700::/32\n\nnonsense')
		expect(list).toHaveLength(3)
		expect(list.map((entry) => entry.family)).toEqual([4, 4, 6])
	})

	it('answers an empty list for an empty feed', () => {
		expect(parseCidrList('')).toEqual([])
		expect(ipInAny('104.16.0.1', [])).toBe(false)
	})
})
