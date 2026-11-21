// RFC 7838 cache behavior: header/frame values, freshness, invalidation, and the
// dial-target-vs-origin split consumed by the automatic transport.

import { beforeEach, describe, expect, it } from 'vitest'

import {
	authorizedAltsvcOrigin,
	clearAltSvcCache,
	forgetAltSvc,
	markAltSvcBroken,
	originKey,
	rememberAltSvc,
	selectAltSvc
} from '../../lib/alt-svc.ts'

const ORIGIN = 'https://example.com/'

beforeEach(() => clearAltSvcCache())

describe('alt-svc cache', () => {
	it('normalizes default ports in origin keys', () => {
		expect(originKey(ORIGIN)).toBe('https://example.com:443')
		expect(originKey('https://example.com:443/path')).toBe(originKey(ORIGIN))
		expect(originKey('http://EXAMPLE.com')).toBe('http://example.com:80')
	})

	it('parses h3 hints with ma and quoted authorities', () => {
		rememberAltSvc('h3=":443"; ma=3600', ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443)).toEqual({
			hint: 'h3',
			host: 'example.com',
			port: 443,
			altUsed: 'example.com:443'
		})
	})

	it('dials the advertised host while keeping the selection origin-keyed', () => {
		rememberAltSvc('h3="alt.example.net:8443"; ma=60, h2=":443"', ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443)).toMatchObject({
			hint: 'h3',
			host: 'alt.example.net',
			port: 8443
		})
		expect(selectAltSvc('https://other.example/', 'other.example', 443).hint).toBeNull()
	})

	it('prefers h2, then h1 (both skip the QUIC race)', () => {
		rememberAltSvc('h2=":443"; ma=120', ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443)).toMatchObject({ hint: 'h2', port: 443 })

		clearAltSvcCache()
		rememberAltSvc('h1=":8443"; ma=120', ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443)).toMatchObject({
			hint: 'h1',
			port: 8443,
			altUsed: 'example.com:8443'
		})
	})

	it('honors clear, 421 invalidation, and ma=0 expiry', () => {
		rememberAltSvc('h3=":443"; ma=3600', ORIGIN)
		rememberAltSvc('clear', ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443).hint).toBeNull()

		rememberAltSvc('h3=":443"; ma=3600', ORIGIN)
		forgetAltSvc(ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443).hint).toBeNull()

		rememberAltSvc('h3=":443"; ma=0', ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443).hint).toBeNull()
	})

	it('marks a dead h3 entry broken so the next request skips QUIC', () => {
		rememberAltSvc('h3=":443"; ma=3600', ORIGIN)
		markAltSvcBroken(ORIGIN, 'h3')
		expect(selectAltSvc(ORIGIN, 'example.com', 443).hint).toBeNull()
	})

	it('ignores malformed fields without poisoning the cache', () => {
		rememberAltSvc('h3="not-an-authority"; ma=60, nonsense, h3=":443"; ma=60', ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443)).toMatchObject({ hint: 'h3', port: 443 })
	})

	it('replaces all prior alternatives instead of merging them', () => {
		rememberAltSvc('h3=":443"; ma=3600, h2=":443"', ORIGIN)
		rememberAltSvc('h2=":443"; ma=3600', ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443)).toMatchObject({ hint: 'h2' })
	})

	it('lets clear win over values in the same response', () => {
		rememberAltSvc('h3=":443"; ma=3600', ORIGIN)
		rememberAltSvc(['clear', 'h3=":443"; ma=3600'], ORIGIN)
		expect(selectAltSvc(ORIGIN, 'example.com', 443).hint).toBeNull()
	})

	it('accepts only authoritative ALTSVC origins', () => {
		expect(authorizedAltsvcOrigin('https://example.com', ORIGIN, 0)).toBe('https://example.com:443')
		expect(authorizedAltsvcOrigin('', ORIGIN, 0)).toBeNull()
		expect(authorizedAltsvcOrigin('https://evil.example', ORIGIN, 0)).toBeNull()
		expect(authorizedAltsvcOrigin('not a url', ORIGIN, 0)).toBeNull()
		expect(authorizedAltsvcOrigin('', ORIGIN, 5)).toBe('https://example.com:443')
		expect(authorizedAltsvcOrigin('https://example.com', ORIGIN, 5)).toBeNull()
		expect(authorizedAltsvcOrigin(null, ORIGIN, 5)).toBeNull()
	})
})
