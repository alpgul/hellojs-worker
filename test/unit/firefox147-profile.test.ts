// Firefox 147 profile: pinned TLS/HTTP2 fingerprint values and header behaviour.

import { expect, it } from 'vitest'

import { buildH2Headers } from '../../lib/headers.ts'
import firefox from '../../lib/profiles/firefox147.ts'
import * as profiles from '../../lib/profiles/index.ts'

it('firefox147 is registered', () => {
	expect(profiles.get('firefox147').name).toBe('firefox147')
	expect(profiles.list()).toContain('firefox147')
})

it('firefox147 cipher order matches the Firefox 147 offer', () => {
	expect(firefox.tls.ciphers).toStrictEqual([
		0x1301, 0x1303, 0x1302,
		0xc02b, 0xc02f, 0xcca9, 0xcca8,
		0xc02c, 0xc030,
		0xc00a, 0xc009, 0xc013, 0xc014,
		0x009c, 0x009d, 0x002f, 0x0035
	])
})

it('firefox147 extension order is preserved and fully buildable', () => {
	expect(firefox.tls.extensionPermutation).toBe('preserve')
	expect(firefox.tls.useGrease).toBe(false)
	expect(firefox.tls.extensionOrder.map((e) => e.id)).toStrictEqual([
		0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037
	])

	// Semantic builders in lib/tls/tls.ts; 34 and 28 come from rawExtensionBodies.
	const semantic = new Set([0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 65037, 65281])
	const rawBodies = firefox.tls.rawExtensionBodies as Record<number, Buffer | undefined>
	for (const e of firefox.tls.extensionOrder) {
		expect(semantic.has(e.id) || rawBodies[e.id], `extension ${e.id} has no builder`).toBeTruthy()
	}
})

it('firefox147 groups, versions and key shares', () => {
	expect(firefox.tls.supportedGroups).toStrictEqual([0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101])
	expect(firefox.tls.supportedVersions).toStrictEqual([0x0304, 0x0303])
	expect(firefox.tls.keyShareGroups).toStrictEqual([0x11ec, 0x001d])
	expect(firefox.tls.certCompressionAlgorithms).toStrictEqual([0x0001, 0x0002, 0x0003])
})

it('firefox147 http2 fingerprint values', () => {
	expect(Object.keys(firefox.http2.settings)).toStrictEqual([
		'headerTableSize',
		'enablePush',
		'initialWindowSize',
		'maxFrameSize'
	])
	expect(firefox.http2.settings.initialWindowSize).toBe(131_072)
	expect(firefox.http2.windowUpdateIncrement).toBe(12_517_377)
	expect(firefox.http2.priority).toStrictEqual({ weight: 42, exclusive: false, parent: 0 })
	expect(firefox.http2.pseudoHeaderOrder).toStrictEqual([':method', ':path', ':authority', ':scheme'])
})

it('firefox147 headers are emitted in profile order with m,p,a,s pseudo-headers', () => {
	const h = buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: {}, profile: firefox })
	expect(Object.keys(h)).toStrictEqual([
		':method',
		':path',
		':authority',
		':scheme',
		'user-agent',
		'accept',
		'accept-language',
		'accept-encoding',
		'upgrade-insecure-requests',
		'sec-fetch-dest',
		'sec-fetch-mode',
		'sec-fetch-site',
		'sec-fetch-user',
		'priority',
		'te'
	])
	expect(h['user-agent']).toBe(firefox.userAgent)
	expect(h.te).toBe('trailers')
})

it('firefox147 fixes only the user-agent', () => {
	expect(() =>
		buildH2Headers({
			method: 'GET',
			host: 'example.com',
			path: '/',
			userHeaders: { 'user-agent': 'spoofed' },
			profile: firefox
		})
	).toThrow(expect.objectContaining({ code: 'EHEADERFIXED' }))
	const h = buildH2Headers({
		method: 'GET',
		host: 'example.com',
		path: '/',
		userHeaders: { accept: 'application/json' },
		profile: firefox
	})
	expect(h.accept).toBe('application/json')
	expect(h['sec-fetch-site']).toBe('none')
})
