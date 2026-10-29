// Firefox 147 profile: pinned TLS/HTTP2 fingerprint values and header behaviour.

import assert from 'node:assert'
import test from 'node:test'

import { buildH2Headers } from '../../lib/headers.ts'
import firefox from '../../lib/profiles/firefox147.ts'
import * as profiles from '../../lib/profiles/index.ts'

test('firefox147 is registered', () => {
	assert.strictEqual(profiles.get('firefox147').name, 'firefox147')
	assert.ok(profiles.list().includes('firefox147'))
})

test('firefox147 cipher order matches the Firefox 147 offer', () => {
	assert.deepStrictEqual(firefox.tls.ciphers, [
		0x1301, 0x1303, 0x1302,
		0xc02b, 0xc02f, 0xcca9, 0xcca8,
		0xc02c, 0xc030,
		0xc00a, 0xc009, 0xc013, 0xc014,
		0x009c, 0x009d, 0x002f, 0x0035,
	])
})

test('firefox147 extension order is preserved and fully buildable', () => {
	assert.strictEqual(firefox.tls.extensionPermutation, 'preserve')
	assert.strictEqual(firefox.tls.useGrease, false)
	assert.deepStrictEqual(
		firefox.tls.extensionOrder.map((e) => e.id),
		[0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037],
	)

	// Semantic builders in lib/tls/tls.ts; 34 and 28 come from rawExtensionBodies.
	const semantic = new Set([0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 65037, 65281])
	for (const e of firefox.tls.extensionOrder) {
		const raw = firefox.tls.rawExtensionBodies && firefox.tls.rawExtensionBodies[e.id]
		assert.ok(semantic.has(e.id) || raw, `extension ${e.id} has no builder`)
	}
})

test('firefox147 groups, versions and key shares', () => {
	assert.deepStrictEqual(firefox.tls.supportedGroups, [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101])
	assert.deepStrictEqual(firefox.tls.supportedVersions, [0x0304, 0x0303])
	assert.deepStrictEqual(firefox.tls.keyShareGroups, [0x11ec, 0x001d])
	assert.deepStrictEqual(firefox.tls.certCompressionAlgorithms, [0x0001, 0x0002, 0x0003])
})

test('firefox147 http2 fingerprint values', () => {
	assert.deepStrictEqual(Object.keys(firefox.http2.settings), [
		'headerTableSize', 'enablePush', 'initialWindowSize', 'maxFrameSize',
	])
	assert.strictEqual(firefox.http2.settings.initialWindowSize, 131072)
	assert.strictEqual(firefox.http2.windowUpdateIncrement, 12517377)
	assert.deepStrictEqual(firefox.http2.priority, { weight: 42, exclusive: false, parent: 0 })
	assert.deepStrictEqual(firefox.http2.pseudoHeaderOrder, [':method', ':path', ':authority', ':scheme'])
})

test('firefox147 headers are emitted in profile order with m,p,a,s pseudo-headers', () => {
	const h = buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: {}, profile: firefox })
	assert.deepStrictEqual(Object.keys(h), [
		':method', ':path', ':authority', ':scheme',
		'user-agent', 'accept', 'accept-language', 'accept-encoding', 'upgrade-insecure-requests',
		'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'priority', 'te',
	])
	assert.strictEqual(h['user-agent'], firefox.userAgent)
	assert.strictEqual(h.te, 'trailers')
})

test('firefox147 fixes only the user-agent', () => {
	assert.throws(
		() => buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: { 'user-agent': 'spoofed' }, profile: firefox }),
		(err) => err.code === 'EHEADERFIXED')
	const h = buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: { accept: 'application/json' }, profile: firefox })
	assert.strictEqual(h.accept, 'application/json')
	assert.strictEqual(h['sec-fetch-site'], 'none')
})
