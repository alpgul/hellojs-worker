// Profile-driven request headers: injected automatically in the profile's order, caller
// extras appended, non-identity values overridable in place, identity headers fixed.

import assert from 'node:assert'
import test from 'node:test'

import { buildH1Headers, buildH2Headers, mergeProfileHeaders } from '../../lib/headers.ts'
import chrome from '../../lib/profiles/chrome147-mac.ts'

const PROFILE_ORDER = Object.keys(chrome.headers)

test('h2: profile headers are injected in profile order after pseudo-headers', () => {
	const h = buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: {}, profile: chrome })
	const keys = Object.keys(h)
	assert.deepStrictEqual(keys.slice(0, 4), [':method', ':authority', ':scheme', ':path'])
	assert.deepStrictEqual(keys.slice(4), PROFILE_ORDER)
	assert.strictEqual(h['user-agent'], chrome.headers['user-agent'])
	assert.strictEqual(h['sec-ch-ua'], chrome.headers['sec-ch-ua'])
})

test('h2: caller-only headers append after the profile block', () => {
	const h = buildH2Headers({
		method: 'GET', host: 'example.com', path: '/',
		userHeaders: { 'x-app': 'demo', authorization: 'Bearer t' }, profile: chrome,
	})
	const keys = Object.keys(h)
	assert.deepStrictEqual(keys.slice(4, 4 + PROFILE_ORDER.length), PROFILE_ORDER)
	assert.deepStrictEqual(keys.slice(4 + PROFILE_ORDER.length), ['x-app', 'authorization'])
})

test('h2: non-identity headers are overridable in place', () => {
	const h = buildH2Headers({
		method: 'GET', host: 'example.com', path: '/',
		userHeaders: { accept: 'application/json', 'accept-encoding': 'identity' }, profile: chrome,
	})
	assert.strictEqual(h.accept, 'application/json')
	assert.strictEqual(h['accept-encoding'], 'identity')
	const keys = Object.keys(h)
	assert.ok(keys.indexOf('accept') < keys.indexOf('sec-fetch-site'), 'accept keeps its profile position')
	assert.ok(keys.indexOf('accept-encoding') < keys.indexOf('accept-language'), 'accept-encoding keeps its profile position')
})

test('h2: identity headers cannot be replaced', () => {
	for (const name of ['user-agent', 'User-Agent', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform']) {
		assert.throws(
			() => buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: { [name]: 'spoofed' }, profile: chrome }),
			(err) => err.code === 'EHEADERFIXED' && err.category === 'usage',
			`${name} should be fixed`)
	}
})

test('identity headers may be restated with the profile value', () => {
	const h = buildH2Headers({
		method: 'GET', host: 'example.com', path: '/',
		userHeaders: { 'User-Agent': chrome.headers['user-agent'] }, profile: chrome,
	})
	assert.strictEqual(h['user-agent'], chrome.headers['user-agent'])
})

test('h1: Host stays first, then the profile block', () => {
	const block = buildH1Headers({ host: 'example.com', userHeaders: { 'x-app': 'demo' }, profile: chrome })
	const lines = block.split('\r\n')
	assert.strictEqual(lines[0], 'Host: example.com')
	assert.deepStrictEqual(lines.slice(1, 1 + PROFILE_ORDER.length), PROFILE_ORDER.map((k) => `${k}: ${chrome.headers[k]}`))
	assert.strictEqual(lines.at(-1), 'x-app: demo')
})

test('cookie jar header lands just before priority', () => {
	const h = mergeProfileHeaders({ Cookie: 'sid=abc' }, chrome)
	assert.strictEqual(h.Cookie, 'sid=abc')
	const keys = Object.keys(h)
	assert.deepStrictEqual(keys.slice(-2), ['Cookie', 'priority'])
})

test('no profile means no injection', () => {
	const h = buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: { 'x-a': '1' }, profile: null })
	assert.deepStrictEqual(Object.keys(h), [':method', ':authority', ':scheme', ':path', 'x-a'])
})
