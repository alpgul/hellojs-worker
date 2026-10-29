// Profile-driven request headers: injected automatically in the profile's order, caller
// extras appended, non-identity values overridable in place, identity headers fixed.

import { expect, it } from 'vitest'

import { buildH1Headers, buildH2Headers, mergeProfileHeaders } from '../../lib/headers.ts'
import chrome from '../../lib/profiles/chrome147-mac.ts'

const PROFILE_HEADERS: Record<string, string> = chrome.headers
const PROFILE_ORDER = Object.keys(PROFILE_HEADERS)

it('h2: profile headers are injected in profile order after pseudo-headers', () => {
	const h = buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: {}, profile: chrome })
	const keys = Object.keys(h)
	expect(keys.slice(0, 4)).toStrictEqual([':method', ':authority', ':scheme', ':path'])
	expect(keys.slice(4)).toStrictEqual(PROFILE_ORDER)
	expect(h['user-agent']).toBe(PROFILE_HEADERS['user-agent'])
	expect(h['sec-ch-ua']).toBe(PROFILE_HEADERS['sec-ch-ua'])
})

it('h2: caller-only headers append after the profile block', () => {
	const h = buildH2Headers({
		method: 'GET', host: 'example.com', path: '/',
		userHeaders: { 'x-app': 'demo', authorization: 'Bearer t' }, profile: chrome,
	})
	const keys = Object.keys(h)
	expect(keys.slice(4, 4 + PROFILE_ORDER.length)).toStrictEqual(PROFILE_ORDER)
	expect(keys.slice(4 + PROFILE_ORDER.length)).toStrictEqual(['x-app', 'authorization'])
})

it('h2: non-identity headers are overridable in place', () => {
	const h = buildH2Headers({
		method: 'GET', host: 'example.com', path: '/',
		userHeaders: { accept: 'application/json', 'accept-encoding': 'identity' }, profile: chrome,
	})
	expect(h.accept).toBe('application/json')
	expect(h['accept-encoding']).toBe('identity')
	const keys = Object.keys(h)
	expect(keys.indexOf('accept') < keys.indexOf('sec-fetch-site'), 'accept keeps its profile position').toBe(true)
	expect(keys.indexOf('accept-encoding') < keys.indexOf('accept-language'), 'accept-encoding keeps its profile position').toBe(true)
})

it('h2: identity headers cannot be replaced', () => {
	for (const name of ['user-agent', 'User-Agent', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform']) {
		expect(
			() => buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: { [name]: 'spoofed' }, profile: chrome }),
			`${name} should be fixed`,
		).toThrow(expect.objectContaining({ code: 'EHEADERFIXED', category: 'usage' }))
	}
})

it('identity headers may be restated with the profile value', () => {
	const h = buildH2Headers({
		method: 'GET', host: 'example.com', path: '/',
		userHeaders: { 'User-Agent': PROFILE_HEADERS['user-agent'] }, profile: chrome,
	})
	expect(h['user-agent']).toBe(PROFILE_HEADERS['user-agent'])
})

it('h1: Host stays first, then the profile block', () => {
	const block = buildH1Headers({ host: 'example.com', userHeaders: { 'x-app': 'demo' }, profile: chrome })
	const lines = block.split('\r\n')
	expect(lines[0]).toBe('Host: example.com')
	expect(lines.slice(1, 1 + PROFILE_ORDER.length)).toStrictEqual(PROFILE_ORDER.map((k) => `${k}: ${PROFILE_HEADERS[k]}`))
	expect(lines.at(-1)).toBe('x-app: demo')
})

it('cookie jar header lands just before priority', () => {
	const h = mergeProfileHeaders({ Cookie: 'sid=abc' }, chrome)
	expect(h.Cookie).toBe('sid=abc')
	const keys = Object.keys(h)
	expect(keys.slice(-2)).toStrictEqual(['Cookie', 'priority'])
})

it('no profile means no injection', () => {
	const h = buildH2Headers({ method: 'GET', host: 'example.com', path: '/', userHeaders: { 'x-a': '1' }, profile: null })
	expect(Object.keys(h)).toStrictEqual([':method', ':authority', ':scheme', ':path', 'x-a'])
})
