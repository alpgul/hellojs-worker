// Host is builder-managed: exactly one Host (h1) / :authority (h2), even when the caller passes
// their own Host header. Two Host headers are malformed (RFC 7230 5.4) and a fingerprint tell; a
// stray `host` header over h2 is likewise a tell (Chrome carries the origin only in :authority).

import { expect, it } from 'vitest'

import { buildH1Headers, buildH2Headers } from '../../lib/headers.ts'

function hostLines(block: string): string[] {
	return block.split('\r\n').filter((l) => /^host:/i.test(l))
}

it('h1: no caller Host -> exactly one Host from the URL', () => {
	const lines = hostLines(buildH1Headers({ host: 'real.example', userHeaders: {}, profile: null }))
	expect(lines).toStrictEqual(['Host: real.example'])
})

it('h1: caller-supplied host does not duplicate, and overrides', () => {
	for (const key of ['host', 'Host', 'HOST']) {
		const lines = hostLines(buildH1Headers({ host: 'real.example', userHeaders: { [key]: 'override.example' }, profile: null }))
		expect(lines.length, `expected one Host line for caller key ${key}, got ${JSON.stringify(lines)}`).toBe(1)
		expect(lines[0]).toBe('Host: override.example')
	}
})

it('h1: Host stays first in the header block', () => {
	const block = buildH1Headers({ host: 'real.example', userHeaders: { 'x-foo': 'bar' }, profile: null })
	expect(block.startsWith('Host: real.example\r\n'), 'Host must be the first header line').toBe(true)
})

it('h2: no caller host -> :authority from the URL, no regular host header', () => {
	const h = buildH2Headers({ method: 'GET', host: 'real.example', path: '/', userHeaders: {}, profile: null })
	expect(h[':authority']).toBe('real.example')
	expect(h.host).toBeUndefined()
})

it('h2: caller-supplied host overrides :authority and is not emitted as a regular header', () => {
	for (const key of ['host', 'Host', 'HOST']) {
		const h = buildH2Headers({ method: 'GET', host: 'real.example', path: '/', userHeaders: { [key]: 'override.example' }, profile: null })
		expect(h[':authority'], `:authority should reflect caller ${key}`).toBe('override.example')
		expect(h.host, `no regular host header should leak for caller ${key}`).toBeUndefined()
	}
})
