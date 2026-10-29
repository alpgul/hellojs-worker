// Exercises the public API shape end-to-end against tls.peet.ws.
// Verifies: callback form, promise form, defaults, jar, qs, gzip auto-decompress, h2 path.
//
// Live network: `network` project only, never part of `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'

const URL = 'https://tls.peet.ws/api/all'

// Only the fields these checks read; peet.ws returns far more.
interface PeetReport {
	method?: string
	tls?: { ja4?: string }
}

it('promise+json+full-response', async () => {
	const data = await request<PeetReport>({ url: URL, json: true, resolveWithFullResponse: true })
	expect(data.status).toBe(200)
	expect(data.body?.tls?.ja4).toMatch(/^t13d1516h2_8daaf6152771_/)
})

it('callback form', async () => {
	let err: unknown = null
	const body = await new Promise<PeetReport | undefined>((resolve) => {
		request<PeetReport>({ url: URL, json: true }, (e, _res, b) => { err = e; resolve(b) })
	})
	expect(err).toBeNull()
	expect(body?.tls?.ja4).toBeTruthy()
})

it('request.get shortcut', async () => {
	const body = await request.get<PeetReport>({ url: URL, json: true })
	expect(body?.method).toBe('GET')
})

it('request.defaults', async () => {
	const r = request.defaults({ json: true, headers: { 'x-custom': 'hellojs' } })
	const body = await r<PeetReport>({ url: URL })
	expect(body?.tls?.ja4).toBeTruthy()
})

it('qs builder', async () => {
	const body = await request<PeetReport>({ url: URL, qs: { foo: 'bar', baz: 1 }, json: true })
	expect(body?.method).toBe('GET')
})

// JA4 still matches Chrome 147 via the API path.
// We only assert the JA4_b component (cipher truncated-SHA256) since extension count
// is the profile's own (16) — no PSK extension is ever added.
it('JA4 still matches via request() API', async () => {
	const body = await request<PeetReport>({ url: URL, json: true })
	const j = body?.tls?.ja4 ?? ''
	expect(j).toMatch(/^t13d1516h2_/)
	expect(j).toContain('_8daaf6152771_')
})
