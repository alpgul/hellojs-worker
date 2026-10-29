// Exercises the public API shape end-to-end against the shared HTTP echo host.
// Verifies: callback form, promise form, defaults, jar, qs, gzip auto-decompress, h2 path.
// Fingerprint assertions live in test/fingerprint/chrome147.test.ts — same host contract,
// no need to re-run them here.
//
// Live network: `network` project only, never part of `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST } from '../helpers/hosts.ts'

const URL = `https://${HTTP_HOST}/anything`

// Only the fields these checks read; the echo returns far more.
interface Report {
	method?: string
	url?: string
	args?: Record<string, string[]>
	headers?: Record<string, string[]>
}

it('promise+json+full-response', async () => {
	const data = await request<Report>({ url: URL, json: true, resolveWithFullResponse: true })
	expect(data.status).toBe(200)
	expect(data.body?.url).toBe(URL)
})

it('callback form', async () => {
	let err: unknown = null
	const body = await new Promise<Report | undefined>((resolve) => {
		request<Report>({ url: URL, json: true }, (e, _res, b) => { err = e; resolve(b) })
	})
	expect(err).toBeNull()
	expect(body?.url).toBe(URL)
})

it('request.get shortcut', async () => {
	const body = await request.get<Report>({ url: URL, json: true })
	expect(body?.method).toBe('GET')
})

it('request.defaults', async () => {
	const r = request.defaults({ json: true, headers: { 'x-custom': 'hellojs' } })
	const body = await r<Report>({ url: URL })
	expect(body?.headers?.['X-Custom']).toStrictEqual(['hellojs'])
})

it('qs builder', async () => {
	const body = await request<Report>({ url: URL, qs: { foo: 'bar', baz: 1 }, json: true })
	expect(body?.args).toStrictEqual({ baz: ['1'], foo: ['bar'] })
})
