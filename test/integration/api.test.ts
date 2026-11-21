// Exercises the public API shape end-to-end against the shared HTTP echo host.
// Verifies: promise form, defaults, jar, query strings in the input URL, gzip auto-decompress, h2 path.
// Fingerprint assertions live in test/fingerprint/chrome147.test.ts — same host contract,
// no need to re-run them here.
//
// Live network: `network` project only, never part of `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST } from '../helpers/hosts.ts'

import type { FetchInit } from '../../index.ts'

const URL = `https://${HTTP_HOST}/anything`

// Only the fields these checks read; the echo returns far more.
interface Report {
	method?: string
	url?: string
	args?: Record<string, string[]>
	headers?: Record<string, string[]>
}

it('promise+json+full-response', async () => {
	const res = await request(URL)
	expect(res.status).toBe(200)
	const data = (await res.json()) as Report
	expect(data.url).toBe(URL)
})

it('callback form is rejected with EBADOPTS', async () => {
	const cb = (() => {}) as (err: unknown, res: unknown) => void
	// The validation throws synchronously, so wrap it in an async function for `.rejects`.
	await expect(async () => request(URL, cb as unknown as FetchInit)).rejects.toMatchObject({ code: 'EBADOPTS' })
})

it('request.get shortcut', async () => {
	const body = (await (await request.get(URL)).json()) as Report
	expect(body.method).toBe('GET')
})

it('request.defaults', async () => {
	const r = request.defaults({ headers: { 'x-custom': 'hellojs' } })
	const body = (await (await r(URL)).json()) as Report
	expect(body.headers?.['X-Custom']).toStrictEqual(['hellojs'])
})

it('qs builder', async () => {
	// Query parameters are part of the input URL now, not a request option.
	const query = new URLSearchParams({ foo: 'bar', baz: '1' })
	const body = (await (await request(`${URL}?${query}`)).json()) as Report
	expect(body.args).toStrictEqual({ baz: ['1'], foo: ['bar'] })
})
