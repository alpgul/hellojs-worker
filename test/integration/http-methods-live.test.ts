// Live check of every HTTP method against the shared HTTP echo host.
// Uses httpbin's dedicated per-verb endpoints (/get, /post, …) plus /anything, so the server
// itself reports which verb arrived. Live network — `network` project only, never `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST } from '../helpers/hosts.ts'

const BASE = `https://${HTTP_HOST}`

interface Echo {
	url?: string
	method?: string
	headers?: Record<string, string | string[]>
	json?: Record<string, unknown>
	origin?: string
}

const viaMethod = (verb: string, url: string) =>
	request<Echo>({ simple: false, url, method: verb, json: true, timeout: 15_000 })

it('GET /get', async () => {
	const body = await request.get<Echo>({ simple: false, url: `${BASE}/get`, json: true, timeout: 15_000 })
	expect(body?.method).toBe('GET')
})

it('POST /post', async () => {
	const body = await request.post<Echo>({ simple: false, url: `${BASE}/post`, json: { probe: 'post' }, timeout: 15_000 })
	expect(body?.method).toBe('POST')
	expect(body?.json?.probe).toBe('post')
})

it('PUT /put', async () => {
	const body = await request.put<Echo>({ simple: false, url: `${BASE}/put`, json: { probe: 'put' }, timeout: 15_000 })
	expect(body?.method).toBe('PUT')
	expect(body?.json?.probe).toBe('put')
})

it('PATCH /patch', async () => {
	const body = await request.patch<Echo>({ simple: false, url: `${BASE}/patch`, json: { probe: 'patch' }, timeout: 15_000 })
	expect(body?.method).toBe('PATCH')
	expect(body?.json?.probe).toBe('patch')
})

it('DELETE /delete', async () => {
	const body = await request.del<Echo>({ simple: false, url: `${BASE}/delete`, json: { probe: 'delete' }, timeout: 15_000 })
	expect(body?.method).toBe('DELETE')
})

it('HEAD /head — headers only, empty body', async () => {
	const res = await request.head({ simple: false, url: `${BASE}/head`, resolveWithFullResponse: true, timeout: 15_000 })
	expect(res.status).toBe(200)
	expect(Object.keys(res.headers).length).toBeGreaterThan(0)
	// HEAD carries no body: '' or a zero-length buffer, whichever representation the client uses.
	const empty = res.body === '' || (Buffer.isBuffer(res.body) && res.body.length === 0)
	expect(empty).toBe(true)
})

it('OPTIONS /options — CORS preflight: headers only, empty body', async () => {
	// httpbin answers OPTIONS as a CORS preflight: 200 + access-control-allow-* headers and a
	// zero-length body, so there is no JSON echo to read. Assert the headers, not a body.
	const res = await request.options({ simple: false, url: `${BASE}/options`, resolveWithFullResponse: true, timeout: 15_000 })
	expect(res.status).toBe(200)
	const allow = res.headers['access-control-allow-methods']
	expect(String(allow)).toContain('OPTIONS')
	const empty = res.body === '' || (Buffer.isBuffer(res.body) && res.body.length === 0)
	expect(empty).toBe(true)
})

it('every verb round-trips at /anything', async () => {
	// /anything echoes the verb in a JSON body for the body-carrying methods; OPTIONS is a
	// preflight with an empty body, so it is asserted separately above.
	for (const verb of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
		const body = await viaMethod(verb, `${BASE}/anything`)
		expect(body?.method).toBe(verb)
	}
})
