// Live check of every HTTP method against the shared HTTP echo host.
// Uses httpbin's dedicated per-verb endpoints (/get, /post, …) plus /anything, so the server
// itself reports which verb arrived. Live network — `network` project only, never `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST } from '../helpers/hosts.ts'

import type { HttpMethod } from '../../index.ts'

const BASE = `https://${HTTP_HOST}`

interface Echo {
	url?: string
	method?: string
	headers?: Record<string, string | string[]>
	json?: Record<string, unknown>
	origin?: string
}

const jsonBody = async (p: Promise<Response>): Promise<Echo> => (await p).json() as Promise<Echo>

// No response-header watchdog in the library any more — carry the deadline on the signal.
const deadline = () => AbortSignal.timeout(15_000)
const json = (value: unknown) => ({
	headers: { 'content-type': 'application/json' },
	body: JSON.stringify(value)
})

const viaMethod = (verb: HttpMethod, url: string) => jsonBody(request(url, { method: verb, signal: deadline() }))

it('GET /get', async () => {
	const body = await jsonBody(request.get(`${BASE}/get`, { signal: deadline() }))
	expect(body.method).toBe('GET')
})

it('POST /post', async () => {
	const body = await jsonBody(request.post(`${BASE}/post`, { ...json({ probe: 'post' }), signal: deadline() }))
	expect(body.method).toBe('POST')
	expect(body.json?.probe).toBe('post')
})

it('PUT /put', async () => {
	const body = await jsonBody(request.put(`${BASE}/put`, { ...json({ probe: 'put' }), signal: deadline() }))
	expect(body.method).toBe('PUT')
	expect(body.json?.probe).toBe('put')
})

it('PATCH /patch', async () => {
	const body = await jsonBody(request.patch(`${BASE}/patch`, { ...json({ probe: 'patch' }), signal: deadline() }))
	expect(body.method).toBe('PATCH')
	expect(body.json?.probe).toBe('patch')
})

it('DELETE /delete', async () => {
	const body = await jsonBody(request.del(`${BASE}/delete`, { ...json({ probe: 'delete' }), signal: deadline() }))
	expect(body.method).toBe('DELETE')
})

it('HEAD /head — headers only, empty body', async () => {
	const res = await request.head(`${BASE}/head`, { signal: deadline() })
	expect(res.status).toBe(200)
	expect(Array.from(res.headers.keys()).length).toBeGreaterThan(0)
	// HEAD carries no body at all.
	expect(res.body).toBeNull()
	expect(await res.text()).toBe('')
})

it('OPTIONS /options — CORS preflight: headers only, empty body', async () => {
	// httpbin answers OPTIONS as a CORS preflight: 200 + access-control-allow-* headers and a
	// zero-length body, so there is no JSON echo to read. Assert the headers, not a body.
	const res = await request.options(`${BASE}/options`, { signal: deadline() })
	expect(res.status).toBe(200)
	expect(String(res.headers.get('access-control-allow-methods'))).toContain('OPTIONS')
	expect(await res.text()).toBe('')
})

it('every verb round-trips at /anything', async () => {
	// /anything echoes the verb in a JSON body for the body-carrying methods; OPTIONS is a
	// preflight with an empty body, so it is asserted separately above.
	for (const verb of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const) {
		const body = await viaMethod(verb, `${BASE}/anything`)
		expect(body.method).toBe(verb)
	}
})
