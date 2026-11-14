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
	request({ simple: false, bodyOnly: true, url, method: verb, json: true, timeout: 15_000 }) as Promise<Echo>

it('GET /get', async () => {
	const body = (await request.get({ simple: false, bodyOnly: true, url: `${BASE}/get`, json: true, timeout: 15_000 })) as Echo
	expect(body.method).toBe('GET')
})

it('POST /post', async () => {
	const body = (await request.post({ simple: false, bodyOnly: true, url: `${BASE}/post`, json: { probe: 'post' }, timeout: 15_000 })) as Echo
	expect(body.method).toBe('POST')
	expect(body.json?.probe).toBe('post')
})

it('PUT /put', async () => {
	const body = (await request.put({ simple: false, bodyOnly: true, url: `${BASE}/put`, json: { probe: 'put' }, timeout: 15_000 })) as Echo
	expect(body.method).toBe('PUT')
	expect(body.json?.probe).toBe('put')
})

it('PATCH /patch', async () => {
	const body = (await request.patch({ simple: false, bodyOnly: true, url: `${BASE}/patch`, json: { probe: 'patch' }, timeout: 15_000 })) as Echo
	expect(body.method).toBe('PATCH')
	expect(body.json?.probe).toBe('patch')
})

it('DELETE /delete', async () => {
	const body = (await request.del({ simple: false, bodyOnly: true, url: `${BASE}/delete`, json: { probe: 'delete' }, timeout: 15_000 })) as Echo
	expect(body.method).toBe('DELETE')
})

it('HEAD /head — headers only, empty body', async () => {
	const res = await request.head({ simple: false, url: `${BASE}/head`, timeout: 15_000 })
	expect(res.status).toBe(200)
	expect(Array.from(res.headers.keys()).length).toBeGreaterThan(0)
	// HEAD carries no body at all.
	expect(res.body).toBeNull()
	expect(await res.text()).toBe('')
})

it('OPTIONS /options — CORS preflight: headers only, empty body', async () => {
	// httpbin answers OPTIONS as a CORS preflight: 200 + access-control-allow-* headers and a
	// zero-length body, so there is no JSON echo to read. Assert the headers, not a body.
	const res = await request.options({ simple: false, url: `${BASE}/options`, timeout: 15_000 })
	expect(res.status).toBe(200)
	expect(String(res.headers.get('access-control-allow-methods'))).toContain('OPTIONS')
	expect(await res.text()).toBe('')
})

it('every verb round-trips at /anything', async () => {
	// /anything echoes the verb in a JSON body for the body-carrying methods; OPTIONS is a
	// preflight with an empty body, so it is asserted separately above.
	for (const verb of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
		const body = await viaMethod(verb, `${BASE}/anything`)
		expect(body.method).toBe(verb)
	}
})
