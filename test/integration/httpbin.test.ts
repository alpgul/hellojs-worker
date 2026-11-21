// Basic httpbin usage — exercises common request patterns end-to-end against a live server.
//
// Target: the shared HTTP echo host (modern Go-based httpbin, TLS 1.3 + h2 + zstd).
// httpbin.org is TLS 1.2 only and we don't support that. Same endpoints, same response shape.
//
// Live network, so this lives in the `network` project and never runs under `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST } from '../helpers/hosts.ts'

const BASE = `https://${HTTP_HOST}`

// httpbin answers every endpoint with its own echo document; this is the subset the checks read.
interface HttpbinEcho {
	url?: string
	headers?: Record<string, string | string[]>
	args?: Record<string, string | string[]>
	form?: Record<string, string | string[]>
	json?: Record<string, unknown>
	gzipped?: boolean
	cookies?: Record<string, string | string[]>
	'user-agent'?: string
	user_agent?: string
}

// httpbin reports every repeated parameter as an array; the fixtures here send one value each.
const v = (x: string | string[] | undefined): string | undefined => (Array.isArray(x) ? x[0] : x)
const jsonBody = async (p: Promise<Response>): Promise<HttpbinEcho> => (await p).json() as Promise<HttpbinEcho>

it('GET /get returns JSON with url + headers', async () => {
	const body = await jsonBody(request(`${BASE}/get`))
	expect(body?.url?.includes('/get')).toBe(true)
	expect(body?.headers).toBeTruthy()
})

it('GET with query string in the input URL', async () => {
	const query = new URLSearchParams({ foo: 'bar', n: '42' })
	const body = await jsonBody(request(`${BASE}/get?${query}`))
	expect(v(body?.args?.foo)).toBe('bar')
	expect(String(v(body?.args?.n))).toBe('42')
})

it('custom header echoed', async () => {
	const body = await jsonBody(request(`${BASE}/headers`, { headers: { 'x-hellojs-test': '147' } }))
	// httpbin lowercases + multivalues, and which spelling depends on the deployment.
	const echoed = body?.headers?.['X-Hellojs-Test'] ?? body?.headers?.['x-hellojs-test']
	expect(v(echoed)).toBe('147')
})

it('POST with json body', async () => {
	const body = await jsonBody(
		request(`${BASE}/post`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ hello: 'world', n: 1 })
		})
	)
	expect(body?.json?.hello).toBe('world')
	expect(body?.json?.n).toBe(1)
})

it('POST with form body', async () => {
	const body = await jsonBody(
		request(`${BASE}/post`, {
			method: 'POST',
			body: new URLSearchParams({ name: 'jack', age: '30' })
		})
	)
	expect(v(body?.form?.name)).toBe('jack')
	expect(v(body?.form?.age)).toBe('30')
})

it('418 resolves like fetch', async () => {
	const r = await request(`${BASE}/status/418`)
	expect(r.status).toBe(418)
	expect(r.ok).toBe(false)
	await r.text()
})

it('follows redirects (3 hops)', async () => {
	const r = await request(`${BASE}/redirect/2`)
	expect(r.status).toBe(200)
	await r.text()
})

it("redirect:'manual' stops at 302", async () => {
	const r = await request(`${BASE}/redirect/1`, { redirect: 'manual' })
	expect(r.status).toBeGreaterThanOrEqual(300)
	expect(r.status).toBeLessThan(400)
	expect(r.headers.get('location')).toBeTruthy()
	await r.text()
})

it('gzip auto-decompresses', async () => {
	// Decoding is automatic — no request option needed.
	const body = await jsonBody(request(`${BASE}/gzip`))
	expect(body?.gzipped).toBe(true)
})

it('cookie jar persists', async () => {
	const jar = request.jar()
	// Set a cookie via /cookies/set redirect chain
	await (await request(`${BASE}/cookies/set?testcookie=hellojs147`, { jar })).text()
	const body = await jsonBody(request(`${BASE}/cookies`, { jar }))
	// httpbin returns cookies as plain strings or arrays of strings depending on version.
	expect(v(body?.cookies?.testcookie)).toBe('hellojs147')
})

it('default UA is Chrome 147', async () => {
	const body = await jsonBody(request(`${BASE}/user-agent`))
	const ua = body?.['user-agent'] ?? body?.user_agent
	expect(typeof ua).toBe('string')
	expect(ua).toContain('Chrome/147')
})
