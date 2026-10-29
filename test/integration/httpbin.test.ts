// Basic httpbin usage — exercises common request patterns end-to-end against a live server.
//
// Target: httpbingo.org (modern Go-based httpbin, TLS 1.3 + h2 + zstd).
// httpbin.org is TLS 1.2 only and we don't support that. Same endpoints, same response shape.
//
// Live network, so this lives in the `network` project and never runs under `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'

const BASE = 'https://httpbingo.org'

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

it('GET /get returns JSON with url + headers', async () => {
	const body = await request<HttpbinEcho>({ simple: false, url: `${BASE}/get`, json: true })
	expect(body?.url?.includes('/get')).toBe(true)
	expect(body?.headers).toBeTruthy()
})

it('GET with qs builder', async () => {
	const body = await request<HttpbinEcho>({ simple: false, url: `${BASE}/get`, qs: { foo: 'bar', n: 42 }, json: true })
	expect(v(body?.args?.foo)).toBe('bar')
	expect(String(v(body?.args?.n))).toBe('42')
})

it('custom header echoed', async () => {
	const body = await request<HttpbinEcho>({ simple: false, url: `${BASE}/headers`, headers: { 'x-hellojs-test': '147' }, json: true })
	// httpbin lowercases + multivalues, and which spelling depends on the deployment.
	const echoed = body?.headers?.['X-Hellojs-Test'] ?? body?.headers?.['x-hellojs-test']
	expect(v(echoed)).toBe('147')
})

it('POST with json body', async () => {
	const body = await request<HttpbinEcho>({ simple: false, url: `${BASE}/post`, method: 'POST', json: { hello: 'world', n: 1 } })
	expect(body?.json?.hello).toBe('world')
	expect(body?.json?.n).toBe(1)
})

it('POST with form body', async () => {
	const body = await request<HttpbinEcho>({ simple: false, url: `${BASE}/post`, method: 'POST', form: { name: 'jack', age: '30' }, json: true })
	expect(v(body?.form?.name)).toBe('jack')
	expect(v(body?.form?.age)).toBe('30')
})

it('simple:true rejects on 418', async () => {
	await expect(request({ url: `${BASE}/status/418` })).rejects.toMatchObject({
		code: 'EHTTP',
		response: { status: 418 },
	})
})

it('simple:false resolves on 418', async () => {
	const r = await request({ simple: false, url: `${BASE}/status/418`, resolveWithFullResponse: true })
	expect(r.status).toBe(418)
})

it('follows redirects (3 hops)', async () => {
	const r = await request({ simple: false, url: `${BASE}/redirect/2`, json: true, resolveWithFullResponse: true })
	expect(r.status).toBe(200)
})

it('followRedirect:false stops at 302', async () => {
	const r = await request({ simple: false, url: `${BASE}/redirect/1`, followRedirect: false, resolveWithFullResponse: true })
	expect(r.status).toBeGreaterThanOrEqual(300)
	expect(r.status).toBeLessThan(400)
	expect(r.headers.location).toBeTruthy()
})

it('gzip auto-decompresses', async () => {
	const body = await request<HttpbinEcho>({ simple: false, url: `${BASE}/gzip`, gzip: true, json: true })
	expect(body?.gzipped).toBe(true)
})

it('cookie jar persists', async () => {
	const jar = request.jar()
	// Set a cookie via /cookies/set redirect chain
	await request({ simple: false, url: `${BASE}/cookies/set?testcookie=hellojs147`, jar, resolveWithFullResponse: true })
	const body = await request<HttpbinEcho>({ simple: false, url: `${BASE}/cookies`, jar, json: true })
	// httpbin returns cookies as plain strings or arrays of strings depending on version.
	expect(v(body?.cookies?.testcookie)).toBe('hellojs147')
})

it('default UA is Chrome 147', async () => {
	const body = await request<HttpbinEcho>({ simple: false, url: `${BASE}/user-agent`, json: true })
	const ua = body?.['user-agent'] ?? body?.user_agent
	expect(typeof ua).toBe('string')
	expect(ua).toContain('Chrome/147')
})
