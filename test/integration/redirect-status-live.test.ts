// Live check of redirect codes and status classes against the shared HTTP echo host.
// httpbin's /redirect-to picks an exact 3xx and lands on /anything (which echoes the arrived
// verb + body); /status/:code answers with a chosen status. Live network — `network` project only.
//
// 1xx informational is deliberately NOT covered here: a real echo host does not emit interim 100/103
// on demand, so that class is asserted against a deterministic local server instead (status-classes.test.ts).

import { describe, expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST } from '../helpers/hosts.ts'

import type { FetchInit } from '../../index.ts'

const BASE = `https://${HTTP_HOST}`
const TO = (code: number) => `${BASE}/redirect-to?url=/anything&status_code=${code}`

interface Echo {
	method?: string
	url?: string
	json?: Record<string, unknown>
	data?: string
	headers?: Record<string, string | string[]>
}

// No response-header watchdog in the library any more; callers bring their own deadline.
const deadline = () => AbortSignal.timeout(20_000)
const jsonBody = async (p: Promise<Response>): Promise<Echo> => (await p).json() as Promise<Echo>

const redirect = (url: string, extra: FetchInit = {}) =>
	jsonBody(request(url, { verifyTLS: false, signal: deadline(), ...extra }))

const postJson = (url: string, payload: Record<string, unknown>) =>
	redirect(url, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(payload)
	})

describe('live redirect codes', () => {
	it('301: GET stays GET after the hop', async () => {
		const body = await redirect(TO(301))
		expect(body?.method).toBe('GET')
	})

	it('301: POST downgrades to a bodyless GET', async () => {
		const body = await postJson(TO(301), { drop: 'me' })
		expect(body?.method).toBe('GET')
		// httpbin echoes an absent JSON body as `null`; assert the body was dropped.
		expect(body?.json).toBeFalsy()
	})

	it('302: POST downgrades to a bodyless GET', async () => {
		const body = await postJson(TO(302), { drop: 'me' })
		expect(body?.method).toBe('GET')
	})

	it('303: POST becomes a bodyless GET (RFC 9110 §15.4.4)', async () => {
		const body = await postJson(TO(303), { drop: 'me' })
		expect(body?.method).toBe('GET')
		expect(body?.json).toBeFalsy()
	})

	it('307: POST method AND body preserved (RFC 9110 §15.4.7)', async () => {
		const body = await postJson(TO(307), { keep: 'me' })
		expect(body?.method).toBe('POST')
		expect(body?.json?.keep).toBe('me')
	})

	it('308: POST method AND body preserved (RFC 9110 §15.4.8)', async () => {
		const body = await postJson(TO(308), { keep: 'too' })
		expect(body?.method).toBe('POST')
		expect(body?.json?.keep).toBe('too')
	})

	it('redirect chains within the fixed 20-hop limit are followed', async () => {
		// No maxRedirects option any more: a short chain inside the browser-fixed 20-hop budget is
		// followed end-to-end. The >20-hop rejection is covered locally in
		// test/node/redirect-codes.test.ts. Keep a generous deadline: each hop is a live request.
		const res = await request(`${BASE}/redirect/3`, { verifyTLS: false, signal: AbortSignal.timeout(60_000) })
		expect(res.status).toBe(200)
		await res.text()
	}, 120_000)

	it("redirect:'manual' stops at the first 3xx and surfaces Location", async () => {
		const res = await request(`${BASE}/redirect/1`, { verifyTLS: false, redirect: 'manual', signal: deadline() })
		expect(res.status).toBe(302)
		// httpbin's /redirect/1 points at /get; assert a Location came back, not its exact path.
		expect(res.headers.get('location')).toBeTruthy()
		await res.text()
	})
})

describe('live status classes', () => {
	it('2xx: /status/200 resolves', async () => {
		const res = await request(`${BASE}/status/200`, { verifyTLS: false, signal: deadline() })
		expect(res.status).toBe(200)
		await res.text()
	})

	it('2xx: /status/204 resolves with an empty body', async () => {
		const res = await request(`${BASE}/status/204`, { verifyTLS: false, signal: deadline() })
		expect(res.status).toBe(204)
		expect(res.body).toBeNull()
		expect(await res.text()).toBe('')
	})

	it('4xx: /status/404 resolves like fetch', async () => {
		const res = await request(`${BASE}/status/404`, { verifyTLS: false, signal: deadline() })
		expect(res.status).toBe(404)
		expect(res.ok).toBe(false)
		await res.text()
	})

	it('4xx: /status/429 resolves like fetch', async () => {
		const res = await request(`${BASE}/status/429`, { verifyTLS: false, signal: deadline() })
		expect(res.status).toBe(429)
		await res.text()
	})

	it('5xx: /status/500 resolves like fetch', async () => {
		const res = await request(`${BASE}/status/500`, { verifyTLS: false, signal: deadline() })
		expect(res.status).toBe(500)
		await res.text()
	})

	it('5xx: /status/503 resolves like fetch', async () => {
		const res = await request(`${BASE}/status/503`, { verifyTLS: false, signal: deadline() })
		expect(res.status).toBe(503)
		await res.text()
	})
})
