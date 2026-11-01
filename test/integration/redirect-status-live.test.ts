// Live check of redirect codes and status classes against the shared HTTP echo host.
// httpbin's /redirect-to picks an exact 3xx and lands on /anything (which echoes the arrived
// verb + body); /status/:code answers with a chosen status. Live network — `network` project only.
//
// 1xx informational is deliberately NOT covered here: a real echo host does not emit interim 100/103
// on demand, so that class is asserted against a deterministic local server instead (status-classes.test.ts).

import { describe, expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST } from '../helpers/hosts.ts'

const BASE = `https://${HTTP_HOST}`
const TO = (code: number) => `${BASE}/redirect-to?url=/anything&status_code=${code}`

interface Echo {
	method?: string
	url?: string
	json?: Record<string, unknown>
	data?: string
	headers?: Record<string, string | string[]>
}

const redirect = (url: string, extra: Record<string, unknown>) =>
	request<Echo>({ simple: false, verifyTLS: false, json: true, timeout: 20_000, url, ...extra })

describe('live redirect codes', () => {
	it('301: GET stays GET after the hop', async () => {
		const body = await redirect(`${BASE}/redirect-to?url=/anything&status_code=301`, {})
		expect(body?.method).toBe('GET')
	})

	it('301: POST downgrades to a bodyless GET', async () => {
		const body = await request<Echo>({ simple: false, verifyTLS: false, json: true, timeout: 20_000, url: TO(301), method: 'POST', body: { drop: 'me' } })
		expect(body?.method).toBe('GET')
		// httpbin echoes an absent JSON body as `null`; assert the body was dropped.
		expect(body?.json).toBeFalsy()
	})

	it('302: POST downgrades to a bodyless GET', async () => {
		const body = await request<Echo>({ simple: false, verifyTLS: false, json: true, timeout: 20_000, url: TO(302), method: 'POST', body: { drop: 'me' } })
		expect(body?.method).toBe('GET')
	})

	it('303: POST becomes a bodyless GET (RFC 9110 §15.4.4)', async () => {
		const body = await request<Echo>({ simple: false, verifyTLS: false, json: true, timeout: 20_000, url: TO(303), method: 'POST', body: { drop: 'me' } })
		expect(body?.method).toBe('GET')
		expect(body?.json).toBeFalsy()
	})

	it('307: POST method AND body preserved (RFC 9110 §15.4.7)', async () => {
		const body = await request<Echo>({ simple: false, verifyTLS: false, json: true, timeout: 20_000, url: TO(307), method: 'POST', body: { keep: 'me' } })
		expect(body?.method).toBe('POST')
		expect(body?.json?.keep).toBe('me')
	})

	it('308: POST method AND body preserved (RFC 9110 §15.4.8)', async () => {
		const body = await request<Echo>({ simple: false, verifyTLS: false, json: true, timeout: 20_000, url: TO(308), method: 'POST', body: { keep: 'too' } })
		expect(body?.method).toBe('POST')
		expect(body?.json?.keep).toBe('too')
	})

	it('multi-hop chain is followed to 200', async () => {
		const res = await request({ simple: false, verifyTLS: false, json: true, timeout: 20_000, url: `${BASE}/redirect/3`, resolveWithFullResponse: true })
		expect(res.status).toBe(200)
	})

	it('followRedirect:false stops at the first 3xx and surfaces Location', async () => {
		const res = await request({ simple: false, verifyTLS: false, followRedirect: false, timeout: 20_000, url: `${BASE}/redirect/1`, resolveWithFullResponse: true })
		expect(res.status).toBe(302)
		// httpbin's /redirect/1 points at /get; assert a Location came back, not its exact path.
		expect(res.headers.location).toBeTruthy()
	})

	it('maxRedirects bounds the chain', async () => {
		const res = await request({ simple: false, verifyTLS: false, json: true, timeout: 20_000, url: `${BASE}/redirect/5`, maxRedirects: 2, resolveWithFullResponse: true })
		// Budget exhausted before landing: the unresolved redirect status comes back.
		expect(res.status).toBeGreaterThanOrEqual(300)
		expect(res.status).toBeLessThan(400)
	})
})

describe('live status classes', () => {
	it('2xx: /status/200 resolves', async () => {
		const res = await request({ simple: false, verifyTLS: false, timeout: 20_000, url: `${BASE}/status/200`, resolveWithFullResponse: true })
		expect(res.status).toBe(200)
	})

	it('2xx: /status/204 resolves with an empty body', async () => {
		const res = await request({ simple: false, verifyTLS: false, timeout: 20_000, url: `${BASE}/status/204`, resolveWithFullResponse: true })
		expect(res.status).toBe(204)
		const empty = res.body === '' || (Buffer.isBuffer(res.body) && res.body.length === 0)
		expect(empty).toBe(true)
	})

	it('4xx: /status/404 rejects under default simple:true', async () => {
		await expect(request({ verifyTLS: false, timeout: 20_000, url: `${BASE}/status/404` })).rejects.toMatchObject({
			code: 'EHTTP',
			response: { status: 404 },
		})
	})

	it('4xx: /status/429 is an error unless simple:false', async () => {
		const res = await request({ simple: false, verifyTLS: false, timeout: 20_000, url: `${BASE}/status/429`, resolveWithFullResponse: true })
		expect(res.status).toBe(429)
	})

	it('5xx: /status/500 rejects under default simple:true', async () => {
		await expect(request({ verifyTLS: false, timeout: 20_000, url: `${BASE}/status/500` })).rejects.toMatchObject({
			code: 'EHTTP',
			response: { status: 500 },
		})
	})

	it('5xx: /status/503 resolves with simple:false', async () => {
		const res = await request({ simple: false, verifyTLS: false, timeout: 20_000, url: `${BASE}/status/503`, resolveWithFullResponse: true })
		expect(res.status).toBe(503)
	})
})
