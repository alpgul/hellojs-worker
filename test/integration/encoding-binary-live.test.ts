// Live check of the response-decoding + binary-download paths.
//
// The library auto-decompresses gzip / deflate / br / zstd from the response's Content-Encoding —
// no opt-in. Each encoding case asserts two independent things: the wire Content-Encoding header
// matches the codec, AND the body decoded to valid JSON (a decompression failure would either throw
// EDECOMPRESS or leave the body as a non-parsable Buffer).
//
// Codec availability is split across the two hosts: httpbingo.org (Go httpbin, TLS1.3 + h2) serves
// gzip + deflate but returns 501/404 for brotli/zstd; httpbin.io (Python httpbin, TLS1.2 + HTTP/1.1)
// serves brotli + zstd. So brotli/zstd also exercise the TLS 1.2 + HTTP/1.1 fallback path end-to-end.
//
// Live network — `network` project only, never `npm test`.

import { describe, expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST } from '../helpers/hosts.ts'

const GO = `https://${HTTP_HOST}` // httpbingo.org — TLS1.3 + h2
const PY = 'https://httpbin.io' // httpbin.io — TLS1.2 + HTTP/1.1

interface Echo {
	method?: string
	url?: string
	headers?: Record<string, string | string[]>
	gzipped?: boolean
	deflated?: boolean
}

const get = (url: string) =>
	request<Echo>({ simple: false, verifyTLS: false, json: true, timeout: 30_000, url, resolveWithFullResponse: true })

describe('response content-encoding — auto-decompress', () => {
	it('gzip (httpbingo)', async () => {
		const res = await get(`${GO}/gzip`)
		expect(res.headers['content-encoding']).toBe('gzip')
		// Decoded + JSON-parsed successfully → the gzip body was inflated.
		expect(res.status).toBe(200)
		expect(res.body?.method).toBe('GET')
		expect(res.body?.gzipped).toBe(true)
	})

	it('deflate (httpbingo)', async () => {
		const res = await get(`${GO}/deflate`)
		expect(res.headers['content-encoding']).toBe('deflate')
		expect(res.body?.method).toBe('GET')
		expect(res.body?.deflated).toBe(true)
	})

	it('brotli (httpbin.io — also drives TLS1.2 + HTTP/1.1)', async () => {
		const res = await get(`${PY}/brotli`)
		expect(res.headers['content-encoding']).toBe('br')
		expect(res.body?.method).toBe('GET')
	})

	it('zstd (httpbin.io — also drives TLS1.2 + HTTP/1.1)', async () => {
		const res = await get(`${PY}/zstd`)
		expect(res.headers['content-encoding']).toBe('zstd')
		expect(res.body?.method).toBe('GET')
	})
})

describe('binary downloads — no content-encoding, raw bytes preserved', () => {
	it('/bytes/1024 returns exactly 1024 raw bytes', async () => {
		// No json:true — the body must stay a byte Buffer, not be coerced to text.
		const res = await request<Buffer>({ simple: false, verifyTLS: false, timeout: 30_000, url: `${GO}/bytes/1024`, resolveWithFullResponse: true })
		expect(res.status).toBe(200)
		expect(res.headers['content-type']).toContain('application/octet-stream')
		expect(Buffer.isBuffer(res.rawBody)).toBe(true)
		expect((res.rawBody as Buffer).length).toBe(1024)
	})

	it('/image/jpeg returns a real JPEG (SOI magic FF D8 FF)', async () => {
		const res = await request<Buffer>({ simple: false, verifyTLS: false, timeout: 30_000, url: `${GO}/image/jpeg`, resolveWithFullResponse: true })
		expect(res.status).toBe(200)
		expect(res.headers['content-type']).toContain('image/jpeg')
		const buf = res.rawBody as Buffer
		expect(Buffer.isBuffer(buf)).toBe(true)
		expect(buf.length).toBeGreaterThan(1000)
		// JPEG starts with the SOI marker and ends with the EOI marker.
		expect([buf[0], buf[1], buf[2]]).toEqual([0xff, 0xd8, 0xff])
		expect([buf[buf.length - 2], buf[buf.length - 1]]).toEqual([0xff, 0xd9])
	})
})
