// Status-class behavior for 1xx / 2xx / 4xx / 5xx (RFC 9110 §13–15), one describe block per class.
// Deterministic, loopback-only HTTP/2 server: runs under the `node` project, never `npm test`'s
// network gates.
//
// The behaviors pinned here:
//   1xx  informational  — interim (100/103) is not surfaced; the client resolves the FINAL status.
//   2xx  success         — resolves; 204 carries no body and must not break JSON parsing.
//   4xx  client error    — simple:true rejects with EHTTP; simple:false resolves with the status.
//   5xx  server error    — same reject/resolve split; a transient 5xx is retried when asked.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import request from '../../index.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type { RequestOptions } from '../../index.ts'
import type { IncomingHttpHeaders } from 'node:http2'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjst-'))
	const k = path.join(dir, 'k.pem')
	const c = path.join(dir, 'c.pem')
	try {
		execSync(
			`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`,
		)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

let server: http2.Http2SecureServer | null = null
let base = ''
// Per-path hit counter so /flaky can fail once then succeed (retry path).
const hits = new Map<string, number>()

beforeAll(async () => {
	const { key, cert } = genServerCert()
	server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream: http2.ServerHttp2Stream, headers: IncomingHttpHeaders) => {
		const p = String(headers[':path'] ?? '')
		const n = (hits.get(p) ?? 0) + 1
		hits.set(p, n)
		stream.on('error', () => { /* client half-closes */ })
		const send = (status: number, body: string, contentType = 'application/json') => {
			stream.respond({ ':status': status, 'content-type': contentType })
			stream.end(status === 204 ? undefined : body)
		}
		switch (p) {
			case '/s200': return send(200, 'ok')
			case '/s201': return send(201, 'created')
			case '/s204': return send(204, '')
			case '/s103': {
				// 103 Early Hints is an interim response: informational HEADERS, then the real 200.
				stream.additionalHeaders({ ':status': 103, link: '</style.css>; rel=preload' })
				return send(200, 'final-after-hints')
			}
			case '/s100': {
				// 100 Continue before the client's body is accepted; final status here is 201.
				// ServerHttp2Stream has no writeContinue() — send the interim response via additionalHeaders.
				stream.additionalHeaders({ ':status': 100 })
				return send(201, 'continue-accepted')
			}
			case '/e400': return send(400, 'bad request')
			case '/e404': return send(404, 'not found')
			case '/e429': return send(429, 'rate limited')
			case '/e500': return send(500, 'boom')
			case '/e503': return send(503, 'unavailable')
			case '/flaky': return n === 1 ? send(500, 'first attempt fails') : send(200, 'second attempt ok')
			default: return send(404, 'no route')
		}
	})
	const port = await listenOnLoopback(server)
	base = `https://127.0.0.1:${port}`
})

afterAll(async () => {
	if (server) {
		await new Promise<void>((resolve) => server!.close(() => resolve()))
		server = null
	}
})

const full = (extra: Record<string, unknown>): RequestOptions & { resolveWithFullResponse: true } => ({
	simple: false,
	verifyTLS: false,
	timeout: 5000,
	resolveWithFullResponse: true,
	...extra,
})

describe('1xx informational', () => {
	it('103 Early Hints is not surfaced; the final 200 is returned', async () => {
		const res = await request(full({ url: `${base}/s103` }))
		expect(res.status).toBe(200)
		expect(String(res.body)).toBe('final-after-hints')
	})

	it('100 Continue is not surfaced; the final 201 is returned', async () => {
		const res = await request(full({ url: `${base}/s100`, method: 'POST', body: 'payload' }))
		expect(res.status).toBe(201)
		expect(String(res.body)).toBe('continue-accepted')
	})
})

describe('2xx success', () => {
	it('200 resolves as a success (default simple:true)', async () => {
		const body = await request({ verifyTLS: false, timeout: 5000, url: `${base}/s200` })
		expect(String(body)).toBe('ok')
	})

	it('201 Created resolves and surfaces the status', async () => {
		const res = await request(full({ url: `${base}/s201` }))
		expect(res.status).toBe(201)
	})

	it('204 No Content resolves with an empty body and survives json:true', async () => {
		const res = await request(full({ url: `${base}/s204`, json: true }))
		expect(res.status).toBe(204)
		const empty = res.body === '' || res.body === undefined || (Buffer.isBuffer(res.body) && res.body.length === 0)
		expect(empty).toBe(true)
	})
})

describe('4xx client error', () => {
	it('simple:true rejects with EHTTP and the status on the error', async () => {
		await expect(request({ verifyTLS: false, timeout: 5000, url: `${base}/e404` })).rejects.toMatchObject({
			code: 'EHTTP',
			response: { status: 404 },
		})
	})

	it('simple:false resolves the 4xx response instead of rejecting', async () => {
		const res = await request(full({ url: `${base}/e404` }))
		expect(res.status).toBe(404)
		expect(String(res.body)).toBe('not found')
	})

	it('429 is treated as an error (rejects under simple:true)', async () => {
		await expect(request({ verifyTLS: false, timeout: 5000, url: `${base}/e429` })).rejects.toMatchObject({
			code: 'EHTTP',
			response: { status: 429 },
		})
	})

	it('400 rejects under simple:true', async () => {
		await expect(request({ verifyTLS: false, timeout: 5000, url: `${base}/e400` })).rejects.toMatchObject({
			code: 'EHTTP',
			response: { status: 400 },
		})
	})
})

describe('5xx server error', () => {
	it('simple:true rejects with EHTTP for 500', async () => {
		await expect(request({ verifyTLS: false, timeout: 5000, url: `${base}/e500` })).rejects.toMatchObject({
			code: 'EHTTP',
			response: { status: 500 },
		})
	})

	it('simple:false resolves the 5xx response', async () => {
		const res = await request(full({ url: `${base}/e503` }))
		expect(res.status).toBe(503)
		expect(String(res.body)).toBe('unavailable')
	})

	it('a transient 500 is retried on GET and the retry succeeds', async () => {
		// Retry only fires on a thrown (simple:true) transient status: the first 500 must reject
		// for the policy to re-issue the GET. simple:false would resolve 500 immediately, no retry.
		const res = await request<unknown>({
			verifyTLS: false,
			timeout: 5000,
			resolveWithFullResponse: true,
			url: `${base}/flaky`,
			retry: { limit: 1, baseDelayMs: 10 },
		})
		expect(res.status).toBe(200)
		expect(String(res.body)).toBe('second attempt ok')
	})

	it('without a retry policy the 500 propagates (simple:false still resolves it)', async () => {
		const res = await request(full({ url: `${base}/e500` }))
		expect(res.status).toBe(500)
	})
})
