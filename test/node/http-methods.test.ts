// Exercises every HTTP method the public API exposes (GET, POST, PUT, PATCH, DELETE, HEAD,
// OPTIONS) against a local HTTP/2 echo server. Deterministic, loopback-only, no live network —
// so it runs under the `node` project, never `npm test`'s network gates.
//
// Each case asserts two things: (1) the server observed the right request line/method, and
// (2) the client surfaced the right status/body shape. HEAD is checked for the no-body contract.

import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'
import { execSync } from 'node:child_process'

import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import request from '../../index.ts'
import type { FetchInit } from '../../index.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type { IncomingHttpHeaders } from 'node:http2'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjhm-'))
	const k = path.join(dir, 'k.pem')
	const c = path.join(dir, 'c.pem')
	try {
		execSync(
			`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`
		)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

// Echo document the server writes back: which method it saw and what body it received.
interface Echo {
	method?: string
	path?: string
	body?: string
}

interface Harness {
	server: http2.Http2SecureServer
	port: number
	base: string
}

let harness: Harness | null = null

function startServer(): Promise<Harness> {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream: http2.ServerHttp2Stream, headers: IncomingHttpHeaders) => {
		const method = headers[':method'] ?? ''
		const urlPath = headers[':path'] ?? ''
		let body = ''
		stream.on('data', (chunk) => {
			body += chunk
		})
		stream.on('error', () => {
			/* the client half-closes; nothing to report */
		})
		stream.on('end', () => {
			const echo: Echo = { method, path: urlPath, body }
			const payload = JSON.stringify(echo)
			// HEAD responses must carry headers but never a body (RFC 9110 §9.3.4).
			if (method === 'HEAD') {
				stream.respond({
					':status': 200,
					'content-type': 'application/json',
					'content-length': Buffer.byteLength(payload)
				})
				stream.end()
				return
			}
			stream.respond({
				':status': 200,
				'content-type': 'application/json',
				'content-length': Buffer.byteLength(payload)
			})
			stream.end(payload)
		})
	})
	return listenOnLoopback(server).then((port) => ({ server, port, base: `https://127.0.0.1:${port}` }))
}

beforeAll(async () => {
	harness = await startServer()
})

afterAll(async () => {
	if (harness) {
		await new Promise<void>((resolve) => harness!.server.close(() => resolve()))
		harness = null
	}
})

function baseUrl(): string {
	if (!harness) throw new Error('server not started')
	return harness.base
}

const call = (url: string, init: FetchInit = {}) => request(url, { verifyTLS: false, ...init })

// The public API resolves a fetch Response; read the echo JSON body explicitly.
const echoBody = async (p: Promise<Response>): Promise<Echo> => (await p).json() as Promise<Echo>

describe('HTTP methods via shortcut API', () => {
	it('GET — server sees GET, empty body echoed back', async () => {
		const body = await echoBody(call(`${baseUrl()}/get`, { method: 'GET' }))
		expect(body.method).toBe('GET')
		expect(body.path).toBe('/get')
		expect(body.body).toBe('')
	})

	it('request.get shortcut issues GET', async () => {
		const body = await echoBody(request.get(`${baseUrl()}/g`, { verifyTLS: false }))
		expect(body.method).toBe('GET')
	})

	it('POST — body round-trips', async () => {
		const res = await echoBody(request.post(`${baseUrl()}/p`, { verifyTLS: false, body: 'payload-1' }))
		expect(res.method).toBe('POST')
		expect(res.body).toBe('payload-1')
	})

	it('PUT — full resource body round-trips', async () => {
		const res = await echoBody(request.put(`${baseUrl()}/r/1`, { verifyTLS: false, body: '{"name":"full"}' }))
		expect(res.method).toBe('PUT')
		expect(res.body).toBe('{"name":"full"}')
		expect(res.path).toBe('/r/1')
	})

	it('PATCH — partial body round-trips', async () => {
		const res = await echoBody(request.patch(`${baseUrl()}/r/1`, { verifyTLS: false, body: '{"name":"part"}' }))
		expect(res.method).toBe('PATCH')
		expect(res.body).toBe('{"name":"part"}')
	})

	it('DELETE — server sees DELETE, del + delete shortcuts agree', async () => {
		const viaDelete = await echoBody(request.del(`${baseUrl()}/r/2`, { verifyTLS: false }))
		expect(viaDelete.method).toBe('DELETE')
		const viaAlias = await echoBody(request.delete(`${baseUrl()}/r/2`, { verifyTLS: false }))
		expect(viaAlias.method).toBe('DELETE')
	})

	it('HEAD — status/headers returned, body empty', async () => {
		const res = await request.head(`${baseUrl()}/h`, { verifyTLS: false })
		expect(res.status).toBe(200)
		expect(res.headers.get('content-type')).toBe('application/json')
		// A GET-style request to this endpoint advertises content-length, but a HEAD response
		// must carry headers and never a body (RFC 9110 §9.3.4).
		expect(res.headers.get('content-length')).toBeTruthy()
		expect(res.body).toBeNull()
		expect(await res.text()).toBe('')
	})

	it('OPTIONS — server sees OPTIONS verb', async () => {
		const res = await echoBody(request.options(`${baseUrl()}/o`, { verifyTLS: false }))
		expect(res.method).toBe('OPTIONS')
	})
})

describe('HTTP methods via generic `method` option', () => {
	const verbs = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const
	for (const verb of verbs) {
		it(`${verb} via method option`, async () => {
			const res = await echoBody(call(`${baseUrl()}/m`, { method: verb, body: verb === 'GET' ? undefined : 'x' }))
			expect(res.method).toBe(verb)
		})
	}

	it('lowercase method string is normalised to the wire verb', async () => {
		const res = await echoBody(call(`${baseUrl()}/lc`, { method: 'post', body: 'y' }))
		expect(res.method).toBe('POST')
	})
})
