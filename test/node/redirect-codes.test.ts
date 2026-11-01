// Redirect semantics for the whole 3xx family (RFC 9110 §15.4): 300, 301, 302, 303, 304, 307, 308.
// Each case asserts the two things that distinguish the codes — whether the request is auto-followed,
// and what happens to the method + body on the followed hop. Deterministic, loopback-only: runs under
// the `node` project, never `npm test`'s network gates.
//
// The matrix these encode:
//   300  Multiple Choices  — body is an HTML option list, no Location → NOT auto-followed
//   301  Moved Permanently — GET stays; POST downgrades to bodyless GET (browser behavior)
//   302  Found             — GET stays; POST downgrades to bodyless GET
//   303  See Other         — every method becomes a bodyless GET
//   304  Not Modified      — conditional revalidation, no Location/no body → NOT auto-followed
//   307  Temporary Redirect— method AND body preserved verbatim
//   308  Permanent Redirect— method AND body preserved verbatim

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
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjrc-'))
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

// What the landing endpoint (/target) observed: the verb that arrived and the bytes of the body.
interface Seen {
	method?: string
	body?: string
}

// The redirect server routes three families of path:
//   /from/<status>   -> respond with <status> and, when the code carries a Location, point at /target
//   /target          -> record method + body, echo them back as 200 JSON
//   /loop/<n>        -> redirect to itself n more times (for maxRedirects exhaustion)
let lastSeen: Seen = {}

let server: http2.Http2SecureServer | null = null
let base = ''

beforeAll(async () => {
	const { key, cert } = genServerCert()
	server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream: http2.ServerHttp2Stream, headers: IncomingHttpHeaders) => {
		const p = String(headers[':path'] ?? '')
		let body = ''
		stream.on('data', (chunk) => {
			body += chunk
		})
		stream.on('error', () => {
			/* client half-closes */
		})
		stream.on('end', () => {
			if (p === '/target') {
				lastSeen = { method: String(headers[':method']), body }
				const payload = JSON.stringify(lastSeen)
				stream.respond({ ':status': 200, 'content-type': 'application/json' })
				stream.end(payload)
				return
			}
			if (p.startsWith('/from/')) {
				const status = Number(p.slice('/from/'.length))
				// 300 and 304 have no Location: they are terminal, not auto-followed.
				if (status === 300) {
					stream.respond({ ':status': 300, 'content-type': 'text/html' })
					stream.end('<html><body>choices</body></html>')
					return
				}
				if (status === 304) {
					// 304 must not carry a body (RFC 9110 §15.4.5).
					stream.respond({ ':status': 304, etag: '"v1"' })
					stream.end()
					return
				}
				stream.respond({ ':status': status, location: '/target' })
				stream.end()
				return
			}
			if (p.startsWith('/loop/')) {
				const remaining = Number(p.slice('/loop/'.length))
				if (remaining > 0) {
					stream.respond({ ':status': 302, location: `/loop/${remaining - 1}` })
					stream.end()
				} else {
					stream.respond({ ':status': 200 })
					stream.end('exhausted')
				}
				return
			}
			stream.respond({ ':status': 404 })
			stream.end('no route')
		})
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

const call = (extra: Record<string, unknown>): RequestOptions & { resolveWithFullResponse: true } => ({
	simple: false,
	verifyTLS: false,
	timeout: 5000,
	resolveWithFullResponse: true,
	...extra,
})

describe('3xx redirect codes — method/body semantics', () => {
	it('300 Multiple Choices: no Location → returned as-is, not followed', async () => {
		const res = await request(call({ url: `${base}/from/300` }))
		expect(res.status).toBe(300)
		expect(res.headers.location).toBeUndefined()
		expect(String(res.body)).toContain('choices')
	})

	it('301: GET stays GET and is followed', async () => {
		await request(call({ url: `${base}/from/301` }))
		expect(lastSeen.method).toBe('GET')
		expect(lastSeen.body).toBe('')
	})

	it('301: POST downgrades to a bodyless GET', async () => {
		await request(call({ url: `${base}/from/301`, method: 'POST', body: 'x=1', headers: { 'content-type': 'application/x-www-form-urlencoded' } }))
		expect(lastSeen.method).toBe('GET')
		expect(lastSeen.body).toBe('')
	})

	it('302: GET stays GET and is followed', async () => {
		await request(call({ url: `${base}/from/302` }))
		expect(lastSeen.method).toBe('GET')
	})

	it('302: POST downgrades to a bodyless GET', async () => {
		await request(call({ url: `${base}/from/302`, method: 'POST', body: 'x=1' }))
		expect(lastSeen.method).toBe('GET')
		expect(lastSeen.body).toBe('')
	})

	it('303: POST, PUT and PATCH all become a bodyless GET', async () => {
		for (const verb of ['POST', 'PUT', 'PATCH']) {
			await request(call({ url: `${base}/from/303`, method: verb, body: 'keep=me' }))
			expect(lastSeen.method).toBe('GET')
			expect(lastSeen.body).toBe('')
		}
	})

	it('304 Not Modified: no Location, no body → returned as-is, not followed', async () => {
		const res = await request(call({ url: `${base}/from/304` }))
		expect(res.status).toBe(304)
		expect(res.headers.location).toBeUndefined()
		expect(res.headers.etag).toBe('"v1"')
		expect(String(res.body)).toBe('')
	})

	it('307: POST method AND body preserved', async () => {
		await request(call({ url: `${base}/from/307`, method: 'POST', body: 'preserved=1' }))
		expect(lastSeen.method).toBe('POST')
		expect(lastSeen.body).toBe('preserved=1')
	})

	it('307: non-GET verb PUT preserved with body', async () => {
		await request(call({ url: `${base}/from/307`, method: 'PUT', body: 'put=1' }))
		expect(lastSeen.method).toBe('PUT')
		expect(lastSeen.body).toBe('put=1')
	})

	it('308: POST method AND body preserved', async () => {
		await request(call({ url: `${base}/from/308`, method: 'POST', body: 'still=here' }))
		expect(lastSeen.method).toBe('POST')
		expect(lastSeen.body).toBe('still=here')
	})
})

describe('redirect controls', () => {
	it("redirect:'manual' stops at the 3xx and surfaces Location", async () => {
		const res = await request(call({ url: `${base}/from/302`, redirect: 'manual' }))
		expect(res.status).toBe(302)
		expect(res.headers.location).toBe('/target')
	})

	it("redirect:'follow' explicitly follows the 3xx to the target", async () => {
		const res = await request(call({ url: `${base}/from/302`, redirect: 'follow' }))
		expect(res.status).toBe(200)
		expect(lastSeen.method).toBe('GET')
	})

	it('default (no redirect option) follows', async () => {
		const res = await request(call({ url: `${base}/from/302` }))
		expect(res.status).toBe(200)
	})

	it('maxRedirects bounds a redirect chain', async () => {
		// /loop/5 needs 5 hops; a budget of 2 must stop before reaching /target.
		const res = await request(call({ url: `${base}/loop/5`, maxRedirects: 2 }))
		expect(res.status).toBe(302)
		expect(String(res.body)).not.toBe('exhausted')
	})
})
