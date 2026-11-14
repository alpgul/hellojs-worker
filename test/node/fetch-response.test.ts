// Fetch-compatible response contract: `request()` returns a real WHATWG `Response` with the
// same shape and semantics as `fetch()`, regardless of ALPN (HTTP/1.1 and HTTP/2 over TLS)
// and regardless of whether the body was buffered or streamed.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as https from 'node:https'
import * as os from 'node:os'
import * as path from 'node:path'

import { describe, expect, it } from 'vitest'

import request from '../../index.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjfr-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	try {
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

async function startH2(handler: (s: http2.ServerHttp2Stream) => void) {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', handler)
	const port = await listenOnLoopback(server)
	return { server, url: `https://127.0.0.1:${port}` }
}

async function startH1(handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void) {
	const { key, cert } = genServerCert()
	const server = https.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, handler)
	const port = await listenOnLoopback(server as unknown as import('node:net').Server)
	return { server, url: `https://127.0.0.1:${port}` }
}

const req = (url: string, extra: Record<string, unknown> = {}) =>
	request({ url, verifyTLS: false, timeout: 5000, ...extra })

describe('fetch-compatible Response shape', () => {
	it('buffered H2 response is a real Response', async () => {
		const { server, url } = await startH2((s) => {
			s.respond({ ':status': 200, 'content-type': 'text/plain', 'x-id': '1' })
			s.end('hello')
		})
		try {
			const res = await req(url)
			expect(res).toBeInstanceOf(Response)
			expect(res.ok).toBe(true)
			expect(res.status).toBe(200)
			expect(typeof res.statusText).toBe('string')
			expect(res.headers).toBeInstanceOf(Headers)
			expect(res.headers.get('x-id')).toBe('1')
			expect(res.body).toBeInstanceOf(ReadableStream)
			expect(res.url).toContain('127.0.0.1')
			expect(res.redirected).toBe(false)
			expect(await res.text()).toBe('hello')
		} finally { server.close() }
	})

	it('buffered H1 (ALPN http/1.1) response is a real Response', async () => {
		const { server, url } = await startH1((_req, res) => {
			res.writeHead(200, { 'content-type': 'application/json', 'x-alpn': 'h1' })
			res.end('{"ok":true}')
		})
		try {
			const res = await req(url)
			expect(res).toBeInstanceOf(Response)
			expect(res.ok).toBe(true)
			expect(res.status).toBe(200)
			expect(res.headers.get('x-alpn')).toBe('h1')
			expect(await res.json()).toEqual({ ok: true })
		} finally { server.close() }
	})

	it('clone() yields an independent readable body', async () => {
		const { server, url } = await startH2((s) => { s.respond({ ':status': 200 }); s.end('clone-me') })
		try {
			const res = await req(url)
			const copy = res.clone()
			expect(await copy.text()).toBe('clone-me')
			expect(await res.text()).toBe('clone-me')
		} finally { server.close() }
	})
})

describe('streaming (progressive web ReadableStream body)', () => {
	it('H2 resolves at headers with a readable body', async () => {
		const { server, url } = await startH2((s) => {
			s.respond({ ':status': 200 })
			s.write('a')
			setTimeout(() => s.end('b'), 10)
		})
		try {
			const res = await req(url)
			expect(res.body).toBeInstanceOf(ReadableStream)
			const reader = res.body!.getReader()
			const chunks: Uint8Array[] = []
			for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value) }
			expect(Buffer.concat(chunks).toString()).toBe('ab')
		} finally { server.close() }
	})

	it('H1 resolves at headers with a readable body', async () => {
		const { server, url } = await startH1((_req, res) => {
			res.writeHead(200, { 'content-type': 'text/plain' })
			res.write('one-')
			setTimeout(() => res.end('two'), 10)
		})
		try {
			const res = await req(url)
			expect(res.body).toBeInstanceOf(ReadableStream)
			expect(await res.text()).toBe('one-two')
		} finally { server.close() }
	})
})

describe('status and redirect semantics (fetch parity)', () => {
	it('4xx/5xx resolve (no throw) by default; ok is false', async () => {
		const { server, url } = await startH2((s) => { s.respond({ ':status': 404 }); s.end('nope') })
		try {
			const res = await req(url)
			expect(res.ok).toBe(false)
			expect(res.status).toBe(404)
			expect(await res.text()).toBe('nope')
		} finally { server.close() }
	})

	it('removed simple/bodyOnly options are rejected with EBADOPTS', async () => {
		const { server, url } = await startH2((s) => { s.respond({ ':status': 200 }); s.end('ok') })
		try {
			await expect(req(url, { simple: true })).rejects.toMatchObject({ code: 'EBADOPTS' })
			await expect(req(url, { bodyOnly: true })).rejects.toMatchObject({ code: 'EBADOPTS' })
			// Explicit false promises nothing legacy; it is tolerated.
			const res = await req(url, { simple: false, bodyOnly: false })
			expect(await res.text()).toBe('ok')
		} finally { server.close() }
	})

	it('204 has a null body', async () => {
		const { server, url } = await startH2((s) => { s.respond({ ':status': 204 }); s.end() })
		try {
			const res = await req(url)
			expect(res.status).toBe(204)
			expect(res.body).toBeNull()
			expect(await res.text()).toBe('')
		} finally { server.close() }
	})

	it('follows redirects and reports redirected + final url', async () => {
		const { key, cert } = genServerCert()
		const server = http2.createSecureServer({ key, cert })
		server.on('stream', (s, h) => {
			if (h[':path'] === '/start') { s.respond({ ':status': 302, location: '/end' }); s.end() }
			else { s.respond({ ':status': 200 }); s.end('done') }
		})
		const port = await listenOnLoopback(server)
		try {
			const res = await req(`https://127.0.0.1:${port}/start`)
			expect(res.status).toBe(200)
			expect(res.redirected).toBe(true)
			expect(res.url).toContain('/end')
			expect(await res.text()).toBe('done')
		} finally { server.close() }
	})

	it("redirect: 'manual' returns the 3xx without following", async () => {
		const { server, url } = await startH2((s) => { s.respond({ ':status': 302, location: '/next' }); s.end() })
		try {
			const res = await req(url, { redirect: 'manual' })
			expect(res.status).toBe(302)
			expect(res.redirected).toBe(false)
			expect(res.headers.get('location')).toBe('/next')
		} finally { server.close() }
	})

	it("redirect: 'error' rejects on a redirect", async () => {
		const { server, url } = await startH2((s) => { s.respond({ ':status': 302, location: '/next' }); s.end() })
		try {
			await expect(req(url, { redirect: 'error' })).rejects.toThrow()
		} finally { server.close() }
	})
})

describe('abort', () => {
	it('rejects when the signal aborts before headers', async () => {
		const { server, url } = await startH2((s) => {
			// Never respond: the promise is still waiting for headers.
			void s
		})
		const ac = new AbortController()
		setTimeout(() => ac.abort(), 30)
		try {
			await expect(req(url, { signal: ac.signal, timeout: 5000 })).rejects.toThrow()
		} finally { server.close() }
	})

	it('resolves at headers, then errors the streamed body when the signal aborts', async () => {
		const { server, url } = await startH2((s) => {
			s.respond({ ':status': 200 })
			s.write('first')
			// never ends
			void s
		})
		const ac = new AbortController()
		try {
			// Headers resolve immediately; the body is still open.
			const res = await req(url, { signal: ac.signal })
			expect(res.status).toBe(200)
			const reader = res.body!.getReader()
			expect(new TextDecoder().decode((await reader.read()).value)).toBe('first')
			ac.abort()
			await expect(reader.read()).rejects.toThrow()
		} finally { server.close() }
	})
})
