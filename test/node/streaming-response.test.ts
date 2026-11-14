// request() resolves a fetch Response as soon as the headers arrive; `body` is a web
// ReadableStream that delivers chunks progressively (no buffering).

import { execSync } from 'node:child_process'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as https from 'node:https'
import * as os from 'node:os'
import * as path from 'node:path'

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type { Server as NetServer } from 'node:net'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjsrv-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	try {
		// Fixed tmpdir paths, no user input reaches the shell string.
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

it('resolves a Response whose body yields chunks progressively', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert, allowHTTP1: false })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-type': 'application/octet-stream' })
		// Write 16 chunks of 8KB so the client receives them piecewise.
		let n = 0
		const tick = () => {
			if (n >= 16) { stream.end(); return }
			stream.write(crypto.randomBytes(8192))
			n++
			setImmediate(tick)
		}
		tick()
	})
	const port = await listenOnLoopback(server)

	try {
		// localhost cert is not in trust store, so we must disable cert validation.
		const res = await request({
			url: `https://127.0.0.1:${port}/`,
			verifyTLS: false,
		})

		expect(res.body).toBeInstanceOf(ReadableStream)
		const reader = res.body!.getReader()
		let bytes = 0
		let chunkCount = 0
		for (;;) {
			const { done, value } = await reader.read()
			if (done) break
			bytes += value.length
			chunkCount++
		}

		expect(bytes, 'all bytes received').toBe(16 * 8192)
		expect(chunkCount, `expected multiple progressive chunks, got ${chunkCount}`).toBeGreaterThanOrEqual(2)
	} finally {
		server.close()
	}
}, 10_000)

it('exposes status, headers and a web body stream', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 201, 'x-hello': 'world' })
		stream.end('payload')
	})
	const port = await listenOnLoopback(server)

	try {
		const res = await request({
			url: `https://127.0.0.1:${port}/`,
			verifyTLS: false,
		})
		expect(res.status).toBe(201)
		expect(res.headers.get('x-hello')).toBe('world')
		expect(res.body).toBeInstanceOf(ReadableStream)
		expect(await res.text()).toBe('payload')
	} finally {
		server.close()
	}
}, 10_000)

// Return a release function that lets the server finish the body; the request must not wait
// for it — that is the whole point of the default.
function holdBody(stream: http2.ServerHttp2Stream): () => void {
	return () => stream.end('tail')
}

it('streams by default: resolves at HEADERS before the body finishes', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	let release!: () => void
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-type': 'text/plain' })
		stream.write('head')
		release = holdBody(stream)
	})
	const port = await listenOnLoopback(server)

	try {
		const res = await Promise.race([
			request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false }),
			new Promise((_, reject) => setTimeout(() => reject(new Error('request did not resolve at headers')), 5_000)),
		]) as Response

		expect(res.status).toBe(200)
		const reader = res.body!.getReader()
		expect(new TextDecoder().decode((await reader.read()).value)).toBe('head')
		release()
		let rest = ''
		for (;;) {
			const { done, value } = await reader.read()
			if (done) break
			rest += new TextDecoder().decode(value)
		}
		expect(rest).toBe('tail')
	} finally {
		server.close()
	}
}, 10_000)

it('bodyOnly buffers implicitly even though streaming is the default', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-type': 'application/json' })
		stream.end('{"ok":true}')
	})
	const port = await listenOnLoopback(server)

	try {
		const body = await request({ url: `https://127.0.0.1:${port}/`, json: true, bodyOnly: true, verifyTLS: false })
		expect(body).toEqual({ ok: true })
	} finally {
		server.close()
	}
}, 10_000)

it('callback form buffers implicitly', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-type': 'text/plain' })
		stream.end('legacy')
	})
	const port = await listenOnLoopback(server)

	try {
		const res = await new Promise<Response>((resolve, reject) => {
			request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false }, (err, response) => {
				if (err) reject(err)
				else resolve(response as Response)
			})
		})
		expect(await res.text()).toBe('legacy')
	} finally {
		server.close()
	}
}, 10_000)

it('H2 applies inbound backpressure and resumes a slow consumer', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	const payload = crypto.randomBytes(512 * 1024)
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-type': 'application/octet-stream' })
		stream.end(payload)
	})
	const port = await listenOnLoopback(server)

	try {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false })
		const reader = res.body!.getReader()
		const first = await reader.read()
		expect(first.done).toBe(false)

		// Stop reading long enough for the stream window to fill and the transport to pause,
		// then drain. A broken pause/resume would either hang or drop bytes.
		await new Promise((resolve) => setTimeout(resolve, 100))

		let bytes = first.value!.length
		for (;;) {
			const { done, value } = await reader.read()
			if (done) break
			bytes += value.length
		}
		expect(bytes).toBe(payload.length)
	} finally {
		server.close()
	}
}, 10_000)

it('H1 pauses the socket for a slow consumer and resumes without dropping bytes', async () => {
	const { key, cert } = genServerCert()
	const payload = crypto.randomBytes(512 * 1024)
	const server = https.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, (_req, res) => {
		res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': payload.length })
		res.end(payload)
	})
	const port = await listenOnLoopback(server as unknown as NetServer)

	try {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false })
		const reader = res.body!.getReader()
		const first = await reader.read()
		expect(first.done).toBe(false)

		await new Promise((resolve) => setTimeout(resolve, 100))

		let bytes = first.value!.length
		for (;;) {
			const { done, value } = await reader.read()
			if (done) break
			bytes += value.length
		}
		expect(bytes).toBe(payload.length)
	} finally {
		server.close()
	}
}, 10_000)

it('an empty body with a content-encoding does not report a decoder error', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-encoding': 'gzip', 'content-length': '0' })
		stream.end()
	})
	const port = await listenOnLoopback(server)

	try {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false })
		expect(await res.text()).toBe('')
	} finally {
		server.close()
	}
}, 10_000)

it('an empty chunked body with a content-encoding closes cleanly', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-encoding': 'gzip' })
		stream.end()
	})
	const port = await listenOnLoopback(server)

	try {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false })
		expect(await res.text()).toBe('')
	} finally {
		server.close()
	}
}, 10_000)

it('timeouts.bodyIdle fails a stalled streamed body with EBODYIDLE', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200 })
		stream.write('start')
		// Never finish.
	})
	const port = await listenOnLoopback(server)

	try {
		const res = await request({
			url: `https://127.0.0.1:${port}/`,
			verifyTLS: false,
			timeouts: { bodyIdle: 50 },
		})
		const reader = res.body!.getReader()
		await reader.read()
		await expect(reader.read()).rejects.toMatchObject({ code: 'EBODYIDLE' })
	} finally {
		server.close()
	}
}, 10_000)
