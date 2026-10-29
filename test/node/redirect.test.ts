// Redirect handling: cross-origin credential stripping, same-origin retention, and method/body
// downgrade (303 -> GET, and POST -> GET on 301/302) per RFC 9110 §15.4 / browser behavior.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type { IncomingHttpHeaders } from 'node:http2'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjrd-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	try {
		// Fixed tmpdir paths, no user input reaches the shell string.
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

interface Harness { server: http2.Http2SecureServer; port: number }
type StreamHandler = (stream: http2.ServerHttp2Stream, headers: IncomingHttpHeaders, body: string) => void

async function startServer(onReq: StreamHandler): Promise<Harness> {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream, headers) => {
		let body = ''
		stream.on('data', (c) => { body += c })
		stream.on('end', () => onReq(stream, headers, body))
		stream.on('error', () => { /* the client half-closes; nothing to report */ })
	})
	return { server, port: await listenOnLoopback(server) }
}

// What the server side of a test saw, recorded from inside the stream callback. A holder object
// rather than a `let`, because TS control flow cannot see an assignment that happens in a
// callback and would narrow the variable back to its initial null at the read.
interface Seen { headers?: IncomingHttpHeaders; body?: string }

it('cross-origin redirect strips Authorization and Cookie', async () => {
	const landed: Seen = {}
	const target = await startServer((stream, h) => { landed.headers = h; stream.respond({ ':status': 200 }); stream.end('landed') })
	const origin = await startServer((stream) => {
		stream.respond({ ':status': 302, location: `https://127.0.0.1:${target.port}/landing` })
		stream.end()
	})
	try {
		const res = await request({
			url: `https://127.0.0.1:${origin.port}/`,
			headers: { authorization: 'Bearer secret', cookie: 'sid=abc' },
			verifyTLS: false, timeout: 5000, resolveWithFullResponse: true,
		})
		expect(String(res.body)).toBe('landed')
		expect(landed.headers?.authorization, 'Authorization must not cross origins').toBeUndefined()
		expect(landed.headers?.cookie, 'Cookie must not cross origins').toBeUndefined()
	} finally {
		origin.server.close(); target.server.close()
	}
}, 10_000)

it('same-origin redirect keeps Authorization', async () => {
	const next: Seen = {}
	const s = await startServer((stream, h) => {
		if (h[':path'] === '/start') { stream.respond({ ':status': 302, location: '/next' }); stream.end() }
		else { next.headers = h; stream.respond({ ':status': 200 }); stream.end('ok') }
	})
	try {
		await request({ url: `https://127.0.0.1:${s.port}/start`, headers: { authorization: 'Bearer secret' }, verifyTLS: false, timeout: 5000 })
		expect(next.headers?.authorization, 'Authorization should follow a same-origin redirect').toBe('Bearer secret')
	} finally {
		s.server.close()
	}
}, 10_000)

it('303 downgrades POST to a bodyless GET', async () => {
	const done: Seen = {}
	const s = await startServer((stream, h, body) => {
		if (h[':path'] === '/submit') { stream.respond({ ':status': 303, location: '/done' }); stream.end() }
		else { done.headers = h; done.body = body; stream.respond({ ':status': 200 }); stream.end('done') }
	})
	try {
		await request({
			url: `https://127.0.0.1:${s.port}/submit`, method: 'POST', body: 'payload=1',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			verifyTLS: false, timeout: 5000,
		})
		expect(done.headers?.[':method'], '303 must redirect as GET').toBe('GET')
		expect(done.body, 'redirected GET must carry no body').toBe('')
		expect(done.headers?.['content-type'], 'body-framing headers should be dropped').toBeUndefined()
	} finally {
		s.server.close()
	}
}, 10_000)
