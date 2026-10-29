// Redirect handling: cross-origin credential stripping, same-origin retention, and method/body
// downgrade (303 -> GET, and POST -> GET on 301/302) per RFC 9110 §15.4 / browser behavior.

import assert from 'node:assert'
import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'
import test from 'node:test'

import request from '../../index.ts'

function genServerCert() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjrd-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
	const key = fs.readFileSync(k), cert = fs.readFileSync(c)
	fs.rmSync(dir, { recursive: true, force: true })
	return { key, cert }
}

async function startServer(onReq) {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream, headers) => {
		let body = ''
		stream.on('data', (c) => { body += c })
		stream.on('end', () => onReq(stream, headers, body))
		stream.on('error', () => {})
	})
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	return { server, port: server.address().port }
}

test('cross-origin redirect strips Authorization and Cookie', { timeout: 10000 }, async () => {
	let recv = null
	const target = await startServer((stream, h) => { recv = h; stream.respond({ ':status': 200 }); stream.end('landed') })
	const origin = await startServer((stream) => { stream.respond({ ':status': 302, location: `https://127.0.0.1:${target.port}/landing` }); stream.end() })
	try {
		const res = await request({
			url: `https://127.0.0.1:${origin.port}/`,
			headers: { authorization: 'Bearer secret', cookie: 'sid=abc' },
			verifyTLS: false, timeout: 5000, resolveWithFullResponse: true,
		})
		assert.strictEqual(res.body.toString(), 'landed')
		assert.strictEqual(recv.authorization, undefined, 'Authorization must not cross origins')
		assert.strictEqual(recv.cookie, undefined, 'Cookie must not cross origins')
	} finally {
		origin.server.close(); target.server.close()
	}
})

test('same-origin redirect keeps Authorization', { timeout: 10000 }, async () => {
	let recvNext = null
	const s = await startServer((stream, h) => {
		if (h[':path'] === '/start') { stream.respond({ ':status': 302, location: '/next' }); stream.end() }
		else { recvNext = h; stream.respond({ ':status': 200 }); stream.end('ok') }
	})
	try {
		await request({ url: `https://127.0.0.1:${s.port}/start`, headers: { authorization: 'Bearer secret' }, verifyTLS: false, timeout: 5000 })
		assert.strictEqual(recvNext.authorization, 'Bearer secret', 'Authorization should follow a same-origin redirect')
	} finally {
		s.server.close()
	}
})

test('303 downgrades POST to a bodyless GET', { timeout: 10000 }, async () => {
	let recv = null, recvBody = null
	const s = await startServer((stream, h, body) => {
		if (h[':path'] === '/submit') { stream.respond({ ':status': 303, location: '/done' }); stream.end() }
		else { recv = h; recvBody = body; stream.respond({ ':status': 200 }); stream.end('done') }
	})
	try {
		await request({ url: `https://127.0.0.1:${s.port}/submit`, method: 'POST', body: 'payload=1', headers: { 'content-type': 'application/x-www-form-urlencoded' }, verifyTLS: false, timeout: 5000 })
		assert.strictEqual(recv[':method'], 'GET', '303 must redirect as GET')
		assert.strictEqual(recvBody, '', 'redirected GET must carry no body')
		assert.strictEqual(recv['content-type'], undefined, 'body-framing headers should be dropped')
	} finally {
		s.server.close()
	}
})
