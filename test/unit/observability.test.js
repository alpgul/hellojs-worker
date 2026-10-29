// Observability hooks fire on the expected lifecycle.

import assert from 'node:assert'
import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'
import test from 'node:test'

import request from '../../index.ts'

function genCert() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'obs-'))
	const k = path.join(dir, 'k'), c = path.join(dir, 'c')
	execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
	const key = fs.readFileSync(k), cert = fs.readFileSync(c)
	fs.rmSync(dir, { recursive: true, force: true })
	return { key, cert }
}

test('request lifecycle emits start, headersSent, firstByte, end', { timeout: 10_000 }, async () => {
	const { key, cert } = genCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (s) => { s.respond({ ':status': 200 }); s.end('ok') })
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port

	const events = []
	const recorder = (name) => (ev) => events.push({ name, ...ev })
	for (const e of ['request:start', 'request:headersSent', 'request:firstByte', 'request:end']) {
		request.observability.on(e, recorder(e))
	}

	const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, resolveWithFullResponse: true })
	assert.strictEqual(res.statusCode, 200)

	const names = new Set(events.map((e) => e.name))
	assert.ok(names.has('request:start'))
	assert.ok(names.has('request:headersSent'))
	assert.ok(names.has('request:firstByte'))
	assert.ok(names.has('request:end'))

	const endEv = events.find((e) => e.name === 'request:end')
	assert.strictEqual(endEv.status, 200)
	assert.ok(endEv.durationMs >= 0)

	for (const e of ['request:start', 'request:headersSent', 'request:firstByte', 'request:end']) {
		request.observability.removeAllListeners(e)
	}
	server.close()
})

test('throwing in a hook listener does not break the request', { timeout: 10_000 }, async () => {
	const { key, cert } = genCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (s) => { s.respond({ ':status': 200 }); s.end('ok') })
	await new Promise((r) => server.listen(0, '127.0.0.1', r))
	const port = server.address().port

	request.observability.on('request:start', () => { throw new Error('boom') })
	const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, resolveWithFullResponse: true })
	assert.strictEqual(res.statusCode, 200)
	request.observability.removeAllListeners('request:start')
	server.close()
})
