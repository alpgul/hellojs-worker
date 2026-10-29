// Observability hooks fire on the expected lifecycle.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

interface ObsEvent { name: string; status?: number; durationMs?: number }

const LIFECYCLE = ['request:start', 'request:headersSent', 'request:firstByte', 'request:end']

function genCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'obs-'))
	const k = path.join(dir, 'k'), c = path.join(dir, 'c')
	try {
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

it('request lifecycle emits start, headersSent, firstByte, end', async () => {
	const { key, cert } = genCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (s) => { s.respond({ ':status': 200 }); s.end('ok') })
	const port = await listenOnLoopback(server)

	const events: ObsEvent[] = []
	const recorder = (name: string) => (ev: unknown) => { events.push({ ...(ev as ObsEvent), name }) }
	for (const e of LIFECYCLE) request.observability.on(e, recorder(e))

	try {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, resolveWithFullResponse: true })
		expect(res.statusCode).toBe(200)

		const names = new Set(events.map((e) => e.name))
		expect(names.has('request:start')).toBe(true)
		expect(names.has('request:headersSent')).toBe(true)
		expect(names.has('request:firstByte')).toBe(true)
		expect(names.has('request:end')).toBe(true)

		const endEv = events.find((e) => e.name === 'request:end')
		expect(endEv?.status).toBe(200)
		expect(endEv?.durationMs).toBeGreaterThanOrEqual(0)
	} finally {
		for (const e of LIFECYCLE) request.observability.removeAllListeners(e)
		server.close()
	}
}, 10_000)

it('throwing in a hook listener does not break the request', async () => {
	const { key, cert } = genCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (s) => { s.respond({ ':status': 200 }); s.end('ok') })
	const port = await listenOnLoopback(server)

	request.observability.on('request:start', () => { throw new Error('boom') })
	try {
		const res = await request({ url: `https://127.0.0.1:${port}/`, verifyTLS: false, resolveWithFullResponse: true })
		expect(res.statusCode).toBe(200)
	} finally {
		request.observability.removeAllListeners('request:start')
		server.close()
	}
}, 10_000)
