// A failed h3 Alt-Svc attempt must retry the ORIGIN over TCP, not the dead alternative,
// and must not claim `Alt-Used` on that fallback request.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

import { afterEach, expect, it } from 'vitest'

import request from '../../index.ts'
import { clearAltSvcCache } from '../../lib/alt-svc.ts'
import { clearPool } from '../../lib/pool.ts'
import { fallbackToOrigin } from '../../lib/transport-race.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type * as net from 'node:net'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjaltfall-'))
	const key = path.join(dir, 'key.pem')
	const cert = path.join(dir, 'cert.pem')
	try {
		execSync(
			`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${key} -out ${cert} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`
		)
		return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

afterEach(() => {
	clearAltSvcCache()
	clearPool('test-teardown')
})

it('rebuilds the TCP fallback options around the origin authority', () => {
	const fallback = fallbackToOrigin(
		{
			host: 'alt.example.net',
			port: 8443,
			sniHost: 'example.com',
			proxy: null,
			transport: 'quic'
		},
		{ host: 'example.com', port: 443 }
	)

	expect(fallback).toMatchObject({
		host: 'example.com',
		port: 443,
		sniHost: 'example.com',
		transport: 'tcp'
	})
})

it('h3 failure falls back to the origin without Alt-Used', async () => {
	const { key, cert } = genServerCert()
	const sockets = new Set<net.Socket>()
	const altUsed: (string | string[] | undefined)[] = []
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream, headers) => {
		altUsed.push(headers['alt-used'])
		if (headers[':path'] === '/advertise') {
			stream.respond({ ':status': 200, 'alt-svc': 'h3=":65534"; ma=3600' })
			stream.end('ok')
			return
		}
		stream.respond({ ':status': 200, 'content-type': 'text/plain' })
		stream.end('ok')
	})
	server.on('connection', (raw) => {
		sockets.add(raw)
		raw.on('close', () => sockets.delete(raw))
	})
	const port = await listenOnLoopback(server)
	const origin = `https://127.0.0.1:${port}`

	try {
		const first = await request(`${origin}/advertise`, { verifyTLS: false })
		expect(await first.text()).toBe('ok')

		const second = await request(`${origin}/get`, {
			verifyTLS: false,
			signal: AbortSignal.timeout(30_000)
		})
		expect(await second.text()).toBe('ok')
		expect(altUsed[0]).toBeUndefined()
		expect(altUsed[1]).toBeUndefined()
	} finally {
		await new Promise<void>((resolve) => {
			for (const sock of sockets) sock.destroy()
			server.close(() => resolve())
		})
	}
}, 40_000)
