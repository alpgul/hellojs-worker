// Aborting one request on a shared h2 session must cancel only that stream; the next request
// reuses the same socket instead of paying for a new TLS handshake.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

import { afterEach, expect, it } from 'vitest'

import request from '../../index.ts'
import { clearPool } from '../../lib/pool.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type * as net from 'node:net'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjpooliso-'))
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

afterEach(() => clearPool('test-teardown'))

it('abort releases the h2 slot without killing the pooled connection', async () => {
	const { key, cert } = genServerCert()
	const sockets = new Set<net.Socket>()
	let connections = 0
	let sawSlow: () => void = () => {}
	const slowSeen = new Promise<void>((resolve) => {
		sawSlow = resolve
	})

	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream, headers) => {
		if (headers[':path'] === '/slow') {
			sawSlow()
			return // hold the stream open until the client aborts
		}
		if (headers[':path'] === '/reset') {
			stream.close(http2.constants.NGHTTP2_CANCEL)
			return
		}
		stream.respond({ ':status': 200, 'content-type': 'text/plain' })
		stream.end('ok')
	})
	server.on('connection', (raw) => {
		connections += 1
		sockets.add(raw)
		raw.on('close', () => sockets.delete(raw))
	})
	const port = await listenOnLoopback(server)
	const url = `https://127.0.0.1:${port}`

	try {
		const controller = new AbortController()
		const first = request(`${url}/slow`, { verifyTLS: false, signal: controller.signal })
		await slowSeen
		controller.abort()
		await expect(first).rejects.toBeDefined()

		const second = await request(`${url}/ok`, { verifyTLS: false })
		expect(await second.text()).toBe('ok')
		expect(connections).toBe(1)
	} finally {
		await new Promise<void>((resolve) => {
			for (const sock of sockets) sock.destroy()
			server.close(() => resolve())
		})
	}
})

it('a per-stream RST_STREAM does not kill the pooled h2 session', async () => {
	const { key, cert } = genServerCert()
	const sockets = new Set<net.Socket>()
	let connections = 0
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream, headers) => {
		if (headers[':path'] === '/reset') {
			stream.close(http2.constants.NGHTTP2_CANCEL)
			return
		}
		stream.respond({ ':status': 200, 'content-type': 'text/plain' })
		stream.end('ok')
	})
	server.on('connection', (raw) => {
		connections += 1
		sockets.add(raw)
		raw.on('close', () => sockets.delete(raw))
	})
	const port = await listenOnLoopback(server)
	const url = `https://127.0.0.1:${port}`

	try {
		await expect(request(`${url}/reset`, { verifyTLS: false })).rejects.toMatchObject({
			code: 'EH2STREAM'
		})
		const second = await request(`${url}/ok`, { verifyTLS: false })
		expect(await second.text()).toBe('ok')
		expect(connections).toBe(1)
	} finally {
		await new Promise<void>((resolve) => {
			for (const sock of sockets) sock.destroy()
			server.close(() => resolve())
		})
	}
})
