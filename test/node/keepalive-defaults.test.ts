// Connection reuse is on by default: `keepalive: false` is the opt-out, not the opt-in.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

import { afterEach, expect, it } from 'vitest'

import request from '../../index.ts'
import { clearPool } from '../../lib/pool.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type { Socket } from 'node:net'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjkeep-'))
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

async function startH2(): Promise<{ port: number; connections: () => number; close: () => Promise<void> }> {
	const { key, cert } = genServerCert()
	const sockets = new Set<Socket>()
	let connections = 0
	const server = http2.createSecureServer({ key, cert })
	server.on('connection', (sock) => {
		connections += 1
		sockets.add(sock)
		sock.on('close', () => sockets.delete(sock))
	})
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200 })
		stream.end('ok')
	})
	const port = await listenOnLoopback(server)
	return {
		port,
		connections: () => connections,
		close: () =>
			new Promise<void>((resolve) => {
				for (const sock of sockets) sock.destroy()
				server.close(() => resolve())
			})
	}
}

afterEach(() => clearPool('test-teardown'))

it('sequential requests reuse one h2 socket by default', async () => {
	const server = await startH2()
	try {
		for (const path of ['/a', '/b']) {
			const res = await request(`https://127.0.0.1:${server.port}${path}`, { verifyTLS: false })
			expect(await res.text()).toBe('ok')
		}
		expect(server.connections()).toBe(1)
	} finally {
		await server.close()
	}
})

it('keepalive: false opens a fresh h2 socket per request', async () => {
	const server = await startH2()
	try {
		for (const path of ['/a', '/b']) {
			const res = await request(`https://127.0.0.1:${server.port}${path}`, {
				verifyTLS: false,
				keepalive: false
			})
			expect(await res.text()).toBe('ok')
		}
		expect(server.connections()).toBe(2)
	} finally {
		await server.close()
	}
})
