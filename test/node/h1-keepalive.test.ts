// HTTP/1.1 keep-alive: a completed, framed response parks the socket in the bounded pool and
// the next request reuses it. A server-close or keepalive:false keeps the old one-shot behavior.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as https from 'node:https'
import * as os from 'node:os'
import * as path from 'node:path'

import { afterEach, expect, it } from 'vitest'

import request from '../../index.ts'
import { clearPool } from '../../lib/pool.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type * as net from 'node:net'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjh1keep-'))
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

async function startH1(
	closeResponse = false
): Promise<{ url: string; connections: () => number; close: () => Promise<void> }> {
	const { key, cert } = genServerCert()
	const sockets = new Set<net.Socket>()
	let connections = 0
	const server = https.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, (_req, res) => {
		if (closeResponse) res.setHeader('Connection', 'close')
		res.writeHead(200, { 'content-type': 'text/plain' })
		res.end('ok')
	})
	server.on('connection', (raw) => {
		const sock = raw as net.Socket
		connections += 1
		sockets.add(sock)
		sock.on('close', () => sockets.delete(sock))
	})
	const port = await listenOnLoopback(server as unknown as net.Server)
	return {
		url: `https://127.0.0.1:${port}`,
		connections: () => connections,
		close: () =>
			new Promise<void>((resolve) => {
				for (const sock of sockets) sock.destroy()
				server.close(() => resolve())
			})
	}
}

afterEach(() => clearPool('test-teardown'))

it('sequential h1 requests reuse one socket by default', async () => {
	const server = await startH1()
	try {
		for (const p of ['/a', '/b', '/c']) {
			const res = await request(`${server.url}${p}`, { verifyTLS: false })
			expect(await res.text()).toBe('ok')
		}
		expect(server.connections()).toBe(1)
	} finally {
		await server.close()
	}
})

it('Connection: close on the response disables h1 reuse', async () => {
	const server = await startH1(true)
	try {
		for (const p of ['/a', '/b']) {
			const res = await request(`${server.url}${p}`, { verifyTLS: false })
			expect(await res.text()).toBe('ok')
		}
		expect(server.connections()).toBe(2)
	} finally {
		await server.close()
	}
})

it('keepalive: false opens a fresh h1 socket per request', async () => {
	const server = await startH1()
	try {
		for (const p of ['/a', '/b']) {
			const res = await request(`${server.url}${p}`, { verifyTLS: false, keepalive: false })
			expect(await res.text()).toBe('ok')
		}
		expect(server.connections()).toBe(2)
	} finally {
		await server.close()
	}
})
