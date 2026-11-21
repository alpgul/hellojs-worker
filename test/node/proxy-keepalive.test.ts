// `proxy.keepAlive`: the connection to an HTTP proxy survives the destination session and is
// reused for a later CONNECT. A loopback CONNECT proxy counts accepted sockets and tunnels so the
// reuse (and the fallback when a pooled hop went stale) is observable without any network access.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as net from 'node:net'
import { createSocket } from 'node:dgram'
import * as os from 'node:os'
import * as path from 'node:path'
import * as tls from 'node:tls'

import { afterEach, expect, it } from 'vitest'

import request from '../../index.ts'
import type { FetchInit } from '../../index.ts'
import { clearProxyPool } from '../../lib/proxy-pool.ts'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjpk-'))
	const k = path.join(dir, 'k.pem')
	const c = path.join(dir, 'c.pem')
	try {
		execSync(
			`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`
		)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

const pair = genServerCert()

function startOrigin(): Promise<{ port: number; close: () => Promise<void> }> {
	const clients = new Set<tls.TLSSocket>()
	const server = tls.createServer({ key: pair.key, cert: pair.cert, ALPNProtocols: ['http/1.1'] }, (sock) => {
		clients.add(sock)
		sock.on('error', () => {})
		sock.on('data', () => {
			sock.end('HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok')
		})
	})
	return new Promise((resolve) => {
		server.listen({ port: 0, host: '127.0.0.1' }, () => {
			const addr = server.address()
			if (!addr || typeof addr === 'string') throw new Error('no port')
			resolve({
				port: addr.port,
				close: () =>
					new Promise<void>((r) => {
						for (const c of clients) c.destroy()
						server.close(() => r())
					})
			})
		})
	})
}

interface ConnectProxy {
	port: number
	connections: number
	tunnels: string[]
	close: () => Promise<void>
}

function startProxy(dropAfterTunnel = false, secure = false): Promise<ConnectProxy> {
	const clients = new Set<net.Socket>()
	const targets = new Set<net.Socket>()
	const state = { port: 0, connections: 0, tunnels: [] as string[], close: async () => {} }

	const handler = (sock: net.Socket) => {
		state.connections += 1
		clients.add(sock)
		sock.on('error', () => {})
		let buf = Buffer.alloc(0)
		let target: net.Socket | null = null

		const reset = () => {
			target = null
			buf = Buffer.alloc(0)
		}

		sock.on('data', (chunk) => {
			if (target) return // the established tunnel owns the bytes
			buf = Buffer.concat([buf, chunk])
			const sep = buf.indexOf('\r\n\r\n')
			if (sep === -1) return
			const req = buf.subarray(0, sep).toString('latin1')
			const leftover = buf.subarray(sep + 4)
			state.tunnels.push(req)
			sock.write('HTTP/1.1 200 Connection established\r\n\r\n')
			const authority = /^CONNECT (\S+) HTTP\/1\.1/.exec(req)?.[1] ?? ''
			const port = Number(authority.split(':').pop())
			target = net.connect({ host: '127.0.0.1', port }, () => {
				if (leftover.length) target?.write(leftover)
				// Keep the client side alive when the tunneled destination closes: a persistent
				// proxy connection is what `proxy.keepAlive` is meant to reuse.
				if (target) sock.pipe(target, { end: false })
				if (target) target.pipe(sock, { end: false })
			})
			const tunnel = target
			targets.add(tunnel)
			tunnel.on('error', () => sock.destroy())
			tunnel.on('close', () => {
				targets.delete(tunnel)
				if (sock.destroyed) return
				sock.unpipe(tunnel)
				tunnel.unpipe(sock)
				// unpipe() pauses the source; resume so the next CONNECT can be read.
				sock.resume()
				reset()
				if (dropAfterTunnel) setTimeout(() => sock.destroy(), 5)
			})
		})
		sock.on('close', () => {
			clients.delete(sock)
			for (const t of targets) t.destroy()
		})
	}

	const server = secure
		? tls.createServer({ key: pair.key, cert: pair.cert, ALPNProtocols: ['http/1.1'] }, handler)
		: net.createServer(handler)

	return new Promise((resolve) => {
		server.listen({ port: 0, host: '127.0.0.1' }, () => {
			const addr = server.address()
			if (!addr || typeof addr === 'string') throw new Error('no port')
			state.port = addr.port
			state.close = () =>
				new Promise<void>((r) => {
					for (const t of targets) t.destroy()
					targets.clear()
					for (const c of clients) c.destroy()
					server.close(() => r())
				})
			resolve(state)
		})
	})
}

const full = (opts: { url: string } & FetchInit): [string, FetchInit] => {
	const { url, ...init } = opts
	return [url, { verifyTLS: false, ...init }]
}

let origin: Awaited<ReturnType<typeof startOrigin>> | null = null
let proxy: ConnectProxy | null = null

afterEach(async () => {
	clearProxyPool()
	await proxy?.close()
	await origin?.close()
	proxy = null
	origin = null
})

it('proxy.keepAlive defaults to on and reuses one proxy socket', async () => {
	origin = await startOrigin()
	proxy = await startProxy()
	const opts = { url: `http://127.0.0.1:${proxy.port}` }

	for (const path of ['/a', '/b']) {
		const res = await request(...full({ url: `https://127.0.0.1:${origin.port}${path}`, proxy: opts }))
		expect(await res.text()).toBe('ok')
		// Give the fake proxy's tunnel teardown a tick before the next CONNECT.
		await new Promise((r) => setTimeout(r, 30))
	}

	expect(proxy.connections).toBe(1)
	expect(proxy.tunnels).toHaveLength(2)
	expect(proxy.tunnels[0]).toMatch(/^CONNECT 127\.0\.0\.1:\d+ HTTP\/1\.1/)
}, 20000)

it('proxy.keepAlive: false dials a fresh proxy socket per request', async () => {
	origin = await startOrigin()
	proxy = await startProxy()
	const opts = { url: `http://127.0.0.1:${proxy.port}`, keepAlive: false }

	for (const p of ['/a', '/b']) {
		const res = await request(...full({ url: `https://127.0.0.1:${origin.port}${p}`, proxy: opts }))
		expect(await res.text()).toBe('ok')
	}

	expect(proxy.connections).toBe(2)
	expect(proxy.tunnels).toHaveLength(2)
}, 20000)

it('a stale pooled hop is discarded and retried once with a fresh socket', async () => {
	origin = await startOrigin()
	proxy = await startProxy(true)
	const opts = { url: `http://127.0.0.1:${proxy.port}`, keepAlive: true }

	const first = await request(...full({ url: `https://127.0.0.1:${origin.port}/a`, proxy: opts }))
	expect(await first.text()).toBe('ok')
	// Let the fake proxy tear the first socket down, leaving a dead entry in the hop pool.
	await new Promise((r) => setTimeout(r, 60))

	const second = await request(...full({ url: `https://127.0.0.1:${origin.port}/b`, proxy: opts }))
	expect(await second.text()).toBe('ok')
	expect(proxy.connections).toBe(2)
}, 20000)

it('different proxy authorization values never share a hop', async () => {
	origin = await startOrigin()
	proxy = await startProxy()
	const opts = { url: `http://127.0.0.1:${proxy.port}`, keepAlive: true }

	await request(...full({ url: `https://127.0.0.1:${origin.port}/a`, proxy: { ...opts, authorization: 'Bearer a' } }))
	await request(...full({ url: `https://127.0.0.1:${origin.port}/b`, proxy: { ...opts, authorization: 'Bearer b' } }))

	expect(proxy.connections).toBe(2)
	expect(proxy.tunnels[0]).toContain('Proxy-Authorization: Bearer a')
	expect(proxy.tunnels[1]).toContain('Proxy-Authorization: Bearer b')
}, 20000)

it('proxy.keepAlive reuses the outer TLS hop of an HTTPS proxy', async () => {
	origin = await startOrigin()
	proxy = await startProxy(false, true)
	const opts = { url: `https://127.0.0.1:${proxy.port}`, keepAlive: true }

	for (const p of ['/a', '/b']) {
		const res = await request(...full({ url: `https://127.0.0.1:${origin.port}${p}`, proxy: opts }))
		expect(await res.text()).toBe('ok')
		await new Promise((r) => setTimeout(r, 30))
	}

	expect(proxy.connections).toBe(1)
	expect(proxy.tunnels).toHaveLength(2)
}, 20000)

it('concurrent requests open separate proxy hops instead of sharing one', async () => {
	origin = await startOrigin()
	const originPort = origin.port
	proxy = await startProxy()
	const opts = { url: `http://127.0.0.1:${proxy.port}`, keepAlive: true }

	const results = await Promise.all(
		['/a', '/b'].map((p) => request(...full({ url: `https://127.0.0.1:${originPort}${p}`, proxy: opts })))
	)
	for (const res of results) expect(await res.text()).toBe('ok')

	expect(proxy.connections).toBe(2)
	expect(proxy.tunnels).toHaveLength(2)
}, 20000)

it('request.defaults merges proxy fields, and proxy: null clears the default', async () => {
	origin = await startOrigin()
	proxy = await startProxy()
	const withDefaults = request.defaults({
		proxy: { url: `http://127.0.0.1:${proxy.port}`, keepAlive: true, authorization: 'Bearer default' }
	})

	const first = await withDefaults(
		...full({
			url: `https://127.0.0.1:${origin.port}/a`,
			proxy: { headers: { 'x-tenant': 'acme' } } as unknown as FetchInit['proxy']
		})
	)
	expect(await first.text()).toBe('ok')
	expect(proxy.tunnels[0]).toContain('Proxy-Authorization: Bearer default')
	expect(proxy.tunnels[0]).toContain('x-tenant: acme')

	const second = await withDefaults(...full({ url: `https://127.0.0.1:${origin.port}/b`, proxy: null }))
	expect(await second.text()).toBe('ok')
	expect(proxy.connections).toBe(1)
	expect(proxy.tunnels).toHaveLength(1)
}, 20000)

it('a forced TCP fallback still reuses the CONNECT tunnel', async () => {
	origin = await startOrigin()
	proxy = await startProxy()
	const opts = { url: `http://127.0.0.1:${proxy.port}`, keepAlive: true }
	// With QUIC out of reach, transport selection must fall back to TCP+CONNECT; the proxy
	// hop is still pooled the same way.
	request.udp.setUdpProvider(null)
	try {
		for (const p of ['/a', '/b']) {
			const res = await request(...full({ url: `https://127.0.0.1:${origin.port}${p}`, proxy: opts }))
			expect(await res.text()).toBe('ok')
		}
	} finally {
		request.udp.setUdpProvider(
			(type) => createSocket(type) as unknown as ReturnType<typeof request.udp.createSocket>
		)
	}

	expect(proxy.connections).toBe(1)
}, 30000)

it('a proxy object without a usable url rejects with EBADOPTS before dialling', async () => {
	for (const proxyOpt of [{}, { url: null }, { url: '  ' }]) {
		const err = (await request(...full({ url: 'https://127.0.0.1:1/', proxy: proxyOpt as { url: string } })).catch(
			(e: Error) => e
		)) as Error & { code?: string; category?: string }
		expect(err).toBeInstanceOf(Error)
		expect(err.code).toBe('EBADOPTS')
		expect(err.category).toBe('usage')
	}
})
