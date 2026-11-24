// End-to-end routing: a host that resolves only to Cloudflare-owned addresses leaves through the
// proxy pool, and the pool learns from what happened.
//
// Loopback-only and deterministic: a cleartext CONNECT proxy, a TLS origin behind it, and an
// injected resolver that reports Cloudflare ranges. Node has no rule against dialling Cloudflare
// IPs, so the platform refusal itself cannot be reproduced here — what these cases pin is the
// routing decision, the single reroute, and the bookkeeping around them.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as net from 'node:net'
import * as os from 'node:os'
import * as path from 'node:path'
import * as tls from 'node:tls'

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import request from '../../index.ts'
import { getCfRanges, resetCfRanges } from '../../lib/cf-ranges.ts'
import { setResolverForTests } from '../../lib/dns-cache.ts'
import { clearProxyPool, getProxyList, recordProxyOutcome, setProxyPool } from '../../lib/proxy-store.ts'

import type { ProxyOptions } from '../../index.ts'

/** Self-signed for both origin and proxy; every request here runs with `verifyTLS: false`. */
function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjroute-'))
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

interface FakeProxy {
	port: number
	/** The request line of every CONNECT this proxy received. */
	connects: string[]
	close: () => Promise<void>
}

/**
 * A cleartext CONNECT proxy. `reply` makes it reject the CONNECT instead of tunnelling; the
 * destination is always the loopback origin, so the CONNECT authority is only observed, never
 * resolved.
 */
function startConnectProxy(targetPort: number, reply?: string): Promise<FakeProxy> {
	const state = { port: 0, connects: [] as string[], close: async () => {} } as FakeProxy
	const sockets = new Set<net.Socket>()

	const server = net.createServer((sock) => {
		sockets.add(sock)
		sock.on('close', () => sockets.delete(sock))
		sock.on('error', () => {
			/* the client tears down; assertions do not depend on it */
		})

		let buf = Buffer.alloc(0)
		let tunnelled = false
		sock.on('data', (chunk) => {
			if (tunnelled) return
			buf = Buffer.concat([buf, chunk])
			const sep = buf.indexOf('\r\n\r\n')
			if (sep === -1) return

			tunnelled = true
			state.connects.push(buf.subarray(0, sep).toString('latin1').split('\r\n')[0] ?? '')
			// Stop reading until the tunnel is wired up, so the ClientHello that follows the
			// CONNECT is written in order instead of racing the pipe.
			sock.pause()
			const leftover = buf.subarray(sep + 4)

			if (reply) {
				sock.write(reply)
				sock.end()
				return
			}
			sock.write('HTTP/1.1 200 Connection established\r\n\r\n')

			const target = net.connect({ host: '127.0.0.1', port: targetPort }, () => {
				if (leftover.length) target.write(leftover)
				sock.pipe(target)
				target.pipe(sock)
				sock.resume()
			})
			sockets.add(target)
			target.on('close', () => sockets.delete(target))
			target.on('error', () => sock.destroy())
		})
	})

	return new Promise((resolve) => {
		server.listen({ port: 0, host: '127.0.0.1' }, () => {
			const addr = server.address()
			if (!addr || typeof addr === 'string') throw new Error('expected a bound TCP port')
			state.port = addr.port
			state.close = () =>
				new Promise<void>((r) => {
					for (const socket of sockets) socket.destroy()
					sockets.clear()
					server.close(() => r())
				})
			resolve(state)
		})
	})
}

/** A TLS origin that answers every request with one fixed response. */
function startTlsOrigin(
	key: Buffer,
	cert: Buffer,
	status: number,
	body: string
): Promise<{ port: number; close: () => Promise<void> }> {
	const clients = new Set<tls.TLSSocket>()
	const server = tls.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, (sock) => {
		clients.add(sock)
		sock.on('close', () => clients.delete(sock))
		sock.on('error', () => {
			/* half-closed client */
		})
		sock.on('data', () => {
			sock.end(
				`HTTP/1.1 ${status} ${status === 403 ? 'Forbidden' : 'OK'}\r\ncontent-type: text/plain\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`
			)
		})
	})
	return new Promise((resolve) => {
		server.listen({ port: 0, host: '127.0.0.1' }, () => {
			const addr = server.address()
			if (!addr || typeof addr === 'string') throw new Error('expected a bound TCP port')
			resolve({
				port: addr.port,
				close: () =>
					new Promise<void>((r) => {
						for (const client of clients) client.destroy()
						server.close(() => r())
					})
			})
		})
	})
}

const CF_V4_FEED = `104.16.0.0/13
172.64.0.0/13
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18`

/** Prime the shared range cache so routing never reaches the network. */
async function primeRanges(): Promise<void> {
	await getCfRanges({
		fetchImpl: (async (input: string | URL | Request) =>
			new Response(String(input).endsWith('ips-v4') ? CF_V4_FEED : '2606:4700::/32')) as unknown as typeof fetch
	})
}

const proxyUrl = (proxy: FakeProxy): string => `http://127.0.0.1:${proxy.port}`
const poolEntry = (url: string) => getProxyList().find((entry) => entry.url === url)

const BODY = 'through the tunnel'

let key: Buffer
let cert: Buffer
let okOrigin: { port: number; close: () => Promise<void> }
let denyOrigin: { port: number; close: () => Promise<void> }
let live: FakeProxy
let dead: FakeProxy
let denies: FakeProxy

beforeAll(async () => {
	;({ key, cert } = genServerCert())
	okOrigin = await startTlsOrigin(key, cert, 200, BODY)
	denyOrigin = await startTlsOrigin(key, cert, 403, 'no')
	live = await startConnectProxy(okOrigin.port)
	dead = await startConnectProxy(okOrigin.port, 'HTTP/1.1 502 Bad Gateway\r\n\r\n')
	denies = await startConnectProxy(denyOrigin.port)

	await primeRanges()
	setResolverForTests(async (hostname) => {
		// Everything Cloudflare-owned in this suite, plus one loopback host for the direct case.
		if (hostname === 'cf.example') return [{ address: '104.16.1.1', family: 4 }]
		if (hostname === 'local.example') return [{ address: '127.0.0.1', family: 4 }]
		throw new Error(`ENOTFOUND ${hostname}`)
	})
})

afterAll(async () => {
	setResolverForTests(null)
	resetCfRanges()
	await Promise.all([okOrigin.close(), denyOrigin.close(), live.close(), dead.close(), denies.close()])
})

beforeEach(() => {
	clearProxyPool()
	live.connects.length = 0
	dead.connects.length = 0
	denies.connects.length = 0
})

afterEach(() => vi.restoreAllMocks())

describe('automatic routing', () => {
	it('sends a Cloudflare-owned host through the pool and books the success', async () => {
		setProxyPool([{ url: proxyUrl(live) }])

		const res = await request('https://cf.example/', { verifyTLS: false })

		expect(await res.text()).toBe(BODY)
		expect(live.connects).toEqual(['CONNECT cf.example:443 HTTP/1.1'])
		expect(poolEntry(proxyUrl(live))).toMatchObject({ success: 1, fail: 0, live: true, lastOutcome: 'ok' })
	})

	it('keeps a host outside the ranges on the direct path', async () => {
		setProxyPool([{ url: proxyUrl(live) }])

		const res = await request(`https://local.example:${okOrigin.port}/`, { verifyTLS: false })

		expect(await res.text()).toBe(BODY)
		expect(live.connects).toEqual([])
	})

	it('honours an explicit proxy without consulting the pool', async () => {
		setProxyPool([{ url: proxyUrl(dead) }])

		const res = await request('https://cf.example/', { proxy: { url: proxyUrl(live) }, verifyTLS: false })

		expect(await res.text()).toBe(BODY)
		expect(live.connects).toHaveLength(1)
		// A caller-supplied proxy never picks up pool statistics.
		expect(poolEntry(proxyUrl(dead))).toMatchObject({ success: 0, fail: 0 })
	})

	it('honours proxy:null over a populated pool', async () => {
		setProxyPool([{ url: proxyUrl(live) }])

		const res = await request(`https://local.example:${okOrigin.port}/`, { proxy: null, verifyTLS: false })

		expect(await res.text()).toBe(BODY)
		expect(live.connects).toEqual([])
	})
})

describe('failover', () => {
	it('reroutes to another proxy and books the loss', async () => {
		// Weighted selection is random by design; pinning it to the first slot makes "the dead one
		// was tried first" a property of the test rather than of the draw.
		vi.spyOn(Math, 'random').mockReturnValue(0)
		setProxyPool([{ url: proxyUrl(dead) }, { url: proxyUrl(live) }])

		const res = await request('https://cf.example/', { verifyTLS: false })

		expect(await res.text()).toBe(BODY)
		expect(dead.connects).toHaveLength(1)
		expect(live.connects).toHaveLength(1)
		expect(poolEntry(proxyUrl(dead))).toMatchObject({ fail: 1, live: false })
		expect(poolEntry(proxyUrl(live))).toMatchObject({ success: 1, live: true })
	})

	it('reports EPROXYFAILED when every proxy fails', async () => {
		setProxyPool([{ url: proxyUrl(dead) }])

		await expect(request('https://cf.example/', { verifyTLS: false })).rejects.toMatchObject({
			code: 'EPROXYFAILED'
		})
		expect(poolEntry(proxyUrl(dead))).toMatchObject({ fail: 1, live: false })
	})
})

describe('origin rejection', () => {
	it('counts a 403 against that host only and surfaces the response', async () => {
		setProxyPool([{ url: proxyUrl(denies) }])

		const res = await request('https://cf.example/', { verifyTLS: false })

		expect(res.status).toBe(403)
		// Host-specific rejection: the proxy is denied for this host, but not globally tainted.
		expect(poolEntry(proxyUrl(denies))).toMatchObject({ fail: 0, lastOutcome: null, live: true })

		// The only proxy is now denied for this host, so routing refuses instead of retrying it.
		await expect(request('https://cf.example/', { verifyTLS: false })).rejects.toMatchObject({ code: 'ENOPROXY' })
		expect(denies.connects).toHaveLength(1)
	})

	it('fails with ENOPROXY when the pool cannot serve the host', async () => {
		const proxy: ProxyOptions = { url: proxyUrl(live) }
		setProxyPool([proxy])
		recordProxyOutcome(proxy, 'cf.example', 'blocked')

		await expect(request('https://cf.example/', { verifyTLS: false })).rejects.toMatchObject({ code: 'ENOPROXY' })
		expect(live.connects).toEqual([])
	})
})
