// HTTPS proxy (CONNECT over a TLS hop to the proxy).
//
// Loopback-only, deterministic: a TLS proxy that terminates our outer handshake and answers the
// CONNECT, and a TLS origin reached through the tunnel. The behaviors pinned here:
//   1. the request reaches the origin through the tunnel (inner handshake runs inside outer TLS)
//   2. the CONNECT pre-tile is encrypted — cleartext CONNECT to the same port cannot work
//   3. Proxy-Authorization comes from the proxy URL, and only then
//   4. the origin sees the ClientHello it would see unproxied: JA3/JA4 identical, one fingerprint
//   5. non-2xx CONNECT and an untrusted proxy certificate surface as EPROXY
//   6. h3 through a proxy falls back to TCP+CONNECT instead of bypassing the proxy
//   7. the cleartext http:// CONNECT path is unchanged

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as net from 'node:net'
import * as os from 'node:os'
import * as path from 'node:path'
import * as tls from 'node:tls'

import { afterAll, beforeAll, expect, it } from 'vitest'

import request from '../../index.ts'
import { get as getProfile } from '../../lib/profiles/index.ts'
import { ja3, parseClientHello } from '../../lib/tls/fingerprint.ts'
import { TLS } from '../../lib/tls/tls.ts'

import type { RequestOptions } from '../../index.ts'
import type { Profile } from '../../lib/profiles/types.ts'

// Self-signed pair for the proxy and the origin; both are trusted by nothing, so requests here run
// with verifyTLS:false except in the test that proves the proxy certificate IS validated.
function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjpx-'))
	const k = path.join(dir, 'k.pem')
	const c = path.join(dir, 'c.pem')
	try {
		execSync(
			`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`,
		)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

interface ProxyState {
	/** The CONNECT request line + headers, as decoded on the far side of the proxy's TLS session. */
	connectRequest: string
	/** ALPN the proxy selected, and the SNI it was given. */
	alpn: string | null
	servername: string
	/** First bytes the client pushed into the tunnel — its ClientHello. */
	tunnelHead: Buffer
}

interface FakeProxy extends ProxyState {
	port: number
	close: () => Promise<void>
}

// A TLS CONNECT proxy: terminates the client's TLS session, reads the CONNECT exchange off the
// plaintext side (which is what makes the encryption observable), then bridges to the origin.
// `reply` overrides the CONNECT response to exercise rejection paths.
function startTlsProxy(
	key: Buffer,
	cert: Buffer,
	reply?: (req: string) => string,
	dropTunnelAfterConnect = false
): Promise<FakeProxy> {
	// Mutated by the connection handler and read back through the same object by the assertions.
	const state = {
		connectRequest: '',
		alpn: null as string | null,
		servername: '',
		tunnelHead: Buffer.alloc(0),
		port: 0,
		close: async () => {}
	} as FakeProxy
	const clients = new Set<tls.TLSSocket>()
	// Bridged outbound sockets must be destroyed too: server.close() waits for every connection still
	// open, and a live tunnel would hang the origin's close until the test times out.
	const targets = new Set<net.Socket>()
	const server = tls.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, (sock) => {
		clients.add(sock)
		sock.on('error', () => { /* client tears down mid-test; assertions do not depend on it */ })
		let buf = Buffer.alloc(0)
		sock.on('data', (chunk) => {
			if (state.connectRequest) {
				// Post-tunnel bytes: the destination handshake arrives here in plaintext, carried
				// inside the proxy session's application data. Accumulate so a ClientHello split
				// across records still parses.
				state.tunnelHead = Buffer.concat([state.tunnelHead, chunk])
				return
			}
			// Negotiated parameters are only readable once the handshake finished.
			state.alpn = typeof sock.alpnProtocol === 'string' ? sock.alpnProtocol : null
			state.servername = typeof sock.servername === 'string' ? sock.servername : ''
			buf = Buffer.concat([buf, chunk])
			const sep = buf.indexOf('\r\n\r\n')
			if (sep === -1) return
			state.connectRequest = buf.subarray(0, sep).toString('latin1')
			const leftover = buf.subarray(sep + 4)
			const answer = reply ? reply(state.connectRequest) : 'HTTP/1.1 200 Connection established\r\n\r\n'
			sock.write(answer)
			if (!/^HTTP\/1\.[01] 2\d\d/.test(answer)) {
				sock.end()
				return
			}
			if (leftover.length) state.tunnelHead = leftover
			if (dropTunnelAfterConnect) {
				// A proxy that opens the tunnel and then dies: the session on the other side of it
				// has to find out, not wait out its handshake.
				setTimeout(() => sock.destroy(), 20)
				return
			}
			const authority = /^CONNECT (\S+) HTTP\/1\.1/.exec(state.connectRequest)?.[1] ?? ''
			const port = Number(authority.split(':').pop())
			const target = net.connect({ host: '127.0.0.1', port }, () => {
				if (leftover.length) target.write(leftover)
				sock.pipe(target)
				target.pipe(sock)
			})
			targets.add(target)
			target.on('close', () => targets.delete(target))
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
					for (const t of targets) t.destroy()
					targets.clear()
					for (const c of clients) c.destroy()
					server.close(() => r())
				})
			resolve(state)
		})
	})
}

// The origin: a TLS server that speaks one HTTP/1.1 response, so the inner handshake and the
// tunnel both have to work for the request to come back.
function startTlsOrigin(key: Buffer, cert: Buffer, body: string): Promise<{ port: number; close: () => Promise<void> }> {
	const clients = new Set<tls.TLSSocket>()
	const server = tls.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, (sock) => {
		clients.add(sock)
		sock.on('error', () => { /* half-closed client */ })
		sock.on('data', () => {
			sock.end(`HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`)
		})
	})
	return new Promise((resolve) => {
		server.listen({ port: 0, host: '127.0.0.1' }, () => {
			const addr = server.address()
			if (!addr || typeof addr === 'string') throw new Error('expected a bound TCP port')
			resolve({
				port: addr.port,
				close: () => new Promise<void>((r) => {
					for (const c of clients) c.destroy()
					server.close(() => r())
				})
			})
		})
	})
}

// GREASE-free and extension-order preserving, so JA3 is stable across connections and the proxied
// and unproxied hellos can be compared byte for byte. The stock profile shuffles extensions, the
// way Chrome does, which is a per-connection difference rather than a proxy difference.
function deterministicProfile(): Profile {
	const base = getProfile('default')
	return { ...base, tls: { ...base.tls, useGrease: false, extensionPermutation: 'preserve' } }
}

// Drive one handshake with the library's own TLS class and report the ClientHello fingerprint it
// published — nothing else should ever write it.
function fingerprintOf(tlsSession: TLS): Promise<string> {
	return new Promise((resolve, reject) => {
		tlsSession.on('fingerprint', (fp: { ja3: string }) => resolve(fp.ja3))
		tlsSession.on('error', (err: Error) => reject(err))
		void tlsSession.connect().catch(reject)
	})
}

// Poll for a condition the peer satisfies asynchronously: the ClientHello is captured at the proxy
// a moment after our own session finishes writing it.
async function waitFor(cond: () => boolean, ms = 3000): Promise<void> {
	const until = Date.now() + ms
	while (!cond()) {
		if (Date.now() > until) throw new Error('timed out waiting for condition')
		await new Promise((r) => setTimeout(r, 10))
	}
}

const full = (extra: Record<string, unknown>): RequestOptions & { resolveWithFullResponse: true } => ({
	simple: false,
	verifyTLS: false,
	timeout: 8000,
	resolveWithFullResponse: true,
	...extra,
})

let key: Buffer
let cert: Buffer
interface Origin { port: number; close: () => Promise<void> }
// A closed no-op stands in until a test starts one, so afterAll and every test can call close()
// without a null check.
let origin: Origin = { port: 0, close: async () => {} }
let proxy: FakeProxy | null = null

beforeAll(() => {
	const pair = genServerCert()
	key = pair.key
	cert = pair.cert
})

afterAll(async () => {
	await proxy?.close()
	await origin.close()
	proxy = null
})

async function withOrigins(body: string): Promise<number> {
	origin = await startTlsOrigin(key, cert, body)
	return origin.port
}

it('HTTPS proxy: the request round-trips through the tunnel', async () => {
	const originPort = await withOrigins('proxied-ok')
	proxy = await startTlsProxy(key, cert)

	const res = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://localhost:${proxy.port}`,
	}))
	expect(res.statusCode).toBe(200)
	expect(String(res.body)).toBe('proxied-ok')
	expect(proxy.connectRequest).toMatch(new RegExp(`^CONNECT 127\\.0\\.0\\.1:${originPort} HTTP/1\\.1`))
	expect(proxy.connectRequest).toMatch(new RegExp(`Host: 127\\.0\\.0\\.1:${originPort}`))

	await proxy.close()
	await origin.close()
	proxy = null
}, 20000)

it('the CONNECT pre-tile travels encrypted, and the proxy sees the proxy hostname as SNI', async () => {
	const originPort = await withOrigins('encrypted-ok')
	proxy = await startTlsProxy(key, cert)

	const res = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://localhost:${proxy.port}`,
	}))
	expect(String(res.body)).toBe('encrypted-ok')
	// The pre-tile was decoded from a TLS session, so it cannot have been sent in the clear.
	expect(proxy.alpn).toBe('http/1.1')
	expect(proxy.servername).toBe('localhost')

	await proxy.close()
	await origin.close()
	proxy = null
}, 20000)

it('cleartext CONNECT to a TLS proxy port cannot work', async () => {
	const originPort = await withOrigins('nope')
	proxy = await startTlsProxy(key, cert)

	await expect(
		request(full({ url: `https://127.0.0.1:${originPort}/`, proxy: `http://localhost:${proxy.port}` }))
	).rejects.toThrow()
	// The proxy never produced a CONNECT request line: the client's first bytes were a ClientHello,
	// which is exactly what the https:// scheme is for.
	expect(proxy.connectRequest).toBe('')

	await proxy.close()
	await origin.close()
	proxy = null
}, 20000)

it('Proxy-Authorization is sent from URL credentials and omitted without them', async () => {
	const originPort = await withOrigins('auth-ok')
	const expected = 'Basic ' + Buffer.from('alice:secret').toString('base64')
	proxy = await startTlsProxy(key, cert)

	const res = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://alice:secret@localhost:${proxy.port}`,
	}))
	expect(String(res.body)).toBe('auth-ok')
	expect(proxy.connectRequest).toContain(`Proxy-Authorization: ${expected}`)
	await proxy.close()

	proxy = await startTlsProxy(key, cert)
	await request(full({ url: `https://127.0.0.1:${originPort}/`, proxy: `https://localhost:${proxy.port}` }))
	expect(proxy.connectRequest).not.toMatch(/Proxy-Authorization/i)
	await proxy.close()

	// Percent-encoded userinfo is decoded before it becomes Basic credentials.
	proxy = await startTlsProxy(key, cert)
	const encoded = 'Basic ' + Buffer.from('a<b:c/d').toString('base64')
	await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://a%3Cb:c%2Fd@localhost:${proxy.port}`,
	}))
	expect(proxy.connectRequest).toContain(`Proxy-Authorization: ${encoded}`)
	await proxy.close()

	await origin.close()
	proxy = null
}, 20000)

it('a non-2xx CONNECT answer rejects as EPROXY, status line included', async () => {
	const originPort = await withOrigins('nope')

	for (const status of ['407 Proxy Authentication Required', '502 Bad Gateway']) {
		proxy = await startTlsProxy(key, cert, () => `HTTP/1.1 ${status}\r\n\r\n`)
		const err = await request(full({
			url: `https://127.0.0.1:${originPort}/`,
			proxy: `https://localhost:${proxy.port}`,
		})).catch((e: Error) => e) as Error & { code?: string; category?: string }
		expect(err).toBeInstanceOf(Error)
		expect(err.code).toBe('EPROXY')
		expect(err.category).toBe('transport')
		expect(err.message).toContain(`HTTP/1.1 ${status}`)
		await proxy.close()
		proxy = null
	}

	await origin.close()
}, 20000)

it('an untrusted proxy certificate is rejected by default, as EPROXY', async () => {
	const originPort = await withOrigins('nope')
	proxy = await startTlsProxy(key, cert)

	const err = await request({
		simple: false,
		timeout: 8000,
		resolveWithFullResponse: true,
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://localhost:${proxy.port}`,
	} as RequestOptions).catch((e: Error) => e) as Error & { code?: string }
	expect(err.code).toBe('EPROXY')
	expect(err.message).toMatch(/Proxy TLS handshake failed/)

	await proxy.close()
	await origin.close()
	proxy = null
}, 20000)

it('the origin sees the same ClientHello as unproxied, and only that one is reported', async () => {
	const originPort = await withOrigins('fp')
	const profile = deterministicProfile()
	const px = await startTlsProxy(key, cert)
	proxy = px

	// Baseline: direct handshake to the same origin with the same profile.
	const direct = new TLS('127.0.0.1', originPort, null, { verifyTLS: false, profile })
	const directJa3 = await fingerprintOf(direct)
	direct.h2Session?.close()
	direct.socket?.destroy()

	// Proxied: same profile, one extra TLS hop to the proxy.
	const viaProxy = new TLS('127.0.0.1', originPort, `https://localhost:${px.port}`, { verifyTLS: false, profile })
	const proxiedJa3 = await fingerprintOf(viaProxy)

	// The hello lands at the proxy a tick after our session put it on the wire; wait for the whole
	// handshake record (type 0x16, 2-byte length at offset 3).
	await waitFor(() => {
		const head = px.tunnelHead
		return head.length >= 5 && head[0] === 0x16 && head.length >= 5 + head.readUInt16BE(3)
	})

	viaProxy.h2Session?.close()
	viaProxy.socket?.destroy()

	expect(proxiedJa3).toBe(directJa3)
	// The fingerprint the caller reports is the hello that reached the origin, not the proxy's:
	// the head of the tunnel, captured on the far side of the proxy session, hashes to the same value.
	expect(ja3(parseClientHello(px.tunnelHead)).hash).toBe(proxiedJa3)
	expect(viaProxy.proxyTunnel).toBe(false)
	// The outer hop publishes nothing: its hello is the proxy's business alone.
	expect(viaProxy._proxyTls?.actualFingerprint).toBeUndefined()

	await px.close()
	await origin.close()
	proxy = null
}, 25000)

it('h3 through a proxy falls back to TCP+CONNECT instead of bypassing it', async () => {
	const originPort = await withOrigins('h3-fallback')
	proxy = await startTlsProxy(key, cert)

	const res = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://localhost:${proxy.port}`,
		h3: true,
	}))
	expect(String(res.body)).toBe('h3-fallback')
	expect(proxy.connectRequest).toMatch(/^CONNECT /)

	await proxy.close()
	await origin.close()
	proxy = null
}, 20000)

it('timeouts.connect covers the proxy hop without a false timeout', async () => {
	const originPort = await withOrigins('timed-ok')
	proxy = await startTlsProxy(key, cert)

	const res = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://localhost:${proxy.port}`,
		timeouts: { connect: 5000 },
	}))
	expect(String(res.body)).toBe('timed-ok')

	await proxy.close()
	await origin.close()
	proxy = null
}, 20000)

it('a proxy that dies right after opening the tunnel fails the request', async () => {
	const originPort = await withOrigins('nope')
	proxy = await startTlsProxy(key, cert, undefined, true)

	const t0 = Date.now()
	const err = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://localhost:${proxy.port}`,
	})).catch((e: Error) => e) as Error & { code?: string }
	// Before the fix this hung: the outer session handed the tunnel a clean EOF and the destination
	// handshake sat on it. The cleartext path fails the same way, from its TCP socket.
	expect(err).toBeInstanceOf(Error)
	expect(err.code).toBe('ECONNRESET')
	expect(Date.now() - t0).toBeLessThan(5000)

	await proxy.close()
	await origin.close()
	proxy = null
}, 20000)

it('a proxy that accepts TCP and stalls the TLS handshake is bounded', async () => {
	const originPort = await withOrigins('nope')
	// Speaks no TLS at all: reads the ClientHello, never answers.
	const sink = new net.Server((sock) => { sock.on('data', () => {}) })
	await new Promise<void>((resolve) => sink.listen({ port: 0, host: '127.0.0.1' }, () => resolve()))
	const sinkAddr = sink.address()
	if (!sinkAddr || typeof sinkAddr === 'string') throw new Error('expected a bound TCP port')

	const err = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://localhost:${sinkAddr.port}`,
		timeouts: { connect: 1500 },
	})).catch((e: Error) => e) as Error & { code?: string }
	expect(err.code).toBe('ETIMEDOUT')

	sink.close()
	await origin.close()
}, 20000)

it('regression: cleartext http:// CONNECT proxying still round-trips', async () => {
	const originPort = await withOrigins('clear-ok')
	let connectRequest = ''
	const clients = new Set<net.Socket>()
	const targets = new Set<net.Socket>()
	const plainProxy = net.createServer((sock) => {
		clients.add(sock)
		let buf = Buffer.alloc(0)
		sock.on('data', (chunk) => {
			if (connectRequest) return
			buf = Buffer.concat([buf, chunk])
			const sep = buf.indexOf('\r\n\r\n')
			if (sep === -1) return
			connectRequest = buf.subarray(0, sep).toString('latin1')
			const leftover = buf.subarray(sep + 4)
			const port = Number((/^CONNECT (\S+) HTTP\/1\.1/.exec(connectRequest)?.[1] ?? '').split(':').pop())
			const target = net.connect({ host: '127.0.0.1', port }, () => {
				sock.write('HTTP/1.1 200 Connection established\r\n\r\n')
				if (leftover.length) target.write(leftover)
				sock.pipe(target)
				target.pipe(sock)
			})
			targets.add(target)
			target.on('error', () => sock.destroy())
		})
		sock.on('error', () => { /* half-closed client */ })
	})
	await new Promise<void>((resolve) => plainProxy.listen({ port: 0, host: '127.0.0.1' }, () => resolve()))
	const proxyAddr = plainProxy.address()
	if (!proxyAddr || typeof proxyAddr === 'string') throw new Error('expected a bound TCP port')

	const res = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `http://127.0.0.1:${proxyAddr.port}`,
	}))
	expect(String(res.body)).toBe('clear-ok')
	expect(connectRequest).toMatch(new RegExp(`^CONNECT 127\\.0\\.0\\.1:${originPort} HTTP/1\\.1`))

	for (const t of targets) t.destroy()
	for (const c of clients) c.destroy()
	await new Promise<void>((resolve) => plainProxy.close(() => resolve()))
	await origin.close()
}, 20000)


it('proxyAuthorization overrides URL Basic auth and sends Bearer on CONNECT', async () => {
	const originPort = await withOrigins('bearer-ok')
	const bearer = 'Bearer eyJhbGciOiJIUzI1NiJ9.test.signature'
	proxy = await startTlsProxy(key, cert)

	const res = await request(full({
		url: `https://127.0.0.1:${originPort}/`,
		proxy: `https://ignored:creds@localhost:${proxy.port}`,
		proxyAuthorization: bearer,
	}))
	expect(String(res.body)).toBe('bearer-ok')
	expect(proxy.connectRequest).toContain(`Proxy-Authorization: ${bearer}`)
	expect(proxy.connectRequest).not.toMatch(/Proxy-Authorization:\s*Basic/i)

	await proxy.close()
	await origin.close()
	proxy = null
}, 20000)
