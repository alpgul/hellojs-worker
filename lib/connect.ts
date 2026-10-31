// Per-request connection factory. Each request opens a fresh TLS (or QUIC) connection
// and closes it once the response completes — there is no pooling or reuse.

import { HellojsError } from './errors.ts'
import { QuicConnection } from './h3/connection.ts'
import { H3Client } from './h3/h3.ts'
import { TLS } from './tls/tls.ts'

import type { H2Session } from './h2/session.ts'
import type { Profile } from './profiles/types.ts'
import type { TLSTransport, TLSOptions } from './tls/tls.ts'

// Per-phase timeouts, all optional. `response` is applied by lib/client.ts; the connect and
// handshake phases are armed here.
export interface PerPhaseTimeouts {
	connect?: number
	tlsHandshake?: number
	response?: number
}

export interface ConnectOptions {
	host: string
	port?: number
	profile?: Profile | string | null
	proxy?: string | null
	transport?: 'tcp' | 'quic'
	verifyTLS?: boolean
	resume?: boolean
	timeouts?: PerPhaseTimeouts | null
}

export type Alpn = 'h2' | 'http/1.1' | 'h3'

class Connection {
	declare tls: TLS | null
	declare alpn: Alpn | null
	declare h2Session: H2Session | null
	declare h2Transport: TLSTransport | null
	// Populated for h3 connections.
	declare h3Client: H3Client | null
	declare quicConn: QuicConnection | null
	declare closed: boolean

	constructor(tls: TLS | null) {
		this.tls = tls
		this.alpn = null
		this.h2Session = null
		this.h2Transport = null
		this.h3Client = null
		this.quicConn = null
		this.closed = false
	}

	close(_reason: string): void {
		if (this.closed) return
		this.closed = true
		try { this.quicConn?.close() } catch {}
		try { this.h2Session?.close?.() } catch {}
		try { this.tls?.socket?.destroy() } catch {}
	}
}

function createH3(host: string, port: number, timeouts: PerPhaseTimeouts | null = null): Promise<Connection> {
	return new Promise((resolve, reject) => {
		const qc = new QuicConnection(host, port)
		const conn = new Connection(null)
		conn.quicConn = qc
		let settled = false
		let handshakeTimer: ReturnType<typeof setTimeout> | null = null
		const clearTimer = () => {
			if (handshakeTimer) { clearTimeout(handshakeTimer); handshakeTimer = null }
		}
		const fail = (err: Error) => {
			if (settled) return
			settled = true
			clearTimer()
			conn.close('error')
			reject(err)
		}
		qc.on('ready', () => {
			if (settled) return
			settled = true
			clearTimer()
			conn.alpn = 'h3'
			conn.h3Client = new H3Client(qc)
			// Swallow post-handshake errors so a mid-request QUIC failure closes the
			// connection instead of crashing on an unhandled 'error' event.
			qc.on('error', () => conn.close('error'))
			resolve(conn)
		})
		qc.on('error', (e: Error) => fail(e))
		qc.connect().catch((e: Error) => fail(e))

		// QUIC has no TCP connect phase to bound, so the caller's `connect` budget covers the
		// whole handshake: Initial packets retransmit until the idle timeout (~55s) against a
		// server that ignores UDP, and `h3: true` would wait that long before falling back.
		if (timeouts?.connect) {
			handshakeTimer = setTimeout(() => {
				fail(new HellojsError(`QUIC handshake timed out after ${timeouts.connect}ms`, 'ETIMEDOUT'))
			}, timeouts.connect)
			handshakeTimer.unref?.()
		}
	})
}

function createTLS(
	host: string,
	port: number,
	profile: Profile | string | null | undefined,
	proxy: string | null | undefined,
	opts: { verifyTLS?: boolean; resume?: boolean; timeouts?: PerPhaseTimeouts | null } = {}
): Promise<Connection> {
	return new Promise((resolve, reject) => {
		const tlsOpts: TLSOptions = {}
		tlsOpts.verifyTLS = opts.verifyTLS !== false
		if (opts.resume) tlsOpts.resume = true
		if (profile) tlsOpts.profile = profile
		const tls = new TLS(host, port, proxy ?? null, tlsOpts)
		const conn = new Connection(tls)
		let settled = false
		let connectTimer: ReturnType<typeof setTimeout> | null = null
		let handshakeTimer: ReturnType<typeof setTimeout> | null = null
		const clearAllTimers = () => {
			if (connectTimer) { clearTimeout(connectTimer); connectTimer = null }
			if (handshakeTimer) { clearTimeout(handshakeTimer); handshakeTimer = null }
		}
		const fail = (err: Error) => {
			if (settled) return
			settled = true
			clearAllTimers()
			try { tls.socket?.destroy() } catch {}
			reject(err)
		}
		const onReady = (alpn: Alpn) => {
			if (settled) return
			settled = true
			clearAllTimers()
			conn.alpn = alpn
			conn.h2Session = tls.h2Session ?? null
			conn.h2Transport = tls.h2Transport ?? null
			resolve(conn)
		}
		tls.on('ready', () => onReady('h2'))
		tls.on('ready-http1', () => onReady('http/1.1'))
		tls.on('error', (e: Error) => fail(e))
		tls.connect().catch((e: Error) => fail(e))

		// Per-phase timeouts. Each is optional; without one the connection inherits
		// only Node's default socket and TLS behavior.
		const timeouts = opts.timeouts || {}
		if (timeouts.connect) {
			connectTimer = setTimeout(() => {
				if (!tls.socket || !tls.socket.connecting === false) {
					fail(new HellojsError(`TCP connect timed out after ${timeouts.connect}ms`, 'ETIMEDOUT'))
				}
			}, timeouts.connect)
			connectTimer.unref?.()
			// Once TCP is connected, cancel the connect timer.
			const onConnect = () => { if (connectTimer) { clearTimeout(connectTimer); connectTimer = null } }
			queueMicrotask(() => tls.socket?.once?.('connect', onConnect))
		}
		if (timeouts.tlsHandshake) {
			// Start the TLS-handshake stopwatch ONLY when ClientHello actually goes on the
			// wire, so it doesn't count MLKEM-keypair acquisition + TCP connect + proxy
			// CONNECT tunnel time. startClientHello re-fires on HRR; arm the timer once.
			tls.once('handshake-start', () => {
				if (settled) return
				handshakeTimer = setTimeout(() => {
					fail(new HellojsError(`TLS handshake timed out after ${timeouts.tlsHandshake}ms`, 'ETIMEDOUT'))
				}, timeouts.tlsHandshake)
				handshakeTimer.unref?.()
			})
		}
	})
}

function connect({ host, port = 443, profile, proxy, transport = 'tcp', verifyTLS = true, resume = false, timeouts = null }: ConnectOptions): Promise<Connection> {
	if (transport === 'quic') return createH3(host, port, timeouts)
	return createTLS(host, port, profile, proxy, { verifyTLS, resume, timeouts })
}

// h3 is opt-in per request and takes priority: start QUIC, and only fall back to TCP + TLS
// when the handshake cannot complete (an origin with no QUIC endpoint ignores our Initial
// packets). The budget keeps that fallback bounded — without it the QUIC layer would spend
// ~55s in Initial retransmits before the TCP attempt begins.
const DEFAULT_H3_HANDSHAKE_BUDGET_MS = 2_000

async function connectPreferred(opts: ConnectOptions): Promise<Connection> {
	const quicTimeouts: PerPhaseTimeouts = {
		...opts.timeouts,
		connect: opts.timeouts?.connect ?? DEFAULT_H3_HANDSHAKE_BUDGET_MS,
	}
	try {
		return await connect({ ...opts, transport: 'quic', timeouts: quicTimeouts })
	} catch {
		return connect({ ...opts, transport: 'tcp' })
	}
}

export { connect, connectPreferred, Connection }
