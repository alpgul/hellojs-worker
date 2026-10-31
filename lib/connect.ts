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
	timeouts?: PerPhaseTimeouts | null
	/** Cancels an in-flight handshake. Used by `connectPreferred` to drop the losing race. */
	signal?: AbortSignal
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

function createH3(host: string, port: number, timeouts: PerPhaseTimeouts | null = null, signal?: AbortSignal): Promise<Connection> {
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
			signal?.removeEventListener('abort', onAbort)
			conn.close('error')
			reject(err)
		}
		const onAbort = () => fail(new HellojsError('connection attempt aborted', 'EABORTED'))
		if (signal?.aborted) { onAbort(); return }
		signal?.addEventListener('abort', onAbort, { once: true })
		qc.on('ready', () => {
			if (settled) return
			settled = true
			clearTimer()
			signal?.removeEventListener('abort', onAbort)
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
	opts: { verifyTLS?: boolean; timeouts?: PerPhaseTimeouts | null; signal?: AbortSignal } = {}
): Promise<Connection> {
	return new Promise((resolve, reject) => {
		const signal = opts.signal
		const tlsOpts: TLSOptions = {}
		tlsOpts.verifyTLS = opts.verifyTLS !== false
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
			signal?.removeEventListener('abort', onAbort)
			try { tls.socket?.destroy() } catch {}
			reject(err)
		}
		const onAbort = () => fail(new HellojsError('connection attempt aborted', 'EABORTED'))
		if (signal?.aborted) { onAbort(); return }
		signal?.addEventListener('abort', onAbort, { once: true })
		const onReady = (alpn: Alpn) => {
			if (settled) return
			settled = true
			clearAllTimers()
			signal?.removeEventListener('abort', onAbort)
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

function connect({ host, port = 443, profile, proxy, transport = 'tcp', verifyTLS = true, timeouts = null, signal }: ConnectOptions): Promise<Connection> {
	if (transport === 'quic') return createH3(host, port, timeouts, signal)
	return createTLS(host, port, profile, proxy, { verifyTLS, timeouts, signal })
}

// h3 is opt-in per request, but an origin that ignores QUIC would otherwise sit in Initial
// retransmits (~55s) before the TCP fallback. Race both handshakes and keep whichever is
// ready first: QUIC for h3 origins, TCP for everything else. The losing handshake is aborted
// so neither its socket nor its timers outlive the request.
async function connectPreferred(opts: ConnectOptions): Promise<Connection> {
	const tcpCtl = new AbortController()
	const quicCtl = new AbortController()
	const attempt = (transport: 'tcp' | 'quic', signal: AbortSignal) =>
		connect({ ...opts, transport, signal }).then(conn => ({ transport, conn }))
	const tcp = attempt('tcp', tcpCtl.signal)
	const quic = attempt('quic', quicCtl.signal)
	try {
		const winner = await Promise.any([tcp, quic])
		const loserSide = winner.transport === 'tcp' ? 'quic' : 'tcp'
		;(loserSide === 'tcp' ? tcpCtl : quicCtl).abort()
		// A loser that settled before the abort still owns a live connection.
		for (const p of [tcp, quic]) p.then(r => { if (r !== winner) r.conn.close('race-lost') }).catch(() => {})
		return winner.conn
	} catch (e) {
		// Both failed: surface the meaningful handshake error (skip "no UDP transport" /
		// "aborted", which only describe the losing attempt).
		const errors = (e as AggregateError).errors as NodeJS.ErrnoException[]
		throw errors.find(err => err.code !== 'EUDPUNAVAILABLE' && err.code !== 'EABORTED') ?? errors[0]
	}
}

export { connect, connectPreferred, Connection }
