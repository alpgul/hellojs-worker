// Per-request connection factory. Each request opens a fresh TLS (or QUIC) connection
// and closes it once the response completes, unless the caller opts into the process-wide
// keep-alive pool (lib/pool.ts).

import { HellojsError } from './errors.ts'
import { QuicConnection } from './h3/connection.ts'
import { H3Client } from './h3/h3.ts'
import * as proxyPool from './proxy-pool.ts'
import { TLS } from './tls/tls.ts'

import type { ProxyOptions } from './client.ts'
import type { H2Session } from './h2/session.ts'
import type { Profile } from './profiles/types.ts'
import type { ProxyHop, TLSOptions, TLSTransport } from './tls/tls.ts'

// Browser-like transport budgets. These are internal policy — there is no public timeout
// option; the only caller-controlled deadline is `signal` (AbortSignal.timeout() etc.).
// Values follow Chromium: a single connect attempt (DNS + TCP, or a proxy CONNECT) is capped
// at 30s, the TLS handshake gets 30s, and the whole connect job has a 30s ceiling. QUIC gets a
// shorter 2s budget so the TCP fallback is not held hostage by Initial retransmits.
const TCP_CONNECT_ATTEMPT_MS = 30_000
const CONNECT_JOB_TOTAL_MS = 30_000
const TLS_HANDSHAKE_MS = 30_000
const QUIC_HANDSHAKE_MS = 2_000

/** Forward an external abort signal into an internal controller. */
function linkAbort(source: AbortSignal | null | undefined, target: AbortController): () => void {
	if (!source) return () => {}
	if (source.aborted) {
		target.abort(source.reason)
		return () => {}
	}
	const onAbort = () => target.abort(source.reason)
	source.addEventListener('abort', onAbort, { once: true })
	return () => source.removeEventListener('abort', onAbort)
}

export interface ConnectOptions {
	/** Dial target. With Alt-Svc this can differ from the origin authority. */
	host: string
	port?: number
	/** SNI / certificate identity. Defaults to `host`; always the origin for Alt-Svc. */
	sniHost?: string
	profile?: Profile | string | null
	proxy?: ProxyOptions | null
	transport?: 'tcp' | 'quic'
	verifyTLS?: boolean
	/** Caller deadline; the internal 30s connect ceiling applies on top of it. */
	signal?: AbortSignal | null
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
	// Set by the keep-alive pool when the connection is registered: fired once per close so the
	// pool can evict the entry no matter which request path tore the socket down.
	declare onClosed: ((reason: string) => void) | null
	// Proxy hop checked out for this connection. Released back to lib/proxy-pool.ts on close.
	declare proxyHop: ProxyHop | null
	declare proxyPoolKey: string | null

	constructor(tls: TLS | null) {
		this.tls = tls
		this.alpn = null
		this.h2Session = null
		this.h2Transport = null
		this.h3Client = null
		this.quicConn = null
		this.closed = false
		this.onClosed = null
		this.proxyHop = null
		this.proxyPoolKey = null
	}

	close(reason = 'closed'): void {
		if (this.closed) return
		this.closed = true
		// h2 fails its streams in H2Session._fatalError; h3 needs the same fan-out so sibling
		// requests on a pooled QUIC session do not hang after the connection is torn down.
		if (this.quicConn) {
			const failure = new Error(`QUIC connection closed: ${reason}`)
			for (const stream of this.quicConn.streams.values()) {
				if (stream.listenerCount('error') > 0) stream.emit('error', failure)
			}
		}
		try {
			this.quicConn?.close()
		} catch {}
		try {
			this.h2Session?.close?.()
		} catch {}
		if (this.proxyHop && this.proxyPoolKey) {
			// Detach the destination session from the proxy transport and hand the still-live hop
			// back. Destroying tls.socket here would defeat the point of pooling the proxy hop.
			try {
				this.tls?.detachSocketListeners()
			} catch {}
			if (this.tls?.h2Transport) {
				// The inner session is done, but the TCP/TLS connection to the proxy is not.
				this.tls.h2Transport.keepUnderlyingAlive = true
				try {
					this.tls.h2Transport.destroy()
				} catch {}
			}
			proxyPool.release(this.proxyHop, this.proxyPoolKey)
			this.proxyHop = null
		} else {
			try {
				this.tls?.socket?.destroy()
			} catch {}
		}
		try {
			this.onClosed?.(reason)
		} catch {}
	}
}

function createH3(
	host: string,
	port: number,
	signal?: AbortSignal | null,
	sniHost?: string,
	verifyTLS = true
): Promise<Connection> {
	return new Promise((resolve, reject) => {
		const qc = new QuicConnection(host, port, sniHost, verifyTLS)
		const conn = new Connection(null)
		conn.quicConn = qc
		let settled = false
		let handshakeTimer: ReturnType<typeof setTimeout> | null = null
		const clearTimer = () => {
			if (handshakeTimer) {
				clearTimeout(handshakeTimer)
				handshakeTimer = null
			}
			signal?.removeEventListener?.('abort', onAbort)
		}
		const fail = (err: unknown) => {
			if (settled) return
			settled = true
			clearTimer()
			conn.close('error')
			reject(err instanceof Error ? err : new Error(String(err)))
		}
		const onAbort = () => fail(abortReason(signal))
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

		// QUIC has no TCP connect phase to bound, so a fixed handshake budget covers the whole
		// exchange: Initial packets retransmit until the idle timeout (~55s) against a server
		// that ignores UDP, and the browser-like TCP fallback must not wait that long.
		handshakeTimer = setTimeout(() => {
			fail(new HellojsError(`QUIC handshake timed out after ${QUIC_HANDSHAKE_MS}ms`, 'ETIMEDOUT'))
		}, QUIC_HANDSHAKE_MS)
		handshakeTimer.unref?.()
		if (signal?.aborted) onAbort()
		else signal?.addEventListener?.('abort', onAbort, { once: true })
	})
}

function abortReason(signal?: AbortSignal | null): unknown {
	if (signal?.reason !== undefined) return signal.reason
	return new DOMException('The operation was aborted.', 'AbortError')
}

function createTLS(
	host: string,
	port: number,
	profile: Profile | string | null | undefined,
	proxy: ProxyOptions | null | undefined,
	opts: {
		verifyTLS?: boolean
		signal?: AbortSignal | null
		proxyHop?: ProxyHop | null
		proxyPoolKey?: string | null
		/** Alt-Svc: dial `host` but keep SNI / certificate identity on the origin. */
		sniHost?: string
	} = {}
): Promise<Connection> {
	return new Promise((resolve, reject) => {
		const tlsOpts: TLSOptions = {}
		if (opts.sniHost) tlsOpts.sniHost = opts.sniHost
		tlsOpts.verifyTLS = opts.verifyTLS !== false
		// Resumption is always driven by the internal session-ticket store, like a browser.
		tlsOpts.resume = true
		if (profile) tlsOpts.profile = profile
		if (proxy?.authorization != null) tlsOpts.proxyAuthorization = proxy.authorization
		if (proxy?.headers != null) tlsOpts.proxyHeaders = proxy.headers
		if (opts.proxyHop) tlsOpts.proxyHop = opts.proxyHop
		const tls = new TLS(host, port, proxy?.url ?? null, tlsOpts)
		const conn = new Connection(tls)
		let settled = false
		let connectTimer: ReturnType<typeof setTimeout> | null = null
		let handshakeTimer: ReturnType<typeof setTimeout> | null = null
		const removeAbort = () => opts.signal?.removeEventListener?.('abort', onAbort)
		const clearAllTimers = () => {
			if (connectTimer) {
				clearTimeout(connectTimer)
				connectTimer = null
			}
			if (handshakeTimer) {
				clearTimeout(handshakeTimer)
				handshakeTimer = null
			}
			removeAbort()
		}
		const fail = (err: unknown) => {
			if (settled) return
			settled = true
			clearAllTimers()
			try {
				tls.socket?.destroy()
			} catch {}
			reject(err instanceof Error ? err : new Error(String(err)))
		}
		const onAbort = () => fail(abortReason(opts.signal))
		const onReady = (alpn: Alpn) => {
			if (settled) return
			settled = true
			clearAllTimers()
			conn.alpn = alpn
			conn.h2Session = tls.h2Session ?? null
			conn.h2Transport = tls.h2Transport ?? null
			if (alpn === 'http/1.1') {
				// Unlike h2/h3, h1 has no session object to notify us when the peer closes a
				// pooled socket. Evict on EOF so the pool never hands out a dead transport.
				const peerGone = () => conn.close('h1-peer-closed')
				tls.socket?.once('end', peerGone)
				tls.socket?.once('close', peerGone)
				tls.h2Transport?.once('end', peerGone)
			}
			if (opts.proxyPoolKey && tls.proxyHop) {
				conn.proxyHop = tls.proxyHop
				conn.proxyPoolKey = opts.proxyPoolKey
			}
			resolve(conn)
		}
		tls.on('ready', () => onReady('h2'))
		tls.on('ready-http1', () => onReady('http/1.1'))
		tls.on('error', (e: Error) => fail(e))
		tls.connect().catch((e: Error) => fail(e))

		// `transportEstablished` covers every establishment path — plain TCP, SOCKS5,
		// cleartext CONNECT and CONNECT-over-TLS. Fixed 30s budget, like Chromium's per-attempt
		// TCP connect timeout; the proxy CONNECT hop has its own matching budget in tls.ts.
		connectTimer = setTimeout(() => {
			if (!tls.transportEstablished) {
				fail(new HellojsError(`TCP connect timed out after ${TCP_CONNECT_ATTEMPT_MS}ms`, 'ETIMEDOUT'))
			}
		}, TCP_CONNECT_ATTEMPT_MS)
		connectTimer.unref?.()
		const onTransportReady = () => {
			if (connectTimer) {
				clearTimeout(connectTimer)
				connectTimer = null
			}
		}
		tls.once('transport-ready', onTransportReady)

		// Start the TLS-handshake stopwatch ONLY when ClientHello actually goes on the wire,
		// so it doesn't count MLKEM-keypair acquisition + TCP connect + proxy CONNECT time.
		// startClientHello re-fires on HRR; arm the timer once.
		tls.once('handshake-start', () => {
			if (settled) return
			handshakeTimer = setTimeout(() => {
				fail(new HellojsError(`TLS handshake timed out after ${TLS_HANDSHAKE_MS}ms`, 'ETIMEDOUT'))
			}, TLS_HANDSHAKE_MS)
			handshakeTimer.unref?.()
		})

		if (opts.signal?.aborted) onAbort()
		else opts.signal?.addEventListener?.('abort', onAbort, { once: true })
	})
}

// Only CONNECT-based proxies can have their transport reused. SOCKS5 handshakes are bound to a
// destination and are deliberately left one-shot.
function poolableProxy(proxy: ProxyOptions | null | undefined): proxy is ProxyOptions {
	if (!proxy || proxy.keepAlive === false) return false
	try {
		const scheme = new URL(proxy.url).protocol
		return scheme === 'http:' || scheme === 'https:' || scheme === 'ws:' || scheme === 'wss:'
	} catch {
		return false
	}
}

// One connection attempt, bounded internally by the per-phase timers in createTLS/createH3.
async function connectOnce({
	host,
	port = 443,
	sniHost,
	profile,
	proxy,
	transport = 'tcp',
	verifyTLS = true,
	signal
}: ConnectOptions): Promise<Connection> {
	if (transport === 'quic') {
		// QUIC/HTTP/3 has no proxy path. Rejecting instead of silently dropping `proxy` is what
		// makes connectPreferred fall through to TCP, so a request through a proxy still goes
		// through the proxy rather than straight to the origin.
		if (proxy) {
			throw new HellojsError('HTTP/3 is not supported through a proxy', 'EBADOPTS')
		}
		return createH3(host, port, signal, sniHost, verifyTLS)
	}

	let key: string | null = null
	let hop: ProxyHop | null = null
	if (poolableProxy(proxy)) {
		key = proxyPool.key(proxy, verifyTLS)
		hop = proxyPool.take(key)
	}
	const opts = {
		verifyTLS,
		signal,
		proxyHop: hop,
		proxyPoolKey: key,
		sniHost
	}
	try {
		return await createTLS(host, port, profile, proxy, opts)
	} catch (err) {
		if (!hop) throw err
		// A pooled hop can go stale between release and reuse. Discard it and retry once with a
		// freshly dialed proxy connection rather than surfacing a spurious EPROXY to the caller.
		proxyPool.evict(hop)
		return createTLS(host, port, profile, proxy, { ...opts, proxyHop: null })
	}
}

// Whole-job ceiling: DNS + all establishment phases must finish inside 30s. A caller signal
// (including AbortSignal.timeout()) can shorten it; it can never lengthen it.
async function connect(opts: ConnectOptions): Promise<Connection> {
	const job = new AbortController()
	const unlink = linkAbort(opts.signal, job)
	const budget = setTimeout(() => {
		job.abort(new HellojsError(`connect timed out after ${CONNECT_JOB_TOTAL_MS}ms`, 'ETIMEDOUT'))
	}, CONNECT_JOB_TOTAL_MS)
	budget.unref?.()
	try {
		return await connectOnce({ ...opts, signal: job.signal })
	} finally {
		clearTimeout(budget)
		unlink()
	}
}

// Sequential QUIC-then-TCP fallback, kept for low-level/bench callers. The public HTTP path
// uses lib/transport-race.ts instead, which races both with TCP delayed like Chromium.
async function connectPreferred(opts: ConnectOptions): Promise<Connection> {
	try {
		return await connect({ ...opts, transport: 'quic' })
	} catch {
		return connect({ ...opts, transport: 'tcp' })
	}
}

export {
	connect,
	connectPreferred,
	Connection,
	TCP_CONNECT_ATTEMPT_MS,
	CONNECT_JOB_TOTAL_MS,
	TLS_HANDSHAKE_MS,
	QUIC_HANDSHAKE_MS
}
