// Automatic transport selection: Happy Eyeballs QUIC / TCP race.
//
// No public `h3` switch. On a fresh connection QUIC and TCP+TLS start in the same tick and
// whichever handshake completes first wins; the loser is aborted immediately. Chrome gives QUIC
// a 300ms head start (`quic_delay_tcp_race`), but that makes every origin without a working
// QUIC path pay a fixed 300ms tax. This client is speed-first, so both transports are raced
// from the outset. When UDP is unavailable (Workers), a proxy is configured, or Alt-Svc only
// advertises h2/h1, we skip QUIC entirely and go straight to TCP/CONNECT. An Alt-Svc h3 hint
// starts QUIC without the race; if that handshake fails we fall back to TCP at once.
//
// Every attempt is bounded by lib/connect.ts's fixed 30s connect ceiling; the caller's
// `signal` cancels all outstanding attempts.

import { markAltSvcBroken } from './alt-svc.ts'
import { connect, type ConnectOptions, type Connection } from './connect.ts'
import { udpAvailable } from './h3/udp.ts'

export type TransportHint = 'h3' | 'h2' | 'h1' | null

export interface TransportResult {
	conn: Connection
	/** True when the request was actually sent to an Alt-Svc alternative (`Alt-Used`). */
	usedAlternative: boolean
}

/** Rebuild the connect options for a TCP fallback to the ORIGIN after a bad h3 hint. */
export function fallbackToOrigin(opts: ConnectOptions, origin: { host: string; port: number }): ConnectOptions {
	return { ...opts, host: origin.host, port: origin.port, sniHost: origin.host, transport: 'tcp' }
}

/** QUIC needs a datagram socket and cannot tunnel through an HTTP/SOCKS proxy. */
export function canUseQuic(proxy: ConnectOptions['proxy']): boolean {
	return !proxy && udpAvailable()
}

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

/**
 * Pick one transport for this request. A live pooled h2 connection is handled by the caller
 * before this point, so reaching here means a fresh handshake is needed.
 */
export function connectWithTransport(
	opts: ConnectOptions,
	hint: TransportHint = null,
	origin?: string,
	originEndpoint?: { host: string; port: number }
): Promise<TransportResult> {
	const quic = canUseQuic(opts.proxy)
	if (!quic || hint === 'h2' || hint === 'h1') {
		return connect({ ...opts, transport: 'tcp' }).then((conn) => ({
			conn,
			usedAlternative: hint !== null
		}))
	}

	// Alt-Svc advertised h3: go straight to QUIC, but fall back to the ORIGIN over TCP on failure.
	if (hint === 'h3') {
		return connect({ ...opts, transport: 'quic' })
			.then((conn) => ({ conn, usedAlternative: true }))
			.catch(() => {
				if (origin && !opts.signal?.aborted) markAltSvcBroken(origin, 'h3')
				const fallback = fallbackToOrigin(opts, originEndpoint ?? { host: opts.host, port: opts.port ?? 443 })
				return connect(fallback).then((conn) => ({ conn, usedAlternative: false }))
			})
	}

	return new Promise<TransportResult>((resolve, reject) => {
		let settled = false
		let tcpStarted = false
		const controllers = { quic: new AbortController(), tcp: new AbortController() }
		const conns: { quic?: Connection; tcp?: Connection } = {}
		const errors: { quic?: unknown; tcp?: unknown } = {}
		const unlinks = [linkAbort(opts.signal, controllers.quic), linkAbort(opts.signal, controllers.tcp)]

		const cleanup = () => {
			for (const unlink of unlinks) unlink()
		}

		const startTcp = () => {
			if (settled || tcpStarted) return
			tcpStarted = true
			connect({ ...opts, transport: 'tcp', signal: controllers.tcp.signal })
				.then((conn) => onReady('tcp', conn))
				.catch((err) => onFailure('tcp', err))
		}

		const onReady = (kind: 'quic' | 'tcp', conn: Connection) => {
			if (settled) {
				// Both handshakes finished in the same tick: close the one that arrived second.
				conn.close(`${kind}-race-lost`)
				return
			}
			settled = true
			cleanup()
			conns[kind] = conn
			const loser = kind === 'quic' ? 'tcp' : 'quic'
			controllers[loser].abort(new Error('transport race lost'))
			conns[loser]?.close(`${loser}-race-lost`)
			resolve({ conn, usedAlternative: false })
		}

		const onFailure = (kind: 'quic' | 'tcp', err: unknown) => {
			if (settled) return
			errors[kind] = err
			if (kind === 'quic') {
				// A failed handshake means this origin's cached h3 entry is stale. TCP is already
				// racing, so there is nothing to start here.
				if (origin && !opts.signal?.aborted) markAltSvcBroken(origin, 'h3')
			}
			if (errors.quic !== undefined && errors.tcp !== undefined) {
				settled = true
				cleanup()
				reject(errors.quic instanceof Error ? errors.quic : new Error(String(errors.quic)))
			}
		}

		connect({ ...opts, transport: 'quic', signal: controllers.quic.signal })
			.then((conn) => onReady('quic', conn))
			.catch((err) => onFailure('quic', err))

		// Happy Eyeballs: both transports are in flight from the first tick.
		startTcp()
	})
}
