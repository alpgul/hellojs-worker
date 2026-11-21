// Automatic transport selection: Chromium-style QUIC / TCP race.
//
// No public `h3` switch. On a fresh connection we start QUIC first and delay TCP by 300ms
// (Chrome's `quic_delay_tcp_race`); whichever handshake completes first wins and the loser is
// aborted immediately. When UDP is unavailable (Workers), a proxy is configured, or Alt-Svc
// only advertises h2/h1, we skip QUIC entirely and go straight to TCP/CONNECT. An Alt-Svc h3
// hint starts QUIC without the race; if that handshake fails we fall back to TCP at once.
//
// Every attempt is bounded by lib/connect.ts's fixed 30s connect ceiling; the caller's
// `signal` cancels all outstanding attempts.

import { markAltSvcBroken } from './alt-svc.ts'
import { connect, type ConnectOptions, type Connection } from './connect.ts'
import { udpAvailable } from './h3/udp.ts'

/** Chromium's QUIC-before-TCP race delay. */
const TCP_RACE_DELAY_MS = 300

export type TransportHint = 'h3' | 'h2' | 'h1' | null

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
	origin?: string
): Promise<Connection> {
	const quic = canUseQuic(opts.proxy)
	if (!quic || hint === 'h2' || hint === 'h1') return connect({ ...opts, transport: 'tcp' })

	// Alt-Svc advertised h3: go straight to QUIC, but fall back to TCP immediately on failure.
	if (hint === 'h3') {
		return connect({ ...opts, transport: 'quic' }).catch(() => {
			if (origin && !opts.signal?.aborted) markAltSvcBroken(origin, 'h3')
			return connect({ ...opts, transport: 'tcp' })
		})
	}

	return new Promise<Connection>((resolve, reject) => {
		let settled = false
		let tcpStarted = false
		let tcpTimer: ReturnType<typeof setTimeout> | null = null
		const controllers = { quic: new AbortController(), tcp: new AbortController() }
		const conns: { quic?: Connection; tcp?: Connection } = {}
		const errors: { quic?: unknown; tcp?: unknown } = {}
		const unlinks = [linkAbort(opts.signal, controllers.quic), linkAbort(opts.signal, controllers.tcp)]

		const cleanup = () => {
			if (tcpTimer) {
				clearTimeout(tcpTimer)
				tcpTimer = null
			}
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
			resolve(conn)
		}

		const onFailure = (kind: 'quic' | 'tcp', err: unknown) => {
			if (settled) return
			errors[kind] = err
			if (kind === 'quic') {
				// A failed handshake means this origin's cached h3 entry is stale.
				if (origin && !opts.signal?.aborted) markAltSvcBroken(origin, 'h3')
				// A QUIC failure before TCP even starts must not cost the 300ms race delay.
				startTcp()
			}
			if (errors.quic !== undefined && errors.tcp !== undefined) {
				settled = true
				cleanup()
				reject(errors.quic)
			}
		}

		connect({ ...opts, transport: 'quic', signal: controllers.quic.signal })
			.then((conn) => onReady('quic', conn))
			.catch((err) => onFailure('quic', err))

		tcpTimer = setTimeout(startTcp, TCP_RACE_DELAY_MS)
		tcpTimer.unref?.()
	})
}
