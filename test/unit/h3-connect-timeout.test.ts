// QUIC's handshake budget is internal policy (2s): a peer that ignores UDP would otherwise
// cost ~55s of Initial retransmits before the request falls back to TCP. The public API has
// no timeout option — AbortSignal is the caller's deadline.

import { expect, it } from 'vitest'

import { connect } from '../../lib/connect.ts'
import * as udp from '../../lib/h3/udp.ts'
import { rejection } from '../helpers/errors.ts'

import type { UdpSocket } from '../../lib/h3/udp.ts'

// A socket that accepts writes and never receives anything: the handshake cannot complete.
function blackHoleSocket(): UdpSocket {
	const socket = {
		destroyed: false,
		on() {},
		bind(_port: number, callback: () => void) {
			queueMicrotask(callback)
		},
		send() {},
		close() {
			socket.destroyed = true
		}
	}
	return socket as unknown as UdpSocket
}

it('an h3 handshake times out on the fixed QUIC budget', async () => {
	udp.setUdpProvider(() => blackHoleSocket())
	try {
		const t0 = Date.now()
		// No configuration: the library's own 2s handshake budget must end the attempt.
		const error = await rejection(connect({ host: '127.0.0.1', port: 1, transport: 'quic' }))
		expect(error.code).toBe('ETIMEDOUT')
		expect(error.message).toMatch(/QUIC handshake timed out after 2000ms/)
		const elapsed = Date.now() - t0
		expect(elapsed, 'the fixed handshake budget ended the attempt').toBeGreaterThanOrEqual(1500)
		expect(elapsed, 'the QUIC idle timeout must not take over').toBeLessThan(5000)
	} finally {
		udp.setUdpProvider(null)
	}
})

it('without a UDP provider an h3 handshake fails fast', async () => {
	udp.setUdpProvider(null)
	// a runtime with no datagram transport fails fast
	const error = await rejection(connect({ host: '127.0.0.1', port: 1, transport: 'quic' }))
	expect(error.code).toBe('EUDPUNAVAILABLE')
})
