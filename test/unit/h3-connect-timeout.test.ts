// The connect budget has to bound the QUIC handshake as well as the TCP one: a peer that
// ignores UDP would otherwise cost ~55s of Initial retransmits before `h3: true` falls back.

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

it('an h3 handshake honors timeouts.connect', async () => {
	udp.setUdpProvider(() => blackHoleSocket())
	try {
		const t0 = Date.now()
		// connect() must reject with the QUIC handshake timeout
		const error = await rejection(connect({ host: '127.0.0.1', port: 1, transport: 'quic', timeouts: { connect: 150 } }))
		expect(error.code).toBe('ETIMEDOUT')
		expect(error.message).toMatch(/QUIC handshake timed out/)
		expect(Date.now() - t0, 'the budget, not the idle timeout, ended the handshake').toBeLessThan(5000)
	} finally {
		udp.setUdpProvider(null)
	}
})

it('without a connect budget an h3 handshake is left to the QUIC layer', async () => {
	udp.setUdpProvider(null)
	// a runtime with no datagram transport fails fast
	const error = await rejection(connect({ host: '127.0.0.1', port: 1, transport: 'quic' }))
	expect(error.code).toBe('EUDPUNAVAILABLE')
})
