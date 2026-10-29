// The connect budget has to bound the QUIC handshake as well as the TCP one: a peer that
// ignores UDP would otherwise cost ~55s of Initial retransmits before `h3: true` falls back.

import assert from 'node:assert'
import test from 'node:test'

import { connect } from '../../lib/connect.ts'
import * as udp from '../../lib/h3/udp.ts'

// A socket that accepts writes and never receives anything: the handshake cannot complete.
function blackHoleSocket() {
	return {
		destroyed: false,
		on() {},
		bind(_port, callback) { queueMicrotask(callback) },
		send() {},
		close() { this.destroyed = true },
	}
}

test('an h3 handshake honors timeouts.connect', async () => {
	udp.setUdpProvider(() => blackHoleSocket())
	try {
		const t0 = Date.now()
		await assert.rejects(
			connect({ host: '127.0.0.1', port: 1, transport: 'quic', timeouts: { connect: 150 } }),
			(e) => e.code === 'ETIMEDOUT' && /QUIC handshake timed out/.test(e.message),
			'connect() must reject with the QUIC handshake timeout',
		)
		assert.ok(Date.now() - t0 < 5000, 'the budget, not the idle timeout, ended the handshake')
	} finally {
		udp.setUdpProvider(null)
	}
})

test('without a connect budget an h3 handshake is left to the QUIC layer', async () => {
	udp.setUdpProvider(null)
	await assert.rejects(
		connect({ host: '127.0.0.1', port: 1, transport: 'quic' }),
		(e) => e.code === 'EUDPUNAVAILABLE',
		'a runtime with no datagram transport fails fast',
	)
})
