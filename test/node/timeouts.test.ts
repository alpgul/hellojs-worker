// Per-phase timeouts — connect/tlsHandshake/response.

import * as net from 'node:net'

import { expect, it } from 'vitest'

import { connect } from '../../lib/connect.ts'
import { rejection } from '../helpers/errors.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

it('connect timeout fires when TCP connect hangs (route to a sinkhole IP)', async () => {
	// 240.0.0.1 is in TEST-NET-3 / reserved; routers drop the SYN, so connect hangs forever.
	const t0 = Date.now()
	const err = await rejection(connect({ host: '240.0.0.1', port: 443, timeouts: { connect: 200 } }))
	const dt = Date.now() - t0
	expect(err.code).toBe('ETIMEDOUT')
	expect(err.message).toMatch(/TCP connect timed out/)
	expect(dt, `expected fail within ~200ms, took ${dt}ms`).toBeLessThan(1000)
})

it('handshake timeout fires when peer accepts TCP but never speaks TLS', async () => {
	// Spin up a TCP server that accepts connections and does nothing — TLS handshake will hang.
	const server = net.createServer(() => { /* silent */ })
	const port = await listenOnLoopback(server)

	try {
		const t0 = Date.now()
		const err = await rejection(connect({ host: '127.0.0.1', port, timeouts: { tlsHandshake: 200 }, verifyTLS: false }))
		const dt = Date.now() - t0
		expect(err.code).toBe('ETIMEDOUT')
		expect(err.message).toMatch(/TLS handshake timed out/)
		expect(dt, `expected handshake fail within ~200ms, took ${dt}ms`).toBeLessThan(1000)
	} finally {
		server.close()
	}
})
