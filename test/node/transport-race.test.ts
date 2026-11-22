// Happy Eyeballs regression: TCP must not wait 300ms for a QUIC head start that never answers.

import { performance } from 'node:perf_hooks'

import { expect, it } from 'vitest'

import { connectWithTransport } from '../../lib/transport-race.ts'
import { startLocalH2Server } from '../bench/helpers.ts'

it('starts TCP in the same tick as QUIC and uses the first handshake that finishes', async () => {
	const server = await startLocalH2Server()
	try {
		const started = performance.now()
		const { conn } = await connectWithTransport({ host: '127.0.0.1', port: server.port, verifyTLS: false })
		const elapsed = performance.now() - started
		expect(conn.alpn).toBe('h2')
		// The old Chromium-style 300ms delay put this well above 300; local TCP+TLS is ~10ms.
		expect(elapsed).toBeLessThan(250)
		conn.close('test-done')
	} finally {
		await server.close()
	}
})
