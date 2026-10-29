// HTTP/3 integration test: open a real QUIC connection against a public h3 server,
// complete the TLS 1.3-in-QUIC handshake, send a GET, decode the response.
//
// Live network + node:dgram, so it runs on the `network` project's Node pool.
// Override the endpoint with H3_HOST / H3_PATH.

import { expect, it } from 'vitest'

import { QuicConnection } from '../../lib/h3/connection.ts'
import { H3Client } from '../../lib/h3/h3.ts'

const HOST = process.env.H3_HOST ?? 'cloudflare-quic.com'
const PATH = process.env.H3_PATH ?? '/'

it('handshakes over QUIC and completes an h3 GET', async () => {
	const conn = new QuicConnection(HOST, 443)
	const ready = new Promise<void>((resolve, reject) => {
		const t = setTimeout(() => reject(new Error('h3 handshake timeout')), 15_000)
		conn.once('ready', () => { clearTimeout(t); resolve() })
		conn.once('error', (e: Error) => { clearTimeout(t); reject(e) })
	})

	try {
		await conn.connect()
		await ready
		expect(conn.alpn).toBe('h3')

		const h3 = new H3Client(conn)
		const res = await Promise.race([
			h3.request({ method: 'GET', path: PATH, host: HOST }),
			new Promise<never>((_, rej) => setTimeout(() => rej(new Error('request timeout')), 10_000)),
		])
		expect(res.status).toBeGreaterThanOrEqual(200)
		expect(res.status).toBeLessThan(400)
		expect(res.body.length).toBeGreaterThan(0)
	} finally {
		conn.close()
	}
}, 30_000)
