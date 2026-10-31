// h3:true prefers QUIC. Only an origin whose QUIC handshake cannot complete falls back
// to TCP + TLS, and that fallback stays bounded (no ~55s of QUIC Initial retransmits).

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { connectPreferred } from '../../lib/connect.ts'
import { HTTP_HOST, QUIC_HOST } from '../helpers/hosts.ts'

it('uses h3 when the origin supports QUIC', async () => {
	const conn = await connectPreferred({ host: QUIC_HOST, port: 443 })
	try {
		expect(conn.alpn).toBe('h3')
	} finally {
		conn.close('done')
	}
}, 40_000)

it('falls back to TCP quickly when the origin has no QUIC endpoint', async () => {
	const t0 = Date.now()
	const conn = await connectPreferred({ host: HTTP_HOST, port: 443 })
	try {
		const dt = Date.now() - t0
		expect(conn.alpn).not.toBe('h3')
		expect(dt, `expected a bounded QUIC attempt then TCP, took ${dt}ms`).toBeLessThan(5000)
	} finally {
		conn.close('done')
	}
}, 40_000)

it('request({ h3: true }) answers from an origin without a QUIC endpoint', async () => {
	const t0 = Date.now()
	const res = await request({
		url: `https://${HTTP_HOST}/get`,
		profile: 'chrome147-mac',
		h3: true,
		timeout: 30_000,
		simple: false,
		resolveWithFullResponse: true,
	})
	const dt = Date.now() - t0
	expect(res.status).toBe(200)
	expect(dt, `expected the TCP fallback to answer quickly, took ${dt}ms`).toBeLessThan(5000)
}, 40_000)
