// Transport selection is automatic: QUIC and TCP race, with a bounded QUIC attempt before a
// TCP-only origin answers. These checks prove both halves still work without any opt-in flag.

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

it('a request to an origin without a QUIC endpoint answers quickly', async () => {
	// No `h3` option: whichever transport wins the race, the answer must arrive promptly.
	const t0 = Date.now()
	const res = await request(`https://${HTTP_HOST}/get`, {
		profile: 'chrome147-mac',
		signal: AbortSignal.timeout(30_000)
	})
	const dt = Date.now() - t0
	expect(res.status).toBe(200)
	expect(dt, `expected the request to answer quickly, took ${dt}ms`).toBeLessThan(5000)
}, 40_000)
