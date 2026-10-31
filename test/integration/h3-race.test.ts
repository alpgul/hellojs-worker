// h3:true races QUIC and TCP: an origin with no HTTP/3 endpoint must not stall the
// request behind QUIC Initial retransmits (~55s) before reaching the TCP fallback.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { HTTP_HOST, QUIC_HOST } from '../helpers/hosts.ts'

it('h3:true resolves quickly against an origin without a QUIC endpoint', async () => {
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
	expect(dt, `expected the TCP attempt to win quickly, took ${dt}ms`).toBeLessThan(5000)
}, 40_000)

it('h3:true still completes against an origin that speaks HTTP/3', async () => {
	const res = await request({
		url: `https://${QUIC_HOST}/`,
		h3: true,
		timeout: 30_000,
		simple: false,
		resolveWithFullResponse: true,
	})
	expect(res.status).toBe(200)
	expect(String(res.body).length).toBeGreaterThan(0)
}, 40_000)
