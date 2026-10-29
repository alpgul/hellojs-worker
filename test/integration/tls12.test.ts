// TLS 1.2 fallback path against a TLS 1.2-only server.
//
// We don't dictate the version — instead, we connect and confirm the negotiation lands
// end-to-end with our custom TLS 1.2 record layer driving the response. The live path is
// exercised once; the record layer itself (PRF, AEAD gates, extensions) is unit-tested.
//
// Like everything here, this may legitimately go red when the server retires TLS 1.2 — that
// is why it sits in the `network` project, which CI never gates on.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { TLS12_HOST } from '../helpers/hosts.ts'
import { probeTls } from '../helpers/tls-probe.ts'

it(`${TLS12_HOST} negotiates against a TLS 1.2-capable server`, async () => {
	const r = await probeTls(TLS12_HOST)
	expect(r.ok, `${TLS12_HOST}: ${r.err}`).toBe(true)
})

it('end-to-end GET over TLS 1.2', async () => {
	const res = await request({ url: `https://${TLS12_HOST}/ip`, timeout: 15_000, resolveWithFullResponse: true })
	expect(res.statusCode).toBe(200)
	expect(String(res.body).length).toBeGreaterThan(0)
})
