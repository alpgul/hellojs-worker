// HelloRetryRequest real-world coverage.
//
// Force the server to send HRR by offering a key_share for a group the server doesn't
// support (or by sending an empty key_share). RFC 8446 §4.1.4: when the server can't
// pick a key_share from CH1, it MUST respond with HelloRetryRequest containing the
// `selected_group` and (typically) a stateless cookie. CH2 includes the new key_share
// and the cookie, and the handshake proceeds.
//
// This suite uses the internal `_forceHRRGroup` test affordance to send a ClientHello
// that DEFINITELY triggers HRR — advertising only a single group with no real key_share.
// Live network: `network` project only.

import { expect, it } from 'vitest'

import { TLS13_HOST } from '../helpers/hosts.ts'
import { probeTls } from '../helpers/tls-probe.ts'

it(`${TLS13_HOST} retries after a HelloRetryRequest`, async () => {
	// Offer only secp256r1 with no real key_share — the server will HRR-select x25519
	// (or whatever its first-preference group is) and we re-send.
	const r = await probeTls(TLS13_HOST, { timeoutMs: 15_000, tlsOpts: { _forceHRRGroup: 0x0017 } })
	expect(r.ok, `${TLS13_HOST}: ${r.err}`).toBe(true)
})
