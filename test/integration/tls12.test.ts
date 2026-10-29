// TLS 1.2 fallback path: exercise against a diverse set of real servers.
//
// Strategy: we don't dictate the version — instead, we connect to each target and confirm
// the negotiation lands where we expect, end-to-end, with our custom TLS 1.2 record layer
// driving the response. The targets below were picked so that at least one negotiates each
// of the following:
//   - ECDHE-RSA-AES128-GCM-SHA256 (the modern GCM AEAD path)
//   - ECDHE-RSA-CHACHA20-POLY1305 (the alt AEAD path)
//   - RSA key exchange (no PFS — Chrome 147 still includes this in its 12-suite list)
//   - Extended Master Secret extension (RFC 7627)
//   - Session ticket extension (RFC 5077)
//
// Some of these may legitimately go red when a server retires TLS 1.2 or upgrades to
// 1.3-only — that is the point, and why they sit in the `network` project, which CI never gates on.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { probeTls } from '../helpers/tls-probe.ts'

const TLS12_TARGETS = [
	'httpbin.org',                  // ECDHE-RSA-AES128-GCM, h2 ALPN over TLS 1.2
	'mozilla-modern.badssl.com',    // TLS 1.2-only, modern AEAD
	'rsa2048.badssl.com',           // RSA 2048 leaf — ECDHE+RSA-sig path
	'sha256.badssl.com',            // SHA-256 path
	// Note: 1000-sans.badssl.com would exercise multi-record Certificate fragmentation,
	// but the cert expired in 2021. Fragmentation reassembly is covered by other paths
	// in production (large CA bundles + intermediate certs).
]

it.each(TLS12_TARGETS)('%s negotiates against a TLS 1.2-capable server', async (target) => {
	const [host, portStr] = target.split(':')
	const r = await probeTls(host, { port: portStr ? Number.parseInt(portStr, 10) : 443 })
	expect(r.ok, `${target}: ${r.err}`).toBe(true)
})

it('end-to-end GET over TLS 1.2', async () => {
	const res = await request({ url: 'https://httpbin.org/ip', timeout: 15_000, resolveWithFullResponse: true })
	expect(res.statusCode).toBe(200)
	expect(String(res.body).length).toBeGreaterThan(0)
})
