// Smoke test: handshake against a variety of real servers.
// Confirms the TLS layer survives the diversity of cipher / group / cert-compression / ALPN
// choices. Live network: `network` project only.

import { expect, it } from 'vitest'

import { probeTls } from '../helpers/tls-probe.ts'

const TARGETS = [
	'tls.peet.ws',
	'www.cloudflare.com',
	'www.google.com',
	'www.amazon.com',
	'github.com',
	'httpbin.org',
]

it.each(TARGETS)('%s completes a handshake', async (host) => {
	const r = await probeTls(host, { timeoutMs: 10_000 })
	expect(r.ok, `${host}: ${r.err}`).toBe(true)
})
