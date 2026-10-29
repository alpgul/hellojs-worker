// Vitest runs the library's tests in three projects, split by the runtime they need.
//
//   workers  -> inside workerd, via the official Workers Vitest integration. The library reads
//               ML-KEM and X25519 off the global `crypto.subtle` (lib/tls/mlkem.ts, lib/tls/x25519.ts),
//               and ML-KEM only exists there behind `webcrypto_modern_algorithms` — which Node has no
//               equivalent of. Those tests are meaningless anywhere else.
//   node     -> Node's own pool, for tests that need local TCP/TLS servers, node:fs fixtures,
//               node:dgram or Node's real CA bundle, none of which workerd provides.
//   network  -> live internet. Never part of `npm test`.
//
// A test moves from workers to node only because of a workerd runtime limitation, never to hide a
// library bug. New tests that import node:fs, node:child_process, node:dgram, a node:net/node:tls
// server, or `tls.rootCertificates` belong in test/node/ straight away.
//
// cloudflareTest() must stay on the workers project alone: it rewrites the project it is attached to
// onto the cloudflare-pool, and root-level plugins are inherited by every project.

import { cloudflareTest } from '@cloudflare/vitest-plugin'
import { defineConfig } from 'vitest/config'

export default defineConfig({
	test: {
		globals: false,
		projects: [
			{
				plugins: [cloudflareTest({ wrangler: { configPath: './wrangler.jsonc' } })],
				test: {
					name: 'workers',
					include: ['test/unit/**/*.test.ts'],
					setupFiles: ['test/setup/workerd.ts'],
					// The pool pays for a workerd boot before the first assertion, and the crypto
					// suites do real key agreement on top of that.
					testTimeout: 30_000,
					hookTimeout: 30_000,
					isolate: true
				}
			},
			{
				test: { name: 'node', include: ['test/node/**/*.test.ts'], testTimeout: 30_000 }
			},
			{
				test: {
					name: 'network',
					include: ['test/integration/**/*.test.ts', 'test/fingerprint/**/*.test.ts'],
					testTimeout: 120_000,
					// beforeAll in the network files performs live captures; the default 10s hook
					// timeout reads a slow handshake as a failure.
					hookTimeout: 60_000,
					// Live hosts occasionally reset a fresh TCP connection before the handshake
					// (observed ~1 in 20 on httpbingo.org). That is a host fact, not a result about
					// this library, so retry the attempt — a real regression fails every attempt.
					retry: 2,
					// Live hosts (tls.peet.ws especially) rate-limit a burst of fresh connections, and
					// every file here opens its own. The pre-Vitest scripts ran one after another for
					// the same reason; files stay independent, they just don't overlap.
					fileParallelism: false
				}
			}
		]
	}
})
