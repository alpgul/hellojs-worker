// Vitest runs the library's tests in three projects, split by the runtime they need.
//
//   workers  -> inside workerd, via the official Workers Vitest integration. The library resolves
//               ML-KEM and X25519 through `crypto.subtle` (lib/utils/webcrypto.ts), and workerd only
//               puts ML-KEM there behind `webcrypto_modern_algorithms`; these tests exercise the
//               workerd path. Node resolves the same interface from node:crypto.webcrypto.
//   node     -> Node's own pool, for tests that need local TCP/TLS servers, node:fs fixtures,
//               node:dgram or Node's real CA bundle, none of which workerd provides. The soak
//               suite (test/soak) lives here too: it drives a local h2 server under load and
//               asserts that heap and handles return to their idle levels.
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
				test: {
					name: 'node',
					include: ['test/node/**/*.test.ts', 'test/soak/**/*.test.ts'],
					testTimeout: 30_000,
					// The soak test compares heap after an explicit GC; without --expose-gc the
					// measurement is whatever the collector happened to do, so it is opt-out only.
					execArgv: ['--expose-gc']
				}
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
