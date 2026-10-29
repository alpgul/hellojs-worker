// hellojs inside a Worker (workerd) — the parts of the client that need no sockets.
//
// Run it locally on the real sandbox:
//
//   npx wrangler dev examples/worker.ts \
//     --compatibility-date 2026-10-01 \
//     --compatibility-flags nodejs_compat
//
// or deploy it and send a request at the Worker's URL. `nodejs_compat` is what gives the
// Worker the `node:crypto` / `node:events` / `node:zlib` modules hellojs runs on.
//
// What the sandbox changes, and what this file does about it:
//
//   1. No outbound UDP. Worker runtime APIs cover HTTP fetch and TCP sockets only, so
//      QUIC has no transport here. hellojs reaches `node:dgram` exclusively through its
//      UDP seam; `setUdpProvider(null)` declares that up front, so `h3: true` fails over to
//      TCP + TLS immediately instead of waiting on a QUIC handshake that cannot start.
//      (A sandbox that DOES expose datagrams would install a provider instead — see
//      README → UDP transport.)
//   2. No built-in root certificates. workerd's TLS ships an empty trust store, so the
//      Mozilla bundle is installed from a text secret on the first request.
//   3. Everything with no I/O works unchanged: profile lookup, the TLS 1.3 record/key
//      layer and certificate verification (both built on Web Crypto, which is what
//      workerd provides), QPACK/Huffman codecs, and the fingerprint derivations.

import request from '../index.ts'

interface Env {
	/** PEM text secret (Mozilla / NSS bundle): `wrangler secret put TRUST_BUNDLE < ca-bundle.pem`. */
	TRUST_BUNDLE?: string
}

interface EchoBody {
	url?: string
}

// Split PEM text into the individual certificates setTrustedRoots() expects.
function pemBlocks(text: string): string[] {
	return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []
}

// The sandbox has no datagram transport: take HTTP/3 out of reach instead of letting each
// request discover that on its own. Module scope runs once per isolate, before any handler.
request.udp.setUdpProvider(null)

let installed = false

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		// Bindings only reach a handler, so the trust store is installed on the first request
		// and then reused by every later handshake in this isolate.
		if (!installed && env.TRUST_BUNDLE) {
			request.setTrustedRoots(pemBlocks(env.TRUST_BUNDLE))
			installed = true
		}

		const url = new URL(req.url)
		const target = url.searchParams.get('target') || 'https://httpbingo.org/get'

		const t0 = Date.now()
		try {
			// h3 is asked for and refused before a packet is sent — the seam has no provider, so
			// the request goes out over TCP + TLS instead of failing.
			const body = await request<EchoBody>({
				url: target,
				profile: 'chrome147-mac',
				json: true,
				h3: true,
				followRedirect: false,
			})
			return Response.json({
				target,
				askedFor: 'h3',
				used: 'tcp+tls',
				h3Available: request.udp.udpAvailable(),
				echo: body.url ?? null,
				ms: Date.now() - t0,
			})
		} catch (e) {
			const err = e as { code?: string; message?: string }
			return Response.json({ target, error: err.code || 'EUNKNOWN', message: err.message }, { status: 502 })
		}
	},
} satisfies ExportedHandler<Env>
