// hellojs inside a Worker (workerd) — the full feature tour, run concurrently.
//
// Run it locally on the real sandbox:
//
//   npx wrangler dev examples/worker.ts \
//     --compatibility-date 2026-10-01 \
//     --compatibility-flags nodejs_compat webcrypto_modern_algorithms
//
// `wrangler dev` prints a URL; open it and the Worker serves run-test.html — one button
// that fires all fourteen scenarios from examples/scenarios.ts in parallel and renders the
// results. `GET /run` is the same answer as JSON, for curl or for another Worker.
//
// What the sandbox changes, and what this file does about it:
//
//   1. No outbound UDP. Worker runtime APIs cover HTTP fetch and TCP sockets only, so QUIC
//      has no transport here. hellojs reaches `node:dgram` exclusively through its UDP seam;
//      `setUdpProvider(null)` declares that up front, so scenario 13 fails over to TCP + TLS
//      immediately instead of waiting on a handshake that cannot start. (A sandbox that DOES
//      expose datagrams installs a provider instead — see README → UDP transport.)
//   2. No built-in root certificates. workerd's TLS ships an empty trust store, so the
//      Mozilla bundle is installed from a text secret on the first request.
//   3. ML-KEM is behind a flag. The Chrome 147 key share is X25519MLKEM768, and workerd only
//      puts ML-KEM on `crypto.subtle` when `webcrypto_modern_algorithms` is set — that flag
//      has no default enable date, so a compatibility date alone will not turn it on and the
//      ClientHello would fail to build without it.
//   4. No direct TCP to Cloudflare's own ranges, which is why the tour's endpoints are
//      httpbingo (Fly.io) and tls.peet.ws rather than cloudflare.com.
//   5. Everything with no sockets works unchanged: profile lookup, the TLS 1.3 record and key
//      layer, certificate verification, QPACK/Huffman codecs, fingerprint derivations.

import request from '../index.ts'

import { scenarios } from './scenarios.ts'

import type { HellojsError } from '../index.ts'
import type { Scenario } from './scenarios.ts'

interface Env {
	/** PEM text secret (Mozilla / NSS bundle): `wrangler secret put TRUST_BUNDLE < ca-bundle.pem`. */
	TRUST_BUNDLE?: string
}

interface ScenarioResult {
	id: number
	name: string
	ok: boolean
	detail: string
	ms: number
}

// One scenario must not be able to hold the whole response open.
const SCENARIO_TIMEOUT_MS = 15_000

// Split PEM text into the individual certificates setTrustedRoots() expects.
function pemBlocks(text: string): string[] {
	return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []
}

function withTimeout(runs: Promise<string>, ms: number): Promise<string> {
	return new Promise<string>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error(`no result within ${ms}ms`)), ms)
		runs.then(
			(detail) => {
				clearTimeout(timer)
				resolve(detail)
			},
			(err: unknown) => {
				clearTimeout(timer)
				reject(err)
			},
		)
	})
}

// Every scenario answers on its own terms: a failure is one row of the report, not a lost response.
async function runScenario(scenario: Scenario): Promise<ScenarioResult> {
	const t0 = Date.now()
	try {
		const detail = await withTimeout(scenario.run(), SCENARIO_TIMEOUT_MS)
		return { id: scenario.id, name: scenario.name, ok: true, detail, ms: Date.now() - t0 }
	} catch (e) {
		const err = e as HellojsError
		return { id: scenario.id, name: scenario.name, ok: false, detail: `${err.code || err.name}: ${String(err.message).slice(0, 160)}`, ms: Date.now() - t0 }
	}
}

// Served at / and /run-test.html. Static text, no interpolation: the page pulls its own
// results from /run and writes them with textContent.
const RUN_TEST_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>hellojs · run tests</title>
<style>
:root { color-scheme: light dark }
body { font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem auto; max-width: 64rem; padding: 0 1rem }
h1 { font-size: 1.1rem; margin-bottom: .25rem }
p.lede { opacity: .7; margin-top: 0 }
button { font: inherit; padding: .45rem 1.2rem; cursor: pointer }
#summary { margin: 1rem 0 }
ul { padding: 0 }
li { list-style: none; margin: .3rem 0; padding: .4rem .6rem; border-left: 3px solid #888; overflow-wrap: anywhere }
li.ok { border-color: #2e7d32; background: rgba(46, 125, 50, .09) }
li.fail { border-color: #c62828; background: rgba(198, 40, 40, .09) }
</style>
</head>
<body>
<h1>hellojs in a Worker</h1>
<p class="lede">Fourteen scenarios from examples/scenarios.ts, run concurrently in one fetch. HTTP/3 needs a datagram socket, which this sandbox has no API for, so that scenario reports the TCP + TLS fallback.</p>
<p><button id="run" type="button">Run tests</button></p>
<p id="summary">not run yet</p>
<ul id="results"></ul>
<script>
const btn = document.getElementById('run')
const summary = document.getElementById('summary')
const results = document.getElementById('results')

btn.addEventListener('click', async () => {
  btn.disabled = true
  results.textContent = ''
  summary.textContent = 'running the tour…'
  const t0 = Date.now()
  try {
    const res = await fetch('/run', { headers: { accept: 'application/json' } })
    const data = await res.json()
    summary.textContent = data.passed + '/' + data.total + ' passed in ' + data.durationMs +
      'ms (' + (Date.now() - t0) + 'ms seen by the browser) · UDP transport: ' +
      (data.h3Available ? 'available' : 'absent, h3 falls back to TCP + TLS')
    data.results.forEach((row) => {
      const li = document.createElement('li')
      li.className = row.ok ? 'ok' : 'fail'
      li.textContent = '#' + row.id + ' ' + row.name + ' — ' + row.detail + ' (' + row.ms + 'ms)'
      results.appendChild(li)
    })
  } catch (e) {
    summary.textContent = 'could not reach /run: ' + e
  }
  btn.disabled = false
})
</script>
</body>
</html>`

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

		const path = new URL(req.url).pathname
		if (path !== '/run' && path !== '/' && path !== '/run-test.html') {
			return new Response('not found', { status: 404 })
		}

		if (path === '/run') {
			const t0 = Date.now()
			const results = await Promise.all(scenarios.map(runScenario))
			const passed = results.filter((row) => row.ok).length
			return Response.json({
				h3Available: request.udp.udpAvailable(),
				total: results.length,
				passed,
				failed: results.length - passed,
				durationMs: Date.now() - t0,
				results,
			})
		}

		return new Response(RUN_TEST_PAGE, { headers: { 'content-type': 'text/html; charset=utf-8' } })
	},
} satisfies ExportedHandler<Env>
