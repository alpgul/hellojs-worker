// hellojs inside a Worker (workerd) — the full feature tour, run concurrently.
//
// Run it locally on the real sandbox:
//
//   npm run example
//
// (wrangler dev with --compatibility-date 2026-10-01 and both compatibility flags; the
// exact command lives in package.json so this comment cannot drift from it.)
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
//      generated Mozilla bundle in ./root-certificates.ts is installed at module scope —
//      no secret, no binding, and verification behaves the same as it does in Node.
//   3. ML-KEM is behind a flag. The Chrome 147 key share is X25519MLKEM768, and workerd only
//      puts ML-KEM on `crypto.subtle` when `webcrypto_modern_algorithms` is set — that flag
//      has no default enable date, so a compatibility date alone will not turn it on and the
//      ClientHello would fail to build without it.
//   4. No direct TCP to Cloudflare's own ranges, which is why the tour's endpoints are
//      httpbingo (Fly.io) and tls.peet.ws rather than cloudflare.com.
//   5. Everything with no sockets works unchanged: profile lookup, the TLS 1.3 record and key
//      layer, certificate verification, QPACK/Huffman codecs, fingerprint derivations.

import request from '../index.ts'

import roots from './root-certificates.ts'
import { scenarios } from './scenarios.ts'

import type { HellojsError } from '../index.ts'
import type { Scenario } from './scenarios.ts'

interface ScenarioResult {
	id: number
	name: string
	ok: boolean
	detail: string
	ms: number
}

// One scenario must not be able to hold the whole response open. The ceiling sits above the
// slowest scenario's own retry budget (scenario 1 allows two ~10s attempts against tls.peet.ws),
// otherwise a slow upstream is cut off before the retry that would have recovered it can finish.
const SCENARIO_TIMEOUT_MS = 30_000

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

// Both fixes are module scope, so they run once per isolate before any handler: the seam
// declares that this sandbox has no datagram transport (HTTP/3 is out of reach instead of
// each request discovering that on its own), and the generated bundle stands in for the
// trust store workerd does not ship.
request.udp.setUdpProvider(null)
request.setTrustedRoots(roots)

export default {
	async fetch(req: Request): Promise<Response> {
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
} satisfies ExportedHandler
