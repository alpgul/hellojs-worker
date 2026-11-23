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
// This Worker is deliberately stateless: it owns no sockets and imports no TLS code. Every
// outbound request is forwarded to one named Durable Object (connection-do.ts), which owns
// the hellojs keep-alive pool in its long-lived isolate. See that file for the workerd
// setup (no UDP, no built-in roots, ML-KEM behind a flag) and for the pool configuration.
//
// Routes:
//   / and /run-test.html — the local test page
//   /run                 — the fourteen-scenario tour, executed inside the DO
//   /proxy?url=...       — an allowlisted pass-through to an external origin, via the DO
//   /bench?url=...&n=5   — native fetch vs hellojs, with keepalive true and false
//   /keepalive?url=...   — keep-alive probe: 2 requests in one DO call, or 1 per Worker call
//
// /proxy is guarded by ALLOWED_HOSTS: an unrestricted `?url=` endpoint would turn this
// Worker into an open relay.

import { keepaliveVerdict, type KeepaliveMode, type KeepaliveProbe, type KeepaliveReport } from './keepalive-report.ts'
import { resolveProxyTarget } from './proxy-policy.ts'

import type { Env } from './connection-do.ts'

// Wrangler discovers the Durable Object class from the Worker's main module, so re-export it.
export { HelloConnectionDO } from './connection-do.ts'

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
#keepalive { white-space: pre-wrap; overflow-wrap: anywhere; margin-top: 1rem }
li { list-style: none; margin: .3rem 0; padding: .4rem .6rem; border-left: 3px solid #888; overflow-wrap: anywhere }
li.ok { border-color: #2e7d32; background: rgba(46, 125, 50, .09) }
li.fail { border-color: #c62828; background: rgba(198, 40, 40, .09) }
</style>
</head>
<body>
<h1>hellojs in a Worker</h1>
<p class="lede">Fourteen scenarios from examples/scenarios.ts, run concurrently in one fetch. HTTP/3 needs a datagram socket, which this sandbox has no API for, so that scenario reports the TCP + TLS fallback.</p>
<p><button id="run" type="button">Run tests</button> <label><input id="fast" type="checkbox"> quick smoke test (4 scenarios)</label></p>
<p id="summary">not run yet</p>
<ul id="results"></ul>
<h1>keep-alive in the Durable Object</h1>
<p><label>target <input id="ka-url" size="34" value="https://httpbingo.org/get"></label></p>
<p><button id="ka-paired" type="button">2 requests in one DO call</button> <button id="ka-across" type="button">two separate Worker requests</button></p>
<pre id="keepalive">not run yet</pre>
<script>
const btn = document.getElementById('run')
const fast = document.getElementById('fast')
const summary = document.getElementById('summary')
const results = document.getElementById('results')

btn.addEventListener('click', async () => {
  btn.disabled = true
  results.textContent = ''
  summary.textContent = 'running the tour…'
  const t0 = Date.now()
  try {
    const res = await fetch(fast.checked ? '/run?fast=1' : '/run', { headers: { accept: 'application/json' } })
    const data = await res.json()
    summary.textContent = data.passed + '/' + data.total + ' passed in ' + data.durationMs +
      'ms (' + (Date.now() - t0) + 'ms seen by the browser) · pooled sockets: ' + data.pooledSockets +
      (data.fast ? ' · skipped: ' + data.skipped.join(',') : '') +
      ' · UDP transport: ' + (data.h3Available ? 'available' : 'absent, h3 falls back to TCP + TLS')
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

const kaUrl = document.getElementById('ka-url')
const kaOut = document.getElementById('keepalive')

async function keepaliveRequest(mode, reset) {
  const query = new URLSearchParams({ mode, url: kaUrl.value })
  if (reset) query.set('reset', '1')
  const res = await fetch('/keepalive?' + query)
  const data = await res.json()
  if (!res.ok) throw new Error(JSON.stringify(data))
  return data
}

document.getElementById('ka-paired').addEventListener('click', async () => {
  kaOut.textContent = 'running…'
  try {
    kaOut.textContent = JSON.stringify(await keepaliveRequest('paired', true), null, 2)
  } catch (e) {
    kaOut.textContent = 'could not run keepalive probe: ' + e
  }
})

document.getElementById('ka-across').addEventListener('click', async () => {
  kaOut.textContent = 'running…'
  try {
    const first = await keepaliveRequest('single', true)
    const second = await keepaliveRequest('single', false)
    const poolSurvived = second.probe.reused &&
      second.probe.poolStatsAfter.created === first.probe.poolStatsAfter.created
    kaOut.textContent = JSON.stringify({ first, second, poolSurvived }, null, 2)
  } catch (e) {
    kaOut.textContent = 'could not run keepalive probe: ' + e
  }
})
</script>
</body>
</html>`

const DO_NAME = 'global'
const KEEPALIVE_DO_NAME = 'keepalive-probe'
const KEEPALIVE_DO_PATH = '/__keepalive'
const DEFAULT_KEEPALIVE_URL = 'https://httpbingo.org/get'

// The DO cleans these too; drop the caller's copies here so a client cannot forge our control
// header or pin the origin's Host to the Worker's hostname. `keepalive` is the only hellojs
// option the proxy exposes: the benchmark needs a true/false pair on the same DO.
function doHeaders(source: Headers | null, keepalive: boolean): Headers {
	const out = new Headers()
	if (source) {
		for (const [name, value] of source) {
			const lower = name.toLowerCase()
			if (lower === 'host' || lower.startsWith('cf-') || lower.startsWith('x-hello-')) continue
			out.set(name, value)
		}
	}
	out.set('x-hello-proxy', '1')
	out.set('x-hello-keepalive', keepalive ? 'true' : 'false')
	return out
}

async function timed(run: () => Promise<Response>): Promise<number> {
	const t0 = performance.now()
	const res = await run()
	await res.arrayBuffer()
	return Math.round(performance.now() - t0)
}

async function pooledSockets(stub: DurableObjectStub): Promise<number> {
	const res = await stub.fetch('https://do/__stats')
	return ((await res.json()) as { pooledSockets: number }).pooledSockets
}

async function keepaliveRoute(query: URLSearchParams, env: Env): Promise<Response> {
	const target = resolveProxyTarget(query.get('url') ?? DEFAULT_KEEPALIVE_URL, env.ALLOWED_HOSTS)
	if (!target.ok) return new Response(target.message, { status: target.status })

	const rawMode = query.get('mode') ?? 'paired'
	if (rawMode !== 'paired' && rawMode !== 'single') {
		return new Response('mode must be paired or single', { status: 400 })
	}
	const mode: KeepaliveMode = rawMode
	const slot = (query.get('slot') ?? '').replaceAll(/[^a-z0-9-]/gi, '').slice(0, 32)
	const stub = env.HELLO_POOL.getByName(slot ? `${KEEPALIVE_DO_NAME}-${slot}` : KEEPALIVE_DO_NAME)

	const probeQuery = new URLSearchParams({ url: target.url.toString(), n: mode === 'paired' ? '2' : '1' })
	if (query.get('reset') === '1') probeQuery.set('reset', '1')
	if (query.get('keepalive') === 'false') probeQuery.set('keepalive', 'false')

	const res = await stub.fetch(`https://do${KEEPALIVE_DO_PATH}?${probeQuery}`)
	if (!res.ok) return new Response(await res.text(), { status: res.status })
	const probe = (await res.json()) as KeepaliveProbe
	const report: KeepaliveReport = {
		url: target.url.toString(),
		mode,
		slot,
		probe,
		pass: keepaliveVerdict(probe, mode),
		note: 'origin latency varies widely; compare created/hits counters, not timings'
	}
	return Response.json(report)
}

const sum = (values: number[]) => values.reduce((a, b) => a + b, 0)

// Upstream latency is wildly variable (httpbingo.org swings from 2s to 20s), so the median
// says more than the total. Report both.
function median(values: number[]): number {
	if (values.length === 0) return 0
	const sorted = [...values].sort((a, b) => a - b)
	const mid = sorted.length >> 1
	return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2)
}

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		const path = new URL(req.url).pathname
		const stub = env.HELLO_POOL.getByName(DO_NAME)

		if (path === '/run') {
			const fast = new URL(req.url).searchParams.get('fast') === '1'
			return stub.fetch(`https://do/__tour${fast ? '?fast=1' : ''}`)
		}

		if (path === '/keepalive') return keepaliveRoute(new URL(req.url).searchParams, env)

		if (path === '/proxy') {
			const target = resolveProxyTarget(new URL(req.url).searchParams.get('url'), env.ALLOWED_HOSTS)
			if (!target.ok) {
				return new Response(target.message, { status: target.status })
			}
			const init: RequestInit = { method: req.method, headers: doHeaders(req.headers, true) }
			if (req.body) init.body = req.body
			return stub.fetch(new Request(target.url.toString(), init))
		}

		if (path === '/bench') {
			const query = new URL(req.url).searchParams
			const target = resolveProxyTarget(query.get('url'), env.ALLOWED_HOSTS)
			if (!target.ok) {
				return new Response(target.message, { status: target.status })
			}
			const n = Math.max(1, Math.min(10, Number(query.get('n')) || 5))
			const mode = query.get('mode') // native | false | true | (absent = all three)
			const url = target.url.toString()
			const report: Record<string, unknown> = {
				url,
				n,
				mode: mode ?? 'all',
				note: 'network-bound: compare medians across runs, not a single total'
			}

			// Native Worker fetch: no DO, no hellojs, platform-managed connection reuse.
			if (mode !== 'false' && mode !== 'true') {
				const native: number[] = []
				for (let i = 0; i < n; i++) native.push(await timed(() => fetch(url)))
				report.native = { ms: native, total: sum(native), median: median(native) }
			}

			// Each hellojs mode starts from an empty pool so the two runs are comparable.
			if (mode !== 'native' && mode !== 'true') {
				await stub.fetch('https://do/__clear')
				const noKeep: number[] = []
				for (let i = 0; i < n; i++) {
					noKeep.push(await timed(() => stub.fetch(new Request(url, { headers: doHeaders(null, false) }))))
				}
				report.helloNoKeepalive = {
					ms: noKeep,
					total: sum(noKeep),
					median: median(noKeep),
					pooledSockets: await pooledSockets(stub)
				}
			}

			if (mode !== 'native' && mode !== 'false') {
				await stub.fetch('https://do/__clear')
				const keep: number[] = []
				for (let i = 0; i < n; i++) {
					keep.push(await timed(() => stub.fetch(new Request(url, { headers: doHeaders(null, true) }))))
				}
				report.helloKeepalive = {
					ms: keep,
					total: sum(keep),
					median: median(keep),
					pooledSockets: await pooledSockets(stub)
				}
			}

			return Response.json(report)
		}

		if (path !== '/' && path !== '/run-test.html') {
			return new Response('not found', { status: 404 })
		}

		return new Response(RUN_TEST_PAGE, { headers: { 'content-type': 'text/html; charset=utf-8' } })
	}
} satisfies ExportedHandler<Env>
