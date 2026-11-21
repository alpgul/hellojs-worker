// Durable Object that owns the hellojs keep-alive pool.
//
// A Worker isolate is short-lived and a TCP socket cannot be handed from one isolate to
// another, so a module-scope pool in the Worker only helps requests that happen to land on
// the same isolate. Routing every request through one named Durable Object gives the pool a
// single long-lived home: the Worker stays stateless, the sockets stay here.
//
// This is "long-lived", not "durable": the pool is in-memory. Eviction or a crash drops it
// and the next request handshakes again. An open socket keeps the DO resident for at most 15
// minutes, after which the normal eviction rules apply.

import { DurableObject } from 'cloudflare:workers'

import request, { setPoolConfig, type RequestOptions } from '../index.ts'
import { clearPool, getPoolConfig, pooledCount } from '../lib/pool.ts'

import roots from './root-certificates.ts'
import { runScenario, type ScenarioResult } from './scenario-runner.ts'
import { scenarios } from './scenarios.ts'

// Module scope: once per DO isolate, before any request arrives. The Worker no longer
// imports hellojs at all, so these fixes belong here now.
request.udp.setUdpProvider(null)
request.setTrustedRoots(roots)

// Widen the reuse window beyond the library default (15s). A socket parked for 60s is still
// available to the next call; past that it closes itself. Trade-off: an idle socket keeps
// this DO in memory and incurs duration charges.
setPoolConfig({ idleMs: 60_000 })

const TOUR_PATH = '/__tour'
const STATS_PATH = '/__stats'
const CONFIG_PATH = '/__config'
const CLEAR_PATH = '/__clear'
const KEEPALIVE_HEADER = 'x-hello-keepalive'

// A profile pins its browser identity headers: passing a client's own values through makes
// hellojs reject the request with EHEADERFIXED (and would defeat the fingerprint anyway).
// This is the union of the fixed headers declared by the bundled profiles.
const FIXED_HEADERS = new Set(['user-agent', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'])

// Never forward transport headers or our own control header to the origin.
const HOP_BY_HOP = new Set([
	'host',
	'connection',
	'keep-alive',
	'proxy-connection',
	'proxy-authenticate',
	'proxy-authorization',
	'te',
	'trailer',
	'transfer-encoding',
	'upgrade'
])
const INTERNAL_PREFIXES = ['cf-', 'x-hello-']

export function cleanHeaders(headers: Headers): Headers {
	const out = new Headers()
	for (const [name, value] of headers) {
		const lower = name.toLowerCase()
		if (
			HOP_BY_HOP.has(lower) ||
			FIXED_HEADERS.has(lower) ||
			INTERNAL_PREFIXES.some((prefix) => lower.startsWith(prefix))
		)
			continue
		out.set(name, value)
	}
	return out
}

export interface Env {
	HELLO_POOL: DurableObjectNamespace<HelloConnectionDO>
	ALLOWED_HOSTS: string
}

/** The DO keeps the same report shape the HTML page already renders. */
export interface TourReport {
	h3Available: boolean
	total: number
	passed: number
	failed: number
	durationMs: number
	pooledSockets: number
	fast: boolean
	skipped: number[]
	results: ScenarioResult[]
}

// Fast mode keeps four representative scenarios (GET, POST json, custom headers, status
// policy) and skips the rest. Every scenario is a live internet round trip, and even a plain
// GET can take 20s when the upstream is having a bad moment — fewer requests is the only
// reliable way to keep a local smoke test quick.
const FAST_SCENARIOS = new Set([2, 4, 6, 7])

export class HelloConnectionDO extends DurableObject<Env> {
	override async fetch(req: Request): Promise<Response> {
		const path = new URL(req.url).pathname
		if (path === TOUR_PATH) return this.tour(new URL(req.url).searchParams.get('fast') === '1')
		if (path === STATS_PATH) return Response.json({ pooledSockets: pooledCount() })
		if (path === CONFIG_PATH) return Response.json(getPoolConfig())
		if (path === CLEAR_PATH) {
			clearPool('bench-reset')
			return Response.json({ pooledSockets: pooledCount() })
		}
		return this.proxy(req)
	}

	private async tour(fast: boolean): Promise<Response> {
		const t0 = Date.now()
		const skipped = fast ? scenarios.filter((s) => !FAST_SCENARIOS.has(s.id)).map((s) => s.id) : []
		const selected = fast ? scenarios.filter((s) => FAST_SCENARIOS.has(s.id)) : scenarios
		const results = await Promise.all(selected.map(runScenario))
		const passed = results.filter((row) => row.ok).length
		const report: TourReport = {
			h3Available: request.udp.udpAvailable(),
			total: results.length,
			passed,
			failed: results.length - passed,
			durationMs: Date.now() - t0,
			// One pooled socket per origin+profile; h3 and one-shot requests never join it.
			pooledSockets: pooledCount(),
			fast,
			skipped,
			results
		}
		return Response.json(report)
	}

	private async proxy(req: Request): Promise<Response> {
		// Only the Worker may set this: cleanHeaders() strips x-hello-* before the origin sees it.
		const keepalive = req.headers.get(KEEPALIVE_HEADER) !== 'false'
		const init: RequestOptions = {
			// Fetch exposes the verb as a plain string; hellojs types it as the registered-method union.
			method: req.method as NonNullable<RequestOptions['method']>,
			headers: cleanHeaders(req.headers),
			signal: req.signal,
			// This is the whole point of the DO: every hop reuses the live h2 session.
			keepalive
		}
		if (req.body) init.body = req.body

		const res = await request(req.url, init)
		return new Response(res.body, {
			status: res.status,
			statusText: res.statusText,
			headers: cleanHeaders(res.headers)
		})
	}
}
