// Local profiling driver. Runs the four hellojs-only workloads against a throwaway h2 server
// and reports wall time, RSS delta and observability phase durations.
//
//   npm run bench:profile                         # timings only
//   npm run bench:profile:cpu                     # + V8 CPU profile in test/bench/.out
//   npm run bench:profile:heap                    # + V8 sampling heap profile (512 KB interval)
//   npm run bench:profile:heap:fine               # + 64 KB heap interval + --expose-gc
//   PROFILE_SCENARIO=concurrent PROFILE_ROUNDS=20 npm run bench:profile:cpu
//   PROFILE_SCENARIO=large-body PROFILE_BODY_REPS=100 PROFILE_GC=1 npm run bench:profile:heap:fine
//   PROFILE_BODY_GZIP=1 PROFILE_SCENARIO=large-body npm run bench:profile
//   PROFILE_NO_UDP=1 npm run bench:profile:cpu        # TCP-only control run
//
// Knobs: PROFILE_SCENARIO (cold|warm|concurrent|large-body|all), PROFILE_COLD (30),
// PROFILE_WARM (200), PROFILE_CONCURRENT (50), PROFILE_ROUNDS (1), PROFILE_BODY_REPS (10),
// PROFILE_BODY_GZIP, PROFILE_BODY_IDENTITY, PROFILE_GC (needs --expose-gc),
// PROFILE_WARMUP (2), PROFILE_OUT.

import * as fs from 'node:fs'
import * as path from 'node:path'
import { monitorEventLoopDelay, performance } from 'node:perf_hooks'

import request from '../../index.ts'
import { setUdpProvider } from '../../lib/h3/udp.ts'
import { observability } from '../../lib/observability.ts'
import { poolStats } from '../../lib/pool.ts'

import { fmt, startLocalH2Server, stats, type LocalServer, type Stats } from './helpers.ts'

const SCENARIO = process.env.PROFILE_SCENARIO ?? 'all'
const COLD = Number(process.env.PROFILE_COLD ?? 30)
const WARM = Number(process.env.PROFILE_WARM ?? 200)
const CONCURRENT = Number(process.env.PROFILE_CONCURRENT ?? 50)
const ROUNDS = Number(process.env.PROFILE_ROUNDS ?? 1)
const BODY_REPS = Number(process.env.PROFILE_BODY_REPS ?? 10)
const BODY_GZIP = process.env.PROFILE_BODY_GZIP === '1'
const BODY_IDENTITY = process.env.PROFILE_BODY_IDENTITY === '1'
const GC = process.env.PROFILE_GC === '1'
const WARMUP = Number(process.env.PROFILE_WARMUP ?? 2)
const OUT = process.env.PROFILE_OUT

if (GC && typeof globalThis.gc !== 'function') throw new Error('PROFILE_GC=1 requires node --expose-gc')
// Diagnostic: PROFILE_NO_UDP=1 exercises the TCP-only path (the seam used by Workers).
if (process.env.PROFILE_NO_UDP === '1') setUdpProvider(null)

interface EventStat {
	count: number
	totalMs: number
	maxMs: number
}

interface MemStat {
	rssMB: number
	heapUsedMB: number
	arrayBuffersMB: number
	externalMB: number
}

interface PoolStat {
	pooled: number
	created: number
	hits: number
}

interface TimelineStat {
	headersToFirstByte: Stats | null
	firstByteToEnd: Stats | null
}

interface ScenarioResult {
	wallMs: number
	count: number
	rounds: number
	requestMs: Stats | null
	timeline: TimelineStat | null
	rssDeltaMB: number
	memBefore: MemStat
	memAfter: MemStat
	memAfterGc: MemStat | null
	poolBefore: PoolStat
	poolAfter: PoolStat
	eventLoopLagMs: { mean: number; max: number }
	bytes: number
	events: Record<string, EventStat>
}

interface Workload {
	times: number[]
	bytes: number[]
}

interface RequestStamp {
	headersSent?: number
	firstByte?: number
	end?: number
}

const scenarios: Record<string, ScenarioResult> = {}
let currentEvents = new Map<string, EventStat>()
let currentStamps = new Map<number, RequestStamp>()

// Patch the emitter rather than subscribing to a fixed list: a new lifecycle event then shows
// up in the profile with no change here. Stamps are kept per request id so the concurrent
// scenario can show queueing (headersSent -> firstByte) separately from body time.
const originalEmit = observability.safeEmit.bind(observability)
observability.safeEmit = (event: string | symbol, payload: unknown) => {
	const name = String(event)
	const stat = currentEvents.get(name) ?? { count: 0, totalMs: 0, maxMs: 0 }
	stat.count++
	const body = payload as { durationMs?: unknown; id?: unknown } | null
	if (typeof body?.durationMs === 'number') {
		stat.totalMs += body.durationMs
		stat.maxMs = Math.max(stat.maxMs, body.durationMs)
	}
	if (
		typeof body?.id === 'number' &&
		(name === 'request:headersSent' || name === 'request:firstByte' || name === 'request:end')
	) {
		const key = name.slice('request:'.length) as keyof RequestStamp
		const stamp = currentStamps.get(body.id) ?? {}
		stamp[key] = performance.now()
		currentStamps.set(body.id, stamp)
	}
	currentEvents.set(name, stat)
	return originalEmit(event, payload)
}

const lag = monitorEventLoopDelay({ resolution: 1 })

function memory(): MemStat {
	const m = process.memoryUsage()
	const mb = (bytes: number) => bytes / 1024 / 1024
	return {
		rssMB: mb(m.rss),
		heapUsedMB: mb(m.heapUsed),
		arrayBuffersMB: mb(m.arrayBuffers),
		externalMB: mb(m.external)
	}
}

function forceGc(): void {
	if (GC) globalThis.gc?.()
}

function timelineStats(): TimelineStat {
	const queued: number[] = []
	const body: number[] = []
	for (const stamp of currentStamps.values()) {
		if (stamp.headersSent != null && stamp.firstByte != null) queued.push(stamp.firstByte - stamp.headersSent)
		if (stamp.firstByte != null && stamp.end != null) body.push(stamp.end - stamp.firstByte)
	}
	return {
		headersToFirstByte: queued.length ? stats(queued) : null,
		firstByteToEnd: body.length ? stats(body) : null
	}
}

let server: LocalServer

async function drain(pathname: string, keepalive: boolean, headers?: Record<string, string>): Promise<number> {
	const response = await request(`${server.url}${pathname}`, { verifyTLS: false, keepalive, headers })
	return (await response.arrayBuffer()).byteLength
}

async function timed(
	pathname: string,
	keepalive: boolean,
	headers?: Record<string, string>
): Promise<{ bytes: number; ms: number }> {
	const t0 = process.hrtime.bigint()
	const bytes = await drain(pathname, keepalive, headers)
	return { bytes, ms: Number(process.hrtime.bigint() - t0) / 1e6 }
}

async function runScenario(name: string, fn: () => Promise<Workload>): Promise<void> {
	currentEvents = new Map()
	currentStamps = new Map()
	forceGc()
	const before = memory()
	const poolBefore = poolStats()
	lag.reset()
	lag.enable()
	const t0 = process.hrtime.bigint()
	let work: Workload = { times: [], bytes: [] }
	try {
		work = await fn()
	} finally {
		const wallMs = Number(process.hrtime.bigint() - t0) / 1e6
		lag.disable()
		const eventLoopLagMs = { mean: Number(lag.mean) / 1e6, max: Number(lag.max) / 1e6 }
		const after = memory()
		forceGc()
		const events = Object.fromEntries([...currentEvents.entries()].sort(([a], [b]) => a.localeCompare(b)))
		scenarios[name] = {
			wallMs,
			count: work.times.length,
			rounds: ROUNDS,
			requestMs: work.times.length ? stats(work.times) : null,
			timeline: timelineStats(),
			rssDeltaMB: after.rssMB - before.rssMB,
			memBefore: before,
			memAfter: after,
			memAfterGc: GC ? memory() : null,
			poolBefore,
			poolAfter: poolStats(),
			eventLoopLagMs,
			bytes: work.bytes.reduce((a, b) => a + b, 0),
			events
		}
	}
}

async function serial(
	n: number,
	pathname: string,
	keepalive: boolean,
	headers?: Record<string, string>
): Promise<Workload> {
	const times: number[] = []
	const bytes: number[] = []
	for (let i = 0; i < n; i++) {
		const result = await timed(pathname, keepalive, headers)
		times.push(result.ms)
		bytes.push(result.bytes)
	}
	return { times, bytes }
}

async function main(): Promise<void> {
	server = await startLocalH2Server()
	const wanted = SCENARIO === 'all' ? ['cold', 'warm', 'concurrent', 'large-body'] : [SCENARIO]
	const known = new Set(['cold', 'warm', 'concurrent', 'large-body'])
	for (const name of wanted) if (!known.has(name)) throw new Error(`unknown scenario: ${name}`)

	try {
		for (let i = 0; i < WARMUP; i++) await drain('/', true)

		if (wanted.includes('cold')) await runScenario('cold', () => serial(COLD, '/', false))
		if (wanted.includes('warm')) await runScenario('warm', () => serial(WARM, '/', true))
		if (wanted.includes('concurrent')) {
			await runScenario('concurrent', async () => {
				const times: number[] = []
				const bytes: number[] = []
				for (let round = 0; round < ROUNDS; round++) {
					const started = Array.from({ length: CONCURRENT }, () => process.hrtime.bigint())
					const results = await Promise.all(Array.from({ length: CONCURRENT }, () => timed('/', true)))
					for (let i = 0; i < results.length; i++) {
						times.push(Number(process.hrtime.bigint() - started[i]!) / 1e6)
						bytes.push(results[i]!.bytes)
					}
				}
				return { times, bytes }
			})
		}
		if (wanted.includes('large-body')) {
			const path = BODY_GZIP ? '/large.gz' : '/large'
			const headers = BODY_IDENTITY ? { 'accept-encoding': 'identity' } : undefined
			await runScenario('large-body', () => serial(BODY_REPS, path, true, headers))
		}
	} finally {
		await server.close()
	}

	console.log(
		`Node ${process.version}  scenario=${SCENARIO}  cold=${COLD} warm=${WARM} conc=${CONCURRENT} rounds=${ROUNDS} bodyReps=${BODY_REPS}` +
			` gzip=${BODY_GZIP} identity=${BODY_IDENTITY} gc=${GC}`
	)
	console.log('\nscenario        wall(ms)   n     req-p50  req-p95  req-p99   RSSΔ(MB)     bytes')
	console.log('-'.repeat(86))
	for (const [name, r] of Object.entries(scenarios)) {
		console.log(
			`${name.padEnd(15)} ${fmt(r.wallMs).padStart(9)} ${String(r.count).padStart(4)}` +
				` ${fmt(r.requestMs?.p50).padStart(9)} ${fmt(r.requestMs?.p95).padStart(9)} ${fmt(r.requestMs?.p99).padStart(9)}` +
				` ${fmt(r.rssDeltaMB).padStart(10)} ${String(r.bytes).padStart(10)}`
		)
	}
	console.log('\nDetailed (memory in MB, pool = pooled/created/hits, lag in ms):')
	for (const [name, r] of Object.entries(scenarios)) {
		const m = (v: MemStat) =>
			`rss=${fmt(v.rssMB)} heap=${fmt(v.heapUsedMB)} buf=${fmt(v.arrayBuffersMB)} ext=${fmt(v.externalMB)}`
		console.log(`  ${name}:`)
		console.log(`    memory before   ${m(r.memBefore)}`)
		console.log(`    memory after    ${m(r.memAfter)}`)
		if (r.memAfterGc) console.log(`    memory post-GC  ${m(r.memAfterGc)}`)
		console.log(
			`    pool            ${r.poolBefore.pooled}/${r.poolBefore.created}/${r.poolBefore.hits}` +
				` -> ${r.poolAfter.pooled}/${r.poolAfter.created}/${r.poolAfter.hits}`
		)
		console.log(`    event-loop lag  mean=${fmt(r.eventLoopLagMs.mean, 3)} max=${fmt(r.eventLoopLagMs.max, 3)}`)
		if (r.timeline?.headersToFirstByte) {
			console.log(
				`    queue hSent→FB  p50=${fmt(r.timeline.headersToFirstByte.p50)} p95=${fmt(r.timeline.headersToFirstByte.p95)}` +
					` p99=${fmt(r.timeline.headersToFirstByte.p99)}`
			)
			console.log(
				`    body FB→end     p50=${fmt(r.timeline.firstByteToEnd?.p50)} p95=${fmt(r.timeline.firstByteToEnd?.p95)}` +
					` p99=${fmt(r.timeline.firstByteToEnd?.p99)}`
			)
		}
	}
	console.log('\nObservability events (count / total ms / max ms):')
	for (const [name, r] of Object.entries(scenarios)) {
		console.log(`  ${name}:`)
		for (const [event, e] of Object.entries(r.events)) {
			console.log(
				`    ${event.padEnd(22)} ${String(e.count).padStart(5)}  ${fmt(e.totalMs).padStart(10)}  ${fmt(e.maxMs).padStart(9)}`
			)
		}
	}

	if (OUT) {
		fs.mkdirSync(path.dirname(OUT), { recursive: true })
		fs.writeFileSync(OUT, JSON.stringify({ node: process.version, scenarios }, null, 2) + '\n')
	}
}

await main()
