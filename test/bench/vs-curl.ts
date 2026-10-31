// Benchmark: hellojs vs curl (HTTP/2; HTTP/3 when the curl build supports it).
//
// Both tools use one fresh connection per request (hellojs does not pool), so every sample is
// cold-connection end-to-end latency: DNS + TCP/QUIC + TLS + request + body. Samples are
// interleaved and the order flips each round to reduce drift from network / CDN changes.
//
// hellojs is timed with process.hrtime around request(); curl reports its own timing via
// `-w %{json}`, which excludes process startup. curl h3 is skipped when the binary lacks
// HTTP3 (point CURL_BIN at an h3-capable curl to enable that row). The `http=` line in
// Cloudflare's /cdn-cgi/trace body verifies which protocol actually answered; an h3 request
// that fell back to TCP is detected and the rest of that row is skipped.
//
// Caveats: this is connect/handshake-dominated, hellojs runs its own JS TLS/QUIC stack (JIT
// warm-up on the first sample) while curl is compiled C, and a single run is directional.
//
//   npm run bench:curl
//   SAMPLES=20 npm run bench:curl
//   CURL_BIN=/opt/curl/bin/curl npm run bench:curl

import { spawn } from 'node:child_process'

import request from '../../index.ts'

const TARGET = process.env.BENCH_URL ?? 'https://www.cloudflare.com/cdn-cgi/trace'
const SAMPLES = positiveInt(process.env.SAMPLES, 15)
const CURL_BIN = process.env.CURL_BIN ?? 'curl'
const MAX_CONSECUTIVE_FAILURES = 3
const CURL_TIMEOUT_MS = 45_000

interface Stats {
	min: number
	p50: number
	p95: number
	mean: number
	n: number
}

interface Sample {
	ms: number
	protocol: string
}

interface CurlSample extends Sample {
	dnsMs: number
	tcpMs: number
	tlsMs: number
	ttfbMs: number
}

interface CurlInfo {
	bin: string
	version: string
	hasH3: boolean
	hasHttp3Only: boolean
}

interface ProcessResult {
	code: number
	stdout: string
	stderr: string
}

interface CurlWriteOut {
	http_version: string
	response_code: number
	time_namelookup: number
	time_connect: number
	time_appconnect: number
	time_starttransfer: number
	time_total: number
}

type ComboId = 'hellojs-h2' | 'curl-h2' | 'hellojs-h3' | 'curl-h3'

interface Combo {
	id: ComboId
	label: string
	kind: 'hellojs' | 'curl'
	h3: boolean
	enabled: boolean
	note?: string
	samples: Sample[]
	curlSamples: CurlSample[]
	failures: number
}

function positiveInt(raw: string | undefined, fallback: number): number {
	const n = Number(raw)
	return Number.isInteger(n) && n > 0 ? n : fallback
}

function errorMessage(e: unknown): string {
	return e instanceof Error ? e.message : String(e)
}

function trim(s: string): string {
	return s.trim().slice(0, 200)
}

function stats(xs: number[]): Stats | undefined {
	if (xs.length === 0) return undefined
	const sorted = [...xs].sort((a, b) => a - b)
	const sum = sorted.reduce((a, b) => a + b, 0)
	return {
		min: sorted[0]!,
		p50: sorted[Math.floor(sorted.length * 0.5)]!,
		p95: sorted[Math.floor(sorted.length * 0.95)] ?? sorted.at(-1)!,
		mean: sum / sorted.length,
		n: sorted.length
	}
}

/** Cloudflare /cdn-cgi/trace echoes the negotiated protocol as `http=http/2` or `http/3`. */
function traceProtocol(body: string): string | undefined {
	return body.match(/^http=(http\/[0-9.]+)$/m)?.[1]
}

function runProcess(bin: string, args: string[]): Promise<ProcessResult> {
	return new Promise((resolve, reject) => {
		const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] })
		let stdout = ''
		let stderr = ''
		const timer = setTimeout(() => {
			try {
				child.kill('SIGKILL')
			} catch {}
		}, CURL_TIMEOUT_MS)
		child.stdout.on('data', (d: Buffer) => {
			stdout += d.toString()
		})
		child.stderr.on('data', (d: Buffer) => {
			stderr += d.toString()
		})
		child.on('error', (e) => {
			clearTimeout(timer)
			reject(e)
		})
		child.on('close', (code) => {
			clearTimeout(timer)
			resolve({ code: code ?? -1, stdout, stderr })
		})
	})
}

async function detectCurl(bin: string): Promise<CurlInfo> {
	const r = await runProcess(bin, ['-V'])
	if (r.code !== 0) throw new Error(`cannot run ${bin} -V: ${trim(r.stderr) || `exit ${r.code}`}`)
	const version = r.stdout.match(/^curl (\S+)/m)?.[1] ?? 'unknown'
	const features = r.stdout.match(/^Features:\s*(.*)$/m)?.[1] ?? ''
	const [major = 0] = version.split('.').map((part) => Number.parseInt(part, 10))
	const hasH3 = /\bHTTP3\b/.test(features)
	// --http3-only landed in curl 8.0; older h3 builds only have --http3 (which may fall back).
	return { bin, version, hasH3, hasHttp3Only: hasH3 && major >= 8 }
}

function isCurlWriteOut(v: unknown): v is CurlWriteOut {
	if (typeof v !== 'object' || v === null) return false
	const o = v as Record<string, unknown>
	const numeric = [
		'response_code',
		'time_namelookup',
		'time_connect',
		'time_appconnect',
		'time_starttransfer',
		'time_total'
	]
	return typeof o.http_version === 'string' && numeric.every((k) => typeof o[k] === 'number')
}

async function runCurl(info: CurlInfo, url: string, h3: boolean): Promise<CurlSample> {
	const proto = h3 ? (info.hasHttp3Only ? '--http3-only' : '--http3') : '--http2'
	const r = await runProcess(info.bin, ['-sS', '-o', '/dev/null', '--max-time', '30', '-w', '%{json}', proto, url])
	if (r.code !== 0) throw new Error(`curl exit ${r.code}: ${trim(r.stderr)}`)
	const line = r.stdout.trim().split('\n').findLast(Boolean)
	if (!line) throw new Error('curl wrote no -w output')
	let parsed: unknown
	try {
		parsed = JSON.parse(line)
	} catch {
		throw new Error('curl -w output was not valid JSON')
	}
	if (!isCurlWriteOut(parsed)) throw new Error('curl -w output missing timing fields')
	if (parsed.response_code < 200 || parsed.response_code >= 400) throw new Error(`HTTP ${parsed.response_code}`)
	// curl reports these in seconds.
	return {
		ms: parsed.time_total * 1000,
		protocol: `http/${parsed.http_version}`,
		dnsMs: parsed.time_namelookup * 1000,
		tcpMs: (parsed.time_connect - parsed.time_namelookup) * 1000,
		tlsMs: (parsed.time_appconnect - parsed.time_connect) * 1000,
		ttfbMs: (parsed.time_starttransfer - parsed.time_appconnect) * 1000
	}
}

async function runHello(url: string, h3: boolean): Promise<Sample> {
	const t0 = process.hrtime.bigint()
	const res = (await request({
		url,
		h3,
		resolveWithFullResponse: true,
		simple: false,
		timeouts: h3 ? { connect: 3000, response: 15_000 } : { response: 15_000 }
	})) as { status?: number; statusCode?: number; body?: unknown }
	const ms = Number(process.hrtime.bigint() - t0) / 1e6
	const status = res.status ?? res.statusCode ?? 0
	if (status && (status < 200 || status >= 400)) throw new Error(`HTTP ${status}`)
	const body = typeof res.body === 'string' ? res.body : Buffer.isBuffer(res.body) ? res.body.toString('utf8') : ''
	return { ms, protocol: traceProtocol(body) ?? 'unknown' }
}

function isCurlSample(s: Sample): s is CurlSample {
	return 'dnsMs' in s
}

function makeCombos(curl: CurlInfo): Combo[] {
	const combos: Combo[] = [
		{
			id: 'hellojs-h2',
			label: 'hellojs h2',
			kind: 'hellojs',
			h3: false,
			enabled: true,
			samples: [],
			curlSamples: [],
			failures: 0
		},
		{
			id: 'curl-h2',
			label: 'curl h2',
			kind: 'curl',
			h3: false,
			enabled: true,
			samples: [],
			curlSamples: [],
			failures: 0
		},
		{
			id: 'hellojs-h3',
			label: 'hellojs h3',
			kind: 'hellojs',
			h3: true,
			enabled: true,
			samples: [],
			curlSamples: [],
			failures: 0
		}
	]
	combos.push({
		id: 'curl-h3',
		label: 'curl h3',
		kind: 'curl',
		h3: true,
		enabled: curl.hasH3,
		note: curl.hasH3 ? undefined : 'curl build lacks HTTP3 (set CURL_BIN to an h3-capable curl)',
		samples: [],
		curlSamples: [],
		failures: 0
	})
	return combos
}

/** Verifies the protocol actually negotiated; h3 falling back to TCP is a hard error here. */
function protocolProblem(c: Combo, protocol: string): string | undefined {
	if (protocol === 'unknown') return undefined
	if (c.h3) return protocol === 'http/3' ? undefined : `negotiated ${protocol}, expected http/3 (fallback)`
	return protocol === 'http/2' ? undefined : `negotiated ${protocol}, expected http/2`
}

async function runSamples(combos: Combo[], curl: CurlInfo): Promise<void> {
	for (let round = 0; round < SAMPLES; round++) {
		const active = combos.filter((c) => c.enabled)
		const order = round % 2 === 0 ? active : [...active].reverse()
		for (const c of order) {
			if (!c.enabled) continue
			try {
				const sample = c.kind === 'hellojs' ? await runHello(TARGET, c.h3) : await runCurl(curl, TARGET, c.h3)
				const problem = protocolProblem(c, sample.protocol)
				if (problem) {
					c.enabled = false
					c.note = problem
					console.warn(`  ! ${c.label}: ${problem}; skipping the rest of this row`)
					continue
				}
				c.samples.push(sample)
				if (isCurlSample(sample)) c.curlSamples.push(sample)
				c.failures = 0
			} catch (e) {
				c.failures++
				console.warn(`  ! ${c.label}: ${errorMessage(e)}`)
				if (c.failures >= MAX_CONSECUTIVE_FAILURES) {
					c.enabled = false
					c.note = `disabled after ${c.failures} consecutive failures`
				}
			}
		}
	}
}

function dominantProtocol(c: Combo): string {
	const counts = new Map<string, number>()
	for (const s of c.samples) counts.set(s.protocol, (counts.get(s.protocol) ?? 0) + 1)
	let best = '—'
	let bestN = 0
	for (const [protocol, n] of counts) {
		if (n > bestN) {
			best = protocol
			bestN = n
		}
	}
	return best
}

function pad(s: string, n: number): string {
	return s.padEnd(n)
}

function num(n: number): string {
	return n.toFixed(1).padStart(9)
}

function latencyRow(c: Combo, s: Stats | undefined): string {
	if (!s) return `  ${pad(c.label, 14)}${c.note ? `N/A — ${c.note}` : 'N/A'}`
	return `  ${pad(c.label, 14)}${num(s.min)}${num(s.p50)}${num(s.p95)}${num(s.mean)}${String(s.n).padStart(6)}  ${dominantProtocol(c)}`
}

function phaseRow(label: string, samples: CurlSample[]): string | undefined {
	if (samples.length === 0) return undefined
	const mean = (f: (s: CurlSample) => number) => samples.reduce((a, s) => a + f(s), 0) / samples.length
	return `  ${pad(label, 14)}${num(mean((s) => s.dnsMs))}${num(mean((s) => s.tcpMs))}${num(mean((s) => s.tlsMs))}${num(mean((s) => s.ttfbMs))}${num(mean((s) => s.ms))}`
}

function deltaRow(label: string, hello: Stats | undefined, curl: Stats | undefined): string | undefined {
	if (!hello || !curl) return undefined
	const pct = (a: number, b: number) => `${a >= b ? '+' : ''}${(((a - b) / b) * 100).toFixed(1)}%`
	return (
		`  ${label}: p50 ${pct(hello.p50, curl.p50)} ` +
		`(hellojs ${hello.p50.toFixed(1)}ms vs curl ${curl.p50.toFixed(1)}ms), ` +
		`mean ${pct(hello.mean, curl.mean)}`
	)
}

function statsOf(c: Combo | undefined): Stats | undefined {
	return c ? stats(c.samples.map((s) => s.ms)) : undefined
}

async function main(): Promise<void> {
	const curl = await detectCurl(CURL_BIN)
	const combos = makeCombos(curl)
	console.log(`Target: ${TARGET}`)
	console.log(`Samples: ${SAMPLES} per row (one fresh connection per request)`)
	console.log(`curl: ${curl.version} — HTTP3 ${curl.hasH3 ? 'yes' : 'no'}`)
	console.log()
	await runSamples(combos, curl)
	console.log()
	console.log('End-to-end latency (ms):')
	console.log(
		`  ${pad('combo', 14)}${'min'.padStart(9)}${'p50'.padStart(9)}${'p95'.padStart(9)}${'mean'.padStart(9)}${'n'.padStart(6)}  protocol`
	)
	for (const c of combos) console.log(latencyRow(c, statsOf(c)))

	const phaseRows: string[] = []
	for (const c of combos) {
		if (c.kind !== 'curl') continue
		const row = phaseRow(c.label, c.curlSamples)
		if (row) phaseRows.push(row)
	}
	if (phaseRows.length > 0) {
		console.log()
		console.log('curl phase means (ms):')
		console.log(
			`  ${pad('combo', 14)}${'DNS'.padStart(9)}${'TCP'.padStart(9)}${'TLS'.padStart(9)}${'TTFB'.padStart(9)}${'total'.padStart(9)}`
		)
		for (const row of phaseRows) console.log(row)
	}

	const delta = deltaRow(
		'hellojs h2 vs curl h2',
		statsOf(combos.find((c) => c.id === 'hellojs-h2')),
		statsOf(combos.find((c) => c.id === 'curl-h2'))
	)
	if (delta) {
		console.log()
		console.log(delta)
	}
}

main().catch((e: unknown) => {
	process.stderr.write(`${errorMessage(e)}\n`)
	process.exit(2)
})
