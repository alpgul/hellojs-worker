// Benchmark: hellojs vs axios vs Node https.
//
// Scenarios:
//   1. Cold single GET — full handshake + 1 request
//   2. Serial GETs — measures keep-alive / connection reuse
//   3. Concurrent GETs — measures multiplexing
//
// Target: a small JSON endpoint on Cloudflare (cdn-cgi/trace) which is fast, keep-alive
// friendly, and supports h2 (for hellojs). The axios column replaces request-promise, which
// is deprecated and no longer installed.
//
//   npm run bench:vs-axios

import * as https from 'node:https'

import hello from '../../index.ts'

const URL = 'https://www.cloudflare.com/cdn-cgi/trace'
const N = 50

interface Stats {
	n: number
	min: number
	p50: number
	p95: number
	max: number
	mean: number
	total: number
}

function stats(arr: number[]): Stats {
	const sorted = [...arr].sort((a, b) => a - b)
	const sum = arr.reduce((a, b) => a + b, 0)
	return {
		n: arr.length,
		min: sorted[0]!,
		p50: sorted[Math.floor(arr.length * 0.5)]!,
		p95: sorted[Math.floor(arr.length * 0.95)] ?? sorted[arr.length - 1]!,
		max: sorted[arr.length - 1]!,
		mean: sum / arr.length,
		total: sum,
	}
}

function fmt(s: Stats): string {
	return `min=${s.min}ms p50=${s.p50}ms p95=${s.p95}ms max=${s.max}ms mean=${s.mean.toFixed(1)}ms`
}

async function timeOne(fn: () => Promise<unknown>): Promise<number> {
	const t0 = Date.now()
	await fn()
	return Date.now() - t0
}

// hellojs runner
const helloAgent = hello.defaults({ resolveWithFullResponse: true, simple: false })
const helloFresh = () => helloAgent({ url: URL })

// axios with a keep-alive https.Agent
const keepAliveAgent = new https.Agent({ keepAlive: true, maxSockets: 30 })
const { default: axios } = await import('axios')
const axiosInst = axios.create({ httpsAgent: keepAliveAgent, validateStatus: () => true })
const axiosRun = () => axiosInst.get(URL)

// Node https direct, with keep-alive (no abstraction overhead — control)
function nodeHttpsGet(): Promise<number> {
	return new Promise((resolve, reject) => {
		const r = https.request(URL, { method: 'GET', agent: keepAliveAgent }, (res) => {
			let len = 0
			res.on('data', (c: Buffer) => {
				len += c.length
			})
			res.on('end', () => resolve(len))
		})
		r.on('error', reject)
		r.end()
	})
}

async function cold(label: string, run: () => Promise<unknown>): Promise<number> {
	const cold1 = await timeOne(run)
	console.log(`  ${label.padEnd(20)} cold-single = ${cold1}ms`)
	return cold1
}

async function serial(label: string, run: () => Promise<unknown>): Promise<Stats> {
	const times: number[] = []
	for (let i = 0; i < N; i++) times.push(await timeOne(run))
	const s = stats(times)
	console.log(`  ${label.padEnd(20)} serial-${N}  total=${s.total}ms  ${fmt(s)}`)
	return s
}

async function concurrent(label: string, run: () => Promise<unknown>): Promise<Stats & { wall: number }> {
	const t0 = Date.now()
	const times = await Promise.all(Array.from({ length: N }, () => timeOne(run)))
	const wall = Date.now() - t0
	const s = stats(times)
	console.log(`  ${label.padEnd(20)} concurr-${N} wall=${wall}ms  ${fmt(s)}`)
	return { ...s, wall }
}

console.log('Target:', URL)
console.log('N =', N)
console.log()

console.log('--- COLD SINGLE (full handshake + 1 request) ---')
await cold('hellojs', helloFresh)
await cold('axios', () => axiosInst.get(URL, { httpsAgent: undefined }))
await cold('node https', nodeHttpsGet)
console.log()

console.log('--- SERIAL ' + N + ' (steady state) ---')
// Warm one connection first to be fair (so we measure steady-state, not handshake)
await helloFresh()
await axiosRun()
await nodeHttpsGet()

const helloSerial = await serial('hellojs', helloFresh)
const axSerial = await serial('axios', axiosRun)
const httpsSerial = await serial('node https', nodeHttpsGet)
console.log()

console.log('--- CONCURRENT ' + N + ' ---')
const helloConc = await concurrent('hellojs', helloFresh)
const axConc = await concurrent('axios', axiosRun)
const httpsConc = await concurrent('node https', nodeHttpsGet)
console.log()

console.log('--- SUMMARY ---')
const means = [helloSerial.mean, axSerial.mean, httpsSerial.mean]
const winner = ['hellojs', 'axios', 'node https'][means.indexOf(Math.min(...means))]!
const tbl: (string | number)[][] = [
	['scenario', 'hellojs', 'axios', 'node https', 'winner'],
	['serial mean', helloSerial.mean.toFixed(1) + 'ms', axSerial.mean.toFixed(1) + 'ms', httpsSerial.mean.toFixed(1) + 'ms', winner],
	['serial total', helloSerial.total + 'ms', axSerial.total + 'ms', httpsSerial.total + 'ms', ''],
	['concurrent wall', helloConc.wall + 'ms', axConc.wall + 'ms', httpsConc.wall + 'ms', ''],
]
for (const r of tbl) console.log(r.map((x) => String(x).padEnd(18)).join(''))

keepAliveAgent.destroy()
