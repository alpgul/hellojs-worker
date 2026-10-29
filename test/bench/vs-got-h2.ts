// Benchmark: hellojs vs got (HTTP/2) vs got (HTTP/1.1) vs axios (HTTP/1.1).
//
// got supports HTTP/2 via {http2: true}: both hellojs and got can stream many requests over
// one h2 connection, but the implementations differ (hellojs runs its own TLS stack, got uses
// its internal h2 session pool).
//
// The fourth column used to be request-promise; that package is deprecated, so the
// HTTP/1.1-with-keep-alive baseline is axios.
//
//   npm run bench:vs-got

import * as https from 'node:https'

import hello from '../../index.ts'

const URL = 'https://www.cloudflare.com/cdn-cgi/trace'
const N = 50

interface Stats {
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

const { default: got } = await import('got')

const helloRun = () => hello({ url: URL, resolveWithFullResponse: true, simple: false })

const gotH2 = got.extend({ http2: true, throwHttpErrors: false })
const gotH2Run = () => gotH2(URL)

const gotH1 = got.extend({ http2: false, throwHttpErrors: false })
const gotH1Run = () => gotH1(URL)

const { default: axios } = await import('axios')
const axiosAgent = new https.Agent({ keepAlive: true, maxSockets: 100 })
const axiosInst = axios.create({ httpsAgent: axiosAgent, validateStatus: () => true })
const axiosRun = () => axiosInst.get(URL)

async function cold(label: string, run: () => Promise<unknown>): Promise<void> {
	const t = await timeOne(run)
	console.log(`  ${label.padEnd(22)} cold = ${t}ms`)
}

async function serial(label: string, run: () => Promise<unknown>, count: number): Promise<Stats> {
	const times: number[] = []
	for (let i = 0; i < count; i++) times.push(await timeOne(run))
	const s = stats(times)
	console.log(`  ${label.padEnd(22)} serial-${count}  total=${s.total}ms ${fmt(s)}`)
	return s
}

async function concurrent(
	label: string,
	run: () => Promise<unknown>,
	count: number
): Promise<Stats & { wall: number }> {
	const t0 = Date.now()
	const times = await Promise.all(Array.from({ length: count }, () => timeOne(run)))
	const wall = Date.now() - t0
	const s = stats(times)
	console.log(`  ${label.padEnd(22)} concurr-${count} wall=${wall}ms ${fmt(s)}`)
	return { ...s, wall }
}

console.log('Target:', URL)
console.log('N =', N)
console.log()

console.log('--- COLD SINGLE (full handshake + 1 request) ---')
await cold('hellojs (h2)', helloRun)
await cold('got (h2)', gotH2Run)
await cold('got (h1)', gotH1Run)
await cold('axios (h1)', axiosRun)
console.log()

console.log('--- SERIAL ' + N + ' (steady-state, keep-alive) ---')
// Warm each connection so we measure steady state
await Promise.all([helloRun(), gotH2Run(), gotH1Run(), axiosRun()])

const hSer = await serial('hellojs (h2)', helloRun, N)
const g2Ser = await serial('got (h2)', gotH2Run, N)
const g1Ser = await serial('got (h1)', gotH1Run, N)
const axSer = await serial('axios (h1)', axiosRun, N)
console.log()

console.log('--- CONCURRENT ' + N + ' (multiplex/fanout) ---')
const hCon = await concurrent('hellojs (h2)', helloRun, N)
const g2Con = await concurrent('got (h2)', gotH2Run, N)
const g1Con = await concurrent('got (h1)', gotH1Run, N)
const axCon = await concurrent('axios (h1)', axiosRun, N)
console.log()

console.log('--- SUMMARY ---')
const row = (lbl: string, vals: (string | number)[]): void =>
	console.log(lbl.padEnd(22) + vals.map((v) => String(v).padEnd(14)).join(''))
row('', ['hellojs', 'got h2', 'got h1', 'axios h1'])
row('serial mean (ms)', [hSer.mean.toFixed(1), g2Ser.mean.toFixed(1), g1Ser.mean.toFixed(1), axSer.mean.toFixed(1)])
row('serial p95 (ms)', [hSer.p95, g2Ser.p95, g1Ser.p95, axSer.p95])
row('concurrent wall (ms)', [hCon.wall, g2Con.wall, g1Con.wall, axCon.wall])
row('throughput (req/s)', [
	((N * 1000) / hCon.wall).toFixed(0),
	((N * 1000) / g2Con.wall).toFixed(0),
	((N * 1000) / g1Con.wall).toFixed(0),
	((N * 1000) / axCon.wall).toFixed(0),
])

axiosAgent.destroy()
