// Benchmark h3 vs h2 (cold + warm steady-state) against a real host.
//
//   npm run bench:h3

import request from '../../index.ts'

const N = 10
const URL = 'https://www.cloudflare.com/cdn-cgi/trace'

interface Stats {
	min: number
	p50: number
	p95: number
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
		mean: sum / arr.length,
		total: sum,
	}
}

function fmt(s: Stats): string {
	return `min=${s.min}ms p50=${s.p50}ms p95=${s.p95}ms mean=${s.mean.toFixed(1)}ms`
}

async function timeOne(fn: () => Promise<unknown>): Promise<number> {
	const t0 = Date.now()
	await fn()
	return Date.now() - t0
}

const { default: got } = await import('got')
const gotH2 = got.extend({ http2: true, throwHttpErrors: false })

const helloH2 = () => request({ url: URL, h3: false, resolveWithFullResponse: true, simple: false })
const helloH3 = () => request({ url: URL, h3: true, resolveWithFullResponse: true, simple: false })
const goth2 = () => gotH2(URL)

console.log('Target:', URL, 'N =', N)
console.log()

console.log('--- COLD (1 req including handshake) ---')
console.log(`  hellojs h2           cold = ${await timeOne(helloH2)}ms`)
console.log(`  hellojs h3           cold = ${await timeOne(helloH3)}ms`)
console.log(`  got h2               cold = ${await timeOne(goth2)}ms`)

console.log()
console.log(`--- SERIAL ${N} (warm reuse) ---`)
const runners: [string, () => Promise<unknown>][] = [
	['hellojs h2', helloH2],
	['hellojs h3', helloH3],
	['got h2', goth2],
]
for (const [label, fn] of runners) {
	const times: number[] = []
	for (let i = 0; i < N; i++) times.push(await timeOne(fn))
	const s = stats(times)
	console.log(`  ${label.padEnd(20)} total=${s.total}ms  ${fmt(s)}`)
}
