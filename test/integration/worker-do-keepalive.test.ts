// End-to-end proof that a Durable Object keeps hellojs' keep-alive pool alive. Run
// `npm run example` first, then point WORKER_URL at that local wrangler dev instance.
// Live origin latency is jittery, so the assertions read the cumulative pool counters, not timings.

import { describe, expect, it } from 'vitest'

import type { KeepaliveReport } from '../../examples/keepalive-report.ts'

const WORKER_URL = process.env.WORKER_URL ?? 'http://127.0.0.1:8787'
const TARGET = process.env.KEEPALIVE_TARGET ?? 'https://httpbingo.org/get'

async function probe(params: URLSearchParams): Promise<KeepaliveReport> {
	const res = await fetch(`${WORKER_URL}/keepalive?${params}`, {
		signal: AbortSignal.timeout(90_000)
	})
	expect(res.status).toBe(200)
	return (await res.json()) as KeepaliveReport
}

function params(slot: string, mode: 'paired' | 'single', reset = false): URLSearchParams {
	const out = new URLSearchParams({ url: TARGET, mode, slot })
	if (reset) out.set('reset', '1')
	return out
}

function opened(report: KeepaliveReport): number {
	return report.probe.poolStatsAfter.created - report.probe.poolStatsBefore.created
}

function hit(report: KeepaliveReport): number {
	return report.probe.poolStatsAfter.hits - report.probe.poolStatsBefore.hits
}

describe('hellojs keep-alive in a Durable Object', () => {
	it('reuses one connection for two requests inside a single DO fetch', async () => {
		const report = await probe(params('it-paired', 'paired', true))

		expect(report.pass).toBe(true)
		expect(report.probe.steps).toHaveLength(2)
		expect(report.probe.steps.every((step) => step.status < 400)).toBe(true)
		expect(opened(report)).toBe(1)
		expect(hit(report)).toBe(1)
		expect(report.probe.reused).toBe(true)
	}, 100_000)

	it('keeps the pool across two separate Worker requests through the same DO', async () => {
		const first = await probe(params('it-across', 'single', true))
		expect(first.probe.steps).toHaveLength(1)
		expect(opened(first)).toBe(1)
		expect(hit(first)).toBe(0)

		const second = await probe(params('it-across', 'single'))
		expect(second.probe.steps).toHaveLength(1)
		// No new handshake and one pooled hand-out: the socket survived the first DO call.
		expect(opened(second)).toBe(0)
		expect(hit(second)).toBe(1)
		expect(second.probe.reused).toBe(true)
	}, 100_000)
})
