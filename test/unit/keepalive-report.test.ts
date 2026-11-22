// The verdict is pure: no Worker, no network, no DO. It reads the pool counters in the probe
// report and answers the two questions the test page asks.

import { describe, expect, it } from 'vitest'

import { keepaliveVerdict, type KeepaliveProbe } from '../../examples/keepalive-report.ts'

function sample(overrides: Partial<KeepaliveProbe> = {}): KeepaliveProbe {
	return {
		url: 'https://httpbingo.org/get',
		n: 2,
		keepalive: true,
		steps: [
			{ index: 1, status: 200, ms: 120, pooledSockets: 1 },
			{ index: 2, status: 200, ms: 30, pooledSockets: 1 }
		],
		pooledSocketsBefore: 0,
		pooledSocketsAfter: 1,
		poolStatsBefore: { pooled: 0, created: 0, hits: 0 },
		poolStatsAfter: { pooled: 1, created: 1, hits: 1 },
		reused: true,
		ms: 150,
		...overrides
	}
}

describe('keepaliveVerdict', () => {
	it('accepts a paired probe with one handshake and one pooled hand-out', () => {
		expect(keepaliveVerdict(sample(), 'paired')).toBe(true)
	})

	it('rejects a paired probe where both requests opened a fresh connection', () => {
		const probe = sample({
			reused: false,
			steps: [
				{ index: 1, status: 200, ms: 120, pooledSockets: 1 },
				{ index: 2, status: 200, ms: 120, pooledSockets: 1 }
			],
			poolStatsAfter: { pooled: 1, created: 2, hits: 0 }
		})
		expect(keepaliveVerdict(probe, 'paired')).toBe(false)
	})

	it('rejects a paired probe with the wrong number of steps or a failed status', () => {
		expect(
			keepaliveVerdict(sample({ steps: [{ index: 1, status: 200, ms: 1, pooledSockets: 1 }] }), 'paired')
		).toBe(false)
		expect(
			keepaliveVerdict(
				sample({
					steps: [
						{ index: 1, status: 200, ms: 1, pooledSockets: 1 },
						{ index: 2, status: 503, ms: 1, pooledSockets: 1 }
					]
				}),
				'paired'
			)
		).toBe(false)
	})

	it('accepts both single steps: the first opens, the second reuses', () => {
		const first = sample({
			n: 1,
			steps: [{ index: 1, status: 200, ms: 120, pooledSockets: 1 }],
			poolStatsAfter: { pooled: 1, created: 1, hits: 0 },
			reused: false
		})
		const second = sample({
			n: 1,
			steps: [{ index: 1, status: 200, ms: 30, pooledSockets: 1 }],
			poolStatsBefore: { pooled: 1, created: 1, hits: 0 },
			poolStatsAfter: { pooled: 1, created: 1, hits: 1 }
		})
		expect(keepaliveVerdict(first, 'single')).toBe(true)
		expect(keepaliveVerdict(second, 'single')).toBe(true)
	})

	it('rejects a single probe that neither opened nor reused a socket', () => {
		const probe = sample({
			n: 1,
			steps: [{ index: 1, status: 200, ms: 1, pooledSockets: 0 }],
			pooledSocketsAfter: 0,
			poolStatsAfter: { pooled: 0, created: 0, hits: 0 }
		})
		expect(keepaliveVerdict(probe, 'single')).toBe(false)
	})

	it('rejects counters that went backwards', () => {
		const probe = sample({ poolStatsAfter: { pooled: 1, created: -1, hits: 1 } })
		expect(keepaliveVerdict(probe, 'paired')).toBe(false)
	})
})
