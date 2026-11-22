// Shared report shape for the Worker/Durable Object keep-alive probe. Kept free of imports from
// cloudflare:workers so the verdict can be unit-tested without booting a Worker.

export interface PoolStatsSample {
	pooled: number
	created: number
	hits: number
}

export interface KeepaliveStep {
	index: number
	status: number
	ms: number
	pooledSockets: number
}

export interface KeepaliveProbe {
	url: string
	n: number
	keepalive: boolean
	steps: KeepaliveStep[]
	pooledSocketsBefore: number
	pooledSocketsAfter: number
	poolStatsBefore: PoolStatsSample
	poolStatsAfter: PoolStatsSample
	/** True when at least one request in this probe got a pooled hand-out. */
	reused: boolean
	ms: number
}

export type KeepaliveMode = 'paired' | 'single'

export interface KeepaliveReport {
	url: string
	mode: KeepaliveMode
	slot: string
	probe: KeepaliveProbe
	pass: boolean
	note: string
}

/**
 * `paired` must show two successful requests with a fresh connection and a pooled hand-out.
 * `single` is one step of the across-calls scenario: either outcome is fine on its own; the
 * integration test asserts the before/after counters of the two calls together.
 */
export function keepaliveVerdict(probe: KeepaliveProbe, mode: KeepaliveMode): boolean {
	if (probe.steps.length === 0) return false
	if (mode === 'paired' && probe.steps.length !== 2) return false
	if (probe.steps.some((step) => step.status < 200 || step.status >= 400)) return false

	const opened = probe.poolStatsAfter.created - probe.poolStatsBefore.created
	const hits = probe.poolStatsAfter.hits - probe.poolStatsBefore.hits
	if (opened < 0 || hits < 0) return false
	if (mode === 'paired') return opened >= 1 && hits >= 1 && probe.reused
	return opened + hits >= 1 && probe.pooledSocketsAfter > 0
}
