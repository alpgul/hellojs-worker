// Ordering score for the pooled proxies.
//
// A raw success ratio cannot rank a pool: one lucky request scores 100% and outranks a proxy that
// has survived a thousand. The lower bound of the Wilson interval prices the sample size in, so a
// proxy climbs the list only as evidence accumulates, and the ranking is self-correcting without
// any probing or measurement pass.
//
// The floor on the selection weight matters more than it looks: without it a proxy that loses its
// first two requests ends up with a weight of ~0 and is never chosen again, so it can never
// recover. Users add proxies by hand and expect them to get a second chance.

const Z_95 = 1.96
/** No history yet: neutral, not last. A fresh proxy is tried but not trusted. */
const NEUTRAL_SCORE = 0.5
/** Smallest selection weight, so a bad start is a setback rather than a life sentence. */
const SCORE_FLOOR = 0.05

/**
 * Lower bound of the Wilson score interval at 95% confidence. `0/0` is neutral.
 * Reference points: `1/1 ≈ 0.21`, `10/10 ≈ 0.72`, `100/100 ≈ 0.96`, `50/100 ≈ 0.40`.
 */
function wilsonLower(success: number, fail: number, z: number = Z_95): number {
	const n = success + fail
	if (n <= 0) return NEUTRAL_SCORE

	const p = success / n
	const z2 = z * z
	const centre = p + z2 / (2 * n)
	const margin = z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))
	return Math.max(0, (centre - margin) / (1 + z2 / n))
}

/** Selection weight for a proxy, never zero. */
function selectionWeight(success: number, fail: number): number {
	return Math.max(SCORE_FLOOR, wilsonLower(success, fail))
}

/**
 * Pick one item with probability proportional to its weight. A zero total falls back to uniform,
 * which keeps the pool usable if every proxy somehow scored below the floor.
 */
function pickWeighted<T>(items: readonly T[], weights: readonly number[], rand: () => number = Math.random): T | null {
	if (items.length === 0) return null

	let total = 0
	for (let i = 0; i < items.length; i++) total += Math.max(0, weights[i] ?? 0)
	if (total <= 0) return items[Math.floor(rand() * items.length)] ?? items.at(-1) ?? null

	let ticket = rand() * total
	for (let i = 0; i < items.length; i++) {
		ticket -= Math.max(0, weights[i] ?? 0)
		if (ticket < 0) return items[i] ?? null
	}
	return items.at(-1) ?? null
}

export { wilsonLower, selectionWeight, pickWeighted, NEUTRAL_SCORE, SCORE_FLOOR }
