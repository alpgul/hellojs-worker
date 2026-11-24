// Proxy ranking. The score decides both the order the caller sees and how often a proxy is picked,
// so these cases pin the properties the pool relies on: small samples are discounted, a bad start
// is recoverable, and selection is proportional rather than winner-takes-all.

import { describe, expect, it } from 'vitest'

import { NEUTRAL_SCORE, SCORE_FLOOR, pickWeighted, selectionWeight, wilsonLower } from '../../lib/proxy-score.ts'

describe('wilsonLower', () => {
	it('is neutral with no history', () => {
		expect(wilsonLower(0, 0)).toBe(NEUTRAL_SCORE)
	})

	it('prices the sample size in: the same ratio ranks higher with more evidence', () => {
		expect(wilsonLower(1, 0)).toBeLessThan(wilsonLower(10, 0))
		expect(wilsonLower(10, 0)).toBeLessThan(wilsonLower(100, 0))
		expect(wilsonLower(100, 0)).toBeGreaterThan(0.9)
	})

	it('ranks a clean record above a mixed one and a mixed one above a bad one', () => {
		expect(wilsonLower(50, 0)).toBeGreaterThan(wilsonLower(50, 50))
		expect(wilsonLower(50, 50)).toBeGreaterThan(wilsonLower(0, 50))
	})

	it('never leaves 0..1', () => {
		for (const [s, f] of [
			[0, 1000],
			[1000, 0],
			[1, 1],
			[3, 7]
		] as const) {
			const score = wilsonLower(s, f)
			expect(score).toBeGreaterThanOrEqual(0)
			expect(score).toBeLessThanOrEqual(1)
		}
	})

	it('does not reward a tiny perfect record over an untried proxy', () => {
		// One success is weak evidence; the neutral prior should still win.
		expect(wilsonLower(1, 0)).toBeLessThan(NEUTRAL_SCORE)
		expect(wilsonLower(5, 0)).toBeGreaterThan(NEUTRAL_SCORE)
	})
})

describe('selectionWeight', () => {
	it('applies the floor so a bad start stays recoverable', () => {
		expect(selectionWeight(0, 1000)).toBe(SCORE_FLOOR)
		expect(selectionWeight(0, 0)).toBe(NEUTRAL_SCORE)
	})
})

describe('pickWeighted', () => {
	it('returns null for an empty pool', () => {
		expect(pickWeighted([], [])).toBeNull()
	})

	it('maps the random draw onto the weight buckets', () => {
		const items = ['a', 'b', 'c']
		const weights = [1, 1, 1]
		expect(pickWeighted(items, weights, () => 0)).toBe('a')
		expect(pickWeighted(items, weights, () => 0.5)).toBe('b')
		expect(pickWeighted(items, weights, () => 0.99)).toBe('c')
	})

	it('favours the heavier weight without excluding the light one', () => {
		const items = ['heavy', 'light']
		const weights = [9, 1]
		let heavy = 0
		let light = 0
		for (let i = 0; i < 100; i++) {
			const picked = pickWeighted(items, weights, () => i / 100)
			if (picked === 'heavy') heavy++
			else light++
		}
		expect(heavy).toBeGreaterThan(light)
		expect(light).toBeGreaterThan(0)
	})

	it('falls back to a uniform draw when every weight is zero', () => {
		expect(pickWeighted(['a', 'b'], [0, 0], () => 0)).toBe('a')
		expect(pickWeighted(['a', 'b'], [0, 0], () => 0.99)).toBe('b')
	})

	it('treats a missing weight as zero instead of NaN', () => {
		expect(pickWeighted(['a', 'b'], [1], () => 0.99)).toBe('a')
	})
})
