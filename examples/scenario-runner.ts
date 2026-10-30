// Shared by the Worker and Node tours: run one scenario with a deadline and turn either
// outcome into a report row. The scenarios themselves stay runtime-agnostic in ./scenarios.ts.

import type { HellojsError } from '../index.ts'
import type { Scenario } from './scenarios.ts'

export interface ScenarioResult {
	id: number
	name: string
	ok: boolean
	detail: string
	ms: number
}

// One scenario must not be able to hold the whole report open. The ceiling sits above the
// slowest scenario's own retry budget (scenario 1 allows two ~10s attempts against tls.peet.ws),
// otherwise a slow upstream is cut off before the retry that would have recovered it can finish.
const SCENARIO_TIMEOUT_MS = 30_000

function withTimeout(runs: Promise<string>, ms: number): Promise<string> {
	return new Promise<string>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error(`no result within ${ms}ms`)), ms)
		runs.then(
			(detail) => {
				clearTimeout(timer)
				resolve(detail)
			},
			(err: unknown) => {
				clearTimeout(timer)
				reject(err)
			},
		)
	})
}

// Every scenario answers on its own terms: a failure is one row of the report, not a lost response.
async function runScenario(scenario: Scenario): Promise<ScenarioResult> {
	const t0 = Date.now()
	try {
		const detail = await withTimeout(scenario.run(), SCENARIO_TIMEOUT_MS)
		return { id: scenario.id, name: scenario.name, ok: true, detail, ms: Date.now() - t0 }
	} catch (e) {
		const err = e as HellojsError
		return { id: scenario.id, name: scenario.name, ok: false, detail: `${err.code || err.name}: ${String(err.message).slice(0, 160)}`, ms: Date.now() - t0 }
	}
}

export { runScenario }
