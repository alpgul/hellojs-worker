// Run with: node examples/basic.ts
//
// The fourteen-scenario tour, one line per scenario, against the expectations in
// examples/scenarios.ts. The same table runs in parallel inside a Worker — see
// examples/worker.ts.

import { scenarios } from './scenarios.ts'

import type { HellojsError } from '../index.ts'

const log = (label: string, ok: boolean, detail = ''): void => {
	const tag = ok ? '\x1B[32m✓\x1B[0m' : '\x1B[31m✗\x1B[0m'
	console.log(`${tag}  ${label}${detail ? '  —  ' + detail : ''}`)
}

await (async (): Promise<void> => {
	console.log('\n=== hellojs example tour ===\n')

	for (const scenario of scenarios) {
		const t0 = Date.now()
		try {
			const detail = await scenario.run()
			log(`${scenario.id}. ${scenario.name}`, true, `${detail} (${Date.now() - t0}ms)`)
		} catch (e) {
			const err = e as HellojsError
			log(`${scenario.id}. ${scenario.name}`, false, `${err.code || err.name}: ${String(err.message).slice(0, 90)}`)
		}
	}

	console.log('\n=== done ===\n')
	process.exit(0)
})().catch((e: HellojsError) => {
	console.error('\n\x1B[31m✗  FATAL\x1B[0m', e)
	process.exit(1)
})
