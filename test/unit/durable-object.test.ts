// The DO can be reached from the workers test project without any network: its control
// routes report the pool configuration and size. Actual socket reuse is exercised by the
// live tour (`npm run example` → /run, which reports `pooledSockets`), not by this file —
// test/unit deliberately never dials an external origin.

import { evictDurableObject } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'

import { cleanHeaders, type Env } from '../../examples/connection-do.ts'

const bindings = env as unknown as Env

async function json(stub: DurableObjectStub, path: string): Promise<Record<string, unknown>> {
	const res = await stub.fetch(`http://do${path}`)
	expect(res.status).toBe(200)
	return (await res.json()) as Record<string, unknown>
}

describe('HelloConnectionDO', () => {
	it('runs with the DO-scoped pool config (60s idle window)', async () => {
		const stub = bindings.HELLO_POOL.getByName('config')
		expect(await json(stub, '/__config')).toEqual({ maxSockets: 16, maxPerOrigin: 1, idleMs: 60_000 })
	})

	it('keeps the pool in memory: a fresh DO starts empty again', async () => {
		const stub = bindings.HELLO_POOL.getByName('eviction')
		expect(await json(stub, '/__stats')).toEqual({ pooledSockets: 0 })

		await evictDurableObject(stub)

		expect(await json(stub, '/__stats')).toEqual({ pooledSockets: 0 })
		expect(await json(stub, '/__config')).toEqual({ maxSockets: 16, maxPerOrigin: 1, idleMs: 60_000 })
	})

	it('strips profile-fixed and transport headers before proxying', () => {
		const cleaned = cleanHeaders(
			new Headers({
				'user-agent': 'curl/8',
				'sec-ch-ua': '"Other"',
				host: 'worker.example',
				connection: 'keep-alive',
				'x-hello-proxy': '1',
				'cf-ray': 'abc',
				'x-app': 'kept'
			})
		)
		expect([...cleaned.keys()]).toEqual(['x-app'])
		expect(cleaned.get('x-app')).toBe('kept')
	})

	it('names route to independent DO instances', async () => {
		const a = bindings.HELLO_POOL.getByName('a')
		const b = bindings.HELLO_POOL.getByName('b')
		expect(a.id.toString()).not.toBe(b.id.toString())
	})
})
