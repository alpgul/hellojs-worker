// The cumulative counters power the Worker/DO keep-alive report. They must survive clearPool()
// so two separate DO calls can be compared: created = a handshake, hits = a pooled hand-out.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { clearPool, poolKey, poolStats, register, release, setPoolConfig, take } from '../../lib/pool.ts'

import type { Connection } from '../../lib/connect.ts'

function fakeConn(): Connection {
	const session = {
		closed: false,
		destroyed: false,
		peerSettings: {},
		on: () => {},
		once: () => {}
	}
	return {
		alpn: 'h2',
		h2Session: session,
		closed: false,
		onClosed: null,
		close: () => {}
	} as unknown as Connection
}

const KEY = poolKey('stats.example', 443, 'chrome147-mac', null, true)

describe('poolStats', () => {
	beforeEach(() => {
		setPoolConfig()
		vi.useFakeTimers()
	})
	afterEach(() => {
		clearPool('test-teardown')
		setPoolConfig()
		vi.useRealTimers()
	})

	it('counts a new connection once and every pooled hand-out afterwards', () => {
		const before = poolStats()
		const conn = fakeConn()
		expect(register(conn, KEY)).toBe(true)
		expect(poolStats().created - before.created).toBe(1)
		expect(poolStats().hits - before.hits).toBe(0)

		expect(release(conn)).toBe(true)
		expect(take(KEY)).toBe(conn)
		expect(poolStats().hits - before.hits).toBe(1)
	})

	it('keeps the counters when the sockets are cleared', () => {
		const before = poolStats()
		const conn = fakeConn()
		register(conn, KEY)
		release(conn)
		take(KEY)
		const counted = poolStats()

		clearPool('probe-reset')
		const after = poolStats()
		expect(after.pooled).toBe(0)
		expect(after.created).toBe(counted.created)
		expect(after.hits).toBe(counted.hits)
		expect(after.created - before.created).toBe(1)
		expect(after.hits - before.hits).toBe(1)
	})
})
