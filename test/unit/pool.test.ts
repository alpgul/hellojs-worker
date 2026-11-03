// Unit tests for the bounded keep-alive pool. Fake connections/sessions stand in for the
// real TLS machinery — the pool only reads alpn/h2Session/closed and the close() side.

import { EventEmitter } from 'node:events'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { clearPool, DEFAULT_CONFIG, poolEvict, poolKey, pooledCount, register, release, take } from '../../lib/pool.ts'

import type { Connection } from '../../lib/connect.ts'

interface FakeSession extends EventEmitter {
	closed: boolean
	destroyed: boolean
	peerSettings: Record<number, number>
}

function fakeConn(session?: Partial<FakeSession>): { conn: Connection; session: FakeSession; closeReasons: string[] } {
	const sess = Object.assign(new EventEmitter(), {
		closed: false,
		destroyed: false,
		peerSettings: { 3: Infinity }, // MAX_CONCURRENT_STREAMS
	}) as FakeSession
	Object.assign(sess, session)
	const closeReasons: string[] = []
	const conn = {
		alpn: 'h2',
		h2Session: sess,
		h2Transport: {},
		closed: false,
		onClosed: null,
		close(reason = 'closed') {
			closeReasons.push(reason)
			// Mirror the real Connection: notify whoever holds a hook, then mark closed.
			;(conn as { onClosed?: ((r: string) => void) | null }).onClosed?.(reason)
			conn.closed = true
		},
	} as unknown as Connection
	return { conn, session: sess, closeReasons }
}

const KEY = poolKey('example.com', 443, 'chrome147-mac', null, true)

describe('pool', () => {
	beforeEach(() => {
		vi.useFakeTimers()
	})
	afterEach(() => {
		clearPool('test-teardown')
		vi.clearAllTimers()
		vi.useRealTimers()
	})

	it('poolKey separates host, port, profile, proxy and verification', () => {
		const base = poolKey('a.com', 443, 'p', null, true)
		expect(poolKey('b.com', 443, 'p', null, true)).not.toBe(base)
		expect(poolKey('a.com', 8443, 'p', null, true)).not.toBe(base)
		expect(poolKey('a.com', 443, 'other', null, true)).not.toBe(base)
		expect(poolKey('a.com', 443, 'p', 'http://proxy:1', true)).not.toBe(base)
		expect(poolKey('a.com', 443, 'p', null, false)).not.toBe(base)
		expect(poolKey('a.com', 443, 'p', null, true)).toBe(base)
	})

	it('register hands a fresh connection to later takers', () => {
		const { conn } = fakeConn()
		expect(register(conn, KEY, DEFAULT_CONFIG)).toBe(true)
		expect(pooledCount()).toBe(1)
		expect(take(KEY)).toBe(conn)
		expect(pooledCount()).toBe(1)
	})

	it('register ignores non-h2 connections and honours maxPerOrigin', () => {
		const h1 = fakeConn()
		;(h1.conn as { alpn: string }).alpn = 'http/1.1'
		expect(register(h1.conn, KEY, DEFAULT_CONFIG)).toBe(false)

		const cfg = { ...DEFAULT_CONFIG, maxPerOrigin: 1 }
		const a = fakeConn()
		const b = fakeConn()
		expect(register(a.conn, KEY, cfg)).toBe(true)
		expect(register(b.conn, KEY, cfg)).toBe(false)
		expect(pooledCount()).toBe(1)
	})

	it('global maxSockets bounds registrations across origins', () => {
		const cfg = { ...DEFAULT_CONFIG, maxSockets: 2 }
		const hosts = ['a.com', 'b.com', 'c.com']
		const accepted: boolean[] = hosts.map((host) => {
			const { conn } = fakeConn()
			return register(conn, poolKey(host, 443, 'p', null, true), cfg)
		})
		expect(accepted).toEqual([true, true, false])
		expect(pooledCount()).toBe(2)
	})

	it('release parks an idle socket and the idle timer closes it', () => {
		const { conn, closeReasons } = fakeConn()
		register(conn, KEY, { ...DEFAULT_CONFIG, idleMs: 1000 })
		// The creating stream holds a slot; releasing empties it.
		expect(release(conn)).toBe(true)
		vi.advanceTimersByTime(999)
		expect(closeReasons).toEqual([])
		vi.advanceTimersByTime(2)
		expect(closeReasons).toEqual(['pool-idle-expired'])
		expect(take(KEY)).toBe(null)
		expect(pooledCount()).toBe(0)
	})

	it('a new stream cancels the pending idle close', () => {
		const { conn, closeReasons } = fakeConn()
		register(conn, KEY, { ...DEFAULT_CONFIG, idleMs: 500 })
		release(conn)
		vi.advanceTimersByTime(100)
		expect(take(KEY)).toBe(conn)
		vi.advanceTimersByTime(1000)
		expect(closeReasons).toEqual([])
		expect(pooledCount()).toBe(1)
	})

	it('release balances concurrent streams', () => {
		const { conn, closeReasons } = fakeConn()
		register(conn, KEY, DEFAULT_CONFIG)
		expect(take(KEY)).toBe(conn) // active 2 (creator + this)
		expect(release(conn)).toBe(true) // still one in flight
		expect(closeReasons).toEqual([])
		expect(release(conn)).toBe(true) // now parked
	})

	it('GOAWAY stops reuse without breaking the slot accounting', () => {
		const { conn } = fakeConn()
		register(conn, KEY, DEFAULT_CONFIG)
		conn.h2Session!.emit('goaway', 0, 0)
		expect(take(KEY)).toBe(null)
		expect(pooledCount()).toBe(0)
	})

	it('session close and connection close both evict', () => {
		const a = fakeConn()
		register(a.conn, KEY, DEFAULT_CONFIG)
		a.session.closed = true
		a.session.emit('close')
		expect(take(KEY)).toBe(null)

		const b = fakeConn()
		register(b.conn, KEY, DEFAULT_CONFIG)
		b.conn.close('h2-stream-error')
		expect(take(KEY)).toBe(null)
		expect(pooledCount()).toBe(0)
	})

	it('peer MAX_CONCURRENT_STREAMS caps hand-outs', () => {
		const { conn } = fakeConn({ peerSettings: { 3: 1 } })
		register(conn, KEY, DEFAULT_CONFIG)
		release(conn) // creator slot back; one stream of headroom
		expect(take(KEY)).toBe(conn) // fills the single slot
		expect(take(KEY)).toBe(null) // no headroom left
	})

	it('poolEvict drops a poisoned socket', () => {
		const { conn } = fakeConn()
		register(conn, KEY, DEFAULT_CONFIG)
		poolEvict(conn)
		expect(take(KEY)).toBe(null)
	})

	it('release on an unregistered connection tells the caller to close', () => {
		const { conn } = fakeConn()
		expect(release(conn)).toBe(false)
	})
})
