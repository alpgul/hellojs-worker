// Unit tests for the bounded keep-alive pool. Fake connections/sessions stand in for the
// real TLS/QUIC machinery — the pool only reads alpn/session state/closed and close().

import { EventEmitter } from 'node:events'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
	clearPool,
	getPoolConfig,
	poolEvict,
	poolKey,
	pooledCount,
	register,
	release,
	setPoolConfig,
	take
} from '../../lib/pool.ts'

import type { Connection } from '../../lib/connect.ts'

interface FakeSession extends EventEmitter {
	closed: boolean
	destroyed: boolean
	peerSettings: Record<number, number>
}

function fakeConn(
	session?: Partial<FakeSession>,
	alpn: 'h2' | 'h3' | 'http/1.1' = 'h2'
): { conn: Connection; session: FakeSession; closeReasons: string[] } {
	const sess = Object.assign(new EventEmitter(), {
		closed: false,
		destroyed: false,
		peerSettings: { 3: Infinity } // MAX_CONCURRENT_STREAMS
	}) as FakeSession
	Object.assign(sess, session)
	const closeReasons: string[] = []
	const conn = {
		alpn,
		h2Session: alpn === 'h2' ? sess : null,
		h2Transport: { destroyed: false },
		h3Client: alpn === 'h3' ? { requestStream() {} } : null,
		quicConn: alpn === 'h3' ? { _closed: false } : null,
		closed: false,
		onClosed: null,
		close(reason = 'closed') {
			closeReasons.push(reason)
			// Mirror the real Connection: notify whoever holds a hook, then mark closed.
			;(conn as { onClosed?: ((r: string) => void) | null }).onClosed?.(reason)
			conn.closed = true
		}
	} as unknown as Connection
	return { conn, session: sess, closeReasons }
}

const KEY = poolKey('example.com', 443, 'chrome147-mac', null, true)
const DEFAULTS = { maxSockets: 16, maxPerOrigin: 1, idleMs: 15_000 }

describe('pool', () => {
	beforeEach(() => {
		setPoolConfig()
		vi.useFakeTimers()
	})
	afterEach(() => {
		clearPool('test-teardown')
		setPoolConfig()
		vi.clearAllTimers()
		vi.useRealTimers()
	})

	it('setPoolConfig starts from the defaults on every call', () => {
		setPoolConfig({ maxSockets: 4, idleMs: 1000 })
		expect(getPoolConfig()).toEqual({ maxSockets: 4, maxPerOrigin: 1, idleMs: 1000 })
		setPoolConfig({ maxPerOrigin: 3 })
		expect(getPoolConfig()).toEqual({ maxSockets: 16, maxPerOrigin: 3, idleMs: 15_000 })
		setPoolConfig()
		expect(getPoolConfig()).toEqual(DEFAULTS)
	})

	it('setPoolConfig rejects invalid caps without changing the config', () => {
		expect(() => setPoolConfig({ maxSockets: 0 })).toThrow(/maxSockets must be a positive integer/)
		expect(() => setPoolConfig({ maxPerOrigin: 1.5 })).toThrow(/maxPerOrigin must be a positive integer/)
		expect(() => setPoolConfig({ idleMs: -1 })).toThrow(/idleMs must be a non-negative integer/)
		expect(getPoolConfig()).toEqual(DEFAULTS)
	})

	it('poolKey separates host, port, profile, proxy and verification', () => {
		const base = poolKey('a.com', 443, 'p', null, true)
		expect(poolKey('b.com', 443, 'p', null, true)).not.toBe(base)
		expect(poolKey('a.com', 8443, 'p', null, true)).not.toBe(base)
		expect(poolKey('a.com', 443, 'other', null, true)).not.toBe(base)
		expect(poolKey('a.com', 443, 'p', { url: 'http://proxy:1' }, true)).not.toBe(base)
		expect(poolKey('a.com', 443, 'p', null, false)).not.toBe(base)
		expect(poolKey('a.com', 443, 'p', null, true)).toBe(base)
	})

	it('poolKey separates by proxy auth material and keeps it out of the key', () => {
		const proxied = poolKey('a.com', 443, 'p', { url: 'http://proxy:1' }, true)
		const bearerA = poolKey('a.com', 443, 'p', { url: 'http://proxy:1', authorization: 'Bearer a' }, true)
		expect(bearerA).not.toBe(proxied)
		expect(bearerA).toBe(poolKey('a.com', 443, 'p', { url: 'http://proxy:1', authorization: 'Bearer a' }, true))
		expect(bearerA).not.toBe(poolKey('a.com', 443, 'p', { url: 'http://proxy:1', authorization: 'Bearer b' }, true))

		// A tunnel opened with one CONNECT header set must not answer for another: the second
		// request's hop-by-hop headers would never be sent.
		expect(poolKey('a.com', 443, 'p', { url: 'http://proxy:1', headers: { 'x-a': '1' } }, true)).not.toBe(proxied)
		expect(poolKey('a.com', 443, 'p', { url: 'http://proxy:1', headers: { 'x-a': '1' } }, true)).not.toBe(
			poolKey('a.com', 443, 'p', { url: 'http://proxy:1', headers: { 'x-a': '2' } }, true)
		)
		// Header maps are canonicalized, so insertion order and casing cannot fork the bucket.
		expect(poolKey('a.com', 443, 'p', { url: '', headers: { a: '1', b: '2' } }, true)).toBe(
			poolKey('a.com', 443, 'p', { url: '', headers: { B: '2', A: '1' } }, true)
		)
		expect(poolKey('a.com', 443, 'p', null, true)).toBe(poolKey('a.com', 443, 'p', null, true))
		expect(poolKey('a.com', 443, 'p', null, true)).toBe(
			poolKey('a.com', 443, 'p', { url: '', authorization: '', headers: {} }, true)
		)

		// Credentials live in the process-wide map only as a digest.
		expect(proxied).not.toContain('proxy:1')
		expect(
			poolKey('a.com', 443, 'p', { url: 'http://alice:secret@proxy:1', authorization: 'Bearer abc123' }, true)
		).not.toContain('abc123')
	})

	it('register hands a fresh connection to later takers', () => {
		const { conn } = fakeConn()
		expect(register(conn, KEY)).toBe(true)
		expect(pooledCount()).toBe(1)
		expect(take(KEY)).toBe(conn)
		expect(pooledCount()).toBe(1)
	})

	it('poolKey separates the Alt-Svc dial target and the negotiated protocol', () => {
		const base = poolKey('a.com', 443, 'p', null, true)
		const dial = { host: 'edge.example', port: 8443 }
		const alt = poolKey('a.com', 443, 'p', null, true, dial, 'h3')
		expect(alt).not.toBe(base)
		expect(alt).not.toBe(poolKey('a.com', 443, 'p', null, true, dial, 'h2'))
		expect(alt).not.toBe(poolKey('a.com', 443, 'p', null, true, { host: 'other.example', port: 8443 }, 'h3'))
		expect(alt).not.toBe(poolKey('a.com', 443, 'p', null, true, { host: 'edge.example', port: 443 }, 'h3'))
		expect(alt).toBe(poolKey('a.com', 443, 'p', null, true, dial, 'h3'))
	})

	it('register honours maxPerOrigin and rejects unknown protocols', () => {
		const unknown = fakeConn()
		;(unknown.conn as { alpn: string }).alpn = 'ftp'
		expect(register(unknown.conn, KEY)).toBe(false)

		const a = fakeConn()
		const b = fakeConn()
		expect(register(a.conn, KEY)).toBe(true)
		expect(register(b.conn, KEY)).toBe(false)
		expect(pooledCount()).toBe(1)
	})

	it('register and reuse an h3 session', () => {
		const { conn } = fakeConn(undefined, 'h3')
		const key = poolKey('a.com', 443, 'p', null, true, null, 'h3')
		expect(register(conn, key)).toBe(true)
		release(conn)
		expect(take(key)).toBe(conn)
	})

	it('h1 sockets are exclusive: one active request, then parked again', () => {
		const { conn, closeReasons } = fakeConn(undefined, 'http/1.1')
		const key = poolKey('a.com', 443, 'p', null, true, null, 'http/1.1')
		// The completing response registers then releases the socket (active 1 -> 0).
		expect(register(conn, key)).toBe(true)
		expect(release(conn)).toBe(true)
		expect(take(key)).toBe(conn)
		expect(take(key)).toBe(null) // no multiplexing
		expect(release(conn)).toBe(true)
		expect(closeReasons).toEqual([])
	})

	it('global maxSockets bounds registrations across origins', () => {
		setPoolConfig({ maxSockets: 2 })
		const hosts = ['a.com', 'b.com', 'c.com']
		const accepted: boolean[] = hosts.map((host) => {
			const { conn } = fakeConn()
			return register(conn, poolKey(host, 443, 'p', null, true))
		})
		expect(accepted).toEqual([true, true, false])
		expect(pooledCount()).toBe(2)
	})

	it('release parks an idle socket and the idle timer closes it', () => {
		setPoolConfig({ idleMs: 1000 })
		const { conn, closeReasons } = fakeConn()
		register(conn, KEY)
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
		setPoolConfig({ idleMs: 500 })
		const { conn, closeReasons } = fakeConn()
		register(conn, KEY)
		release(conn)
		vi.advanceTimersByTime(100)
		expect(take(KEY)).toBe(conn)
		vi.advanceTimersByTime(1000)
		expect(closeReasons).toEqual([])
		expect(pooledCount()).toBe(1)
	})

	it('release balances concurrent streams', () => {
		const { conn, closeReasons } = fakeConn()
		register(conn, KEY)
		expect(take(KEY)).toBe(conn) // active 2 (creator + this)
		expect(release(conn)).toBe(true) // still one in flight
		expect(closeReasons).toEqual([])
		expect(release(conn)).toBe(true) // now parked
	})

	it('GOAWAY stops reuse without breaking the slot accounting', () => {
		const { conn } = fakeConn()
		register(conn, KEY)
		conn.h2Session!.emit('goaway', 0, 0)
		expect(take(KEY)).toBe(null)
		expect(pooledCount()).toBe(0)
	})

	it('session close and connection close both evict', () => {
		const a = fakeConn()
		register(a.conn, KEY)
		a.session.closed = true
		a.session.emit('close')
		expect(take(KEY)).toBe(null)

		const b = fakeConn()
		register(b.conn, KEY)
		b.conn.close('h2-stream-error')
		expect(take(KEY)).toBe(null)
		expect(pooledCount()).toBe(0)
	})

	it('peer MAX_CONCURRENT_STREAMS caps hand-outs', () => {
		const { conn } = fakeConn({ peerSettings: { 3: 1 } })
		register(conn, KEY)
		release(conn) // creator slot back; one stream of headroom
		expect(take(KEY)).toBe(conn) // fills the single slot
		expect(take(KEY)).toBe(null) // no headroom left
	})

	it('poolEvict drops a poisoned socket', () => {
		const { conn } = fakeConn()
		register(conn, KEY)
		poolEvict(conn)
		expect(take(KEY)).toBe(null)
	})

	it('release on an unregistered connection tells the caller to close', () => {
		const { conn } = fakeConn()
		expect(release(conn)).toBe(false)
	})
})
