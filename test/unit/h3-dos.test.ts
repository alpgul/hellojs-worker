// Tier-2 remote-DoS hardening for the QUIC/HTTP-3 transport: a malicious or buggy server must not
// be able to crash the client process or freeze the event loop or exhaust memory.

import * as crypto from 'node:crypto'

import { expect, it } from 'vitest'

import { QuicConnection, QuicStream } from '../../lib/h3/connection.ts'
import * as qpack from '../../lib/h3/qpack.ts'

it('_onDatagram drops malformed/garbage datagrams without throwing', () => {
	const c = new QuicConnection('127.0.0.1', 443)
	c.on('error', () => {})
	for (let i = 0; i < 300; i++) {
		const buf = crypto.randomBytes(1 + (i % 80))
		expect(() => c._onDatagram(buf), `iteration ${i}`).not.toThrow()
	}
	// long-header-shaped garbage + truncated short-header packet
	expect(() => c._onDatagram(Buffer.from([0xc0, 0, 0, 0, 1, 8, ...Array.from({ length: 20 }, () => 0xab)]))).not.toThrow()
	expect(() => c._onDatagram(Buffer.from([0x40, 0x01]))).not.toThrow()
	expect(() => c._onDatagram(Buffer.alloc(0))).not.toThrow()
})

it('malicious ACK range does not freeze the event loop', () => {
	const c = new QuicConnection('127.0.0.1', 443)
	for (const pn of [0, 1, 2, 3, 4, 5]) {
		c.sentPackets.oneRtt.set(pn, { size: 100, time: 0, includesCrypto: false })
	}
	const start = process.hrtime.bigint()
	// largestAcked tiny, firstAckRange astronomically large -> old code looped ~1e15 times.
	c._handleFrame('oneRtt', { type: 'ack', largestAcked: 5, ackDelay: 0, firstAckRange: 1e15, ranges: [] })
	const ms = Number(process.hrtime.bigint() - start) / 1e6
	expect(ms, `ack handling took ${ms}ms (should be ~instant)`).toBeLessThan(250)
	// The 6 outstanding packets fell inside the (huge) range and were acked.
	expect(c.sentPackets.oneRtt.size).toBe(0)
})

it('ACK still acks exactly the packets within the declared ranges', () => {
	const c = new QuicConnection('127.0.0.1', 443)
	for (const pn of [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) {
		c.sentPackets.oneRtt.set(pn, { size: 100, time: 0, includesCrypto: false })
	}
	// largestAcked=10, firstAckRange=1 -> acks 9,10; then gap=1 (skips 8,7), range len=1 -> acks 5,6.
	c._handleFrame('oneRtt', { type: 'ack', largestAcked: 10, ackDelay: 0, firstAckRange: 1, ranges: [{ gap: 1, length: 1 }] })
	const remaining = [...c.sentPackets.oneRtt.keys()].sort((a, b) => a - b)
	expect(remaining).toStrictEqual([0, 1, 2, 3, 4, 7, 8])
})

it('stream out-of-order reassembly buffer is bounded', () => {
	const c = new QuicConnection('127.0.0.1', 443)
	const s = new QuicStream(c, 0, 'bidi')
	const streamErrors: unknown[] = []
	s.on('error', (err: unknown) => { streamErrors.push(err) })
	s.on('data', () => {})
	// Feed 1 MiB chunks at ever-increasing, never-in-order offsets (recvOffset stays 0).
	const chunk = Buffer.alloc(1024 * 1024, 0xab)
	for (let i = 0; i < 64 && streamErrors.length === 0; i++) s._onData((i + 1) * 1e9, chunk, false)
	expect(streamErrors.length, 'stream should error once the out-of-order buffer cap is exceeded').toBeGreaterThan(0)
	expect(s._pendingBytes, `pending bytes ${s._pendingBytes} should stay bounded`).toBeLessThanOrEqual(8 * 1024 * 1024)
})

it('QPACK encoder-stream parser never throws or over-advances on arbitrary input', () => {
	for (let i = 0; i < 500; i++) {
		const t = new qpack.DynamicTable()
		const buf = crypto.randomBytes(1 + (i % 40))
		let consumed = 0
		expect(() => { consumed = qpack.parseEncoderInstructions(buf, t) }, `iteration ${i}`).not.toThrow()
		expect(consumed, `consumed ${consumed} not in [0, ${buf.length}]`).toBeGreaterThanOrEqual(0)
		expect(consumed, `consumed ${consumed} not in [0, ${buf.length}]`).toBeLessThanOrEqual(buf.length)
	}
})

it('QPACK over-long varint cannot wrap a length negative and stall the parser', () => {
	// 0x5f is "literal name, 5-bit length" whose prefix is saturated; the continuation bytes make
	// the length exceed 2^32. With 32-bit shifts this wrapped negative, moved the cursor backwards
	// and made parseEncoderInstructions crawl forward ~1.3e9 times (event-loop freeze).
	const t = new qpack.DynamicTable()
	const buf = Buffer.from('5fd9fc99e2eb1305333e9ae98a9fb3db', 'hex')
	const start = process.hrtime.bigint()
	const consumed = qpack.parseEncoderInstructions(buf, t)
	const ms = Number(process.hrtime.bigint() - start) / 1e6
	expect(ms, `parse took ${ms}ms (should be ~instant)`).toBeLessThan(100)
	expect(consumed).toBe(0)
	expect(t.totalInserted).toBe(0)
})

it('QPACK encoder instruction split across chunks reassembles without corruption', () => {
	const t = new qpack.DynamicTable()
	const instr = Buffer.from([0x43, 0x66, 0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72]) // Insert "foo: bar"
	let buf = instr.subarray(0, 6)
	// First half: value bytes not all present -> consume nothing, insert nothing.
	let consumed = qpack.parseEncoderInstructions(buf, t)
	expect(consumed).toBe(0)
	expect(t.totalInserted).toBe(0)
	// Append the rest -> the instruction completes and inserts exactly once (no over-advance/dupe).
	buf = Buffer.concat([buf.subarray(consumed), instr.subarray(6)])
	consumed = qpack.parseEncoderInstructions(buf, t)
	expect(consumed).toBe(instr.length)
	expect(t.totalInserted).toBe(1)
})
