// Tier-2 remote-DoS hardening for HTTP/2: malformed HPACK / oversized header blocks from the peer
// must fail the request and tear down the connection, not crash the process or exhaust memory.

import { EventEmitter } from 'node:events'

import { expect, it } from 'vitest'

import * as frame from '../../lib/h2/frame.ts'
import * as hpack from '../../lib/h2/hpack.ts'
import { H2Session } from '../../lib/h2/session.ts'

import type { HellojsError } from '../../lib/errors.ts'
import type { H2Transport } from '../../lib/h2/session.ts'

const REQ = { ':method': 'GET', ':path': '/', ':scheme': 'https', ':authority': 'x' }

// A transport that discards writes (a PassThrough would loop the session's own output back into
// its reader and desync the parser). We drive inbound bytes via session._onData directly.
function fakeTransport(): H2Transport {
	const t = new EventEmitter() as EventEmitter & { write: (chunk: Buffer) => boolean }
	t.write = () => true
	return t
}

it('hpack.decode caps decoded header-list size (decompression bomb)', () => {
	// 7000 indexed references to a static entry decode to ~294 KB, over the 256 KB cap.
	expect(() => hpack.decode(Buffer.alloc(7000, 0x82), new hpack.DynamicTable())).toThrow(/MAX_HEADER_LIST_SIZE/)
	// A small, legitimate block still decodes fine.
	expect(() => hpack.decode(Buffer.from([0x82, 0x84]), new hpack.DynamicTable())).not.toThrow()
})

it('oversized HPACK on a stream fails the request instead of crashing', () => {
	const session = new H2Session(fakeTransport())
	const stream = session.request(REQ)
	const streamErrors: HellojsError[] = []
	const closedEvents: string[] = []
	stream.on('error', (e: HellojsError) => {
		streamErrors.push(e)
	})
	session.on('close', () => {
		closedEvents.push('close')
	})
	// Response HEADERS for stream 1 carrying a decompression-bomb HPACK block.
	expect(() =>
		session._onData(frame.build(frame.TYPE.HEADERS, frame.FLAG.END_HEADERS, 1, Buffer.alloc(7000, 0x82)))
	).not.toThrow()
	expect(streamErrors.length, 'stream should receive a connection error').toBeGreaterThan(0)
	expect(streamErrors[0].message).toMatch(/h2 connection error/)
	expect(streamErrors[0].code).toBe('EH2COMPRESS')
	expect(closedEvents, 'session should emit close so the transport is torn down').toContain('close')
})

it('CONTINUATION flood is bounded (no unbounded fragment growth)', () => {
	const session = new H2Session(fakeTransport())
	const stream = session.request(REQ)
	const streamErrors: HellojsError[] = []
	stream.on('error', (e: HellojsError) => {
		streamErrors.push(e)
	})
	// HEADERS without END_HEADERS, then CONTINUATION frames totalling > 256 KB.
	session._onData(frame.build(frame.TYPE.HEADERS, 0, 1, Buffer.alloc(1024, 0x82)))
	for (let i = 0; i < 6 && streamErrors.length === 0; i++) {
		session._onData(frame.build(frame.TYPE.CONTINUATION, 0, 1, Buffer.alloc(64 * 1024, 0x82)))
	}
	expect(streamErrors.length, 'flood should surface an error').toBeGreaterThan(0)
	expect(streamErrors[0].message, 'expected a size error').toMatch(/too large|connection error/)
})
