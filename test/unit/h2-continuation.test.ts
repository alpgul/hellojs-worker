// h2 CONTINUATION frame send/receive when header blocks exceed MAX_FRAME_SIZE.

import { Duplex } from 'node:stream'

import { expect, it } from 'vitest'

import * as frame from '../../lib/h2/frame.ts'
import * as hpack from '../../lib/h2/hpack.ts'
import { H2Session } from '../../lib/h2/session.ts'

import type { Frame } from '../../lib/h2/frame.ts'

function mockTransport(): Duplex & { written: Buffer[] } {
	const written: Buffer[] = []
	const t = new Duplex({
		write(chunk, _enc, cb) {
			written.push(Buffer.from(chunk))
			cb()
		},
		read() {}
	})
	return Object.assign(t, { written })
}

function readFrames(bytes: Buffer, from: number): Frame[] {
	const frames: Frame[] = []
	let off = from
	while (off < bytes.length) {
		const f = frame.parse(bytes.subarray(off))
		if (!f) break
		frames.push(f)
		off += f.consumed
	}
	return frames
}

it('huge header block is sent as HEADERS + CONTINUATION(s)', () => {
	const t = mockTransport()
	const s = new H2Session(t)

	// 40KB cookie ensures the encoded header block exceeds 16KB MAX_FRAME_SIZE.
	const giant = 'x'.repeat(40_000)
	s.request({ ':method': 'GET', ':scheme': 'https', ':authority': 'a', ':path': '/', cookie: giant })

	// Drop preface (24) + SETTINGS + WINDOW_UPDATE, then look at remaining frames.
	const frames = readFrames(Buffer.concat(t.written), 24)
	const headerFrames = frames.filter((f) => f.type === frame.TYPE.HEADERS)
	const contFrames = frames.filter((f) => f.type === frame.TYPE.CONTINUATION)
	expect(headerFrames.length, 'exactly one HEADERS frame').toBe(1)
	expect(contFrames.length, `expected CONTINUATION frames, got ${contFrames.length}`).toBeGreaterThanOrEqual(1)

	// HEADERS must NOT carry END_HEADERS (the last CONT does).
	expect(headerFrames[0].flags & frame.FLAG.END_HEADERS).toBe(0)
	// The LAST CONT must carry END_HEADERS.
	expect(contFrames.at(-1)!.flags & frame.FLAG.END_HEADERS).toBe(frame.FLAG.END_HEADERS)
	// Non-last CONTs do not.
	for (let i = 0; i < contFrames.length - 1; i++) {
		expect(contFrames[i].flags & frame.FLAG.END_HEADERS).toBe(0)
	}
})

it('inbound: HEADERS+CONTINUATION reassembles into a single response event', async () => {
	const t = mockTransport()
	const s = new H2Session(t)
	// Drive a request so we have a registered stream
	const stream = s.request({ ':method': 'GET', ':scheme': 'https', ':authority': 'a', ':path': '/' })

	// Encode a big response header block and split it across one HEADERS + one CONTINUATION.
	const responsePairs: [string, string][] = [
		[':status', '200'],
		['content-type', 'application/json'],
		['x-huge', 'y'.repeat(40_000)]
	]
	const encoded = hpack.encode(responsePairs, s.peerHpackTable)
	const mid = Math.floor(encoded.length / 2)
	const firstBlock = encoded.subarray(0, mid)
	const restBlock = encoded.subarray(mid)

	const responses: Record<string, string>[] = []
	stream.once('response', (h: Record<string, string>) => {
		responses.push(h)
	})

	// Inbound HEADERS (no END_HEADERS) + CONTINUATION (END_HEADERS)
	const streamId = 1 // first client stream
	t.push(frame.build(frame.TYPE.HEADERS, 0, streamId, firstBlock))
	t.push(frame.build(frame.TYPE.CONTINUATION, frame.FLAG.END_HEADERS, streamId, restBlock))

	await new Promise((r) => setImmediate(r))
	// response event fired after END_HEADERS arrived
	expect(responses.length).toBe(1)
	expect(responses[0][':status']).toBe('200')
	expect(responses[0]['x-huge']?.length).toBe(40_000)
})
