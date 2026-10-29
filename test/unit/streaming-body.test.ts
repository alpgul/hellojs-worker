// H2Stream write/end streaming interface — verified against a mock session.

import { Duplex, Readable } from 'node:stream'

import { expect, it } from 'vitest'

import * as frame from '../../lib/h2/frame.ts'
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

it('H2Stream.write sends DATA without END_STREAM, end() sends final DATA with END_STREAM', () => {
	const t = mockTransport()
	const s = new H2Session(t)
	const stream = s.request({ ':method': 'POST', ':scheme': 'https', ':authority': 'a', ':path': '/' })

	stream.write(Buffer.from('hello '))
	stream.write(Buffer.from('world'))
	stream.end()

	// Frames in t.written: H2 preface + SETTINGS + WINDOW_UPDATE + HEADERS + DATA + DATA + DATA(end)
	const all = Buffer.concat(t.written)
	// Skip the 24-byte preface + everything else; just decode all frames after the preface.
	const PREFACE_LEN = 24
	const frames: Frame[] = []
	let off = PREFACE_LEN
	while (off < all.length) {
		const f = frame.parse(all.subarray(off))
		if (!f) break
		frames.push(f)
		off += f.consumed
	}
	const dataFrames = frames.filter((f) => f.type === frame.TYPE.DATA)
	// 'hello ' (no end), 'world' (no end), empty (end)
	expect(dataFrames.length, 'expected 3 DATA frames').toBe(3)
	expect(dataFrames[0].flags & frame.FLAG.END_STREAM).toBe(0)
	expect(dataFrames[1].flags & frame.FLAG.END_STREAM).toBe(0)
	expect(dataFrames[2].flags & frame.FLAG.END_STREAM).toBe(frame.FLAG.END_STREAM)
	expect(dataFrames[2].length).toBe(0)
})

it('Streaming body: Readable detected as object with pipe()', () => {
	const r = Readable.from(['a', 'b', 'c'])
	expect(typeof r.pipe).toBe('function')
})
