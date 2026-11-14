// Live streaming test with the Fetch API.
//
// The contract: the request resolves as soon as HEADERS arrive, exposing the body as a web
// `ReadableStream` you can consume incrementally — the full payload is NOT buffered in memory.
// This reads a real ~100 MB MP4 from a CDN and proves three things:
//   1. resolution is at header time (status/content-type/length present, body is a ReadableStream),
//   2. bytes flow incrementally (many chunks, first chunk carries the MP4 'ftyp' box magic),
//   3. the whole stream is readable end-to-end (summed length === advertised content-length).
//
// Live network — `network` project only, never `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'

const MP4 = 'https://cdn.truefilesize.com/mp4/sample-100mb.mp4'
const DECLARED_BYTES = 104_857_600 // 100 MiB, matches the server's content-length

it('Stream API reads a 100MB MP4 incrementally, without buffering it whole', async () => {
	// The promise settles at header time, before the body has arrived.
	const res = await request({ url: MP4, timeout: 30_000 })

	// (1) Header-time resolution: metadata available immediately, body is a live stream.
	expect(res.status).toBe(200)
	expect(res.headers.get('content-type')).toContain('video/mp4')
	expect(res.headers.get('content-length')).toBe(String(DECLARED_BYTES))
	expect(res.body, 'body must be a ReadableStream').toBeInstanceOf(ReadableStream)

	// (2)+(3) Consume incrementally: count bytes, sample the head, never retain the full payload.
	const head = Buffer.alloc(12)
	let headFilled = 0
	let total = 0
	let chunks = 0
	let maxChunk = 0

	const reader = res.body!.getReader()
	for (;;) {
		const { done, value } = await reader.read()
		if (done) break
		chunks++
		total += value.length
		if (value.length > maxChunk) maxChunk = value.length
		// Copy the first 12 bytes into a fixed head buffer so nothing else is retained.
		for (let i = 0; i < value.length && headFilled < head.length; i++) head[headFilled++] = value[i]
	}

	// Whole stream readable end-to-end: no truncation, no double counting.
	expect(total).toBe(DECLARED_BYTES)

	// It arrived as a stream of chunks, not one buffered blob.
	expect(chunks, 'must receive many chunks').toBeGreaterThan(1)
	expect(maxChunk, 'individual chunk must be well under the full 100MB').toBeLessThan(DECLARED_BYTES / 10)

	// MP4 framing: offset 4..8 is the 'ftyp' box type (size field precedes it).
	expect(head.subarray(4, 8).toString('latin1')).toBe('ftyp')
})
