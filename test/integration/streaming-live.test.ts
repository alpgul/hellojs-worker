// Live streaming test with the Stream API (`stream: true`).
//
// The contract: with stream:true the request resolves as soon as HEADERS arrive, exposing the body
// as a Node Readable you can consume incrementally / .pipe() — the full payload is NOT buffered in
// memory. This reads a real ~100 MB MP4 from a CDN and proves three things:
//   1. resolution is at header time (status/content-type/length present, body is a Readable),
//   2. bytes flow incrementally (many chunks, first chunk carries the MP4 'ftyp' box magic),
//   3. the whole stream is readable end-to-end (summed length === advertised content-length).
//
// Live network — `network` project only, never `npm test`.

import { expect, it } from 'vitest'

import request from '../../index.ts'

import type { Readable } from 'node:stream'

const MP4 = 'https://cdn.truefilesize.com/mp4/sample-100mb.mp4'
const DECLARED_BYTES = 104_857_600 // 100 MiB, matches the server's content-length

it('Stream API reads a 100MB MP4 incrementally, without buffering it whole', async () => {
	// resolveWithFullResponse gives the Response whose .body is the Readable; stream:true means the
	// promise settles at header time, before the body has arrived.
	const res = await request<Readable>({ url: MP4, stream: true, resolveWithFullResponse: true, timeout: 30_000 })

	// (1) Header-time resolution: metadata available immediately, body is a live stream.
	expect(res.status).toBe(200)
	expect(res.headers['content-type']).toContain('video/mp4')
	expect(String(res.headers['content-length'])).toBe(String(DECLARED_BYTES))
	const stream = res.body
	expect(stream && typeof (stream as Readable).on === 'function', 'body must be a Readable').toBeTruthy()

	// (2)+(3) Consume incrementally: count bytes, sample the head, never retain the full payload.
	const head = Buffer.alloc(12)
	let headFilled = 0
	let total = 0
	let chunks = 0
	let maxChunk = 0

	await new Promise<void>((resolve, reject) => {
		stream.on('data', (chunk: Buffer) => {
			chunks++
			total += chunk.length
			if (chunk.length > maxChunk) maxChunk = chunk.length
			// Copy the first 12 bytes into a fixed head buffer so nothing else is retained.
			for (let i = 0; i < chunk.length && headFilled < head.length; i++) head[headFilled++] = chunk[i]
		})
		stream.on('end', () => resolve())
		stream.on('error', (e) => reject(e))
	})

	// Whole stream readable end-to-end: no truncation, no double counting.
	expect(total).toBe(DECLARED_BYTES)

	// It arrived as a stream of chunks, not one buffered blob.
	expect(chunks, 'must receive many chunks').toBeGreaterThan(1)
	expect(maxChunk, 'individual chunk must be well under the full 100MB').toBeLessThan(DECLARED_BYTES / 10)

	// MP4 framing: offset 4..8 is the 'ftyp' box type (size field precedes it).
	expect(head.subarray(4, 8).toString('latin1')).toBe('ftyp')
})
