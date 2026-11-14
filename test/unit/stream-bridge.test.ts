// Verifies the web-stream bridge that backs `Response.body`. Runs in the workers (workerd)
// project, so it exercises the same `ReadableStream`/`node:stream` compat surface the
// client uses on Cloudflare Workers.

import { PassThrough } from 'node:stream'

import { describe, expect, it } from 'vitest'

import { createPushStream, nodeToWebStream } from '../../lib/web-response.ts'

async function readAll(stream: ReadableStream<Uint8Array>): Promise<string> {
	const reader = stream.getReader()
	const chunks: Uint8Array[] = []
	for (;;) {
		const { done, value } = await reader.read()
		if (done) break
		chunks.push(value)
	}
	const size = chunks.reduce((n, c) => n + c.length, 0)
	const out = new Uint8Array(size)
	let off = 0
	for (const c of chunks) { out.set(c, off); off += c.length }
	return new TextDecoder().decode(out)
}

describe('createPushStream', () => {
	it('delivers written chunks and closes', async () => {
		const ps = createPushStream()
		ps.write(new TextEncoder().encode('a'))
		ps.write(new TextEncoder().encode('b'))
		ps.end()
		expect(await readAll(ps.stream)).toBe('ab')
	})

	it('propagates failures to the reader', async () => {
		const ps = createPushStream()
		const boom = new Error('boom')
		ps.fail(boom)
		await expect(readAll(ps.stream)).rejects.toThrow('boom')
	})
})

describe('nodeToWebStream', () => {
	it('bridges a Node Readable into a web ReadableStream', async () => {
		const src = new PassThrough()
		const web = nodeToWebStream(src)
		src.write('hello ')
		src.end('world')
		expect(await readAll(web)).toBe('hello world')
	})

	it('cancel tears the source down', async () => {
		const src = new PassThrough()
		const web = nodeToWebStream(src)
		src.write('hi')
		await web.cancel('stop')
		// A cancelled/destroyed PassThrough stops accepting writes.
		expect(src.destroyed).toBe(true)
	})
})
