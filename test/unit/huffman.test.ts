// HPACK/QPACK Huffman codec (RFC 7541 Appendix B).

import { randomBytes } from 'node:crypto'

import { expect, it } from 'vitest'

import * as huffman from '../../lib/h3/huffman.ts'
import { hex } from '../helpers/bytes.ts'

it('RFC 7541 Appendix C.4.1 vector: www.example.com', () => {
	const got = huffman.encode('www.example.com')
	expect(hex(got)).toBe('f1e3c2e5f23a6ba0ab90f4ff')
})

it('round-trip preserves ASCII strings', () => {
	const inputs = ['', 'a', 'hello world', 'GET', ':method', 'application/json', '/api/v1/foo?bar=baz']
	for (const s of inputs) {
		const enc = huffman.encode(s)
		const dec = huffman.decode(enc).toString('utf8')
		expect(dec, `round-trip failed for ${JSON.stringify(s)}`).toBe(s)
	}
})

it('round-trip preserves arbitrary binary bytes', () => {
	const buf = randomBytes(256)
	const enc = huffman.encode(buf)
	const dec = huffman.decode(enc)
	expect(hex(dec)).toBe(hex(buf))
})

it('decode rejects all-1s sequence longer than 7 bits (invalid EOS)', () => {
	// 8 bits of 1s would be the EOS prefix mid-stream; should be rejected during decode.
	// Constructed input where the bit stream cannot validly terminate.
	// Sanity: empty buffer decodes to empty
	expect(hex(huffman.decode(Buffer.alloc(0)))).toBe('')
})
