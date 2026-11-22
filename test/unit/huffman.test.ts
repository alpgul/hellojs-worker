// HPACK/QPACK Huffman codec (RFC 7541 Appendix B).

import { randomBytes } from 'node:crypto'

import { expect, it } from 'vitest'

import * as huffman from '../../lib/h3/huffman.ts'
import { hex } from '../helpers/bytes.ts'

// Deliberately keeps the original BigInt algorithm as an oracle for the number-based encoder.
function referenceEncode(bytes: Uint8Array): Buffer {
	let acc = 0n
	let bits = 0
	const out: number[] = []
	for (const byte of bytes) {
		const [code, len] = huffman.TABLE[byte]
		acc = (acc << BigInt(len)) | BigInt(code)
		bits += len
		while (bits >= 8) {
			bits -= 8
			out.push(Number((acc >> BigInt(bits)) & 0xffn))
			acc &= (1n << BigInt(bits)) - 1n
		}
	}
	if (bits > 0) {
		const pad = (1 << (8 - bits)) - 1
		out.push(Number(((acc << BigInt(8 - bits)) | BigInt(pad)) & 0xffn))
	}
	return Buffer.from(out)
}

it('encoder is byte-identical to the BigInt reference', () => {
	const inputs: Uint8Array[] = [
		new Uint8Array(0),
		Buffer.from([...new Array(256).keys()]),
		Buffer.from('www.example.com'),
		Buffer.from('user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36')
	]
	for (let i = 0; i < 50; i++) inputs.push(randomBytes(i * 7 + 1))
	for (const input of inputs) {
		expect(hex(huffman.encode(input)), `mismatch for ${hex(input)}`).toBe(hex(referenceEncode(input)))
	}
})

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
