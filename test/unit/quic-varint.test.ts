// RFC 9000 Appendix A.1 varint vectors.

import { expect, it } from 'vitest'

import * as v from '../../lib/h3/varint.ts'

it('varint encode/decode round-trip', () => {
	const cases = [
		{ value: 0, hex: '00' },
		{ value: 25, hex: '19' },
		{ value: 63, hex: '3f' },
		{ value: 64, hex: '4040' }, // 14-bit
		{ value: 16_383, hex: '7fff' },
		{ value: 16_384, hex: '80004000' }, // 30-bit
		{ value: 1_073_741_823, hex: 'bfffffff' },
		{ value: 1_073_741_824, hex: 'c000000040000000' } // 62-bit
	]
	for (const c of cases) {
		const enc = v.encode(c.value)
		expect(enc.toString('hex'), `encode(${c.value})`).toBe(c.hex)
		// Every vector here is inside Number, and decode only widens to bigint past 2^53.
		expect(Number(v.decode(enc, 0).value), `decode(${c.hex})`).toBe(c.value)
	}
})

// RFC 9000 §16 example: 0x9d7f3e7d should decode to 494878333
it('varint RFC §16 example', () => {
	const buf = Buffer.from('9d7f3e7d', 'hex')
	const { value, length } = v.decode(buf, 0)
	expect(Number(value)).toBe(494_878_333)
	expect(length).toBe(4)
})
