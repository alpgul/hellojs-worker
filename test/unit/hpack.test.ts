// HPACK (RFC 7541) encoder + decoder — for the custom h2 client.

import { expect, it } from 'vitest'

import * as hpack from '../../lib/h2/hpack.ts'
import { hex } from '../helpers/bytes.ts'

it('static table indexes match RFC 7541 Appendix A', () => {
	// Smoke-check a few well-known entries
	expect(hpack.STATIC[2]).toStrictEqual([':method', 'GET'])
	expect(hpack.STATIC[8]).toStrictEqual([':status', '200'])
	expect(hpack.STATIC[16]).toStrictEqual(['accept-encoding', 'gzip, deflate'])
	expect(hpack.STATIC[58]).toStrictEqual(['user-agent', ''])
})

it('encode: all-static-indexed headers produce 1-byte-per-header output', () => {
	const table = new hpack.DynamicTable(4096)
	const got = hpack.encode([
		[':method', 'GET'],
		[':scheme', 'https'],
		[':path', '/'],
	], table)
	expect(hex(got)).toBe(hex(Buffer.from([0x82, 0x87, 0x84])))
})

it('encode + decode round-trip preserves headers', () => {
	const enc = new hpack.DynamicTable(4096)
	const dec = new hpack.DynamicTable(4096)
	const headers: [string, string][] = [
		[':method', 'POST'],
		[':authority', 'api.example.com'],
		[':scheme', 'https'],
		[':path', '/v1/things'],
		['user-agent', 'hellojs-test/1.0'],
		['content-type', 'application/json'],
		['accept', '*/*'],
		['x-custom-header', 'opaque-token-value-here'],
	]
	const wire = hpack.encode(headers, enc)
	const decoded = hpack.decode(wire, dec)
	expect(decoded).toStrictEqual(headers.map(([n, v]) => [n.toLowerCase(), v]))
})

it('Huffman-shorter values get the Huffman bit set', () => {
	// "www.example.com" Huffman is 12 bytes vs raw 15 — encoder should pick Huffman.
	const table = new hpack.DynamicTable(4096)
	const wire = hpack.encode([[':authority', 'www.example.com']], table)
	// First byte is literal-name-ref to static idx 1 (:authority) with 4-bit prefix → 0x01.
	// Next byte is string length: top bit set indicates Huffman.
	expect(wire[0]).toBe(0x01)
	expect((wire[1] & 0x80), 'value should be Huffman-encoded').toBe(0x80)
})

it('Dynamic table can be exercised via Insert With Incremental Indexing', () => {
	// Construct a wire payload that uses literal-with-incremental-indexing for the value
	// and check that the decoder adds it to the dynamic table.
	const dec = new hpack.DynamicTable(4096)
	// 0x40 = Literal Header Field with Incremental Indexing — New Name.
	// Then string-encoded name "custom" + string-encoded value "thing".
	const name = 'custom', value = 'thing'
	const wire = Buffer.concat([
		Buffer.from([0x40]),
		Buffer.from([name.length]), Buffer.from(name),
		Buffer.from([value.length]), Buffer.from(value),
	])
	const decoded = hpack.decode(wire, dec)
	expect(decoded).toStrictEqual([['custom', 'thing']])
	expect(dec.entries.length).toBe(1)
	expect(dec.entries[0]).toStrictEqual(['custom', 'thing'])
})

it('Decoder lookup spans static + dynamic', () => {
	const dec = new hpack.DynamicTable(4096)
	dec.add('x-app', 'mything')
	// Indexed Header Field referencing the freshly-added entry. Index space:
	// 1..STATIC_LEN = static (61 entries), then STATIC_LEN+1.. = dynamic.
	const idx = hpack.STATIC_LEN + 1
	const wire = hpack.encodeInt(idx, 7, 0x80)
	const decoded = hpack.decode(wire, dec)
	expect(decoded).toStrictEqual([['x-app', 'mything']])
})

it('Dynamic table evicts entries when capacity exceeded', () => {
	const t = new hpack.DynamicTable(80)
	t.add('a', 'x')   // 1 + 1 + 32 = 34
	t.add('b', 'y')   // 34 + 34 = 68
	t.add('c', 'z')   // 68 + 34 = 102 > 80 → evict oldest
	expect(t.size).toBeLessThanOrEqual(80)
	// Oldest ('a') should be gone
	expect(t.entries.find(([n]) => n === 'a')).toBeUndefined()
	expect(t.entries.find(([n]) => n === 'c')).toBeDefined()
})
