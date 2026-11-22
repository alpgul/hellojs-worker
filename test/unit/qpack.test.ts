// QPACK static-table lookups must return the same indices after the map-based rewrite.

import { expect, it } from 'vitest'

import { STATIC_TABLE, decodeHeaders, encodeHeaders, findStatic } from '../../lib/h3/qpack.ts'

it('findStatic returns exact, then first name-only, then null', () => {
	for (const [name, value] of STATIC_TABLE) {
		const first = STATIC_TABLE.findIndex(([n, v]) => n === name && v === value)
		expect(findStatic(name, value)).toEqual({ exact: first })
	}
	for (const [name] of STATIC_TABLE) {
		const first = STATIC_TABLE.findIndex(([n]) => n === name)
		expect(findStatic(name, 'a value not in the static table')).toEqual({ nameOnly: first })
	}
	expect(findStatic('x-not-in-the-static-table', 'value')).toBe(null)
})

it('encode/decode round-trips static and literal header fields', () => {
	const headers: Array<[string, string]> = [
		[':method', 'GET'],
		[':path', '/cdn-cgi/trace'],
		['user-agent', 'Mozilla/5.0 Chrome/147'],
		['x-request-id', 'req-123'],
		['x-not-in-table', 'value']
	]
	expect(decodeHeaders(encodeHeaders(headers))).toEqual(headers)
})
