// Error taxonomy: stable shape, codes, categories, and wrap() promotion.

import { expect, it } from 'vitest'

import { HellojsError, CODES, CATEGORY, wrap } from '../../lib/errors.ts'

it('HellojsError has stable name + code + category', () => {
	const e = new HellojsError('boom', 'EHTTP')
	expect(e.name).toBe('HellojsError')
	expect(e.code).toBe('EHTTP')
	expect(e.category).toBe(CATEGORY.HTTP)
	expect(e).toBeInstanceOf(Error)
})

it('Unknown code defaults to protocol category', () => {
	const e = new HellojsError('huh', 'EBOGUS')
	expect(e.category).toBe(CATEGORY.PROTOCOL)
})

it('wrap() passes a HellojsError through unchanged', () => {
	const src = new HellojsError('x', 'ETIMEDOUT')
	expect(wrap(src)).toBe(src)
})

it('wrap() promotes a Node ECONNRESET error to ECONNRESET HellojsError', () => {
	const node = Object.assign(new Error('socket reset'), { code: 'ECONNRESET' })
	const e = wrap(node)
	expect(e).toBeInstanceOf(HellojsError)
	expect(e.code).toBe('ECONNRESET')
	expect(e.category).toBe(CATEGORY.TRANSPORT)
	expect(e.cause).toBe(node)
})

it('wrap() of generic Error uses fallback code EPROTO', () => {
	const node = new Error('something')
	const e = wrap(node)
	expect(e.code).toBe('EPROTO')
	expect(e.category).toBe(CATEGORY.PROTOCOL)
})

it('wrap(null) yields a HellojsError', () => {
	expect(wrap(null)).toBeInstanceOf(HellojsError)
})

it('CODES enum has every code mapped to a known CATEGORY', () => {
	const known = new Set<string>(Object.values(CATEGORY))
	for (const [code, def] of Object.entries(CODES)) {
		expect(known.has(def.category), `code ${code} has unknown category ${def.category}`).toBe(true)
	}
})
