// Profile registry: register a custom profile and use it.

import { expect, it } from 'vitest'

import * as profiles from '../../lib/profiles/index.ts'

import type { Profile } from '../../lib/profiles/index.ts'

it('get(default) returns chrome147-mac', () => {
	expect(profiles.get('default').name).toBe('chrome147-mac')
	expect(profiles.get().name).toBe('chrome147-mac')
})

it('register + get round-trip', () => {
	const fake: Profile = { name: 'chrome148-mac', tls: { ciphers: [] }, http2: {} }
	profiles.register('chrome148-mac', fake)
	expect(profiles.get('chrome148-mac')).toBe(fake)
	expect(profiles.list().includes('chrome148-mac')).toBe(true)
})

it('get(unknown) throws', () => {
	expect(() => profiles.get('not-a-profile')).toThrow(/unknown profile/)
})

it('register validates inputs', () => {
	// The registry's own runtime validation is under test, so the rejected arguments are cast in.
	expect(() => profiles.register('', {} as unknown as Profile)).toThrow(/profile name required/)
	expect(() => profiles.register('x', null as unknown as Profile)).toThrow(/profile must be an object/)
})
