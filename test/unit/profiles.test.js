// Profile registry: register a custom profile and use it.

import assert from 'node:assert'
import test from 'node:test'

import * as profiles from '../../lib/profiles/index.js'

test('get(default) returns chrome147-mac', () => {
	assert.strictEqual(profiles.get('default').name, 'chrome147-mac')
	assert.strictEqual(profiles.get().name, 'chrome147-mac')
})

test('register + get round-trip', () => {
	const fake = { name: 'chrome148-mac', _marker: true }
	profiles.register('chrome148-mac', fake)
	assert.strictEqual(profiles.get('chrome148-mac'), fake)
	assert.ok(profiles.list().includes('chrome148-mac'))
})

test('get(unknown) throws', () => {
	assert.throws(() => profiles.get('not-a-profile'), /unknown profile/)
})

test('register validates inputs', () => {
	assert.throws(() => profiles.register('', {}), /profile name required/)
	assert.throws(() => profiles.register('x', null), /profile must be an object/)
})
