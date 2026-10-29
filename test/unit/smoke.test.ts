// Proof that the Workers pool can carry the library, before any real suite is migrated:
// importing index.ts drags the whole module graph (node:net, node:tls, node:zlib, node:stream,
// Buffer) through Vite into workerd, and the two things the sandbox needs to be told about —
// an installed trust store and ML-KEM on Web Crypto — must both already be in place.

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { trustedRoots } from '../../lib/tls/cert-validate.ts'

it('loads the whole module graph inside workerd', () => {
	expect(typeof request).toBe('function')
})

it('has ML-KEM on the Worker Web Crypto surface', () => {
	// Backed only by the `webcrypto_modern_algorithms` flag in wrangler.jsonc; Node has no equivalent.
	expect(typeof crypto.subtle.encapsulateBits).toBe('function')
	expect(typeof crypto.subtle.decapsulateBits).toBe('function')
})

it('starts every test file with the generated trust store installed', () => {
	expect(trustedRoots().length).toBeGreaterThan(100)
})
