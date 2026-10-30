// lib/utils/webcrypto.ts — WebCrypto resolution must not depend on a global being set.
//
// A standard Node project can run with `globalThis.crypto` absent (older Node, a bundler that
// strips it, an app that deleted it); `node:crypto.webcrypto` carries the same SubtleCrypto.
// The workers project exercises the global path against workerd.

import * as nodeCrypto from 'node:crypto'

import { expect, it } from 'vitest'

import { decapsulateMlKem, generateMlKemKeyPair, MLKEM_CT_LEN, MLKEM_PK_LEN } from '../../lib/tls/mlkem.ts'
import { deriveX25519SharedSecret } from '../../lib/tls/x25519.ts'
import { getSubtle } from '../../lib/utils/webcrypto.ts'
import { hex } from '../helpers/bytes.ts'

import type { WebCryptoKey } from '../../lib/tls/mlkem.ts'

const GLOBAL_CRYPTO = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!

// Node exposes `crypto` as a configurable getter, so it can be removed for the duration of a
// call and restored afterwards — the same shape as a Node project that never had it.
async function withoutGlobalCrypto<T>(fn: () => Promise<T>): Promise<T> {
	Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true })
	try {
		return await fn()
	} finally {
		Object.defineProperty(globalThis, 'crypto', GLOBAL_CRYPTO)
	}
}

it('uses the global WebCrypto when the runtime provides one', () => {
	expect(getSubtle()).toBe(crypto.subtle)
})

it('falls back to node:crypto.webcrypto without installing a global', async () => {
	await withoutGlobalCrypto(async () => {
		const s = getSubtle()
		expect(s).toBe(nodeCrypto.webcrypto.subtle)
		expect((await s.digest('SHA-256', new Uint8Array([1, 2, 3]))).byteLength).toBe(32)
		expect((globalThis as { crypto?: unknown }).crypto).toBeUndefined()
	})
})

it('derives the same X25519 secret through the Node fallback', async () => {
	const a = nodeCrypto.generateKeyPairSync('x25519')
	const b = nodeCrypto.generateKeyPairSync('x25519')
	const bRaw = (b.publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(-32)

	const viaWeb = await withoutGlobalCrypto(() => deriveX25519SharedSecret(a.privateKey, bRaw))
	const viaNode = nodeCrypto.diffieHellman({ publicKey: b.publicKey, privateKey: a.privateKey })
	expect(hex(viaWeb)).toBe(hex(viaNode))
})

it('runs the ML-KEM round-trip through the Node fallback', async () => {
	const { pk, sk }: { pk: Buffer; sk: WebCryptoKey } = await withoutGlobalCrypto(() => generateMlKemKeyPair())

	// A KEM public key cannot be imported from raw bytes, so the encapsulation side is rebuilt
	// from the generated private key, as in the workers ML-KEM suite.
	const subtle = nodeCrypto.webcrypto.subtle as unknown as typeof crypto.subtle
	const pub = await subtle.getPublicKey(sk, ['encapsulateBits'])
	const { ciphertext, sharedKey } = await subtle.encapsulateBits('ML-KEM-768', pub)
	const ss = await withoutGlobalCrypto(() => decapsulateMlKem(new Uint8Array(ciphertext), sk))

	expect(pk.length).toBe(MLKEM_PK_LEN)
	expect(ciphertext.byteLength).toBe(MLKEM_CT_LEN)
	expect(hex(ss)).toBe(hex(new Uint8Array(sharedKey)))
})
