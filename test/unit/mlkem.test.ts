// ML-KEM-768 — the hybrid key_share path (TLS group 0x11EC). This is the one part of the handshake
// that only exists in the Worker's Web Crypto: workerd exposes `ML-KEM-768` behind the
// `webcrypto_modern_algorithms` flag (declared in wrangler.jsonc, which the workers pool loads) and
// Node has no ML-KEM at all, so these tests can only pass in workerd. Drop the flag and this file
// fails with `ML-KEM-768 unavailable: runtime needs Web Crypto with ML-KEM support`.

import { generateKeyPairSync } from 'node:crypto'

import { expect, it } from 'vitest'

import { decapsulateMlKem, deriveHybridSharedSecret, generateMlKemKeyPair, MLKEM_CT_LEN, MLKEM_PK_LEN, X25519_LEN } from '../../lib/tls/mlkem.ts'
import { deriveX25519SharedSecret } from '../../lib/tls/x25519.ts'
import { hex } from '../helpers/bytes.ts'

import type { WebCryptoKey } from '../../lib/tls/mlkem.ts'

// A KEM public key is not importable from raw bytes in workerd, so the encapsulation side of every
// round-trip below is rebuilt from the private key the library generated.
async function encapsulationKey(sk: WebCryptoKey): Promise<CryptoKey> {
	return crypto.subtle.getPublicKey(sk, ['encapsulateBits'])
}

it('generateMlKemKeyPair returns the wire encapsulation key and an opaque private key', async () => {
	const { pk, sk } = await generateMlKemKeyPair()
	expect(pk.length).toBe(MLKEM_PK_LEN)
	expect(sk.type).toBe('private')
	expect(sk.algorithm.name).toBe('ML-KEM-768')
})

it('the exported pk is the JWK "pub" of the matching public key', async () => {
	const { pk, sk } = await generateMlKemKeyPair()
	const pub = await encapsulationKey(sk)
	const jwk = (await crypto.subtle.exportKey('jwk', pub)) as unknown as { pub?: string }
	expect(typeof jwk.pub).toBe('string')
	expect(hex(Buffer.from(jwk.pub as string, 'base64url'))).toBe(hex(pk))
})

it('encapsulateBits -> decapsulateMlKem round-trip agrees on the 32-byte secret', async () => {
	const { sk } = await generateMlKemKeyPair()
	const pub = await encapsulationKey(sk)
	const { ciphertext, sharedKey } = await crypto.subtle.encapsulateBits('ML-KEM-768', pub)
	expect(ciphertext.byteLength).toBe(MLKEM_CT_LEN)

	const ss = await decapsulateMlKem(new Uint8Array(ciphertext), sk)
	expect(ss.length).toBe(X25519_LEN)
	expect(hex(ss)).toBe(hex(Buffer.from(sharedKey)))
})

it('deriveHybridSharedSecret concatenates ML-KEM first, then X25519', async () => {
	const { sk } = await generateMlKemKeyPair()
	const pub = await encapsulationKey(sk)
	const { ciphertext, sharedKey } = await crypto.subtle.encapsulateBits('ML-KEM-768', pub)

	const clientKeys = generateKeyPairSync('x25519')
	const serverKeys = generateKeyPairSync('x25519')
	const serverX25519Raw = Buffer.from(
		(serverKeys.publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(-X25519_LEN)
	)
	// server_share = MLKEM768_ct(1088) || X25519_pk(32), exactly what the handshake parses.
	const serverShare = Buffer.concat([Buffer.from(ciphertext), serverX25519Raw])
	expect(serverShare.length).toBe(MLKEM_CT_LEN + X25519_LEN)

	const hybrid = await deriveHybridSharedSecret(serverShare, sk, clientKeys.privateKey)
	const x25519Ss = await deriveX25519SharedSecret(clientKeys.privateKey, serverX25519Raw)
	expect(hybrid.length).toBe(X25519_LEN * 2)
	expect(hex(hybrid.subarray(0, X25519_LEN))).toBe(hex(Buffer.from(sharedKey)))
	expect(hex(hybrid.subarray(X25519_LEN))).toBe(hex(x25519Ss))
})

it('deriveHybridSharedSecret rejects a server_share of the wrong length', async () => {
	const { sk } = await generateMlKemKeyPair()
	const short = Buffer.alloc(MLKEM_CT_LEN + X25519_LEN - 1)
	await expect(deriveHybridSharedSecret(short, sk, generateKeyPairSync('x25519').privateKey))
		.rejects.toThrow(/unexpected X25519MLKEM768 server_share length/)
})
