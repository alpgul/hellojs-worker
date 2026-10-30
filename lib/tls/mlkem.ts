// X25519MLKEM768 hybrid (draft-kwiatkowski-tls-ecdhe-mlkem-02) for TLS 1.3 group 0x11EC.
//
// Wire layout:
//   client_share = MLKEM768_pk(1184) || X25519_pk(32)            = 1216 bytes
//   server_share = MLKEM768_ct(1088) || X25519_pk(32)            = 1120 bytes
//   shared_secret = MLKEM_ss(32) || X25519_ss(32)                = 64 bytes
//
// Note ordering: MLKEM portion comes FIRST in both client/server shares and in the
// concatenated shared secret. The X25519 portion follows.
//
// ML-KEM-768 itself is done by Web Crypto — workerd exposes it behind its
// `webcrypto_modern_algorithms` flag, and Node from 24.21 through `node:crypto.webcrypto` — so
// there is no pure-JS implementation to ship. `sk` is therefore an opaque Web Crypto key that
// only this module touches: the ClientHello takes `pk` (raw encapsulation key), decapsulation
// takes `sk` back. Both operations are native (~0.4ms for keygen), so nothing is pre-warmed.

// The `Subtle` type comes from ../utils/webcrypto so it stays the host runtime's own —
// workerd's ML-KEM-capable SubtleCrypto.
import { getSubtle, type Subtle } from '../utils/webcrypto.ts'

import { deriveX25519SharedSecret } from './x25519.ts'

import type { KeyObject } from 'node:crypto'

// Named, and exported, because tls.ts stores the opaque `sk` on the handshake state and has to
// call it the same thing this module does.
export type WebCryptoKey = Awaited<ReturnType<Subtle['importKey']>>

const ALG = 'ML-KEM-768'
const KEY_OPS = ['encapsulateBits', 'decapsulateBits']

const MLKEM_PK_LEN = 1184
const MLKEM_CT_LEN = 1088
const X25519_LEN = 32

function mlkemSubtle(): Subtle {
	const s = getSubtle()
	if (typeof s.encapsulateBits !== 'function' || typeof s.decapsulateBits !== 'function') {
		throw new Error(
			`${ALG} unavailable: Web Crypto has no ML-KEM support; requires Node >= 24.21 or Cloudflare Workers with the webcrypto_modern_algorithms flag`
		)
	}
	return s
}

async function generateMlKemKeyPair(): Promise<{ pk: Buffer; sk: WebCryptoKey }> {
	const pair = await mlkemSubtle().generateKey(ALG, true, KEY_OPS)
	// generateKey answers a union for the string-algorithm form; a KEM keygen is always a pair, so
	// this narrows rather than guards.
	if (!('publicKey' in pair)) throw new Error(`${ALG}: keygen returned no key pair`)
	const jwk = (await mlkemSubtle().exportKey('jwk', pair.publicKey)) as { pub?: string }
	if (!jwk || typeof jwk.pub !== 'string') throw new Error(`${ALG}: JWK has no "pub" field`)
	const pk = Buffer.from(jwk.pub, 'base64url')
	if (pk.length !== MLKEM_PK_LEN) {
		throw new Error(`${ALG}: unexpected encapsulation key length ${pk.length}, want ${MLKEM_PK_LEN}`)
	}
	return { pk, sk: pair.privateKey }
}

async function decapsulateMlKem(ct: Uint8Array, sk: WebCryptoKey): Promise<Buffer> {
	return Buffer.from(await mlkemSubtle().decapsulateBits(ALG, sk, ct))
}

// Given the server's 1120-byte X25519MLKEM768 key_share entry and our private keys, compute the 64-byte hybrid shared secret.
async function deriveHybridSharedSecret(
	serverShareBuf: Buffer,
	clientMlKemSk: WebCryptoKey,
	clientX25519PrivateKey: KeyObject
): Promise<Buffer> {
	if (serverShareBuf.length !== MLKEM_CT_LEN + X25519_LEN) {
		throw new Error(
			`unexpected X25519MLKEM768 server_share length ${serverShareBuf.length}, want ${MLKEM_CT_LEN + X25519_LEN}`
		)
	}
	const mlkemCt = serverShareBuf.subarray(0, MLKEM_CT_LEN)
	const serverX25519Raw = serverShareBuf.subarray(MLKEM_CT_LEN)

	const mlkemSs = await decapsulateMlKem(mlkemCt, clientMlKemSk)
	const x25519Ss = await deriveX25519SharedSecret(clientX25519PrivateKey, serverX25519Raw)

	return Buffer.concat([mlkemSs, x25519Ss])
}

export { generateMlKemKeyPair, decapsulateMlKem, deriveHybridSharedSecret, MLKEM_PK_LEN, MLKEM_CT_LEN, X25519_LEN }
