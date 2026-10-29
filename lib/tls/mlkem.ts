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
// ML-KEM-768 itself is done by Web Crypto — the same `ML-KEM-768` algorithm the worker
// runtime exposes behind its `webcrypto_modern_algorithms` flag — so there is no
// pure-JS implementation to ship. `sk` is therefore an opaque CryptoKey that only this
// module touches: the ClientHello takes `pk` (raw encapsulation key), decapsulation takes
// `sk` back. Both operations are native (~0.4ms for keygen), so nothing is pre-warmed.

// `sk` is an opaque Web Crypto key: this module is the only place that touches it, so the
// types come from node's webcrypto namespace rather than a local re-declaration.
import { deriveX25519SharedSecret } from './x25519.ts'

import type { KeyObject, webcrypto } from 'node:crypto'

type CryptoKey = webcrypto.CryptoKey

const ALG = 'ML-KEM-768'
const KEY_OPS = ['encapsulateBits', 'decapsulateBits']

const MLKEM_PK_LEN = 1184
const MLKEM_CT_LEN = 1088
const X25519_LEN = 32

function subtle(): webcrypto.SubtleCrypto {
	const s = globalThis.crypto && globalThis.crypto.subtle
	if (!s || typeof s.encapsulateBits !== 'function' || typeof s.decapsulateBits !== 'function') {
		throw new Error(`${ALG} unavailable: runtime needs Web Crypto with ML-KEM support`)
	}
	return s
}

async function generateMlKemKeyPair(): Promise<{ pk: Buffer; sk: CryptoKey }> {
	// The runtime accepts the bare algorithm name; node's overload set only describes the
	// Rsa/Ec/Ed form, so the call keeps its original shape and the result is narrowed here.
	const pair = await (subtle() as unknown as {
		generateKey(alg: string, extractable: boolean, usages: string[]): Promise<webcrypto.CryptoKeyPair>
	}).generateKey(ALG, true, KEY_OPS)
	const jwk = await subtle().exportKey('jwk', pair.publicKey) as { pub?: string }
	if (!jwk || typeof jwk.pub !== 'string') throw new Error(`${ALG}: JWK has no "pub" field`)
	const pk = Buffer.from(jwk.pub, 'base64url')
	if (pk.length !== MLKEM_PK_LEN) {
		throw new Error(`${ALG}: unexpected encapsulation key length ${pk.length}, want ${MLKEM_PK_LEN}`)
	}
	return { pk, sk: pair.privateKey }
}

async function decapsulateMlKem(ct: Uint8Array, sk: CryptoKey): Promise<Buffer> {
	return Buffer.from(await subtle().decapsulateBits(ALG, sk, ct))
}

// Given the server's 1120-byte X25519MLKEM768 key_share entry and our private keys, compute the 64-byte hybrid shared secret.
async function deriveHybridSharedSecret(
	serverShareBuf: Buffer,
	clientMlKemSk: CryptoKey,
	clientX25519PrivateKey: KeyObject,
): Promise<Buffer> {
	if (serverShareBuf.length !== MLKEM_CT_LEN + X25519_LEN) {
		throw new Error(`unexpected X25519MLKEM768 server_share length ${serverShareBuf.length}, want ${MLKEM_CT_LEN + X25519_LEN}`)
	}
	const mlkemCt = serverShareBuf.subarray(0, MLKEM_CT_LEN)
	const serverX25519Raw = serverShareBuf.subarray(MLKEM_CT_LEN)

	const mlkemSs = await decapsulateMlKem(mlkemCt, clientMlKemSk)
	const x25519Ss = await deriveX25519SharedSecret(clientX25519PrivateKey, serverX25519Raw)

	return Buffer.concat([mlkemSs, x25519Ss])
}

export {
	generateMlKemKeyPair,
	decapsulateMlKem,
	deriveHybridSharedSecret,
	MLKEM_PK_LEN,
	MLKEM_CT_LEN,
	X25519_LEN,
}
