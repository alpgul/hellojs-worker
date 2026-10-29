// X25519 shared secrets through Web Crypto.
//
// workerd's node:crypto diffieHellman() rejects a peer key imported from SPKI/PEM/JWK/raw
// ("Failed to derive shared diffie-hellman secret"), which is the only shape a server's
// key_share can arrive in. Key generation stays in node:crypto because the ClientHello is
// built synchronously; only the exchange itself is async.

import type { KeyObject } from 'node:crypto'

// Read off the global `crypto` VALUE so the type is the host runtime's own: the tsconfig loads
// @cloudflare/workers-types, so this is workerd's SubtleCrypto — @types/node ships its global
// SubtleCrypto as a constructor value with no matching type, so the name cannot be used directly.
type Subtle = typeof crypto.subtle

// privateKey: node:crypto KeyObject (x25519); peerRaw32: the peer's raw 32-byte public key.
async function deriveX25519SharedSecret(privateKey: KeyObject, peerRaw32: Uint8Array): Promise<Buffer> {
	if (!peerRaw32 || peerRaw32.length !== 32) {
		throw new Error(`X25519 peer key must be 32 bytes, got ${peerRaw32 ? peerRaw32.length : 0}`)
	}
	const s = crypto.subtle
	const priv = await s.importKey(
		'pkcs8',
		privateKey.export({ type: 'pkcs8', format: 'der' }),
		{ name: 'X25519' },
		false,
		['deriveBits']
	)
	const pub = await s.importKey('raw', peerRaw32, { name: 'X25519' }, false, [])
	// RFC 7748 §6.1 requires rejecting an all-zero result for a low-order peer key; Web Crypto
	// enforces it (Node and workerd both throw OperationError from deriveBits).
	// The cast papers over the generated workerd typings, which escape the reserved word `public` as
	// `$public` in the derive-algorithm union; the property both runtimes actually read is `public`.
	return Buffer.from(
		await s.deriveBits({ name: 'X25519', public: pub } as unknown as Parameters<Subtle['deriveBits']>[0], priv, 256)
	)
}

export { deriveX25519SharedSecret }
