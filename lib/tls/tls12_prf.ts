// TLS 1.2 PRF and key schedule (RFC 5246 §5, §6.3; RFC 5705 §4 for EMS).
//
// P_hash(secret, seed) = HMAC_hash(secret, A(1) || seed) || HMAC_hash(secret, A(2) || seed) || …
// where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1)).
//
// PRF(secret, label, seed, length) = P_hash(secret, label || seed) truncated to `length`.
//
// Master Secret:
//   normal: PRF(PMS, "master secret", ClientHello.random || ServerHello.random, 48)
//   EMS:    PRF(PMS, "extended master secret", session_hash, 48)
//     where session_hash = Hash(handshake_messages [CH..ClientKeyExchange])
//
// Key block:
//   PRF(MS, "key expansion", ServerHello.random || ClientHello.random, totalLen)
//   then split:  client_write_MAC | server_write_MAC | client_write_key | server_write_key | client_write_IV | server_write_IV
//
// Finished verify_data:
//   PRF(MS, finished_label, Hash(handshake_messages), 12)
//   finished_label = "client finished" | "server finished"
//
// All hashes here are the PRF hash from the cipher suite (sha256 or sha384).

import * as crypto from 'node:crypto'

function pHash(hash: string, secret: Uint8Array, seed: Uint8Array, length: number): Buffer {
	const out: Buffer[] = []
	let total = 0
	let a = seed
	while (total < length) {
		a = crypto.createHmac(hash, secret).update(a).digest()
		const block = crypto.createHmac(hash, secret).update(a).update(seed).digest()
		out.push(block)
		total += block.length
	}
	return Buffer.concat(out).subarray(0, length)
}

function prf(hash: string, secret: Uint8Array, label: string, seed: Uint8Array, length: number): Buffer {
	return pHash(hash, secret, Buffer.concat([Buffer.from(label, 'ascii'), seed]), length)
}

function masterSecret(hash: string, pms: Uint8Array, clientRandom: Uint8Array, serverRandom: Uint8Array): Buffer {
	return prf(hash, pms, 'master secret', Buffer.concat([clientRandom, serverRandom]), 48)
}

function extendedMasterSecret(hash: string, pms: Uint8Array, sessionHash: Uint8Array): Buffer {
	return prf(hash, pms, 'extended master secret', sessionHash, 48)
}

function keyBlock(hash: string, ms: Uint8Array, serverRandom: Uint8Array, clientRandom: Uint8Array, length: number): Buffer {
	return prf(hash, ms, 'key expansion', Buffer.concat([serverRandom, clientRandom]), length)
}

function finishedVerifyData(hash: string, ms: Uint8Array, isClient: boolean, transcriptHash: Uint8Array): Buffer {
	const label = isClient ? 'client finished' : 'server finished'
	return prf(hash, ms, label, transcriptHash, 12)
}

export { pHash, prf, masterSecret, extendedMasterSecret, keyBlock, finishedVerifyData }
