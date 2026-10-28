// lib/tls/x25519.js — the Web Crypto bridge every X25519 exchange goes through.
//
// The helper must produce exactly what node:crypto's diffieHellman does on a runtime where
// it works, because the handshake's wire bytes and the derived secrets must not change.

const test = require('node:test')
const assert = require('node:assert')
const crypto = require('node:crypto')
const { deriveX25519SharedSecret } = require('../../lib/tls/x25519')

// X25519 PKCS8 = fixed 16-byte header + the 32-byte private seed (RFC 8410).
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')
const keyObject = (seed) =>
	crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' })

test('matches RFC 7748 §6.1 vector', async () => {
	// Alice's private + Bob's public, both from the RFC.
	const aliceSeed = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex')
	const bobPublic = Buffer.from('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'hex')
	const expected = Buffer.from('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'hex')

	assert.deepStrictEqual(await deriveX25519SharedSecret(keyObject(aliceSeed), bobPublic), expected)
})

test('agrees with node:crypto diffieHellman for generated keypairs', async () => {
	const a = crypto.generateKeyPairSync('x25519')
	const b = crypto.generateKeyPairSync('x25519')
	const bRaw = b.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)

	const viaWeb = await deriveX25519SharedSecret(a.privateKey, bRaw)
	const viaNode = crypto.diffieHellman({ publicKey: b.publicKey, privateKey: a.privateKey })
	assert.strictEqual(viaWeb.length, 32)
	assert.deepStrictEqual(viaWeb, viaNode)
})

test('rejects a peer key that is not 32 bytes', async () => {
	const { privateKey } = crypto.generateKeyPairSync('x25519')
	await assert.rejects(deriveX25519SharedSecret(privateKey, Buffer.alloc(31)), /must be 32 bytes/)
	await assert.rejects(deriveX25519SharedSecret(privateKey, Buffer.alloc(33)), /must be 32 bytes/)
})

test('rejects a low-order (all-zero) peer key', async () => {
	const { privateKey } = crypto.generateKeyPairSync('x25519')
	// Web Crypto turns the all-zero result into an OperationError before it reaches us.
	await assert.rejects(deriveX25519SharedSecret(privateKey, Buffer.alloc(32)))
})
