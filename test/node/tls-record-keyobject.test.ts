// Caching traffic keys as KeyObject must not change a single byte of a TLS 1.3 record.

import { createCipheriv } from 'node:crypto'

import { expect, it } from 'vitest'

import { TLS } from '../../lib/tls/tls.ts'
import { hex } from '../helpers/bytes.ts'

const key = Buffer.alloc(32, 0x7)
const iv = Buffer.alloc(12, 0x3)
// encrypt/decrypt only read `this.cipher.aead` and use the prototype's nonce helpers.
const ctx = Object.assign(Object.create(TLS.prototype), { cipher: { aead: 'aes-256-gcm' } }) as TLS

/** The original Buffer-key implementation, kept as an oracle. */
function referenceEncrypt(plaintext: Buffer, innerType: number, seq: number): Buffer {
	const payloadLength = plaintext.length + 1 + 16
	const header = Buffer.from([0x17, 0x03, 0x03, (payloadLength >> 8) & 0xff, payloadLength & 0xff])
	const nonce = Buffer.from(iv)
	const hi = Math.floor(seq / 0x100000000) >>> 0
	const lo = seq >>> 0
	nonce[4]! ^= (hi >>> 24) & 0xff
	nonce[5]! ^= (hi >>> 16) & 0xff
	nonce[6]! ^= (hi >>> 8) & 0xff
	nonce[7]! ^= hi & 0xff
	nonce[8]! ^= (lo >>> 24) & 0xff
	nonce[9]! ^= (lo >>> 16) & 0xff
	nonce[10]! ^= (lo >>> 8) & 0xff
	nonce[11]! ^= lo & 0xff
	const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 })
	cipher.setAAD(header)
	const encrypted = Buffer.concat([cipher.update(plaintext), cipher.update(Buffer.from([innerType])), cipher.final()])
	return Buffer.concat([header, encrypted, cipher.getAuthTag()])
}

it('encrypt is byte-identical to the Buffer-key oracle (cold and warm cache)', () => {
	const cases: Array<[Buffer, number, number]> = [
		[Buffer.from('hello'), 0x17, 0],
		[Buffer.alloc(16_384, 0x41), 0x17, 1],
		[Buffer.alloc(1024, 0x42), 0x16, 0x1_0000_0001]
	]
	// First call fills the WeakMap; repeats exercise the hit path with different nonces.
	for (let round = 0; round < 3; round++) {
		for (const [plaintext, innerType, seq] of cases) {
			const got = TLS.prototype.encrypt.call(ctx, key, iv, plaintext, innerType, seq)
			expect(hex(got), `round ${round} seq ${seq}`).toBe(hex(referenceEncrypt(plaintext, innerType, seq)))
		}
	}
})

it('decrypt round-trips repeated records with the same key', () => {
	for (let seq = 0; seq < 8; seq++) {
		const body = Buffer.from(`record-${seq}`)
		const rec = TLS.prototype.encrypt.call(ctx, key, iv, body, 0x17, seq)
		expect(TLS.prototype.decrypt.call(ctx, key, iv, rec, seq)).toEqual({ type: 0x17, body })
	}
})

it('a different key Buffer gets a different cached KeyObject', () => {
	const otherKey = Buffer.alloc(32, 0x9)
	const pt = Buffer.from('different epoch')
	const rec = TLS.prototype.encrypt.call(ctx, key, iv, pt, 0x17, 0)
	// Same nonce, different key: decryption with the new key must fail the AEAD tag check.
	expect(() => TLS.prototype.decrypt.call(ctx, otherKey, iv, rec, 0)).toThrow()
})
