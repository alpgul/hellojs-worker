// TLS 1.2 record codec — AEAD (GCM/ChaCha20) + CBC round-trip.

import * as crypto from 'node:crypto'

import { expect, it } from 'vitest'

import * as records from '../../lib/tls/tls12_records.ts'
import { hex } from '../helpers/bytes.ts'

import type { CipherSuite12, RecordKeys } from '../../lib/tls/tls12_records.ts'

// Each path in the codec reads only some of these fields, so the fixtures spell out the suite they
// are exercising and leave the rest at zero.
const suite = (over: Partial<CipherSuite12>): CipherSuite12 => ({
	name: 'TEST',
	aead: null,
	mac: null,
	keyLen: 0,
	ivLen: 0,
	macLen: 0,
	...over
})
const recordKeys = (over: Partial<RecordKeys>): RecordKeys => ({
	key: Buffer.alloc(0),
	iv: Buffer.alloc(0),
	mac: null,
	...over
})

it('AEAD AAD layout: seq(8) + type(1) + version(2) + length(2) = 13 bytes', () => {
	const aad = records.aeadAAD(0x1234, 0x16, 100)
	expect(aad.length).toBe(13)
	expect(aad.readUInt32BE(4)).toBe(0x1234) // seq low 4 bytes
	expect(aad[8]).toBe(0x16) // type
	expect(aad[9]).toBe(0x03)
	expect(aad[10]).toBe(0x03)
	expect(aad.readUInt16BE(11)).toBe(100)
})

it('AES-128-GCM round-trip: encrypt+decrypt recovers plaintext', () => {
	const cipher = suite({ aead: 'aes-128-gcm' })
	const keys = recordKeys({ key: crypto.randomBytes(16), iv: crypto.randomBytes(4) })
	const plaintext = Buffer.from('hello tls 1.2 application data')
	const record = records.encryptRecord(cipher, keys, 0, 0x17, plaintext)
	// Strip 5-byte record header to get the fragment
	const decoded = records.decryptRecord(cipher, keys, 0, 0x17, record.subarray(5))
	expect(hex(decoded)).toBe(hex(plaintext))
})

it('AES-256-GCM round-trip', () => {
	const cipher = suite({ aead: 'aes-256-gcm' })
	const keys = recordKeys({ key: crypto.randomBytes(32), iv: crypto.randomBytes(4) })
	const plaintext = crypto.randomBytes(200)
	const record = records.encryptRecord(cipher, keys, 5, 0x17, plaintext)
	const decoded = records.decryptRecord(cipher, keys, 5, 0x17, record.subarray(5))
	expect(hex(decoded)).toBe(hex(plaintext))
})

it('ChaCha20-Poly1305 round-trip', () => {
	const cipher = suite({ aead: 'chacha20-poly1305' })
	const keys = recordKeys({ key: crypto.randomBytes(32), iv: crypto.randomBytes(12) })
	const plaintext = Buffer.from('chacha20 record content')
	const record = records.encryptRecord(cipher, keys, 1, 0x16, plaintext)
	const decoded = records.decryptRecord(cipher, keys, 1, 0x16, record.subarray(5))
	expect(hex(decoded)).toBe(hex(plaintext))
})

it('AEAD: decrypt fails with wrong key', () => {
	const cipher = suite({ aead: 'aes-128-gcm' })
	const keys = recordKeys({ key: crypto.randomBytes(16), iv: crypto.randomBytes(4) })
	const wrongKeys = recordKeys({ key: crypto.randomBytes(16), iv: keys.iv })
	const record = records.encryptRecord(cipher, keys, 0, 0x17, Buffer.from('secret'))
	expect(() => records.decryptRecord(cipher, wrongKeys, 0, 0x17, record.subarray(5))).toThrow()
})

it('AEAD: decrypt fails with wrong seq number', () => {
	const cipher = suite({ aead: 'aes-128-gcm' })
	const keys = recordKeys({ key: crypto.randomBytes(16), iv: crypto.randomBytes(4) })
	const record = records.encryptRecord(cipher, keys, 0, 0x17, Buffer.from('secret'))
	expect(() => records.decryptRecord(cipher, keys, 1, 0x17, record.subarray(5))).toThrow()
})

it('CBC AES-128-SHA round-trip', () => {
	const cipher = suite({ mac: 'sha1', macLen: 20, name: 'CBC-SHA' })
	const keys = recordKeys({ key: crypto.randomBytes(16), mac: crypto.randomBytes(20) })
	const plaintext = Buffer.from('cbc data', 'utf8')
	const record = records.encryptRecord(cipher, keys, 0, 0x17, plaintext)
	const decoded = records.decryptRecord(cipher, keys, 0, 0x17, record.subarray(5))
	expect(hex(decoded)).toBe(hex(plaintext))
})

it('CBC: MAC mismatch is detected', () => {
	const cipher = suite({ mac: 'sha1', macLen: 20, name: 'CBC-SHA' })
	const keys = recordKeys({ key: crypto.randomBytes(16), mac: crypto.randomBytes(20) })
	const wrongKeys = recordKeys({ key: keys.key, mac: crypto.randomBytes(20) })
	const record = records.encryptRecord(cipher, keys, 0, 0x17, Buffer.from('data'))
	expect(() => records.decryptRecord(cipher, wrongKeys, 0, 0x17, record.subarray(5))).toThrow(/MAC mismatch/)
})
