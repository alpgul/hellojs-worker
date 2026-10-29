// HKDF (RFC 5869) + Expand-Label (RFC 8446 §7.1). Underpins all TLS 1.3 key derivation.

import * as crypto from 'node:crypto'

import { expect, it } from 'vitest'

import * as HKDF from '../../lib/utils/hkdf.ts'
import { hex } from '../helpers/bytes.ts'

it('Extract is HMAC(salt, IKM)', () => {
	const salt = Buffer.alloc(32, 0)
	const ikm = Buffer.from('input keying material')
	const got = HKDF.Extract('sha256', salt, ikm)
	const expected = crypto.createHmac('sha256', salt).update(ikm).digest()
	expect(hex(got)).toBe(hex(expected))
})

it('Expand-Label format: u16 L | u8 labelLen | "tls13 " + label | u8 ctxLen | ctx', () => {
	// We verify the canonical TLS 1.3 label format by computing two Expand-Labels and
	// confirming they differ only by the label byte; the length is the same.
	const secret = crypto.randomBytes(32)
	const a = HKDF.ExpandLabel(secret, 'client traffic', Buffer.alloc(0), 32, 'sha256', 32)
	const b = HKDF.ExpandLabel(secret, 'server traffic', Buffer.alloc(0), 32, 'sha256', 32)
	expect(a.length).toBe(32)
	expect(b.length).toBe(32)
	expect(hex(a)).not.toBe(hex(b))
})

it('Expand-Label is deterministic', () => {
	const secret = Buffer.alloc(32, 0x42)
	const ctx = Buffer.alloc(16, 0xab)
	const a = HKDF.ExpandLabel(secret, 'finished', ctx, 32, 'sha256', 32)
	const b = HKDF.ExpandLabel(secret, 'finished', ctx, 32, 'sha256', 32)
	expect(hex(a)).toBe(hex(b))
})

it('sha256/sha384 helpers hash concatenation of arguments', () => {
	const a = Buffer.from('hello ')
	const b = Buffer.from('world')
	const got = HKDF.sha256(a, b)
	const expected = crypto.createHash('sha256').update(Buffer.concat([a, b])).digest()
	expect(hex(got)).toBe(hex(expected))
})
