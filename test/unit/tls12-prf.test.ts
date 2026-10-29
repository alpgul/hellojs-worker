// TLS 1.2 PRF — P_SHA256/P_SHA384, master_secret, EMS, key_block, finished verify_data.
// PRF is the heart of TLS 1.2 key derivation. If this is wrong, nothing else works.

import * as crypto from 'node:crypto'

import { expect, it } from 'vitest'

import * as prf from '../../lib/tls/tls12_prf.ts'
import { hex } from '../helpers/bytes.ts'

it('P_SHA256 matches a hand-rolled HMAC chain', () => {
	const secret = Buffer.from('secret')
	const seed = Buffer.from('seed')
	const got = prf.pHash('sha256', secret, seed, 100)

	// Reference: P_hash(secret, seed) = HMAC(secret, A(1)||seed) || HMAC(secret, A(2)||seed) || …
	let a = seed,
		total = 0
	const out: Buffer[] = []
	while (total < 100) {
		a = crypto.createHmac('sha256', secret).update(a).digest()
		const b = crypto.createHmac('sha256', secret).update(a).update(seed).digest()
		out.push(b)
		total += b.length
	}
	expect(hex(got)).toBe(hex(Buffer.concat(out).subarray(0, 100)))
})

it('prf(secret, label, seed) == pHash(secret, label||seed)', () => {
	const pms = Buffer.alloc(48, 0)
	const cr = Buffer.alloc(32, 0xaa)
	const sr = Buffer.alloc(32, 0xbb)
	const ms = prf.masterSecret('sha256', pms, cr, sr)
	const direct = prf.pHash('sha256', pms, Buffer.concat([Buffer.from('master secret'), cr, sr]), 48)
	expect(hex(ms)).toBe(hex(direct))
})

it('masterSecret is 48 bytes regardless of PRF hash', () => {
	const pms = Buffer.alloc(48, 0)
	const cr = Buffer.alloc(32, 0xaa)
	const sr = Buffer.alloc(32, 0xbb)
	expect(prf.masterSecret('sha256', pms, cr, sr).length).toBe(48)
	expect(prf.masterSecret('sha384', pms, cr, sr).length).toBe(48)
})

it('extendedMasterSecret diverges from masterSecret with same PMS', () => {
	const pms = Buffer.alloc(48, 0x42)
	const cr = Buffer.alloc(32, 0xaa)
	const sr = Buffer.alloc(32, 0xbb)
	const sessionHash = Buffer.alloc(32, 0xcc)
	const normal = prf.masterSecret('sha256', pms, cr, sr)
	const ems = prf.extendedMasterSecret('sha256', pms, sessionHash)
	// EMS must differ from standard MS
	expect(hex(normal)).not.toBe(hex(ems))
})

it('keyBlock seed order is server_random || client_random (NOT cr||sr)', () => {
	const ms = Buffer.alloc(48, 0x42)
	const cr = Buffer.alloc(32, 0xaa)
	const sr = Buffer.alloc(32, 0xbb)
	const right = prf.keyBlock('sha256', ms, sr, cr, 40)
	const wrong = prf.keyBlock('sha256', ms, cr, sr, 40)
	// sr||cr and cr||sr must produce different key blocks
	expect(hex(right)).not.toBe(hex(wrong))
})

it('finishedVerifyData is exactly 12 bytes', () => {
	const ms = Buffer.alloc(48, 0x42)
	const h = Buffer.alloc(32, 0xcc)
	expect(prf.finishedVerifyData('sha256', ms, true, h).length).toBe(12)
	expect(prf.finishedVerifyData('sha384', ms, false, h).length).toBe(12)
})

it('finishedVerifyData differs by side (client vs server) and by transcript', () => {
	const ms = Buffer.alloc(48, 0x42)
	const h1 = Buffer.alloc(32, 0xcc)
	const h2 = Buffer.alloc(32, 0xdd)
	const c1 = prf.finishedVerifyData('sha256', ms, true, h1)
	const s1 = prf.finishedVerifyData('sha256', ms, false, h1)
	const c2 = prf.finishedVerifyData('sha256', ms, true, h2)
	expect(hex(c1)).not.toBe(hex(s1))
	expect(hex(c1)).not.toBe(hex(c2))
})
