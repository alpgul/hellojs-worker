// TLS 1.3 resumption tickets: binder derivation (RFC 8448 §4 vector), TTL, ALPN and
// verification-lineage gating.

import * as crypto from 'node:crypto'

import { beforeEach, expect, it } from 'vitest'

import { clearSessionTickets, getSessionTicket, pskBinder, storeSessionTicket } from '../../lib/tls/session-tickets.ts'

const HOST = 'tickets.test'
const PORT = 443

function ticket(overrides: Partial<Parameters<typeof storeSessionTicket>[2]> = {}) {
	return {
		ticket: Buffer.from('ticket-bytes'),
		psk: crypto.randomBytes(32),
		cipherSuite: 0x1301,
		hash: 'sha256' as const,
		hashLen: 32,
		lifetime: 60,
		ageAdd: 0,
		receivedAt: Date.now(),
		alpn: 'h2',
		verified: true,
		...overrides
	}
}

beforeEach(() => clearSessionTickets())

// RFC 8448 §4 "Resumed 0-RTT Handshake": PSK, the truncated ClientHello, and the binder the
// client sends. The derivation must reproduce it byte for byte.
it('derives the RFC 8448 client binder', () => {
	const psk = Buffer.from('4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3', 'hex')
	const chPrefix = Buffer.from(
		'010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb',
		'hex'
	)
	const transcriptHash = crypto.createHash('sha256').update(chPrefix).digest()
	expect(transcriptHash.toString('hex')).toBe('63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14')
	const binder = pskBinder({ psk, hash: 'sha256', hashLen: 32 }, transcriptHash)
	expect(binder.toString('hex')).toBe('3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d')
})

it('returns a stored ticket for the matching host and ALPN', () => {
	storeSessionTicket(HOST, PORT, ticket())
	expect(getSessionTicket(HOST, PORT, ['h2'], true)?.alpn).toBe('h2')
	expect(getSessionTicket(HOST, PORT, ['h2'], true)?.verified).toBe(true)
})

it('expires tickets at ticket_lifetime and ignores lifetime zero', () => {
	storeSessionTicket(HOST, PORT, ticket({ lifetime: 0 }))
	expect(getSessionTicket(HOST, PORT, ['h2'], true)).toBeNull()

	storeSessionTicket(HOST, PORT, ticket({ receivedAt: Date.now() - 61_000 }))
	expect(getSessionTicket(HOST, PORT, ['h2'], true)).toBeNull()
})

it('does not offer a ticket for a different ALPN', () => {
	storeSessionTicket(HOST, PORT, ticket({ alpn: 'h2' }))
	expect(getSessionTicket(HOST, PORT, ['http/1.1'], true)).toBeNull()
})

it('requires a verified lineage when the caller demands verification', () => {
	storeSessionTicket(HOST, PORT, ticket({ verified: false }))
	expect(getSessionTicket(HOST, PORT, ['h2'], true)).toBeNull()
	expect(getSessionTicket(HOST, PORT, ['h2'], false)).not.toBeNull()
})

it('clearSessionTickets drops everything', () => {
	storeSessionTicket(HOST, PORT, ticket())
	clearSessionTickets()
	expect(getSessionTicket(HOST, PORT, ['h2'], true)).toBeNull()
})
