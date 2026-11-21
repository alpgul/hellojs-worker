// QUIC 1-RTT TLS PSK resumption. These tests exercise the handshake seam directly:
// the ClientHello offer (including the binder), ServerHello acceptance and its effect on the
// key schedule, and NewSessionTicket caching. No UDP server is needed.

import * as crypto from 'node:crypto'

import { beforeEach, expect, it } from 'vitest'

import { QuicConnection } from '../../lib/h3/connection.ts'
import * as pkt from '../../lib/h3/packet.ts'
import { clearSessionTickets, getSessionTicket, pskBinder, storeSessionTicket } from '../../lib/tls/session-tickets.ts'
import { CIPHERS, HASHES } from '../../lib/utils/config.ts'
import * as HKDF from '../../lib/utils/hkdf.ts'

import type { SessionTicket } from '../../lib/tls/session-tickets.ts'

const HOST = 'resume.example'
const PORT = 443
const SHA256 = HASHES[CIPHERS.TLS_AES_128_GCM_SHA256.toString(16)]

function u16(n: number): Buffer {
	const b = Buffer.alloc(2)
	b.writeUInt16BE(n, 0)
	return b
}
function u24(n: number): Buffer {
	const b = Buffer.alloc(3)
	b.writeUIntBE(n, 0, 3)
	return b
}

function makeTicket(overrides: Partial<SessionTicket> = {}): SessionTicket {
	return {
		ticket: Buffer.from('quic-ticket-bytes'),
		psk: crypto.randomBytes(32),
		cipherSuite: CIPHERS.TLS_AES_128_GCM_SHA256,
		hash: 'sha256',
		hashLen: 32,
		lifetime: 3600,
		ageAdd: 1234,
		receivedAt: Date.now(),
		alpn: 'h3',
		verified: false,
		...overrides
	}
}

interface ParsedCh {
	msg: Buffer
	body: Buffer
	declaredLen: number
	extensions: { type: number; data: Buffer }[]
}

function parseClientHello(msg: Buffer): ParsedCh {
	const declaredLen = msg.readUIntBE(1, 3)
	const body = msg.subarray(4)
	let p = 0
	p += 2 // legacy_version
	p += 32 // random
	p += 1 + body[p] // session_id
	p += 2 + body.readUInt16BE(p) // cipher_suites
	p += 2 // compression
	const extsLen = body.readUInt16BE(p)
	p += 2
	const end = p + extsLen
	const extensions: { type: number; data: Buffer }[] = []
	while (p + 4 <= end) {
		const type = body.readUInt16BE(p)
		p += 2
		const len = body.readUInt16BE(p)
		p += 2
		extensions.push({ type, data: body.subarray(p, p + len) })
		p += len
	}
	return { msg, body, declaredLen, extensions }
}

function freshConn(): QuicConnection {
	const conn = new QuicConnection(HOST, PORT)
	// Capture the ClientHello off the transcript; don't touch a UDP socket.
	conn._sendInitial = () => {}
	conn._sendClientHello()
	return conn
}

beforeEach(() => clearSessionTickets())

it('offers a cached h3 ticket as the last ClientHello extension with a valid binder', () => {
	const ticket = makeTicket()
	storeSessionTicket(HOST, PORT, ticket)

	const sentAt = Date.now()
	const conn = freshConn()
	expect(conn.pskTicket).not.toBeNull()
	const ch = parseClientHello(conn.transcript[0])
	expect(ch.declaredLen).toBe(ch.body.length)
	expect(ch.extensions.at(-1)?.type).toBe(0x0029) // pre_shared_key must be last
	expect(ch.extensions.filter((e) => e.type === 0x0029)).toHaveLength(1)

	// The ClientHello on the wire (inside CRYPTO) is exactly the transcript message.
	const frames = pkt.decodeFrames(pkt.encodeCryptoFrame(0, conn.transcript[0]))
	expect(frames[0]).toMatchObject({ type: 'crypto', data: conn.transcript[0] })

	const psk = ch.extensions.at(-1)!.data
	let p = 0
	// identities vector: u16 entry length, then one entry of u16 ticket length || ticket || u32 age.
	const identitiesLen = psk.readUInt16BE(p)
	p += 2
	expect(identitiesLen).toBe(2 + ticket.ticket.length + 4)
	expect(psk.readUInt16BE(p)).toBe(ticket.ticket.length)
	p += 2
	expect(psk.subarray(p, p + ticket.ticket.length)).toEqual(ticket.ticket)
	p += ticket.ticket.length
	const age = psk.readUInt32BE(p)
	p += 4
	expect(age).toBeGreaterThanOrEqual((sentAt - ticket.receivedAt + ticket.ageAdd) >>> 0)
	expect(age).toBeLessThanOrEqual((Date.now() - ticket.receivedAt + ticket.ageAdd) >>> 0)
	const binderVecLen = psk.readUInt16BE(p)
	p += 2
	const binderLen = psk[p++]
	expect(binderVecLen).toBe(1 + ticket.hashLen)
	expect(binderLen).toBe(ticket.hashLen)
	const binder = psk.subarray(p, p + binderLen)

	// Transcript-Hash(Truncate(ClientHello)) is everything except the binders vector.
	const truncated = ch.msg.subarray(0, ch.msg.length - (2 + binderVecLen))
	const transcriptHash = crypto.createHash('sha256').update(truncated).digest()
	expect(binder).toEqual(pskBinder(ticket, transcriptHash))
})

it('does not offer a PSK on a fresh handshake or with a TCP-only ticket', () => {
	const fresh = freshConn()
	expect(fresh.pskTicket).toBeNull()
	expect(parseClientHello(fresh.transcript[0]).extensions.some((e) => e.type === 0x0029)).toBe(false)

	storeSessionTicket(HOST, PORT, makeTicket({ alpn: 'h2', verified: true }))
	const h3 = freshConn()
	expect(h3.pskTicket).toBeNull()
	expect(parseClientHello(h3.transcript[0]).extensions.some((e) => e.type === 0x0029)).toBe(false)
	// The h2 ticket is still there for a TCP handshake.
	expect(getSessionTicket(HOST, PORT, ['h2'], true)?.alpn).toBe('h2')
})

function serverHello(pskSelected: boolean, cipherSuite = CIPHERS.TLS_AES_128_GCM_SHA256) {
	const { publicKey } = crypto.generateKeyPairSync('x25519')
	const serverPubRaw = publicKey.export({ type: 'spki', format: 'der' }).slice(-32)
	// ServerHello key_share is a single KeyShareEntry (no list-length prefix).
	const keyShare = Buffer.concat([Buffer.from([0x00, 0x1d, 0x00, 0x20]), serverPubRaw])
	const keyShareExt = Buffer.concat([Buffer.from([0x00, 0x33]), u16(keyShare.length), keyShare])
	const pskExt = Buffer.from([0x00, 0x29, 0x00, 0x02, 0x00, 0x00])
	const exts = pskSelected ? Buffer.concat([keyShareExt, pskExt]) : keyShareExt
	const body = Buffer.concat([
		Buffer.from([0x03, 0x03]),
		crypto.randomBytes(32),
		Buffer.from([0x00]),
		u16(cipherSuite),
		Buffer.from([0x00]),
		u16(exts.length),
		exts
	])
	const full = Buffer.concat([Buffer.from([0x02]), u24(body.length), body])
	return { body, full, serverPubRaw }
}

function expectedTrafficSecret(
	conn: QuicConnection,
	serverPubRaw: Buffer,
	psk: Buffer | null
): { cHsTraffic: Buffer; sHsTraffic: Buffer } {
	const spki = Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), serverPubRaw])
	const shared = crypto.diffieHellman({
		publicKey: crypto.createPublicKey({ type: 'spki', format: 'der', key: spki }),
		privateKey: conn.clientPrivateKey!
	})
	const emptyHash = crypto.createHash('sha256').update(Buffer.alloc(0)).digest()
	const earlySecret = HKDF.Extract('sha256', Buffer.alloc(32), psk ?? Buffer.alloc(32))
	const derived = HKDF.ExpandLabel(earlySecret, 'derived', emptyHash, 32, 'sha256', 32)
	const hs = HKDF.Extract('sha256', derived, shared)
	const thSH = HKDF.sha256(conn.transcript[0], conn.transcript[1])
	return {
		cHsTraffic: HKDF.ExpandLabel(hs, 'c hs traffic', thSH, 32, 'sha256', 32),
		sHsTraffic: HKDF.ExpandLabel(hs, 's hs traffic', thSH, 32, 'sha256', 32)
	}
}

it('uses the PSK in the key schedule only when ServerHello selects it', () => {
	const ticket = makeTicket()
	storeSessionTicket(HOST, PORT, ticket)
	const conn = freshConn()
	const { body, full, serverPubRaw } = serverHello(true)
	conn.transcript.push(full)
	conn._processServerHello(body)

	expect(conn.pskAccepted).toBe(true)
	const expected = expectedTrafficSecret(conn, serverPubRaw, ticket.psk)
	expect(conn.cHsTraffic).toEqual(expected.cHsTraffic)
	expect(conn.sHsTraffic).toEqual(expected.sHsTraffic)
	const fullResult = expectedTrafficSecret(conn, serverPubRaw, null)
	expect(conn.cHsTraffic).not.toEqual(fullResult.cHsTraffic)
})

it('falls back to a full handshake when the server ignores the offered PSK', () => {
	storeSessionTicket(HOST, PORT, makeTicket())
	const conn = freshConn()
	const { body, full, serverPubRaw } = serverHello(false)
	conn.transcript.push(full)
	conn._processServerHello(body)

	expect(conn.pskAccepted).toBe(false)
	expect(conn.cHsTraffic).toEqual(expectedTrafficSecret(conn, serverPubRaw, null).cHsTraffic)
})

it('rejects a ServerHello that selects a PSK bound to a different hash', () => {
	storeSessionTicket(HOST, PORT, makeTicket({ hash: 'sha384', hashLen: 48 }))
	const conn = freshConn()
	const errors: Error[] = []
	conn.on('error', (e: Error) => errors.push(e))
	const { body, full } = serverHello(true)
	conn.transcript.push(full)
	conn._processServerHello(body)
	expect(errors).toHaveLength(1)
	expect(errors[0].message).toContain('does not match')
})

it('stores NewSessionTicket PSKs and clearSessionTickets() forgets them', () => {
	const conn = new QuicConnection(HOST, PORT)
	conn.cipher = SHA256
	conn.cipherSuite = CIPHERS.TLS_AES_128_GCM_SHA256
	conn.alpn = 'h3'
	conn.resumptionMasterSecret = Buffer.alloc(32, 7)

	const nonce = Buffer.from('nonce')
	const ticketBytes = Buffer.from('ticket-01')
	const body = Buffer.concat([
		Buffer.from([0x00, 0x00, 0x0e, 0x10]), // lifetime = 3600
		Buffer.from([0x00, 0x00, 0x04, 0xd2]), // ageAdd = 1234
		Buffer.from([nonce.length]),
		nonce,
		u16(ticketBytes.length),
		ticketBytes
	])
	conn._handleNewSessionTicket(body)

	const stored = getSessionTicket(HOST, PORT, ['h3'], false)
	expect(stored).not.toBeNull()
	expect(stored!.ticket).toEqual(ticketBytes)
	expect(stored!.alpn).toBe('h3')
	expect(stored!.verified).toBe(false)
	expect(stored!.ageAdd).toBe(1234)
	expect(stored!.psk).toEqual(HKDF.ExpandLabel(conn.resumptionMasterSecret, 'resumption', nonce, 32, 'sha256', 32))
	// ALPN scoping: the h3 ticket can never seed a verifying TCP handshake.
	expect(getSessionTicket(HOST, PORT, ['h2'], true)).toBeNull()

	clearSessionTickets()
	expect(getSessionTicket(HOST, PORT, ['h3'], false)).toBeNull()
})

it('clearSessionTickets() forgets h2 and h3 tickets for the same origin', () => {
	storeSessionTicket(HOST, PORT, makeTicket({ alpn: 'h3', verified: false }))
	storeSessionTicket(HOST, PORT, makeTicket({ alpn: 'h2', verified: true }))
	expect(getSessionTicket(HOST, PORT, ['h3'], false)?.alpn).toBe('h3')
	expect(getSessionTicket(HOST, PORT, ['h2'], true)?.alpn).toBe('h2')

	clearSessionTickets()
	expect(getSessionTicket(HOST, PORT, ['h3'], false)).toBeNull()
	expect(getSessionTicket(HOST, PORT, ['h2'], true)).toBeNull()
})

it('ignores zero-lifetime and malformed NewSessionTicket messages', () => {
	const conn = new QuicConnection(HOST, PORT)
	conn.cipher = SHA256
	conn.resumptionMasterSecret = Buffer.alloc(32, 7)
	const zero = Buffer.concat([
		Buffer.from([0, 0, 0, 0]),
		Buffer.from([0, 0, 0, 0]),
		Buffer.from([0]),
		u16(4),
		Buffer.from('abcd')
	])
	conn._handleNewSessionTicket(zero)
	conn._handleNewSessionTicket(Buffer.from([0x01]))
	expect(getSessionTicket(HOST, PORT, ['h3'], false)).toBeNull()
})
