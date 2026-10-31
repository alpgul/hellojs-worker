// TLS 1.3 resumption ticket store.
//
// A server sends NewSessionTicket messages after the handshake; each carries a nonce that,
// together with the connection's resumption_master_secret, derives a PSK for the next
// connection. Tickets are per (host, port) and ALPN-scoped, live only in this process, and
// expire at the server's ticket_lifetime (capped at the RFC 8446 maximum of 7 days).
// Failures are never stored — only tickets the server actually issued.

import * as crypto from 'node:crypto'

import * as HKDF from '../utils/hkdf.ts'

export interface SessionTicket {
	ticket: Buffer
	psk: Buffer
	cipherSuite: number
	hash: 'sha256' | 'sha384'
	hashLen: number
	// Seconds, as sent in NewSessionTicket (0 means discard immediately).
	lifetime: number
	ageAdd: number
	// Date.now() when the NewSessionTicket message arrived.
	receivedAt: number
	// ALPN negotiated on the connection that issued the ticket ('' when none).
	alpn: string
	// True when the PSK's lineage includes a fully validated certificate chain. A resumed
	// handshake skips chain validation, so it may only be offered to callers that want
	// verification when an earlier connection actually verified the origin.
	verified: boolean
}

const MAX_ENTRIES = 64
const MAX_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000

const tickets = new Map<string, SessionTicket>()

function ticketKey(host: string, port: number): string {
	return `${host}:${port}`
}

function storeSessionTicket(host: string, port: number, ticket: SessionTicket): void {
	if (ticket.lifetime <= 0) return
	const key = ticketKey(host, port)
	tickets.delete(key)
	tickets.set(key, ticket)
	while (tickets.size > MAX_ENTRIES) {
		const oldest = tickets.keys().next().value
		if (oldest === undefined) break
		tickets.delete(oldest)
	}
}

// Returns a usable ticket for this target, or null. The ticket is not consumed: 1-RTT PSK
// reuse is allowed by RFC 8446 (single-use is only required for 0-RTT early data).
function getSessionTicket(
	host: string,
	port: number,
	offeredAlpn: readonly string[],
	needVerified = true
): SessionTicket | null {
	const key = ticketKey(host, port)
	const ticket = tickets.get(key)
	if (!ticket) return null
	const ttl = Math.min(ticket.lifetime * 1000, MAX_LIFETIME_MS)
	if (Date.now() - ticket.receivedAt >= ttl) {
		tickets.delete(key)
		return null
	}
	// A ticket is bound to the ALPN of the connection that issued it. Offer it only when the
	// new ClientHello still advertises that protocol.
	if (ticket.alpn && offeredAlpn.length > 0 && !offeredAlpn.includes(ticket.alpn)) return null
	if (needVerified && !ticket.verified) return null
	return ticket
}

function clearSessionTickets(): void {
	tickets.clear()
}

// PskBinderEntry (RFC 8446 §4.2.11.2) for a resumption PSK. The binder is HMAC over the
// transcript hash of the truncated ClientHello, keyed by Expand-Label(binder_key, "finished"),
// where binder_key = Derive-Secret(HKDF-Extract(0, PSK), "res binder", "").
function pskBinder(ticket: Pick<SessionTicket, 'psk' | 'hash' | 'hashLen'>, transcriptHash: Buffer): Buffer {
	const zeros = Buffer.alloc(ticket.hashLen, 0x00)
	const earlySecret = HKDF.Extract(ticket.hash, zeros, ticket.psk)
	const emptyHash = crypto.createHash(ticket.hash).update(Buffer.alloc(0)).digest()
	const binderKey = HKDF.ExpandLabel(
		earlySecret,
		'res binder',
		emptyHash,
		ticket.hashLen,
		ticket.hash,
		ticket.hashLen
	)
	const finishedKey = HKDF.ExpandLabel(
		binderKey,
		'finished',
		Buffer.alloc(0),
		ticket.hashLen,
		ticket.hash,
		ticket.hashLen
	)
	return crypto.createHmac(ticket.hash, finishedKey).update(transcriptHash).digest()
}

export { storeSessionTicket, getSessionTicket, clearSessionTickets, pskBinder }
