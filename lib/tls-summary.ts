// Extract a compact summary of the TLS state on a connection. Called at
// request:end time so observability hooks can carry protocol, cipher, cert,
// server IP, and the connection identifier.
//
// Everything is best-effort — a field missing on the conn produces null in the
// summary, never a throw. Any consumer that wants full fidelity should ask the
// underlying TLS instance directly.

import * as crypto from 'node:crypto'

import type { TLS } from './tls/tls.ts'

// The connection object as this module sees it: only the TLS-facing fields are read.
interface ConnLike {
	tls?: TLS | null
	alpn?: string | null
	key?: string | null
	usedSession?: boolean
	usedEarlyData?: boolean
}

interface CertSummary {
	subject: string
	issuer: string
	validFrom: string
	validTo: string
	sanList: string[]
	fingerprint256: string
}

interface ConnSummary {
	alpn: string | null
	protocol: string | null
	cipher: string | null
	cipherCode: number | null
	keyExchange: string | null
	serverIPAddress: string | null
	serverPort: number | null
	connectionId: string | null
	ja3: string | null
	ja3_str: string | null
	ja4: string | null
	usedSession: boolean
	usedEarlyData: boolean
	cert: CertSummary | null
}

// TLS 1.3 cipher-suite code → RFC name. Extracted from lib/utils/config.ts CIPHERS.
const CIPHER_NAMES: Record<number, string> = {
	0x1301: 'TLS_AES_128_GCM_SHA256',
	0x1302: 'TLS_AES_256_GCM_SHA384',
	0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
	0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
	0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
	0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
	0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
	0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
	0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
}

// IANA named-group codepoints for the key_share echo.
const GROUP_NAMES: Record<number, string> = {
	0x0017: 'secp256r1',
	0x0018: 'secp384r1',
	0x0019: 'secp521r1',
	0x001d: 'X25519',
	0x001e: 'X448',
	0x11ec: 'X25519MLKEM768'
}

// TLS legacy-version → text name for the response.
const PROTOCOL_NAMES: Record<number, string> = {
	0x0304: 'TLS 1.3',
	0x0303: 'TLS 1.2',
	0x0302: 'TLS 1.1',
	0x0301: 'TLS 1.0'
}

function summarizeConn(conn: ConnLike | null | undefined): ConnSummary | null {
	if (!conn) return null
	const tls = conn.tls || null
	const socket = tls?.socket || null
	const tls12 = tls?.tls12 || null

	const cipherCode = tls?.server?.cipherSuite ?? null
	const versionCode = tls?.server?.selVersion ?? null
	const groupCode = tls?.server?.serverKShare?.group ?? null

	// TLS 1.2 carries its state on the handshake object, not on tls.server.
	const protocolName = versionCode != null
		? PROTOCOL_NAMES[versionCode] || `0x${versionCode.toString(16)}`
		: tls12 ? 'TLS 1.2' : null
	const cipherName = cipherCode != null
		? CIPHER_NAMES[cipherCode] || `0x${cipherCode.toString(16)}`
		: tls12?.cipher?.name || null
	const groupName = groupCode != null
		? GROUP_NAMES[groupCode] || `0x${groupCode.toString(16)}`
		: tls12?.ecdheCurve?.node || null

	// Leaf cert (best-effort — we only try to parse if we have chain bytes).
	let cert: CertSummary | null = null
	const leaf = tls?.serverCertChain?.[0]
	if (leaf) {
		try {
			const x = leaf instanceof crypto.X509Certificate ? leaf : new crypto.X509Certificate(leaf)
			const sanList = String(x.subjectAltName || '')
				.split(',')
				.map((s) => {
					const t = s.trim()
					if (t.startsWith('DNS:')) return t.slice(4)
					if (t.startsWith('IP Address:')) return t.slice(11).trim()
					return t
				})
				.filter(Boolean)
			cert = {
				subject: x.subject,
				issuer: x.issuer,
				validFrom: x.validFrom, // e.g. "Aug  1 00:00:00 2026 GMT"
				validTo: x.validTo,
				sanList,
				fingerprint256: x.fingerprint256
			}
		} catch { /* leave cert null */ }
	}

	return {
		alpn: conn.alpn || null,
		protocol: protocolName,
		cipher: cipherName,
		cipherCode: cipherCode ?? tls12?.cipherSuite ?? null,
		keyExchange: groupName,
		serverIPAddress: socket?.remoteAddress || null,
		serverPort: socket?.remotePort || null,
		connectionId: conn.key || null,
		ja3: tls?.actualFingerprint?.ja3 || null,
		ja3_str: tls?.actualFingerprint?.ja3_str || null,
		ja4: tls?.actualFingerprint?.ja4 || null,
		usedSession: !!conn.usedSession,
		usedEarlyData: !!conn.usedEarlyData,
		cert
	}
}

export { summarizeConn }
export type { ConnSummary, CertSummary }
