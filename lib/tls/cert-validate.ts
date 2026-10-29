// Server certificate chain validation (RFC 5280, RFC 6125).
//
// Walks the cert chain leaf → intermediates → trusted root. For each link:
//   - issuer of cert[i] matches subject of cert[i+1]
//   - cert[i]'s signature verifies against cert[i+1]'s pubkey
//   - Date.now() is within notBefore/notAfter
// The leaf's hostname is validated against Subject Alternative Name (or fall back to CN).
// The chain must terminate in a cert present in Node's bundled root CAs.
//
// Signature verification runs on node:crypto's streaming verifier (see ./sig-verify): workerd's one-shot
// crypto.verify() accepts RSA-PSS padding options but ignores them, so PSS signatures come back false and
// PKCS#1 signatures verified with PSS options come back true. The streaming verifier is correct on both
// workerd and Node, which keeps every step below synchronous — the handshake parsers never have to pause
// for a promise.
//
// X509Certificate does the rest: it verifies chain links natively (padding taken from the certificate's
// own signatureAlgorithm) and exports its public key as SPKI PEM for the detached signatures, so no DER
// walking is needed here at all. It also answers metadata workerd gets right: subject, issuer, validity
// window, subjectAltName, basicConstraints (ca) and fingerprint256.

import * as crypto from 'node:crypto'
import * as tls from 'node:tls'


import { extractScts } from './sct.ts'
import { verifySignature as nodeVerify, verifyCertSignature } from './sig-verify.ts'

import type { CertificateTimestamp } from './sct.ts'
import type { KeyMaterial, SignatureSpec } from './sig-verify.ts'
import type { X509Certificate } from 'node:crypto'

// A chain either terminates in a trusted root or explains why it did not.
export type ChainResult =
	| { ok: false; reason: string }
	| { ok: true; root: string; scts: CertificateTimestamp[] }

let _trustedRoots: X509Certificate[] | null = null   // [{cert: X509Certificate, subject, issuer, fingerprint256}]
function trustedRoots() {
	if (_trustedRoots) return _trustedRoots
	_trustedRoots = []
	for (const pem of tls.rootCertificates) {
		try {
			const c = new crypto.X509Certificate(pem)
			_trustedRoots.push(c)
		} catch { /* skip unparseable */ }
	}
	return _trustedRoots
}

// Replace the bundled store. workerd's node:tls ships no roots, so a Worker
// must install its own Mozilla/NSS PEM bundle before the first handshake.
function setTrustedRoots(pems?: string[]): void {
	_trustedRoots = []
	for (const pem of pems || []) {
		try {
			_trustedRoots.push(new crypto.X509Certificate(pem))
		} catch { /* skip unparseable */ }
	}
}

// Match a leaf cert against a hostname per RFC 6125.
function hostnameMatches(cert: X509Certificate, hostname: string): boolean {
	const host = String(hostname).toLowerCase()
	// Subject Alternative Name (DNS:) — modern path, what browsers use.
	const san = cert.subjectAltName || ''
	for (const part of san.split(',')) {
		const trimmed = part.trim()
		if (trimmed.startsWith('DNS:')) {
			const pattern = trimmed.slice(4).toLowerCase()
			if (matchHostname(pattern, host)) return true
		}
		if (trimmed.startsWith('IP Address:') && trimmed.slice(11).trim() === host) return true
	}
	// If SAN didn't match (or didn't exist), the cert is invalid for this hostname.
	// CN-only matching is deprecated by RFC 6125 §6.4.4 and rejected by Chrome since 2017.
	return false
}

function matchHostname(pattern: string, host: string): boolean {
	if (pattern === host) return true
	// Wildcard: *.example.com matches foo.example.com but not example.com or foo.bar.example.com
	if (pattern.startsWith('*.')) {
		const suffix = pattern.slice(1)   // includes the leading "."
		const dot = host.indexOf('.')
		if (dot < 0) return false
		const hostSuffix = host.slice(dot)
		return hostSuffix === suffix
	}
	return false
}

// Validate the chain against the trust store. Returns { ok, reason }.
// Chain order: leaf, intermediate1, intermediate2, ... (server-supplied order).
function validateChain(
	chainDerOrCerts: Array<Uint8Array | X509Certificate>,
	hostname: string,
	{ now = Date.now() }: { now?: number } = {},
): ChainResult {
	const chain = chainDerOrCerts.map(x => x instanceof crypto.X509Certificate ? x : new crypto.X509Certificate(x))
	if (chain.length === 0) return { ok: false, reason: 'empty chain' }
	const leaf = chain[0]

	// Validity window
	for (let i = 0; i < chain.length; i++) {
		const c = chain[i]
		const nb = Date.parse(c.validFrom)
		const na = Date.parse(c.validTo)
		if (now < nb) return { ok: false, reason: `cert[${i}] not yet valid (notBefore=${c.validFrom})` }
		if (now > na) return { ok: false, reason: `cert[${i}] expired (notAfter=${c.validTo})` }
	}

	// Hostname match on leaf
	if (!hostnameMatches(leaf, hostname)) {
		return { ok: false, reason: `leaf cert does not match hostname "${hostname}" (subjectAltName=${leaf.subjectAltName || '(none)'})` }
	}

	// Walk the chain bottom-up. At each cert, first try to terminate the path: does the
	// trust store contain a root whose subject matches this cert's issuer AND whose pubkey
	// verifies this cert's signature? If yes, we've found a valid path — accept the chain
	// regardless of what's above. This handles servers that send a retired self-signed root
	// at the top (e.g. Amazon's VeriSign G5) but where an intermediate is signed by a root
	// still in our trust store.
	const roots = trustedRoots()
	let trustedRoot = null
	for (let i = 0; i < chain.length; i++) {
		const cert = chain[i]
		// Try to terminate the path here: find a root that issued this cert. Subject equality is
		// the cheap filter; only the survivors get a signature check.
		const candidates = roots.filter(r => r.subject === cert.issuer && r.ca === true)
		for (const root of candidates) {
			if (verifyCertSignature(cert, root)) { trustedRoot = root; break }
		}
		if (trustedRoot) break
		// Also check: if this cert IS a trusted root itself (self-signed + in trust store).
		if (cert.issuer === cert.subject) {
			const match = roots.find(r => r.fingerprint256 === cert.fingerprint256)
			if (match) { trustedRoot = match; break }
		}
		// Otherwise verify the next cert in chain signed this one (walking up).
		const parent = chain[i + 1]
		if (!parent) break
		if (cert.issuer !== parent.subject) {
			return { ok: false, reason: `chain break: cert[${i}].issuer != cert[${i + 1}].subject` }
		}
		// The signing cert MUST be a CA (basicConstraints CA:TRUE, RFC 5280 §4.2.1.9). Without this
		// check, anyone holding an ordinary leaf cert could use its key to sign forged certs for
		// arbitrary hosts and chain them up to a real root — a complete authentication bypass.
		if (parent.ca !== true) {
			return { ok: false, reason: `cert[${i + 1}] is not a CA (basicConstraints CA:TRUE absent); cannot have signed cert[${i}]` }
		}
		if (!verifyCertSignature(cert, parent)) {
			return { ok: false, reason: `cert[${i}] signature does not verify against cert[${i + 1}].publicKey` }
		}
	}
	if (!trustedRoot) {
		const top = chain[chain.length - 1]
		return { ok: false, reason: `chain does not terminate in a trusted root (top issuer="${top.issuer}")` }
	}

	// Best-effort: extract embedded SCT(s) for downstream policy inspection. We don't enforce
	// here — Chrome requires CT for certs issued post-2018 but verifying SCT signatures requires
	// shipping the CT log key list, which we expose as an opt-in via tls.options.ctLogKeys.
	let scts: CertificateTimestamp[] = []
	try {
		scts = extractScts(Buffer.from(leaf.raw))
	} catch { /* parse failure is non-fatal */ }

	return { ok: true, root: trustedRoot.subject, scts }
}

// --- TLS 1.3 server CertificateVerify (RFC 8446 §4.4.3) ----------------------------------------

// SignatureScheme code points (RFC 8446 §4.2.3) -> verification parameters.
const SIG_SCHEMES: Record<number, SignatureSpec> = {
	0x0401: { type: 'rsa-pkcs1', hash: 'sha256' },
	0x0501: { type: 'rsa-pkcs1', hash: 'sha384' },
	0x0601: { type: 'rsa-pkcs1', hash: 'sha512' },
	0x0804: { type: 'rsa-pss', hash: 'sha256' },   // rsa_pss_rsae_sha256
	0x0805: { type: 'rsa-pss', hash: 'sha384' },   // rsa_pss_rsae_sha384
	0x0806: { type: 'rsa-pss', hash: 'sha512' },   // rsa_pss_rsae_sha512
	0x0809: { type: 'rsa-pss', hash: 'sha256' },   // rsa_pss_pss_sha256
	0x080a: { type: 'rsa-pss', hash: 'sha384' },   // rsa_pss_pss_sha384
	0x080b: { type: 'rsa-pss', hash: 'sha512' },   // rsa_pss_pss_sha512
	0x0403: { type: 'ecdsa', hash: 'sha256' },     // ecdsa_secp256r1_sha256
	0x0503: { type: 'ecdsa', hash: 'sha384' },     // ecdsa_secp384r1_sha384
	0x0603: { type: 'ecdsa', hash: 'sha512' },     // ecdsa_secp521r1_sha512
	0x0807: { type: 'eddsa', hash: null },         // ed25519
	0x0808: { type: 'eddsa', hash: null },         // ed448
}

// 'sha256' (our profile/TLS naming) is already what node:crypto's createVerify wants; sig-verify
// normalizes the 'SHA-256' spelling the OID tables use, so nothing to map here.

// Verify a detached signature made with the key in `leaf` (an X509Certificate or its DER).
// Returns a boolean; an unknown scheme or a key-type mismatch is false, never an exception.
function verifySignature(scheme: number, leaf: KeyMaterial, content: Uint8Array, signature: Uint8Array): boolean {
	const s = SIG_SCHEMES[scheme]
	if (!s) return false
	// sig-verify binds the scheme to the key's own type, because workerd silently ignored RSA padding
	// options when given an EC key — without this an RSA scheme code could be honored against an EC
	// key, an algorithm-confusion gap. rsa_pss_pss_* (0x0809-0x080b) verify as RSA-PSS either way.
	return nodeVerify(s, leaf, content, signature)
}

// Verify a TLS 1.3 server CertificateVerify signature. `transcriptHash` is the handshake transcript
// hash up to AND INCLUDING the server Certificate (or CompressedCertificate) message. Returns true
// iff the signature is valid for the leaf's public key over the RFC 8446 §4.4.3 signed content
// (64 0x20 octets || context-string || 0x00 || transcriptHash).
export interface CertVerifyInput {
	scheme: number
	signature: Uint8Array
	leaf: KeyMaterial
	transcriptHash: Uint8Array
	context?: string
}

function verifyCertVerify({ scheme, signature, leaf, transcriptHash, context = 'TLS 1.3, server CertificateVerify' }: CertVerifyInput): boolean {
	const content = Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from(context, 'ascii'), Buffer.from([0x00]), transcriptHash])
	return verifySignature(scheme, leaf, content, signature)
}

// Parse a TLS 1.3 Certificate message body (RFC 8446 §4.4.2): 1-byte cert_request_context length +
// context + 3-byte CertificateList length + entries (3-byte cert length + DER + 2-byte ext length +
// extensions). Returns an array of DER Buffers; throws on malformed/truncated input.
function parseCertificateList(body: Buffer): Buffer[] {
	const certs: Buffer[] = []
	let p = 0
	if (body.length < 4) throw new Error('certificate message too short')
	const ctxLen = body[p++]; p += ctxLen
	if (p + 3 > body.length) throw new Error('truncated CertificateList length')
	const listLen = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2]; p += 3
	const end = p + listLen
	if (end > body.length) throw new Error('CertificateList length exceeds message')
	while (p < end) {
		if (p + 3 > end) throw new Error('truncated certificate entry length')
		const clen = (body[p] << 16) | (body[p + 1] << 8) | body[p + 2]; p += 3
		if (p + clen > end) throw new Error('certificate entry length exceeds list')
		certs.push(body.subarray(p, p + clen))
		p += clen
		if (p + 2 > end) throw new Error('truncated certificate extensions length')
		const eLen = (body[p] << 8) | body[p + 1]; p += 2 + eLen
	}
	if (certs.length === 0) throw new Error('empty CertificateList')
	return certs
}

export { validateChain, hostnameMatches, trustedRoots, setTrustedRoots, verifyCertVerify, verifySignature, parseCertificateList }
