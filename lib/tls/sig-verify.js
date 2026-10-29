// X.509 and TLS signature verification, synchronous, on node:crypto's streaming verifier.
//
// Why streaming and not the one-shot crypto.verify(): workerd's one-shot path accepts the RSA padding
// options but never applies them. Measured on workerd 1.20261023.1 through all four specifier forms
// (import/require x node:crypto/crypto — they are the same module there): a genuine RSA-PSS signature
// came back false, and a PKCS#1 signature verified with the PSS options came back TRUE. The streaming
// verifier answers correctly in both directions on workerd and on Node, so every detached signature
// (CertificateVerify, TLS 1.2 ServerKeyExchange, OCSP, SCT) goes through it.
//
// EdDSA is the one exception: createVerify() demands a digest name and EdDSA has none, so
// createVerify(null) throws on both runtimes. Those use one-shot crypto.verify(null, …), which is safe
// here precisely because EdDSA carries no padding parameters for the one-shot path to drop.
//
// Two runtime rules shape the API:
//   - verify() options accept key MATERIAL (PEM text), never a KeyObject — workerd throws otherwise.
//   - X509Certificate.verify(pkey) takes a KeyObject and selects the padding from the certificate's own
//     signatureAlgorithm, so chain links need no scheme bookkeeping from us and no DER parsing at all.
//
// Because the key type is what binds a scheme to a key (measured on both workerd and Node: an EC key with
// RSA padding options is not rejected, the options are ignored and the signature verifies as ECDSA), it is
// resolved for EVERY input shape — including a bare SPKI that carries no certificate around.

import * as crypto from 'node:crypto'

const DIGEST_LEN = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 }

// Scheme -> the asymmetricKeyType a key must have for it. Bound explicitly: honoring an rsa_pss_* code
// point against an EC key is algorithm confusion, not a signature that happened not to match.
const KEY_TYPES = {
	'rsa-pkcs1': ['rsa'],
	'rsa-pss': ['rsa'],
	ecdsa: ['ec'],
	eddsa: ['ed25519', 'ed448'],
}

// 'SHA-256' (OID tables) and 'sha256' (TLS naming) both mean createVerify's 'sha256'.
function normHash(hash) {
	return hash ? String(hash).toLowerCase().replace(/^sha-?/, 'sha') : null
}

// SPKI DER -> PEM text. Pure byte formatting, so we never depend on parsing DER back into a key.
// The body must not keep the wrapping regex's trailing newline: a blank line before the trailer makes
// OpenSSL's decoder answer "unsupported" instead of loading the key.
function derToSpkiPem(der) {
	const b64 = Buffer.from(der).toString('base64').replaceAll(/(.{1,64})/g, '$1\n').trimEnd()
	return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`
}

// The key's asymmetric algorithm family, read WITHOUT putting a KeyObject into verify() options (workerd
// rejects a KeyObject there; the PEM text is what gets handed over). Needed because a bare SPKI carries no
// type we could otherwise see, and both runtimes happily verify an ECDSA signature under an RSA spec —
// createVerify ignores RSA padding on an EC key instead of rejecting the combination.
function keyTypeFromPem(pem) {
	try { return crypto.createPublicKey({ key: pem, format: 'pem' }).asymmetricKeyType || null } catch { return null }
}

// Resolve any key-shaped input to the PEM text workerd's verify() wants, plus its key type. A buffer is
// tried as a certificate first (node:crypto parses it) and only treated as a bare SPKI otherwise, so
// callers can hand us whatever they have; either way the type comes back, so the scheme binding below
// cannot be skipped by passing a different key shape.
function resolveKey(key) {
	if (typeof key === 'string') return { pem: key, keyType: keyTypeFromPem(key) }
	let cert
	if (key instanceof crypto.X509Certificate) cert = key
	else if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
		try { cert = new crypto.X509Certificate(Buffer.from(key)) } catch { cert = null }
		if (cert === null) { const pem = derToSpkiPem(key); return { pem, keyType: keyTypeFromPem(pem) } }
	} else if (key && typeof key.export === 'function') {
		return { pem: String(key.export({ type: 'spki', format: 'pem' })), keyType: key.asymmetricKeyType || null }
	} else {
		throw new Error('unsupported public key material')
	}
	const pub = cert.publicKey
	return { pem: String(pub.export({ type: 'spki', format: 'pem' })), keyType: pub.asymmetricKeyType || null }
}

// Verify `signature` over `content`. spec = { type, hash, saltLength? }.
// Resolves to a boolean synchronously and never throws: an unknown scheme, a key-type mismatch, an
// unparseable key or a bad signature all answer false, which is what every handshake call site expects.
function verifySignature(spec, key, content, signature) {
	const allowed = spec && KEY_TYPES[spec.type]
	if (!allowed) return false
	let pem, actual
	try { ({ pem, keyType: actual } = resolveKey(key)) } catch { return false }
	if (actual && !allowed.includes(actual)) return false
	try {
		if (spec.type === 'eddsa') return crypto.verify(null, content, pem, signature) === true
		const hash = normHash(spec.hash)
		if (!DIGEST_LEN[hash]) return false
		const options = { key: pem }
		if (spec.type === 'rsa-pss') {
			options.padding = crypto.constants.RSA_PKCS1_PSS_PADDING
			// TLS 1.3 §4.2.3 fixes the salt at the digest length; callers may override for other padding rules.
			options.saltLength = spec.saltLength == null ? DIGEST_LEN[hash] : spec.saltLength
		}
		return crypto.createVerify(hash).update(content).verify(options, signature) === true
	} catch {
		return false
	}
}

// RFC 5280 §4 chain link: does `parent`'s key have a signature over `child`? Padding and curve come
// from the child's own signatureAlgorithm, so BoringSSL/OpenSSL picks them — nothing to parse here.
// Accepts X509Certificate instances or DER. False on any parse or verify failure.
function verifyCertSignature(child, parent) {
	try {
		const c = child instanceof crypto.X509Certificate ? child : new crypto.X509Certificate(child)
		const p = parent instanceof crypto.X509Certificate ? parent : new crypto.X509Certificate(parent)
		return c.verify(p.publicKey) === true
	} catch {
		return false
	}
}

export { verifySignature, verifyCertSignature, resolveKey, derToSpkiPem, normHash, KEY_TYPES, DIGEST_LEN }
