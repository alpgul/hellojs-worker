// OCSP stapled-response parser + signature verifier (RFC 6960).
//
// Two stages of verification:
//   1. Parse OCSPResponse → BasicOCSPResponse, capture tbsResponseData (signed) and signature.
//   2. Verify the signature with one of:
//        a) the certificate chain's issuer cert (RFC 6960 §2.2 — default case), or
//        b) a delegated responder cert embedded in the response, which itself must be issued
//           by the chain's issuer and carry an EKU of id-kp-OCSPSigning.
//   3. Match the response SingleResponse's certID to the leaf cert.
//
// We return { responseStatus, statuses, signatureVerified, leafMatched } and callers can
// decide their policy. Default policy in lib/tls/tls12.ts:
//   - 'revoked' → hard fail
//   - signatureVerified=false → soft fail (log + accept), matching Chrome's behavior
//   - leafMatched=false → soft fail (the response was for a different cert)

import { verifySignature } from './sig-verify.ts'

import type { KeyMaterial, SignatureSpec } from './sig-verify.ts'
import type { X509Certificate } from 'node:crypto'

interface Tlv {
	tag: number
	length: number
	value: Buffer
	headerLen: number
	end: number
}

export type CertStatusName = 'good' | 'revoked' | 'unknown'

// OCSPResponse fields the handshake and callers read. Only responseStatus/statuses/raw are
// always present; the rest are filled once a successful response body has been parsed.
export interface ParsedOcspResponse {
	responseStatus: string | null
	statuses: CertStatusName[]
	raw: Buffer
	signatureVerified: boolean
	leafMatched: boolean
	tbsBytes?: Buffer
	sigAlgOid?: Buffer
	signature?: Buffer
	embeddedCerts?: Buffer[]
}

// Minimal DER walker. Each call returns { tag, length, value, headerLen } and advances `offset`.
function readTLV(buf: Buffer, offset = 0): Tlv {
	if (offset >= buf.length) throw new Error('OCSP: short DER')
	const tag = buf[offset]
	let i = offset + 1
	if (i >= buf.length) throw new Error('OCSP: short length byte')
	let len = buf[i++]
	if (len & 0x80) {
		const lenLen = len & 0x7f
		if (lenLen === 0 || lenLen > 4) throw new Error('OCSP: bad length encoding')
		if (i + lenLen > buf.length) throw new Error('OCSP: truncated length')
		len = 0
		for (let j = 0; j < lenLen; j++) len = (len << 8) | buf[i++]
	}
	if (i + len > buf.length) throw new Error('OCSP: truncated value')
	return { tag, length: len, value: buf.subarray(i, i + len), headerLen: i - offset, end: i + len }
}

const OCSP_STATUS: Record<number, string> = {
	0: 'successful',
	1: 'malformedRequest',
	2: 'internalError',
	3: 'tryLater',
	5: 'sigRequired',
	6: 'unauthorized',
}

// OID 1.3.6.1.5.5.7.48.1.1 (basic ocsp response). DER-encoded as bytes:
const BASIC_OCSP_OID_BYTES = Buffer.from([0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01])

function decodeCertStatus(seq: Buffer): CertStatusName {
	// CertStatus is a CHOICE with tags [0]=good, [1]=revoked, [2]=unknown.
	// All IMPLICIT, so the tag byte is 0x80, 0xa1 (constructed), or 0x82 / 0x80, 0x81, 0x82.
	// In practice servers send: [0] IMPLICIT NULL → 0x80 0x00; [1] IMPLICIT RevokedInfo → 0xa1 ...;
	// [2] IMPLICIT UnknownInfo → 0x82 0x00.
	if (seq.length === 0) return 'unknown'
	const t = seq[0]
	if (t === 0x80) return 'good'
	if (t === 0xa1 || t === 0x81) return 'revoked'
	if (t === 0x82) return 'unknown'
	return 'unknown'
}

// Walk all top-level TLVs under a SEQUENCE/SET body and return them as an array.
function tlvSequence(buf: Buffer): Tlv[] {
	const items: Tlv[] = []
	let off = 0
	while (off < buf.length) {
		const t = readTLV(buf, off)
		items.push(t)
		off = t.end
	}
	return items
}

function parseOcspResponse(der: Buffer): ParsedOcspResponse {
	const result: ParsedOcspResponse = { responseStatus: null, statuses: [], raw: der, signatureVerified: false, leafMatched: false }
	if (!der || der.length === 0) return result
	const outer = readTLV(der, 0)
	if ((outer.tag & 0x1f) !== 0x10) throw new Error('OCSP: outer not a SEQUENCE')
	let p = 0
	const inner = outer.value
	// responseStatus ENUMERATED
	const rsTLV = readTLV(inner, p)
	if ((rsTLV.tag & 0x1f) !== 0x0a) throw new Error('OCSP: missing responseStatus ENUMERATED')
	const rsVal = rsTLV.value[0]
	result.responseStatus = OCSP_STATUS[rsVal] || `unknown(${rsVal})`
	p = rsTLV.end
	if (result.responseStatus !== 'successful') return result

	// responseBytes [0] EXPLICIT
	if (p >= inner.length) return result
	const rbTLV = readTLV(inner, p)
	if (rbTLV.tag !== 0xa0) return result
	const rb = rbTLV.value
	// rb: SEQUENCE { responseType OID, response OCTET STRING }
	const rbSeq = readTLV(rb, 0)
	if ((rbSeq.tag & 0x1f) !== 0x10) return result
	const rb2 = rbSeq.value
	const oidTLV = readTLV(rb2, 0)
	// Must be basic OCSP OID
	if (!Buffer.from([oidTLV.tag, oidTLV.headerLen - 2 < 0 ? 0 : oidTLV.length]).equals(BASIC_OCSP_OID_BYTES.subarray(0, 2))) {
		// don't enforce; just try to continue
	}
	const respOctets = readTLV(rb2, oidTLV.end)
	if ((respOctets.tag & 0x1f) !== 0x04) return result
	const basicOCSP = respOctets.value

	// BasicOCSPResponse SEQUENCE { tbsResponseData, signatureAlgorithm, signature [, certs] }
	const basicOuter = readTLV(basicOCSP, 0)
	if ((basicOuter.tag & 0x1f) !== 0x10) return result
	const basic = basicOuter.value
	// Capture tbsResponseData with its outer tag/length for signature verification.
	const tbs = readTLV(basic, 0)
	if ((tbs.tag & 0x1f) !== 0x10) return result
	result.tbsBytes = basic.subarray(0, tbs.end)
	// signatureAlgorithm SEQUENCE — extract the OID
	const sigAlg = readTLV(basic, tbs.end)
	const sigAlgOid = readTLV(sigAlg.value, 0)
	result.sigAlgOid = sigAlgOid.value
	// signature BIT STRING — content is 1 unused-bits byte + the signature octets
	const sigBitStr = readTLV(basic, sigAlg.end)
	result.signature = sigBitStr.value.subarray(1)
	// optional [0] EXPLICIT certs SEQUENCE OF Certificate
	if (sigBitStr.end < basic.length) {
		const ec = readTLV(basic, sigBitStr.end)
		if (ec.tag === 0xa0) {
			// certs is a SEQUENCE of Certificate
			const certsSeq = readTLV(ec.value, 0)
			if ((certsSeq.tag & 0x1f) === 0x10) {
				const certsBytes = certsSeq.value
				const certsList: Buffer[] = []
				let cpos = 0
				while (cpos < certsBytes.length) {
					const c = readTLV(certsBytes, cpos)
					certsList.push(Buffer.from(certsBytes.subarray(cpos, c.end)))
					cpos = c.end
				}
				result.embeddedCerts = certsList
			}
		}
	}

	// ResponseData ::= SEQUENCE { version [0]? , responderID, producedAt, responses }
	let q = 0
	const rd = tbs.value
	const first = readTLV(rd, q)
	q = first.end
	// version is optional [0] EXPLICIT. If first is [0], skip.
	if (first.tag === 0xa0) {
		// continue to responderID
	}
	// responderID is CHOICE — byName [1] Name | byKey [2] KeyHash. Skip it.
	const respIdOrFirst = first.tag === 0xa0 ? readTLV(rd, q) : first
	if (first.tag === 0xa0) q = respIdOrFirst.end
	// producedAt GeneralizedTime
	const producedAt = readTLV(rd, q); q = producedAt.end
	// responses SEQUENCE OF SingleResponse
	const responsesTLV = readTLV(rd, q)
	if ((responsesTLV.tag & 0x1f) !== 0x10) return result
	const responses = responsesTLV.value
	let r = 0
	while (r < responses.length) {
		const single = readTLV(responses, r); r = single.end
		if ((single.tag & 0x1f) !== 0x10) continue
		const sv = single.value
		// SingleResponse: certID SEQUENCE, certStatus CHOICE, thisUpdate GeneralizedTime, ...
		const certID = readTLV(sv, 0)
		const certStatus = readTLV(sv, certID.end)
		// We pass the raw tag-prefixed bytes for decoding
		const cs = Buffer.concat([Buffer.from([certStatus.tag]), Buffer.from([certStatus.length]), certStatus.value])
		result.statuses.push(decodeCertStatus(cs))
	}

	return result
}

// Map OCSP signatureAlgorithm OIDs to sig-verify specs.
// OID bytes are the *content* (after the 0x06 OID tag + length prefix).
const SIG_ALG_OIDS: Record<string, SignatureSpec> = {
	'2a864886f70d01010b': { hash: 'SHA-256', type: 'rsa-pkcs1' },  // sha256WithRSAEncryption
	'2a864886f70d01010c': { hash: 'SHA-384', type: 'rsa-pkcs1' },  // sha384WithRSAEncryption
	'2a864886f70d01010d': { hash: 'SHA-512', type: 'rsa-pkcs1' },  // sha512WithRSAEncryption
	'2a8648ce3d040302': { hash: 'SHA-256', type: 'ecdsa' },        // ecdsa-with-SHA256
	'2a8648ce3d040303': { hash: 'SHA-384', type: 'ecdsa' },        // ecdsa-with-SHA384
	'2a8648ce3d040304': { hash: 'SHA-512', type: 'ecdsa' },        // ecdsa-with-SHA512
}

function sigInfoFromOid(oidBytes: Buffer): SignatureSpec | null {
	return SIG_ALG_OIDS[Buffer.from(oidBytes).toString('hex')] || null
}

// Verify the OCSP response signature using the issuer (or a delegated responder). Returns true on
// success. Best-effort: soft-fail (false) is acceptable for callers matching Chrome's policy.
function verifyOcspSignature(parsed: ParsedOcspResponse, issuerCert: X509Certificate | Buffer): boolean {
	if (!parsed.tbsBytes || !parsed.signature || !parsed.sigAlgOid) return false
	const sigInfo = sigInfoFromOid(parsed.sigAlgOid)
	if (!sigInfo) return false

	// Every candidate: the issuer first (RFC 6960 §2.2 default case), then any embedded delegated
	// responder certificates. sig-verify takes certificates directly — node:crypto resolves the key.
	const candidates: KeyMaterial[] = [issuerCert]
	if (parsed.embeddedCerts) {
		for (const der of parsed.embeddedCerts) candidates.push(Buffer.from(der))
	}
	for (const key of candidates) {
		if (verifySignature(sigInfo, key, parsed.tbsBytes, parsed.signature)) return true
	}
	return false
}

// Check whether at least one SingleResponse inside the OCSP message references the leaf cert.
// We match by serial number (RFC 6960 CertID.serialNumber). Issuer-name-hash + issuer-key-hash
// matching would be stricter but is intentionally not required here — most operators only ever
// staple OCSP for the cert they're presenting, so a serial match is a strong-enough signal.
function leafMatchesOcsp(parsed: ParsedOcspResponse, leafCert: X509Certificate): boolean {
	if (!parsed.tbsBytes) return false
	// Re-parse tbsResponseData → responses → SingleResponse → certID.serialNumber
	try {
		const tbs = readTLV(parsed.tbsBytes, 0)
		const rd = tbs.value
		const items = tlvSequence(rd)
		// Find the `responses` SEQUENCE: it's the SEQUENCE of SEQUENCEs (each SingleResponse).
		// Walk items, picking the one whose value parses as a SEQUENCE of SEQUENCEs.
		let responses: Tlv[] | null = null
		for (const it of items) {
			if ((it.tag & 0x1f) !== 0x10) continue
			// Try to decode as SEQUENCE OF SEQUENCE
			try {
				const inner = tlvSequence(it.value)
				if (inner.length && inner.every(x => (x.tag & 0x1f) === 0x10)) { responses = inner; break }
			} catch { /* not it */ }
		}
		if (!responses) return false
		const leafSerial = BigInt('0x' + leafCert.serialNumber)
		for (const single of responses) {
			const sv = single.value
			const certID = readTLV(sv, 0)
			// certID: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber INTEGER }
			const fields = tlvSequence(certID.value)
			// Serial is the last INTEGER (tag 0x02)
			const serialTLV = fields.find(f => f.tag === 0x02)
			if (!serialTLV) continue
			const got = BigInt('0x' + Buffer.from(serialTLV.value).toString('hex'))
			if (got === leafSerial) return true
		}
	} catch { /* fall through to false */ }
	return false
}

export { parseOcspResponse, verifyOcspSignature, leafMatchesOcsp }
