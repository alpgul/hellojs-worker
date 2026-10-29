// TLS 1.2 fallback path (RFC 5246 + 8446 §D for negotiation, RFC 5288/7905 for AEAD).
// AEAD-only in this iteration — CBC + RSA-PMS suites land in a follow-on phase.

import * as crypto from 'node:crypto'

import { H2Session } from '../h2/session.js'
import logFactory from '../models/log.ts'

import { validateChain } from './cert-validate.ts'
import { parseOcspResponse, verifyOcspSignature, leafMatchesOcsp } from './ocsp.ts'
import { verifySignature } from './sig-verify.ts'
import { errMsg, TLSTransport, type TLS, type TLSError } from './tls.ts'
import * as prf from './tls12_prf.ts'
import * as records from './tls12_records.ts'
import { deriveX25519SharedSecret } from './x25519.ts'

import type { SignatureSpec } from './sig-verify.ts'
import type { CipherSuite12, RecordKeys } from './tls12_records.ts'

const log = logFactory('[tls12]')

// A negotiated suite: the record layer's shape plus the handshake's own fields.
interface Suite12 extends CipherSuite12 {
	kx: 'ECDHE' | 'RSA'
	sig: 'ECDSA' | 'RSA' | null
	prfHash: string
}

interface NamedCurve {
	node: string
	byteLen: number
}

// The signed ECDHE params plus the signature the server put on them.
interface SkeSignature {
	sigInfo: SignatureSpec
	sigAlgId: number
	signature: Buffer
	ecdheParamsBytes: Buffer
}

const CIPHERS: Record<number, Suite12> = {
	0xc02b: {
		name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
		kx: 'ECDHE',
		sig: 'ECDSA',
		aead: 'aes-128-gcm',
		mac: null,
		keyLen: 16,
		ivLen: 4,
		macLen: 0,
		prfHash: 'sha256'
	},
	0xc02c: {
		name: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
		kx: 'ECDHE',
		sig: 'ECDSA',
		aead: 'aes-256-gcm',
		mac: null,
		keyLen: 32,
		ivLen: 4,
		macLen: 0,
		prfHash: 'sha384'
	},
	0xcca9: {
		name: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
		kx: 'ECDHE',
		sig: 'ECDSA',
		aead: 'chacha20-poly1305',
		mac: null,
		keyLen: 32,
		ivLen: 12,
		macLen: 0,
		prfHash: 'sha256'
	},
	0xc02f: {
		name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
		kx: 'ECDHE',
		sig: 'RSA',
		aead: 'aes-128-gcm',
		mac: null,
		keyLen: 16,
		ivLen: 4,
		macLen: 0,
		prfHash: 'sha256'
	},
	0xc030: {
		name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
		kx: 'ECDHE',
		sig: 'RSA',
		aead: 'aes-256-gcm',
		mac: null,
		keyLen: 32,
		ivLen: 4,
		macLen: 0,
		prfHash: 'sha384'
	},
	0xcca8: {
		name: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
		kx: 'ECDHE',
		sig: 'RSA',
		aead: 'chacha20-poly1305',
		mac: null,
		keyLen: 32,
		ivLen: 12,
		macLen: 0,
		prfHash: 'sha256'
	},
	0xc013: {
		name: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
		kx: 'ECDHE',
		sig: 'RSA',
		aead: null,
		mac: 'sha1',
		keyLen: 16,
		ivLen: 0,
		macLen: 20,
		prfHash: 'sha256'
	},
	0xc014: {
		name: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
		kx: 'ECDHE',
		sig: 'RSA',
		aead: null,
		mac: 'sha1',
		keyLen: 32,
		ivLen: 0,
		macLen: 20,
		prfHash: 'sha256'
	},
	0x009c: {
		name: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
		kx: 'RSA',
		sig: null,
		aead: 'aes-128-gcm',
		mac: null,
		keyLen: 16,
		ivLen: 4,
		macLen: 0,
		prfHash: 'sha256'
	},
	0x009d: {
		name: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
		kx: 'RSA',
		sig: null,
		aead: 'aes-256-gcm',
		mac: null,
		keyLen: 32,
		ivLen: 4,
		macLen: 0,
		prfHash: 'sha384'
	},
	0x002f: {
		name: 'TLS_RSA_WITH_AES_128_CBC_SHA',
		kx: 'RSA',
		sig: null,
		aead: null,
		mac: 'sha1',
		keyLen: 16,
		ivLen: 0,
		macLen: 20,
		prfHash: 'sha256'
	},
	0x0035: {
		name: 'TLS_RSA_WITH_AES_256_CBC_SHA',
		kx: 'RSA',
		sig: null,
		aead: null,
		mac: 'sha1',
		keyLen: 32,
		ivLen: 0,
		macLen: 20,
		prfHash: 'sha256'
	}
}

const CONTENT = { CCS: 0x14, ALERT: 0x15, HANDSHAKE: 0x16, APPDATA: 0x17 }
const HANDSHAKE = {
	CERTIFICATE: 0x0b,
	SERVER_KEY_EXCHANGE: 0x0c,
	CERTIFICATE_REQUEST: 0x0d,
	SERVER_HELLO_DONE: 0x0e,
	CLIENT_KEY_EXCHANGE: 0x10,
	CERTIFICATE_STATUS: 0x16, // RFC 6066 §8 — OCSP stapled response
	FINISHED: 0x14
}

// TLS 1.2 SignatureAndHashAlgorithm → sig-verify specs. `type` selects the verifier and binds the
// key type; hash is the digest name. Verification must go through the streaming verifier: workerd's
// one-shot crypto.verify() ignores the RSA padding options and rejects a KeyObject in the options.
const SIG_ALG: Record<number, SignatureSpec> = {
	0x0401: { hash: 'sha256', type: 'rsa-pkcs1' },
	0x0501: { hash: 'sha384', type: 'rsa-pkcs1' },
	0x0601: { hash: 'sha512', type: 'rsa-pkcs1' },
	0x0403: { hash: 'sha256', type: 'ecdsa' },
	0x0503: { hash: 'sha384', type: 'ecdsa' },
	0x0603: { hash: 'sha512', type: 'ecdsa' },
	0x0804: { hash: 'sha256', type: 'rsa-pss' },
	0x0805: { hash: 'sha384', type: 'rsa-pss' },
	0x0806: { hash: 'sha512', type: 'rsa-pss' }
}

const NAMED_CURVE: Record<number, NamedCurve> = {
	0x0017: { node: 'prime256v1', byteLen: 32 }, // secp256r1
	0x0018: { node: 'secp384r1', byteLen: 48 },
	0x001d: { node: 'x25519', byteLen: 32 }
}

class TLS12Handshake {
	declare tls: TLS
	declare serverRandom: Buffer
	declare sessionId: Buffer
	declare cipherSuite: number
	declare cipher: Suite12
	/** Raw bytes of every handshake message sent or received, driving Finished + EMS. */
	declare transcript: Buffer[]
	declare clientSeq: number
	declare serverSeq: number

	declare serverCertDerChain: Buffer[] | null
	declare serverPubKey: crypto.KeyObject | null
	declare ecdheCurve: NamedCurve | null
	declare ecdheNamedCurveId: number
	declare serverEcdheRaw: Buffer | null
	declare clientEcdhePriv: crypto.KeyObject | null
	declare clientEcdheRaw: Buffer | null
	declare preMasterSecret: Buffer | null
	declare masterSecret: Buffer | null
	declare clientKeys: RecordKeys | null
	declare serverKeys: RecordKeys | null
	/** EMS is negotiated: we offered it in ClientHello; only use it if the server echoed the
	 *  extended_master_secret extension in ServerHello. Otherwise compute standard MS. */
	declare useEMS: boolean

	declare changeCipherSpecRecvd: boolean

	// Handshake messages can be fragmented across TLS records (large Certificate messages
	// with many SANs are a common trigger). We accumulate cleartext handshake bytes here
	// and only emit completed messages.
	declare hsBuf: Buffer
	/** Set while an async X25519 pre-master derivation is in flight; parsing pauses so the
	 *  client flight is built only after the shared secret exists. */
	declare _kxPending: boolean

	declare rsaEncryptedPms: Buffer | null
	declare _skeSignatureInfo: SkeSignature | null

	constructor(
		tls: TLS,
		{ random, sessionId, cipherSuite }: { random: Buffer; sessionId: Buffer; cipherSuite: number }
	) {
		this.tls = tls
		this.serverRandom = random
		this.sessionId = sessionId
		this.cipherSuite = cipherSuite
		const cipher = CIPHERS[cipherSuite]
		if (!cipher) throw new Error(`unsupported TLS 1.2 cipher 0x${cipherSuite.toString(16)}`)
		this.cipher = cipher

		// Transcript: starts as a copy of tls.transcript ([CH, SH]); we append every subsequent
		// handshake message we parse or send in raw bytes. Hash drives Finished MAC + EMS.
		this.transcript = tls.transcript.slice()

		this.clientSeq = 0
		this.serverSeq = 0

		this.serverCertDerChain = null // [Buffer, ...]
		this.serverPubKey = null // KeyObject
		this.ecdheCurve = null
		this.ecdheNamedCurveId = 0
		this.serverEcdheRaw = null
		this.clientEcdhePriv = null
		this.clientEcdheRaw = null
		this.preMasterSecret = null
		this.masterSecret = null
		this.clientKeys = null // {key, iv}
		this.serverKeys = null
		this.useEMS = !!tls.serverEMS

		this.changeCipherSpecRecvd = false

		this.hsBuf = Buffer.alloc(0)
		this._kxPending = false

		this.rsaEncryptedPms = null
		this._skeSignatureInfo = null

		log.notify(`negotiated ${this.cipher.name} (0x${cipherSuite.toString(16)})`)
	}

	// ---- inbound record dispatch ---------------------------------------------------

	onRecord(type: number, payload: Buffer, recordBuf: Buffer): void {
		if (type === CONTENT.CCS) {
			if (payload.length !== 1 || payload[0] !== 0x01) {
				this._fatal('bad ChangeCipherSpec')
				return
			}
			this.changeCipherSpecRecvd = true
			this.serverSeq = 0
			return
		}
		if (type === CONTENT.HANDSHAKE) {
			if (this.changeCipherSpecRecvd) {
				// Encrypted Finished message
				let plaintext: Buffer
				try {
					plaintext = records.decryptRecord(
						this.cipher,
						this.serverKeys!,
						this.serverSeq,
						type,
						recordBuf.subarray(5)
					)
				} catch (e) {
					return this._fatal(`decrypt failed: ${errMsg(e)}`)
				}
				this.serverSeq++
				return this._consumeCleartextHandshake(plaintext)
			}
			return this._consumeCleartextHandshake(payload)
		}
		if (type === CONTENT.APPDATA) {
			if (!this.changeCipherSpecRecvd) return this._fatal('app data before ChangeCipherSpec')
			let pt: Buffer
			try {
				pt = records.decryptRecord(this.cipher, this.serverKeys!, this.serverSeq, type, recordBuf.subarray(5))
			} catch (e) {
				return this._fatal(`appdata decrypt failed: ${errMsg(e)}`)
			}
			this.serverSeq++
			if (this.tls.h2Transport) this.tls.h2Transport.push(pt)
			else {
				this.tls.appBuf = Buffer.concat([this.tls.appBuf, pt])
			}
			return
		}
		if (type === CONTENT.ALERT) {
			this.tls._handleAlert(payload[0], payload[1], this.changeCipherSpecRecvd ? 'encrypted' : 'cleartext')
		}
	}

	_consumeCleartextHandshake(buf: Buffer): void {
		// Append to the rolling buffer so messages fragmented across TLS records reassemble.
		this.hsBuf = this.hsBuf.length ? Buffer.concat([this.hsBuf, buf]) : buf
		this._drainHandshake()
	}

	_drainHandshake(): void {
		let p = this.hsBuf
		// Stop between messages while an async X25519 derivation is pending; the remainder is
		// written back below and consumed by the resume call, so nothing is parsed twice.
		while (p.length >= 4 && !this._kxPending) {
			const t = p[0]
			const len = (p[1] << 16) | (p[2] << 8) | p[3]
			if (p.length < 4 + len) break
			const full = p.subarray(0, 4 + len)
			const body = p.subarray(4, 4 + len)
			p = p.subarray(4 + len)
			this.transcript.push(full)
			this._handleHandshakeMessage(t, body)
		}
		this.hsBuf = p.length ? Buffer.from(p) : Buffer.alloc(0)
	}

	_handleHandshakeMessage(type: number, body: Buffer): void {
		switch (type) {
			case HANDSHAKE.CERTIFICATE: {
				return this._onCertificate(body)
			}
			case HANDSHAKE.CERTIFICATE_STATUS: {
				return this._onCertificateStatus(body)
			}
			case HANDSHAKE.SERVER_KEY_EXCHANGE: {
				return this._onServerKeyExchange(body)
			}
			case HANDSHAKE.CERTIFICATE_REQUEST: {
				return // we'll send empty Certificate in client flight if seen — for now ignore
			}
			case HANDSHAKE.SERVER_HELLO_DONE: {
				return this._onServerHelloDone()
			}
			case HANDSHAKE.FINISHED: {
				return this._onServerFinished(body)
			}
			default: {
				log.error(`unexpected handshake 0x${type.toString(16)}`)
			}
		}
	}

	_onCertificate(body: Buffer): void {
		const total = (body[0] << 16) | (body[1] << 8) | body[2]
		let o = 3
		const end = 3 + total
		const chain: Buffer[] = []
		while (o < end) {
			const len = (body[o] << 16) | (body[o + 1] << 8) | body[o + 2]
			o += 3
			chain.push(Buffer.from(body.subarray(o, o + len)))
			o += len
		}
		this.serverCertDerChain = chain
		try {
			const leaf = new crypto.X509Certificate(chain[0])
			this.serverPubKey = leaf.publicKey
		} catch (e) {
			return this._fatal(`leaf cert parse failed: ${errMsg(e)}`)
		}
		if (this.tls.verifyTLS) {
			const r = validateChain(chain, this.tls.host)
			if (!r.ok) return this._fatal(`certificate validation failed: ${r.reason}`)
		}
		log.notify(`Certificate chain: ${chain.length} cert(s)`)
	}

	// RFC 6066 §8 CertificateStatus: u8 status_type | u24 length | OCSPResponse(DER)
	// Server-sent stapled OCSP. Status_type=1 means OCSP. We parse, verify, and:
	//   - hard-fail if responder marks the leaf revoked
	//   - log a warning (soft-fail, matching Chrome) if signature can't be verified
	_onCertificateStatus(body: Buffer): void {
		if (!body.length || body[0] !== 0x01) {
			log.notify('[ocsp] CertificateStatus: unsupported status_type')
			return
		}
		const len = (body[1] << 16) | (body[2] << 8) | body[3]
		const ocspDer = body.subarray(4, 4 + len)
		let r
		try {
			r = parseOcspResponse(ocspDer)
		} catch (e) {
			log.warn(`[ocsp] parse failed: ${errMsg(e)}`)
			return
		}

		// Identify issuer cert from chain: leaf is chain[0], issuer is the next one whose
		// subject matches leaf.issuer. Fall back to chain[1] when present.
		const chain = this.serverCertDerChain || []
		let issuerCert: crypto.X509Certificate | null = null
		try {
			const leafCert = new crypto.X509Certificate(chain[0])
			if (chain[1]) issuerCert = new crypto.X509Certificate(chain[1])
			if (issuerCert) {
				r.signatureVerified = verifyOcspSignature(r, issuerCert)
				r.leafMatched = leafMatchesOcsp(r, leafCert)
			}
		} catch (e) {
			log.warn(`[ocsp] verify error: ${errMsg(e)}`)
		}

		this.tls.ocsp = r
		log.notify(
			`[ocsp] response=${r.responseStatus} statuses=${JSON.stringify(r.statuses)} sig=${r.signatureVerified} leaf=${r.leafMatched}`
		)
		if (this.tls.verifyTLS && r.statuses.includes('revoked')) {
			return this._fatal('certificate validation failed: OCSP responder reported the leaf as revoked')
		}
		if (this.tls.verifyTLS && r.responseStatus === 'successful' && !r.signatureVerified) {
			// Soft-fail (matches Chrome behaviour): warn, accept the connection. Callers that
			// want hard-fail on bad OCSP signatures can inspect tls.ocsp.signatureVerified.
			log.warn('[ocsp] stapled response signature did not verify — soft-fail (connection continues)')
		}
	}

	_onServerKeyExchange(body: Buffer): void {
		if (this.cipher.kx !== 'ECDHE') return this._fatal('SKE received for non-ECDHE suite')
		// ECDHE: curve_type(1) || named_curve(2) || ECPoint(1+len) || sig_alg(2) || sig(2+len)
		const curveType = body[0]
		if (curveType !== 0x03 /*named_curve*/) return this._fatal(`unsupported curve_type ${curveType}`)
		const namedCurve = body.readUInt16BE(1)
		const curveInfo = NAMED_CURVE[namedCurve]
		if (!curveInfo) return this._fatal(`unsupported named curve 0x${namedCurve.toString(16)}`)
		const pubLen = body[3]
		const serverPubRaw = body.subarray(4, 4 + pubLen)
		let o = 4 + pubLen
		// signed params region the server signed: client_random || server_random || ecdhe_params
		const ecdheParamsBytes = body.subarray(0, o)

		const sigAlgId = body.readUInt16BE(o)
		o += 2
		const sigInfo = SIG_ALG[sigAlgId]
		if (!sigInfo) return this._fatal(`unsupported sig_alg 0x${sigAlgId.toString(16)}`)
		const sigLen = body.readUInt16BE(o)
		o += 2
		const signature = body.subarray(o, o + sigLen)

		// Phase 6 will actually VERIFY the signature; for now we just store + parse.
		this.ecdheCurve = curveInfo
		this.ecdheNamedCurveId = namedCurve
		this.serverEcdheRaw = Buffer.from(serverPubRaw)
		this._skeSignatureInfo = {
			sigInfo,
			sigAlgId,
			signature: Buffer.from(signature),
			ecdheParamsBytes: Buffer.from(ecdheParamsBytes)
		}
		log.notify(
			`SKE: curve=0x${namedCurve.toString(16)} pub=${pubLen}B sig_alg=0x${sigAlgId.toString(16)} sig=${sigLen}B`
		)
	}

	_onServerHelloDone(): void {
		log.notify('ServerHelloDone — sending client flight')

		if (this.cipher.kx === 'ECDHE') {
			// Phase 6: verify server's signature on the ServerKeyExchange ECDHE params.
			if (!this._verifySkeSignature()) return // _fatal already called
			this._generateClientEcdhe()
			if (this.ecdheCurve!.node === 'x25519') {
				// Web Crypto can only derive asynchronously; the next messages stay buffered
				// in hsBuf until the client flight has been sent.
				this._kxPending = true
				deriveX25519SharedSecret(this.clientEcdhePriv!, this.serverEcdheRaw!)
					.then((shared) => {
						this._kxPending = false
						this.preMasterSecret = shared
						this._sendClientFlight()
						this._drainHandshake()
					})
					.catch((err: Error) => {
						this._kxPending = false
						this._fatal(`X25519 key exchange failed: ${err.message}`)
					})
				return
			}
			this._computePreMaster()
		} else if (this.cipher.kx === 'RSA') {
			// RSA key transport: generate 48-byte Pre-Master Secret, encrypt to server's
			// RSA pubkey (PKCS#1 v1.5 padding). No SKE in this flow; PMS bytes go directly
			// into ClientKeyExchange.
			const pms = Buffer.alloc(48)
			pms[0] = 0x03
			pms[1] = 0x03 // client_version (1.2) — server checks for downgrade
			crypto.randomFillSync(pms, 2, 46)
			this.preMasterSecret = pms
			this.rsaEncryptedPms = crypto.publicEncrypt(
				{ key: this.serverPubKey!, padding: crypto.constants.RSA_PKCS1_PADDING },
				pms
			)
		} else {
			return this._fatal(`unsupported key-exchange ${this.cipher.kx}`)
		}

		this._sendClientFlight()
	}

	// RFC 5246 §7.4.3: server signs ECDHE params with its cert's private key so the client
	// can authenticate them against the cert. signed bytes = client_random || server_random
	// || ECDHE_params. sig_alg ID tells us which hash + key type to verify with.
	_verifySkeSignature(): boolean {
		const info = this._skeSignatureInfo
		if (!info) {
			this._fatal('no SKE signature to verify')
			return false
		}
		const data = Buffer.concat([this.tls.clientRandom!, this.serverRandom, info.ecdheParamsBytes])
		// Streaming verifier (see ./sig-verify): the one-shot crypto.verify() we used here ignores the
		// RSA padding options in workerd, and its options reject a KeyObject. TLS 1.2 ECDSA signatures
		// are DER, which the streaming path also takes as-is.
		if (verifySignature(info.sigInfo, this.serverPubKey, data, info.signature)) {
			log.notify('SKE signature verified')
			return true
		}
		this._fatal(`SKE signature verification FAILED (alg=0x${info.sigAlgId?.toString(16) || '?'})`)
		return false
	}

	_onServerFinished(body: Buffer): void {
		// verify_data = PRF(MS, "server finished", H(handshake_messages [...]), 12)
		// Transcript at this point includes everything UP TO server's Finished but NOT this msg.
		// We pushed the message into transcript before this handler ran, so peel it off for the
		// hash and then push back.
		const finishedMsg = this.transcript.pop()!
		const transcriptHash = crypto.createHash(this.cipher.prfHash).update(Buffer.concat(this.transcript)).digest()
		this.transcript.push(finishedMsg)

		const expected = prf.finishedVerifyData(this.cipher.prfHash, this.masterSecret!, false, transcriptHash)
		if (!crypto.timingSafeEqual(body, expected)) {
			return this._fatal('Server Finished verify_data mismatch')
		}
		log.notify('Server Finished verified — handshake complete')
		this._handshakeComplete()
	}

	// ---- key exchange + key schedule -----------------------------------------------

	_generateClientEcdhe(): void {
		const { node, byteLen } = this.ecdheCurve!
		let privateKey: crypto.KeyObject
		let publicKey: crypto.KeyObject
		if (node === 'x25519') {
			;({ privateKey, publicKey } = crypto.generateKeyPairSync('x25519'))
		} else {
			;({ privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: node }))
		}
		this.clientEcdhePriv = privateKey
		const der = publicKey.export({ type: 'spki', format: 'der' })
		// X25519: raw key is the last 32 bytes of SPKI. EC: the uncompressed point
		// 0x04 || X || Y is the last (1 + 2*byteLen) bytes.
		const ptLen = node === 'x25519' ? 32 : 1 + 2 * byteLen
		this.clientEcdheRaw = Buffer.from(der.subarray(-ptLen))
	}

	_computePreMaster(): void {
		// EC: Node's createECDH takes raw private scalar + raw uncompressed point. X25519 is
		// derived asynchronously in _onServerHelloDone through the Web Crypto bridge.
		const { node } = this.ecdheCurve!
		const jwk = this.clientEcdhePriv!.export({ format: 'jwk' })
		const d = Buffer.from(jwk.d!, 'base64url')
		const ecdh = crypto.createECDH(node)
		ecdh.setPrivateKey(d)
		this.preMasterSecret = ecdh.computeSecret(this.serverEcdheRaw!)
	}

	// ---- client flight: CKE → [CCS] → Finished -------------------------------------

	_sendClientFlight(): void {
		// 1) ClientKeyExchange
		const cke = this._buildClientKeyExchange()
		this.transcript.push(cke)

		// 2) Now compute master_secret (EMS path uses transcript through CKE). RFC 7627 wants the
		// hash of every message up to but not including Finished, so it is taken here, after CKE
		// has been appended.
		const hash = this.cipher.prfHash
		if (this.useEMS) {
			const sessionHash = crypto.createHash(hash).update(Buffer.concat(this.transcript)).digest()
			this.masterSecret = prf.extendedMasterSecret(hash, this.preMasterSecret!, sessionHash)
		} else {
			this.masterSecret = prf.masterSecret(hash, this.preMasterSecret!, this.tls.clientRandom!, this.serverRandom)
		}
		// PMS no longer needed; zero it out
		this.preMasterSecret = null

		// 3) Derive key block + per-direction keys
		const c = this.cipher
		const keyBlockLen = 2 * c.macLen + 2 * c.keyLen + 2 * c.ivLen
		const kb = prf.keyBlock(hash, this.masterSecret, this.serverRandom, this.tls.clientRandom!, keyBlockLen)
		let o = 0
		const cMac = kb.subarray(o, o + c.macLen)
		o += c.macLen
		const sMac = kb.subarray(o, o + c.macLen)
		o += c.macLen
		const cKey = kb.subarray(o, o + c.keyLen)
		o += c.keyLen
		const sKey = kb.subarray(o, o + c.keyLen)
		o += c.keyLen
		const cIv = kb.subarray(o, o + c.ivLen)
		o += c.ivLen
		const sIv = kb.subarray(o, o + c.ivLen)
		this.clientKeys = { key: Buffer.from(cKey), iv: Buffer.from(cIv), mac: c.macLen ? Buffer.from(cMac) : null }
		this.serverKeys = { key: Buffer.from(sKey), iv: Buffer.from(sIv), mac: c.macLen ? Buffer.from(sMac) : null }

		// 4) Send CKE (cleartext) + CCS + Finished (encrypted under client_write keys)
		const ckeRecord = records.recordHeader(CONTENT.HANDSHAKE, cke.length)
		const ccs = Buffer.from([CONTENT.CCS, 0x03, 0x03, 0x00, 0x01, 0x01])

		const finishedTranscriptHash = crypto.createHash(hash).update(Buffer.concat(this.transcript)).digest()
		const verifyData = prf.finishedVerifyData(hash, this.masterSecret, true, finishedTranscriptHash)
		const finishedMsg = Buffer.concat([Buffer.from([HANDSHAKE.FINISHED, 0x00, 0x00, 0x0c]), verifyData])
		this.transcript.push(finishedMsg)
		const encryptedFinished = records.encryptRecord(
			this.cipher,
			this.clientKeys,
			this.clientSeq++,
			CONTENT.HANDSHAKE,
			finishedMsg
		)

		this.tls.socket!.write(Buffer.concat([ckeRecord, cke, ccs, encryptedFinished]))
	}

	_buildClientKeyExchange(): Buffer {
		let body: Buffer
		if (this.cipher.kx === 'ECDHE') {
			// ECDHE: 1-byte length + uncompressed/raw point bytes
			const pub = this.clientEcdheRaw!
			body = Buffer.concat([Buffer.from([pub.length]), pub])
		} else {
			// RSA key transport: 2-byte length + RSA-encrypted PMS (PKCS#1 v1.5)
			const enc = this.rsaEncryptedPms!
			const lenBuf = Buffer.alloc(2)
			lenBuf.writeUInt16BE(enc.length, 0)
			body = Buffer.concat([lenBuf, enc])
		}
		const header = Buffer.from([
			HANDSHAKE.CLIENT_KEY_EXCHANGE,
			(body.length >> 16) & 0xff,
			(body.length >> 8) & 0xff,
			body.length & 0xff
		])
		return Buffer.concat([header, body])
	}

	_handshakeComplete(): void {
		this.tls.handshakeComplete = true
		this.tls.handshakeKeysReady = true
		// ALPN was parsed in the ServerHello extension scan (tls.ts); default to http/1.1 if
		// the server didn't advertise an application protocol.
		this.tls.alpn = this.tls.alpn || 'http/1.1'
		// Build the plaintext Duplex bridge so app code can write/read through the TLS layer
		// the same way it does in the TLS 1.3 path.
		if (!this.tls.h2Transport) {
			this.tls.h2Transport = new TLSTransport(this.tls)
		}
		if (this.tls.alpn === 'h2') {
			this.tls.h2Session = new H2Session(this.tls.h2Transport)
			this.tls.emit('ready')
		} else {
			this.tls.emit('ready-http1')
		}
	}

	// ---- outbound app-data path (called from client.js via tls.h2Transport / write) -

	encryptAppData(plaintext: Buffer): void {
		const rec = records.encryptRecord(this.cipher, this.clientKeys!, this.clientSeq++, CONTENT.APPDATA, plaintext)
		this.tls.socket!.write(rec)
	}

	_fatal(msg: string): void {
		const err: TLSError = new Error(`TLS 1.2: ${msg}`)
		err.code = 'ETLS12'
		this.tls.emit('error', err)
		this.tls.socket?.destroy()
	}
}

export { TLS12Handshake, CIPHERS, CONTENT, HANDSHAKE, SIG_ALG, NAMED_CURVE }
