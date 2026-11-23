// Tier-1 TLS authentication fixes:
//   - validateChain enforces basicConstraints CA:TRUE on issuers (no leaf-as-CA forgery)
//   - verifyCertVerify checks the TLS 1.3 server CertificateVerify signature (RFC 8446 §4.4.3)
//   - parseCertificateList parses/round-trips the Certificate message (also via the compressed path)

import { execSync } from 'node:child_process'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import * as zlib from 'node:zlib'

import { afterAll, expect, it, vi } from 'vitest'

import { QuicConnection } from '../../lib/h3/connection.ts'
import { validateChain, trustedRoots, verifyCertVerify, parseCertificateList } from '../../lib/tls/cert-validate.ts'
import { TLS } from '../../lib/tls/tls.ts'

// Every openssl invocation is fed names we chose ourselves inside a private mkdtemp directory, with
// cwd pinned to it; nothing user-controlled reaches the shell string.
const D = fs.mkdtempSync(path.join(os.tmpdir(), 'hjcv-'))
const sh = (cmd: string): void => {
	execSync(cmd, { cwd: D, stdio: ['ignore', 'ignore', 'ignore'] })
}
const eckey = (n: string): void => sh(`openssl ecparam -name prime256v1 -genkey -noout -out ${n}`)
const der = (crt: string): Buffer => Buffer.from(new crypto.X509Certificate(fs.readFileSync(path.join(D, crt))).raw)
const u24 = (n: number): Buffer => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
const hsMsg = (type: number, body: Buffer): Buffer => Buffer.concat([Buffer.from([type]), u24(body.length), body])
const writeExt = (n: string, s: string): void => {
	fs.writeFileSync(path.join(D, n), s)
}

// Build a small PKI: root CA -> intermediate CA -> good leaf; plus a non-CA "attacker" leaf signed
// by the root, and a forged victim cert signed with the attacker leaf's (non-CA) key.
eckey('root.key')
sh(
	'openssl req -x509 -new -key root.key -out root.crt -days 2 -subj "/CN=Test Root" -addext "basicConstraints=critical,CA:TRUE"'
)
eckey('int.key')
sh('openssl req -new -key int.key -out int.csr -subj "/CN=Test Intermediate"')
writeExt('int.ext', 'basicConstraints=critical,CA:TRUE\n')
sh('openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 2 -extfile int.ext')
eckey('good.key')
sh('openssl req -new -key good.key -out good.csr -subj "/CN=good.example"')
writeExt('good.ext', 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:good.example\n')
sh('openssl x509 -req -in good.csr -CA int.crt -CAkey int.key -CAcreateserial -out good.crt -days 2 -extfile good.ext')
eckey('att.key')
sh('openssl req -new -key att.key -out att.csr -subj "/CN=attacker.example"')
writeExt('att.ext', 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:attacker.example\n')
sh('openssl x509 -req -in att.csr -CA root.crt -CAkey root.key -CAcreateserial -out att.crt -days 2 -extfile att.ext')
eckey('forged.key')
sh('openssl req -new -key forged.key -out forged.csr -subj "/CN=victim.example"')
writeExt('forged.ext', 'subjectAltName=DNS:victim.example\n')
sh(
	'openssl x509 -req -in forged.csr -CA att.crt -CAkey att.key -CAcreateserial -out forged.crt -days 2 -extfile forged.ext'
)

// Inject our test root into the (process-local) trust store cache.
const roots = trustedRoots()
const restoreLen = roots.length
roots.push(new crypto.X509Certificate(fs.readFileSync(path.join(D, 'root.crt'))))
afterAll(() => {
	roots.length = restoreLen
	fs.rmSync(D, { recursive: true, force: true })
})

it('valid chain (leaf <- intermediate CA <- root) is accepted', () => {
	const r = validateChain([der('good.crt'), der('int.crt'), der('root.crt')], 'good.example')
	expect(r.ok, r.ok ? '' : r.reason).toBe(true)
})

it('forged cert signed by a non-CA leaf is REJECTED (CA:TRUE constraint)', () => {
	const r = validateChain([der('forged.crt'), der('att.crt'), der('root.crt')], 'victim.example')
	expect(r.ok).toBe(false)
	expect(r.ok ? '' : r.reason).toMatch(/not a CA/)
})

it('CertificateVerify: valid ECDSA signature accepted; tamper/wrong-hash/wrong-scheme rejected', () => {
	const leaf = new crypto.X509Certificate(fs.readFileSync(path.join(D, 'good.crt')))
	const priv = crypto.createPrivateKey(fs.readFileSync(path.join(D, 'good.key')))
	const transcriptHash = crypto.createHash('sha256').update('transcript').digest()
	const content = Buffer.concat([
		Buffer.alloc(64, 0x20),
		Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'),
		Buffer.from([0]),
		transcriptHash
	])
	const sig = crypto.sign('sha256', content, priv)
	expect(verifyCertVerify({ scheme: 0x0403, signature: sig, leaf, transcriptHash })).toBe(true)
	const bad = Buffer.from(sig)
	bad[bad.length - 1] ^= 0x01
	expect(verifyCertVerify({ scheme: 0x0403, signature: bad, leaf, transcriptHash }), 'tampered sig').toBe(false)
	expect(
		verifyCertVerify({ scheme: 0x0403, signature: sig, leaf, transcriptHash: crypto.randomBytes(32) }),
		'wrong transcript'
	).toBe(false)
	expect(verifyCertVerify({ scheme: 0x0804, signature: sig, leaf, transcriptHash }), 'rsa scheme for ec key').toBe(
		false
	)
	expect(verifyCertVerify({ scheme: 0xffff, signature: sig, leaf, transcriptHash }), 'unknown scheme').toBe(false)
})

it('_verifyCertificateVerify marks a full handshake authenticated only after a valid signature', () => {
	const t = new TLS('good.example', 443, null, { verifyTLS: true })
	const p = t as unknown as {
		serverAuthenticated: boolean
		serverCertChain: Buffer[]
		cipher: { hash: string; hashLen: number }
		transcript: Buffer[]
		_verifyCertificateVerify(body: Buffer): boolean
	}
	const priv = crypto.createPrivateKey(fs.readFileSync(path.join(D, 'good.key')))
	const transcriptHash = crypto.createHash('sha256').update('transcript').digest()
	const content = Buffer.concat([
		Buffer.alloc(64, 0x20),
		Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'),
		Buffer.from([0]),
		transcriptHash
	])
	const sig = crypto.sign('sha256', content, priv)
	const body = Buffer.concat([Buffer.from([0x04, 0x03, sig.length >> 8, sig.length & 0xff]), sig])
	p.serverCertChain = [der('good.crt')]
	p.cipher = { hash: 'sha256', hashLen: 32 }
	p.transcript = [Buffer.from('transcript')]

	expect(p._verifyCertificateVerify(body)).toBe(true)
	expect(p.serverAuthenticated).toBe(true)
})

it('CertificateVerify: valid RSA-PSS (rsa_pss_rsae_sha384) signature accepted', () => {
	sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -days 2 -subj "/CN=rsa.example"')
	const leaf = new crypto.X509Certificate(fs.readFileSync(path.join(D, 'rsa.crt')))
	const priv = crypto.createPrivateKey(fs.readFileSync(path.join(D, 'rsa.key')))
	const transcriptHash = crypto.createHash('sha384').update('x').digest()
	const content = Buffer.concat([
		Buffer.alloc(64, 0x20),
		Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'),
		Buffer.from([0]),
		transcriptHash
	])
	const sig = crypto.sign('sha384', content, {
		key: priv,
		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
		saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
	})
	expect(verifyCertVerify({ scheme: 0x0805, signature: sig, leaf, transcriptHash })).toBe(true)
})

it('parseCertificateList round-trips a Certificate message (plain + brotli)', () => {
	const leafDer = der('good.crt')
	const entry = Buffer.concat([u24(leafDer.length), leafDer, Buffer.from([0, 0])]) // cert + empty exts
	const body = Buffer.concat([Buffer.from([0]), u24(entry.length), entry]) // empty ctx + list
	const certs = parseCertificateList(body)
	expect(certs.length).toBe(1)
	expect(certs[0].equals(leafDer)).toBe(true)
	const viaBrotli = parseCertificateList(zlib.brotliDecompressSync(zlib.brotliCompressSync(body)))
	expect(viaBrotli[0].equals(leafDer)).toBe(true)
})

it('parseCertificateList rejects truncated input instead of silently mis-parsing', () => {
	expect(() => parseCertificateList(Buffer.from([0x00, 0x00, 0x00, 0x10]))).toThrow() // claims 16-byte list, none present
})

const certificateMessage = (): Buffer => {
	const entries = ['good.crt', 'int.crt', 'root.crt'].map((name) => {
		const derCert = der(name)
		return Buffer.concat([u24(derCert.length), derCert, Buffer.from([0, 0])])
	})
	const list = Buffer.concat(entries)
	return Buffer.concat([Buffer.from([0]), u24(list.length), list])
}

const certVerifyBody = (signature: Buffer): Buffer =>
	Buffer.concat([Buffer.from([0x04, 0x03, signature.length >> 8, signature.length & 0xff]), signature])

const signedTranscript = (): { body: Buffer; badBody: Buffer } => {
	const priv = crypto.createPrivateKey(fs.readFileSync(path.join(D, 'good.key')))
	const transcriptHash = crypto.createHash('sha256').update('transcript').digest()
	const content = Buffer.concat([
		Buffer.alloc(64, 0x20),
		Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'),
		Buffer.from([0]),
		transcriptHash
	])
	const sig = crypto.sign('sha256', content, priv)
	const bad = Buffer.from(sig)
	bad[bad.length - 1] ^= 0x01
	return { body: certVerifyBody(sig), badBody: certVerifyBody(bad) }
}

it('QUIC Certificate ingestion validates the chain and hostname against SNI', () => {
	const c = new QuicConnection('good.example', 443)
	const p = c as unknown as {
		serverCertChain: Buffer[]
		_ingestServerCertificate(body: Buffer, compressed: boolean): boolean
	}
	expect(p._ingestServerCertificate(certificateMessage(), false)).toBe(true)
	expect(p.serverCertChain[0].equals(der('good.crt'))).toBe(true)
})

it('QUIC rejects a valid chain for the wrong SNI', () => {
	const c = new QuicConnection('evil.example', 443)
	let emitted: (Error & { code?: string }) | undefined
	c.on('error', (e) => {
		emitted = e as Error & { code?: string }
	})
	const p = c as unknown as { _ingestServerCertificate(body: Buffer, compressed: boolean): boolean }
	expect(p._ingestServerCertificate(certificateMessage(), false)).toBe(false)
	expect(emitted?.code).toBe('ECERTVALIDATION')
})

it('a rejected QUIC Certificate is terminal for the rest of the CRYPTO buffer', () => {
	const c = new QuicConnection('good.example', 443)
	let emitted: (Error & { code?: string }) | undefined
	c.on('error', (e) => {
		emitted = e as Error & { code?: string }
	})
	const p = c as unknown as {
		serverAuthenticated: boolean
		serverCertChain: Buffer[]
		transcript: Buffer[]
		cipher: { hash: string; hashLen: number }
		cryptoBufIn: { handshake: Buffer }
		cryptoOffsetIn: { handshake: number }
		_validateServerFinished(body: Buffer): void
		_deriveApplicationKeys(): void
		_sendClientFinished(): void
		_deriveResumptionMasterSecret(): void
		_handleNewSessionTicket(body: Buffer): void
		_processCryptoBuffer(epoch: 'handshake'): void
	}

	// Signed by our trusted test root but for the wrong hostname: chain validation rejects it,
	// while its key can still produce a valid CertificateVerify over the retained transcript.
	const attDer = der('att.crt')
	const attEntry = Buffer.concat([u24(attDer.length), attDer, Buffer.from([0, 0])])
	const badCert = Buffer.concat([Buffer.from([0]), u24(attEntry.length), attEntry])
	const transcript = Buffer.from('transcript')
	const signed = Buffer.concat([
		Buffer.alloc(64, 0x20),
		Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'),
		Buffer.from([0]),
		crypto.createHash('sha256').update(transcript).digest()
	])
	const cv = certVerifyBody(
		crypto.sign('sha256', signed, crypto.createPrivateKey(fs.readFileSync(path.join(D, 'att.key'))))
	)

	p.transcript = [transcript]
	p.cipher = { hash: 'sha256', hashLen: 32 }
	p.serverAuthenticated = false
	p.serverCertChain = []
	p.cryptoOffsetIn.handshake = 0
	p.cryptoBufIn.handshake = Buffer.concat([
		hsMsg(0x0b, badCert), // Certificate — rejected (wrong SNI)
		hsMsg(0x0f, cv), // CertificateVerify — would pass if the chain were retained
		hsMsg(0x14, Buffer.alloc(32)), // Finished
		hsMsg(0x04, Buffer.from([0x01])) // NewSessionTicket
	])
	const sendFinished = vi.fn()
	const storeTicket = vi.fn()
	p._validateServerFinished = () => {}
	p._deriveApplicationKeys = () => {}
	p._sendClientFinished = sendFinished
	p._deriveResumptionMasterSecret = () => {}
	p._handleNewSessionTicket = storeTicket

	p._processCryptoBuffer('handshake')

	expect(emitted?.code).toBe('ECERTVALIDATION')
	expect(p.serverAuthenticated).toBe(false)
	expect(p.serverCertChain).toHaveLength(0)
	expect(sendFinished).not.toHaveBeenCalled()
	expect(storeTicket).not.toHaveBeenCalled()
})

it('QUIC CertificateVerify sets the authenticated state only for a valid signature', () => {
	const { body, badBody } = signedTranscript()
	const configure = (c: QuicConnection) => {
		const p = c as unknown as {
			serverCertChain: Buffer[]
			transcript: Buffer[]
			cipher: { hash: string; hashLen: number }
			serverAuthenticated: boolean
			_verifyCertificateVerify(body: Buffer): boolean
		}
		p.serverCertChain = [der('good.crt')]
		p.transcript = [Buffer.from('transcript')]
		p.cipher = { hash: 'sha256', hashLen: 32 }
		return p
	}

	const good = new QuicConnection('good.example', 443)
	const gp = configure(good)
	expect(gp._verifyCertificateVerify(body)).toBe(true)
	expect(gp.serverAuthenticated).toBe(true)

	const bad = new QuicConnection('good.example', 443)
	const bp = configure(bad)
	let emitted: (Error & { code?: string }) | undefined
	bad.on('error', (e) => {
		emitted = e as Error & { code?: string }
	})
	expect(bp._verifyCertificateVerify(badBody)).toBe(false)
	expect(bp.serverAuthenticated).toBe(false)
	expect(emitted?.code).toBe('ECERTVERIFY')
})

it('closes the QUIC connection before emitting a certificate error, even with no listener', () => {
	const c = new QuicConnection('evil.example', 443)
	const p = c as unknown as {
		_closed: boolean
		cryptoBufIn: { handshake: Buffer }
		cryptoOffsetIn: { handshake: number }
		_processCryptoBuffer(epoch: 'handshake'): void
	}
	p.cryptoOffsetIn.handshake = 0
	p.cryptoBufIn.handshake = hsMsg(0x0b, certificateMessage())

	// Node throws on an unhandled 'error' event; the rejection must still be terminal.
	expect(() => p._processCryptoBuffer('handshake')).toThrow()
	expect(p._closed).toBe(true)
})

it('a throwing error listener emits once with the original certificate error code', () => {
	const c = new QuicConnection('evil.example', 443)
	const codes: (string | undefined)[] = []
	c.on('error', (e) => {
		codes.push((e as Error & { code?: string }).code)
		throw new Error('listener boom')
	})
	const p = c as unknown as {
		_closed: boolean
		cryptoBufIn: { handshake: Buffer }
		cryptoOffsetIn: { handshake: number }
		_processCryptoBuffer(epoch: 'handshake'): void
	}
	p.cryptoOffsetIn.handshake = 0
	p.cryptoBufIn.handshake = hsMsg(0x0b, certificateMessage())

	expect(() => p._processCryptoBuffer('handshake')).toThrow('listener boom')
	expect(codes).toEqual(['ECERTVALIDATION'])
	expect(p._closed).toBe(true)
})
