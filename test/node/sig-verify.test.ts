// lib/tls/sig-verify.ts — the synchronous verifier the handshake relies on.
//
// What this guards, in the order it bit us:
//   - chain links verify through X509Certificate.verify(pkey), so the padding comes from the
//     certificate's own signatureAlgorithm and nothing has to be parsed out of the DER by hand;
//   - detached signatures (CertificateVerify, TLS 1.2 SKE, OCSP, SCT) verify through
//     crypto.createVerify. The one-shot crypto.verify() is NOT usable: in workerd it accepts the RSA
//     padding options and never applies them, so a PSS signature answers false and a PKCS#1 signature
//     answers TRUE when asked about PSS. Both directions are asserted here.
//   - ECDSA signatures stay DER — the streaming path takes them as they arrive on the wire.

import { execSync } from 'node:child_process'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import * as tls from 'node:tls'

import { expect, it } from 'vitest'

import { verifySignature, verifyCertSignature, resolveKey, derToSpkiPem, normHash } from '../../lib/tls/sig-verify.ts'

import type { SignatureSpec } from '../../lib/tls/sig-verify.ts'

const K = crypto.constants
const roots = tls.rootCertificates.map((pem) => new crypto.X509Certificate(pem))
// A spec field is only ever a string on the wire, so the deliberately-unknown scheme needs a cast.
const badSpec = (type: string, hash: string | null = 'sha256'): SignatureSpec => ({ type, hash } as unknown as SignatureSpec)

interface KeyPair { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject }
interface Fixtures {
	ca: Buffer
	leaf: Buffer
	rsa: KeyPair
	ec: KeyPair
	ed: KeyPair
	content: Buffer
	pkcs1: Buffer
	pss: Buffer
	ecdsa: Buffer
	eddsa: Buffer
}

// A CA + leaf pair signed by it, plus a detached PSS signature — generated once for the whole suite.
let cached: Fixtures | null = null
function fixtures(): Fixtures {
	if (cached) return cached
	// openssl runs in a private mkdtemp directory with names this file chose; cwd is pinned to it.
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjsig-'))
	const run = (cmd: string): void => { execSync(cmd, { cwd: dir, stdio: ['ignore', 'ignore', 'ignore'] }) }
	try {
		run("openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 1 -subj '/CN=Test CA'")
		run('openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj /CN=leaf.example')
		run('openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 1 -days 1 -out leaf.pem')
		const derOf = (f: string): Buffer => Buffer.from(new crypto.X509Certificate(fs.readFileSync(path.join(dir, f))).raw)
		const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
		const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
		const ed = crypto.generateKeyPairSync('ed25519')
		const content = Buffer.from('the exact bytes a detached signature covers')
		cached = {
			ca: derOf('ca.pem'), leaf: derOf('leaf.pem'),
			rsa, ec, ed, content,
			pkcs1: crypto.sign('sha256', content, rsa.privateKey),
			pss: crypto.createSign('sha256').update(content).sign({ key: rsa.privateKey, padding: K.RSA_PKCS1_PSS_PADDING, saltLength: 32 }),
			ecdsa: crypto.sign('sha256', content, ec.privateKey),
			eddsa: crypto.sign(null, content, ed.privateKey),
		}
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
	return cached
}

it('verifyCertSignature: self-signed roots verify with no DER parsing', () => {
	let checked = 0
	for (const x of roots) {
		if (x.issuer !== x.subject || x.ca !== true) continue
		checked++
		// A few md5WithRSA roots predate our digest support; node:crypto still verifies them.
		expect(verifyCertSignature(Buffer.from(x.raw), Buffer.from(x.raw)), `root ${x.subject.split('\n')[0]} must verify`).toBe(true)
		if (checked >= 25) break
	}
	expect(checked, `expected at least 25 self-signed roots, got ${checked}`).toBeGreaterThanOrEqual(25)
})

it('verifyCertSignature: a real CA verifies its leaf, and not the other way round', () => {
	const f = fixtures()
	expect(verifyCertSignature(f.leaf, f.ca)).toBe(true)
	expect(verifyCertSignature(f.ca, f.leaf), 'a leaf key did not issue the CA').toBe(false)
	// X509Certificate instances are accepted too, which is what the chain walk already holds.
	expect(verifyCertSignature(new crypto.X509Certificate(f.leaf), new crypto.X509Certificate(f.ca))).toBe(true)
})

it('verifyCertSignature: tampering and garbage answer false, never throw', () => {
	const f = fixtures()
	const tampered = Buffer.from(f.leaf); tampered[tampered.length - 4] ^= 0x01
	expect(verifyCertSignature(tampered, f.ca)).toBe(false)
	expect(verifyCertSignature(f.leaf, Buffer.concat([f.ca.subarray(0, 20), Buffer.alloc(40)]))).toBe(false)
	for (let i = 0; i < 20; i++) {
		const blob = crypto.randomBytes(300)
		expect(verifyCertSignature(blob, blob), `iteration ${i}`).toBe(false)
	}
})

it('verifySignature: RSA-PSS over detached content is verified WITH the padding', () => {
	const f = fixtures()
	expect(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pss),
		'a genuine PSS signature must verify — this is what workerd\'s one-shot get wrong').toBe(true)
	// The padding-confusion pair: same key, same content, PKCS#1 signature.
	expect(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pkcs1)).toBe(false)
	expect(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pkcs1)).toBe(true)
	expect(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pss)).toBe(false)
})

it('verifySignature: ECDSA takes the DER signature straight off the wire', () => {
	const f = fixtures()
	expect(verifySignature({ type: 'ecdsa', hash: 'SHA-256' }, f.ec.publicKey, f.content, f.ecdsa),
		'DER must not need transcoding to raw r||s here').toBe(true)
	const flipped = Buffer.from(f.ecdsa); flipped[flipped.length - 1] ^= 0x01
	expect(verifySignature({ type: 'ecdsa', hash: 'SHA-256' }, f.ec.publicKey, f.content, flipped)).toBe(false)
})

it('verifySignature: Ed25519 goes through the one-shot path (no padding to drop)', () => {
	const f = fixtures()
	expect(verifySignature({ type: 'eddsa', hash: null }, f.ed.publicKey, f.content, f.eddsa)).toBe(true)
	const flipped = Buffer.from(f.eddsa); flipped[3] ^= 0x40
	expect(verifySignature({ type: 'eddsa', hash: null }, f.ed.publicKey, f.content, flipped)).toBe(false)
})

it('verifySignature: the scheme is bound to the key type, so no algorithm confusion', () => {
	const f = fixtures()
	// An ecdsa scheme against an RSA key, and the reverse: both false rather than an exception.
	expect(verifySignature({ type: 'ecdsa', hash: 'sha256' }, f.rsa.publicKey, f.content, f.ecdsa)).toBe(false)
	expect(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, f.ec.publicKey, f.content, f.pss)).toBe(false)
	expect(verifySignature({ type: 'eddsa', hash: null }, f.rsa.publicKey, f.content, f.eddsa)).toBe(false)
	expect(verifySignature(badSpec('nonsense'), f.rsa.publicKey, f.content, f.pss)).toBe(false)
	expect(verifySignature(null, f.rsa.publicKey, f.content, f.pss)).toBe(false)
	expect(verifySignature({ type: 'rsa-pkcs1', hash: 'md5' }, f.rsa.publicKey, f.content, f.pkcs1),
		'an unusable digest is false, not a thrown error').toBe(false)
	// Same binding with the certificate nowhere in sight: a bare SPKI is what sct.ts hands us for a log
	// key, and node:crypto happily verifies an ECDSA DER signature under an RSA spec (it ignores the
	// padding options rather than rejecting the combination) unless the type is resolved from the SPKI.
	const ecSpkiDer = f.ec.publicKey.export({ type: 'spki', format: 'der' }) as Buffer
	expect(resolveKey(ecSpkiDer).keyType, 'key type recovered from a bare SPKI DER').toBe('ec')
	expect(resolveKey(derToSpkiPem(ecSpkiDer)).keyType, 'and from PEM text').toBe('ec')
	expect(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, ecSpkiDer, f.content, f.ecdsa)).toBe(false)
	expect(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, ecSpkiDer, f.content, f.ecdsa)).toBe(false)
	expect(verifySignature({ type: 'ecdsa', hash: 'sha256' }, derToSpkiPem(ecSpkiDer), f.content, f.ecdsa),
		'the matching scheme still verifies through the resolved PEM').toBe(true)
	const rsaSpkiDer = f.rsa.publicKey.export({ type: 'spki', format: 'der' }) as Buffer
	expect(verifySignature({ type: 'ecdsa', hash: 'sha256' }, rsaSpkiDer, f.content, f.pss)).toBe(false)
	expect(verifySignature({ type: 'eddsa', hash: null }, rsaSpkiDer, f.content, f.eddsa)).toBe(false)
	expect(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, rsaSpkiDer, f.content, f.pss)).toBe(true)
})

it('verifySignature: a KeyObject, PEM text, an SPKI DER buffer and PEM armored from DER all work', () => {
	const f = fixtures()
	const spec: SignatureSpec = { type: 'rsa-pkcs1', hash: 'sha256' }
	const spkiPem = f.rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string
	const spkiDer = f.rsa.publicKey.export({ type: 'spki', format: 'der' }) as Buffer
	expect(verifySignature(spec, f.rsa.publicKey, f.content, f.pkcs1), 'KeyObject form').toBe(true)
	expect(verifySignature(spec, spkiPem, f.content, f.pkcs1), 'PEM text form').toBe(true)
	expect(verifySignature(spec, spkiDer, f.content, f.pkcs1), 'bare SPKI DER buffer').toBe(true)
	expect(verifySignature(spec, derToSpkiPem(spkiDer), f.content, f.pkcs1), 'PEM armored from SPKI DER').toBe(true)
	expect(derToSpkiPem(spkiDer).includes('\n\n'), 'no blank line before the PEM trailer — OpenSSL rejects it').toBe(false)
	// A certificate DER handed in as the key is parsed by node:crypto, so the chain walk can pass what
	// it already holds. Its key type comes back for the scheme binding.
	expect(resolveKey(f.ca).keyType).toBe('rsa')
	expect(resolveKey(f.ca).pem.startsWith('-----BEGIN PUBLIC KEY-----')).toBe(true)
})

it('resolveKey: garbage and unsupported shapes answer false at the verify call, not a throw', () => {
	const f = fixtures()
	expect(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, Buffer.from('not a key'), f.content, f.pkcs1)).toBe(false)
	expect(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, 42 as unknown as crypto.KeyObject, f.content, f.pkcs1)).toBe(false)
	expect(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, null, f.content, f.pkcs1)).toBe(false)
	expect(resolveKey(f.ec.publicKey).keyType).toBe('ec')
	expect(resolveKey('-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n').keyType).toBeNull()
})

it('normHash: both spellings reach the same digest name', () => {
	expect(normHash('SHA-256')).toBe('sha256')
	expect(normHash('sha256')).toBe('sha256')
	expect(normHash('SHA-384')).toBe('sha384')
	expect(normHash(null)).toBeNull()
})
