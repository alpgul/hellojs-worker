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

import assert from 'node:assert'
import { execSync } from 'node:child_process'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import test from 'node:test'
import * as tls from 'node:tls'

import { verifySignature, verifyCertSignature, resolveKey, derToSpkiPem, normHash } from '../../lib/tls/sig-verify.ts'

const K = crypto.constants
const roots = tls.rootCertificates.map(pem => new crypto.X509Certificate(pem))

// A CA + leaf pair signed by it, plus a detached PSS signature — generated once for the whole suite.
function fixtures() {
	if (fixtures.cache) return fixtures.cache
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjsig-'))
	const run = (cmd) => execSync(cmd, { cwd: dir, stdio: ['ignore', 'ignore', 'ignore'] })
	try {
		run("openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 1 -subj '/CN=Test CA'")
		run('openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj /CN=leaf.example')
		run('openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -set_serial 1 -days 1 -out leaf.pem')
		const derOf = (f) => Buffer.from(new crypto.X509Certificate(fs.readFileSync(path.join(dir, f))).raw)
		const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
		const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
		const ed = crypto.generateKeyPairSync('ed25519')
		const content = Buffer.from('the exact bytes a detached signature covers')
		fixtures.cache = {
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
	return fixtures.cache
}

test('verifyCertSignature: self-signed roots verify with no DER parsing', () => {
	let checked = 0
	for (const x of roots) {
		if (x.issuer !== x.subject || x.ca !== true) continue
		checked++
		// A few md5WithRSA roots predate our digest support; node:crypto still verifies them.
		assert.strictEqual(verifyCertSignature(Buffer.from(x.raw), Buffer.from(x.raw)), true,
			`root ${x.subject.split('\n')[0]} must verify`)
		if (checked >= 25) break
	}
	assert.ok(checked >= 25, `expected at least 25 self-signed roots, got ${checked}`)
})

test('verifyCertSignature: a real CA verifies its leaf, and not the other way round', () => {
	const f = fixtures()
	assert.strictEqual(verifyCertSignature(f.leaf, f.ca), true)
	assert.strictEqual(verifyCertSignature(f.ca, f.leaf), false, 'a leaf key did not issue the CA')
	// X509Certificate instances are accepted too, which is what the chain walk already holds.
	assert.strictEqual(verifyCertSignature(new crypto.X509Certificate(f.leaf), new crypto.X509Certificate(f.ca)), true)
})

test('verifyCertSignature: tampering and garbage answer false, never throw', () => {
	const f = fixtures()
	const tampered = Buffer.from(f.leaf); tampered[tampered.length - 4] ^= 0x01
	assert.strictEqual(verifyCertSignature(tampered, f.ca), false)
	assert.strictEqual(verifyCertSignature(f.leaf, Buffer.concat([f.ca.slice(0, 20), Buffer.alloc(40)])), false)
	for (let i = 0; i < 20; i++) {
		const blob = crypto.randomBytes(300)
		assert.strictEqual(verifyCertSignature(blob, blob), false)
	}
})

test('verifySignature: RSA-PSS over detached content is verified WITH the padding', () => {
	const f = fixtures()
	assert.strictEqual(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pss), true,
		'a genuine PSS signature must verify — this is what workerd\'s one-shot get wrong')
	// The padding-confusion pair: same key, same content, PKCS#1 signature.
	assert.strictEqual(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pkcs1), false)
	assert.strictEqual(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pkcs1), true)
	assert.strictEqual(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pss), false)
})

test('verifySignature: ECDSA takes the DER signature straight off the wire', () => {
	const f = fixtures()
	assert.strictEqual(verifySignature({ type: 'ecdsa', hash: 'SHA-256' }, f.ec.publicKey, f.content, f.ecdsa), true,
		'DER must not need transcoding to raw r||s here')
	const flipped = Buffer.from(f.ecdsa); flipped[flipped.length - 1] ^= 0x01
	assert.strictEqual(verifySignature({ type: 'ecdsa', hash: 'SHA-256' }, f.ec.publicKey, f.content, flipped), false)
})

test('verifySignature: Ed25519 goes through the one-shot path (no padding to drop)', () => {
	const f = fixtures()
	assert.strictEqual(verifySignature({ type: 'eddsa', hash: null }, f.ed.publicKey, f.content, f.eddsa), true)
	const flipped = Buffer.from(f.eddsa); flipped[3] ^= 0x40
	assert.strictEqual(verifySignature({ type: 'eddsa', hash: null }, f.ed.publicKey, f.content, flipped), false)
})

test('verifySignature: the scheme is bound to the key type, so no algorithm confusion', () => {
	const f = fixtures()
	// An ecdsa scheme against an RSA key, and the reverse: both false rather than an exception.
	assert.strictEqual(verifySignature({ type: 'ecdsa', hash: 'sha256' }, f.rsa.publicKey, f.content, f.ecdsa), false)
	assert.strictEqual(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, f.ec.publicKey, f.content, f.pss), false)
	assert.strictEqual(verifySignature({ type: 'eddsa', hash: null }, f.rsa.publicKey, f.content, f.eddsa), false)
	assert.strictEqual(verifySignature({ type: 'nonsense', hash: 'sha256' }, f.rsa.publicKey, f.content, f.pss), false)
	assert.strictEqual(verifySignature(null, f.rsa.publicKey, f.content, f.pss), false)
	assert.strictEqual(verifySignature({ type: 'rsa-pkcs1', hash: 'md5' }, f.rsa.publicKey, f.content, f.pkcs1), false,
		'an unusable digest is false, not a thrown error')
	// Same binding with the certificate nowhere in sight: a bare SPKI is what sct.ts hands us for a log
	// key, and node:crypto happily verifies an ECDSA DER signature under an RSA spec (it ignores the
	// padding options rather than rejecting the combination) unless the type is resolved from the SPKI.
	const ecSpkiDer = f.ec.publicKey.export({ type: 'spki', format: 'der' })
	assert.strictEqual(resolveKey(ecSpkiDer).keyType, 'ec', 'key type recovered from a bare SPKI DER')
	assert.strictEqual(resolveKey(derToSpkiPem(ecSpkiDer)).keyType, 'ec', 'and from PEM text')
	assert.strictEqual(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, ecSpkiDer, f.content, f.ecdsa), false)
	assert.strictEqual(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, ecSpkiDer, f.content, f.ecdsa), false)
	assert.strictEqual(verifySignature({ type: 'ecdsa', hash: 'sha256' }, derToSpkiPem(ecSpkiDer), f.content, f.ecdsa), true,
		'the matching scheme still verifies through the resolved PEM')
	const rsaSpkiDer = f.rsa.publicKey.export({ type: 'spki', format: 'der' })
	assert.strictEqual(verifySignature({ type: 'ecdsa', hash: 'sha256' }, rsaSpkiDer, f.content, f.pss), false)
	assert.strictEqual(verifySignature({ type: 'eddsa', hash: null }, rsaSpkiDer, f.content, f.eddsa), false)
	assert.strictEqual(verifySignature({ type: 'rsa-pss', hash: 'sha256' }, rsaSpkiDer, f.content, f.pss), true)
})

test('verifySignature: a KeyObject, PEM text, an SPKI DER buffer and PEM armored from DER all work', () => {
	const f = fixtures()
	const spec = { type: 'rsa-pkcs1', hash: 'sha256' }
	const spkiPem = f.rsa.publicKey.export({ type: 'spki', format: 'pem' })
	const spkiDer = f.rsa.publicKey.export({ type: 'spki', format: 'der' })
	assert.strictEqual(verifySignature(spec, f.rsa.publicKey, f.content, f.pkcs1), true, 'KeyObject form')
	assert.strictEqual(verifySignature(spec, spkiPem, f.content, f.pkcs1), true, 'PEM text form')
	assert.strictEqual(verifySignature(spec, spkiDer, f.content, f.pkcs1), true, 'bare SPKI DER buffer')
	assert.strictEqual(verifySignature(spec, derToSpkiPem(spkiDer), f.content, f.pkcs1), true, 'PEM armored from SPKI DER')
	assert.ok(!derToSpkiPem(spkiDer).includes('\n\n'), 'no blank line before the PEM trailer — OpenSSL rejects it')
	// A certificate DER handed in as the key is parsed by node:crypto, so the chain walk can pass what
	// it already holds. Its key type comes back for the scheme binding.
	assert.strictEqual(resolveKey(f.ca).keyType, 'rsa')
	assert.ok(resolveKey(f.ca).pem.startsWith('-----BEGIN PUBLIC KEY-----'))
})

test('resolveKey: garbage and unsupported shapes answer false at the verify call, not a throw', () => {
	const f = fixtures()
	assert.strictEqual(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, Buffer.from('not a key'), f.content, f.pkcs1), false)
	assert.strictEqual(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, 42, f.content, f.pkcs1), false)
	assert.strictEqual(verifySignature({ type: 'rsa-pkcs1', hash: 'sha256' }, null, f.content, f.pkcs1), false)
	assert.strictEqual(resolveKey(f.ec.publicKey).keyType, 'ec')
	assert.strictEqual(resolveKey('-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n').keyType, null)
})

test('normHash: both spellings reach the same digest name', () => {
	assert.strictEqual(normHash('SHA-256'), 'sha256')
	assert.strictEqual(normHash('sha256'), 'sha256')
	assert.strictEqual(normHash('SHA-384'), 'sha384')
	assert.strictEqual(normHash(null), null)
})
