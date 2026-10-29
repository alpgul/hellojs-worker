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

import { afterAll, expect, it } from 'vitest'

import { validateChain, trustedRoots, verifyCertVerify, parseCertificateList } from '../../lib/tls/cert-validate.ts'

// Every openssl invocation is fed names we chose ourselves inside a private mkdtemp directory, with
// cwd pinned to it; nothing user-controlled reaches the shell string.
const D = fs.mkdtempSync(path.join(os.tmpdir(), 'hjcv-'))
const sh = (cmd: string): void => { execSync(cmd, { cwd: D, stdio: ['ignore', 'ignore', 'ignore'] }) }
const eckey = (n: string): void => sh(`openssl ecparam -name prime256v1 -genkey -noout -out ${n}`)
const der = (crt: string): Buffer => Buffer.from(new crypto.X509Certificate(fs.readFileSync(path.join(D, crt))).raw)
const u24 = (n: number): Buffer => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
const writeExt = (n: string, s: string): void => { fs.writeFileSync(path.join(D, n), s) }

// Build a small PKI: root CA -> intermediate CA -> good leaf; plus a non-CA "attacker" leaf signed
// by the root, and a forged victim cert signed with the attacker leaf's (non-CA) key.
eckey('root.key')
sh('openssl req -x509 -new -key root.key -out root.crt -days 2 -subj "/CN=Test Root" -addext "basicConstraints=critical,CA:TRUE"')
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
sh('openssl x509 -req -in forged.csr -CA att.crt -CAkey att.key -CAcreateserial -out forged.crt -days 2 -extfile forged.ext')

// Inject our test root into the (process-local) trust store cache.
const roots = trustedRoots()
const restoreLen = roots.length
roots.push(new crypto.X509Certificate(fs.readFileSync(path.join(D, 'root.crt'))))
afterAll(() => { roots.length = restoreLen; fs.rmSync(D, { recursive: true, force: true }) })

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
	const content = Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'), Buffer.from([0]), transcriptHash])
	const sig = crypto.sign('sha256', content, priv)
	expect(verifyCertVerify({ scheme: 0x0403, signature: sig, leaf, transcriptHash })).toBe(true)
	const bad = Buffer.from(sig); bad[bad.length - 1] ^= 0x01
	expect(verifyCertVerify({ scheme: 0x0403, signature: bad, leaf, transcriptHash }), 'tampered sig').toBe(false)
	expect(verifyCertVerify({ scheme: 0x0403, signature: sig, leaf, transcriptHash: crypto.randomBytes(32) }), 'wrong transcript').toBe(false)
	expect(verifyCertVerify({ scheme: 0x0804, signature: sig, leaf, transcriptHash }), 'rsa scheme for ec key').toBe(false)
	expect(verifyCertVerify({ scheme: 0xffff, signature: sig, leaf, transcriptHash }), 'unknown scheme').toBe(false)
})

it('CertificateVerify: valid RSA-PSS (rsa_pss_rsae_sha384) signature accepted', () => {
	sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -days 2 -subj "/CN=rsa.example"')
	const leaf = new crypto.X509Certificate(fs.readFileSync(path.join(D, 'rsa.crt')))
	const priv = crypto.createPrivateKey(fs.readFileSync(path.join(D, 'rsa.key')))
	const transcriptHash = crypto.createHash('sha384').update('x').digest()
	const content = Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'), Buffer.from([0]), transcriptHash])
	const sig = crypto.sign('sha384', content, { key: priv, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST })
	expect(verifyCertVerify({ scheme: 0x0805, signature: sig, leaf, transcriptHash })).toBe(true)
})

it('parseCertificateList round-trips a Certificate message (plain + brotli)', () => {
	const leafDer = der('good.crt')
	const entry = Buffer.concat([u24(leafDer.length), leafDer, Buffer.from([0, 0])])  // cert + empty exts
	const body = Buffer.concat([Buffer.from([0]), u24(entry.length), entry])          // empty ctx + list
	const certs = parseCertificateList(body)
	expect(certs.length).toBe(1)
	expect(certs[0].equals(leafDer)).toBe(true)
	const viaBrotli = parseCertificateList(zlib.brotliDecompressSync(zlib.brotliCompressSync(body)))
	expect(viaBrotli[0].equals(leafDer)).toBe(true)
})

it('parseCertificateList rejects truncated input instead of silently mis-parsing', () => {
	expect(() => parseCertificateList(Buffer.from([0x00, 0x00, 0x00, 0x10]))).toThrow()  // claims 16-byte list, none present
})
