// Certificate chain validation — accept/reject paths.

import { execSync } from 'node:child_process'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import * as tls from 'node:tls'

import { expect, it } from 'vitest'

import { validateChain, hostnameMatches, trustedRoots, setTrustedRoots } from '../../lib/tls/cert-validate.ts'

// openssl is fed paths we generated ourselves under os.tmpdir(); nothing user-controlled reaches it.
function withCertDir(fn: (dir: string) => void): void {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjcert-'))
	try { fn(dir) } finally { fs.rmSync(dir, { recursive: true, force: true }) }
}

function genSelfSigned(cn: string, san = `DNS:${cn}`, validity = 1): Buffer {
	let der!: Buffer
	withCertDir((dir) => {
		const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days ${validity} -subj "/CN=${cn}" -addext "subjectAltName=${san}" 2>/dev/null`)
		der = Buffer.from(new crypto.X509Certificate(fs.readFileSync(c)).raw)
	})
	return der
}

function genCertPem(cn: string, san: string): string {
	let pem!: string
	withCertDir((dir) => {
		const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=${cn}" -addext "subjectAltName=${san}" 2>/dev/null`)
		pem = fs.readFileSync(c, 'utf8')
	})
	return pem
}

it('hostnameMatches: exact match', () => {
	const cert = new crypto.X509Certificate(genCertPem('example.com', 'DNS:example.com,DNS:*.example.com'))
	expect(hostnameMatches(cert, 'example.com')).toBe(true)
})

it('hostnameMatches: wildcard match', () => {
	const cert = new crypto.X509Certificate(genCertPem('test', 'DNS:*.example.com'))
	expect(hostnameMatches(cert, 'foo.example.com'), 'one-level wildcard match').toBe(true)
	expect(hostnameMatches(cert, 'example.com'), 'wildcard does not match parent').toBe(false)
	expect(hostnameMatches(cert, 'foo.bar.example.com'), 'wildcard does not match nested').toBe(false)
})

it('hostnameMatches: case-insensitive', () => {
	const cert = new crypto.X509Certificate(genCertPem('test', 'DNS:Example.COM'))
	expect(hostnameMatches(cert, 'example.com')).toBe(true)
	expect(hostnameMatches(cert, 'EXAMPLE.COM')).toBe(true)
})

it('validateChain rejects self-signed not in trust store', () => {
	expect(validateChain([genSelfSigned('localhost')], 'localhost'))
		.toEqual({ ok: false, reason: expect.stringMatching(/chain does not terminate in a trusted root/) })
})

it('validateChain rejects hostname mismatch', () => {
	expect(validateChain([genSelfSigned('legit.com')], 'evil.com'))
		.toEqual({ ok: false, reason: expect.stringMatching(/does not match hostname/) })
})

it('validateChain rejects expired cert (notAfter in past)', () => {
	// Generate a cert valid for 1 day, then evaluate it 2 days from "now".
	const der = genSelfSigned('localhost')
	const future = Date.now() + 2 * 24 * 60 * 60 * 1000
	expect(validateChain([der], 'localhost', { now: future }))
		.toEqual({ ok: false, reason: expect.stringMatching(/expired/) })
})

it('validateChain rejects empty chain', () => {
	expect(validateChain([], 'example.com').ok).toBe(false)
})

it('trustedRoots populates from Node bundled CAs (non-zero)', () => {
	const roots = trustedRoots()
	expect(roots.length, `expected > 50 bundled roots, got ${roots.length}`).toBeGreaterThan(50)
})

it('cached chain result is keyed by host and cleared when the trust store changes', () => {
	const pem = genCertPem('localhost', 'DNS:localhost')
	const der = Buffer.from(new crypto.X509Certificate(pem).raw)
	try {
		setTrustedRoots([pem])
		expect(validateChain([der], 'localhost').ok, 'trusted chain accepted').toBe(true)
		expect(validateChain([der], 'localhost').ok, 'repeat call served from cache').toBe(true)
		expect(validateChain([der], 'other.example').ok, 'different host must not reuse the entry').toBe(false)
		setTrustedRoots([])
		expect(validateChain([der], 'localhost').ok, 'same chain rejected after trust store reset').toBe(false)
	} finally {
		setTrustedRoots(tls.rootCertificates)
	}
})
