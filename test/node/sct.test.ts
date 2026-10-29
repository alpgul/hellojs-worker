// Signed Certificate Timestamp parser tests — the fixture-driven half. The live half
// (a real CT-enforced certificate) lives in test/integration/sct-live.test.ts.

import { execSync } from 'node:child_process'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'

import { expect, it } from 'vitest'

import { extractScts, parseSctList } from '../../lib/tls/sct.ts'

import type { CertificateTimestamp } from '../../lib/tls/sct.ts'

it('extractScts on a cert with no SCT extension returns []', () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sct-'))
	const k = path.join(dir, 'k'), c = path.join(dir, 'c')
	try {
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" 2>/dev/null`)
		const cert = new crypto.X509Certificate(fs.readFileSync(c))
		expect(extractScts(cert.raw)).toStrictEqual([])
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
})

it('parseSctList handles a synthetic 2-SCT list', () => {
	// Build a SignedCertificateTimestampList with two SCTs.
	// Each SCT: version(1)=0 | logId(32) | timestamp(8) | extensions u16-prefixed | sigAlg(2) | sig u16-prefixed.
	function makeSct(logSeed: number, ts: number): Buffer {
		const buf = Buffer.alloc(1 + 32 + 8 + 2 + 2 + 2 + 16)
		let o = 0
		buf[o++] = 0
		Buffer.alloc(32, logSeed).copy(buf, o); o += 32
		buf.writeBigUInt64BE(BigInt(ts), o); o += 8
		buf.writeUInt16BE(0, o); o += 2   // extensions empty
		buf[o++] = 4; buf[o++] = 1        // sha256, RSA
		buf.writeUInt16BE(16, o)          // signature length
		// 16 zero bytes
		return buf
	}
	const sct1 = makeSct(0xaa, 1700000000000)
	const sct2 = makeSct(0xbb, 1700000001000)
	// Wrap each in 2-byte length, then the whole in 2-byte length.
	const inner = Buffer.concat([
		Buffer.from([(sct1.length >> 8) & 0xff, sct1.length & 0xff]), sct1,
		Buffer.from([(sct2.length >> 8) & 0xff, sct2.length & 0xff]), sct2,
	])
	const list = Buffer.concat([
		Buffer.from([(inner.length >> 8) & 0xff, inner.length & 0xff]),
		inner,
	])
	const out: CertificateTimestamp[] = parseSctList(list)
	expect(out.length).toBe(2)
	expect(out[0].timestamp).toBe(1700000000000)
	expect(out[1].timestamp).toBe(1700000001000)
	expect(out[0].logId.length).toBe(32)
	expect(out[0].logId[0]).toBe(0xaa)
	expect(out[1].logId[0]).toBe(0xbb)
})
