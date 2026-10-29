// Tests for lib/tls/fingerprint.ts — parseClientHello + ja3 + ja4. Plus an end-to-end check
// that the JA3 hellojs computes from the CH it just emitted matches the middlebox parrot's
// stated JA3 hash (so users can run profiles.verify(...) without round-tripping through peet).

import * as fs from 'node:fs'
import * as path from 'node:path'
import { Writable } from 'node:stream'

import { expect, it } from 'vitest'

import * as profiles from '../../lib/profiles/index.ts'
import { parseClientHello, ja3, isGrease } from '../../lib/tls/fingerprint.ts'
import { TLS } from '../../lib/tls/tls.ts'

import type net from 'node:net'

interface EmittedFingerprint { ja3: string; ja3_str: string; ja4: string }
type PeetSample = Parameters<typeof profiles.registerFromPeet>[1]

const SAMPLE_PATH = path.join(import.meta.dirname, '../fixtures/middlebox-tls12-peet.json')
const SAMPLE = JSON.parse(fs.readFileSync(SAMPLE_PATH, 'utf8')) as PeetSample

// Run a synchronous CH emission and return the captured record + parsed structure.
function emitCh(profileName: string): { tls: TLS; rec: Buffer; parsed: ReturnType<typeof parseClientHello> } {
	const tls = new TLS('tls.peet.ws', 443, null, { profile: profileName })
	const chunks: Buffer[] = []
	// The test writes into a capturing sink instead of a TCP socket.
	tls.socket = new Writable({ write(chunk, _enc, cb) { chunks.push(chunk as Buffer); cb() } }) as unknown as net.Socket
	tls.mlkemPk = Buffer.alloc(1184)
	tls.startClientHello()
	const rec = Buffer.concat(chunks)
	return { tls, rec, parsed: parseClientHello(rec) }
}

it('isGrease: recognises GREASE codepoints', () => {
	expect(isGrease(0x0a0a)).toBe(true)
	expect(isGrease(0xfafa)).toBe(true)
	expect(isGrease(0xeaea)).toBe(true)
	expect(isGrease(0x1301)).toBe(false)
	expect(isGrease(0x00ff)).toBe(false)
	expect(isGrease(0x0a00)).toBe(false)
	expect(isGrease(0xa0a0)).toBe(false)
})

it('ja3 over chrome147 CH excludes GREASE codepoints in version, ciphers, exts, groups', () => {
	const { parsed } = emitCh('chrome147-mac')
	const j = ja3(parsed)
	// Format: version,ciphers,extensions,groups,point_formats
	const [verStr, ciphersStr, extsStr, groupsStr] = j.str.split(',')
	expect(verStr).toBe('771')
	// No GREASE values anywhere in the string parts.
	const allCodes = [...ciphersStr!.split('-'), ...extsStr!.split('-'), ...groupsStr!.split('-')]
		.filter(Boolean).map(Number)
	for (const c of allCodes) expect(isGrease(c), `JA3 contains GREASE ${c.toString(16)}`).toBe(false)
})

it('ja3 + ja4 are recorded on TLS.actualFingerprint after startClientHello', () => {
	const { tls } = emitCh('chrome147-mac')
	expect(tls.actualFingerprint, 'actualFingerprint set').toBeTruthy()
	expect(tls.actualFingerprint.ja3).toMatch(/^[0-9a-f]{32}$/)
	expect(tls.actualFingerprint.ja4).toMatch(/^t\d\d[di]\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$/)
})

it('ja3 over the middlebox parrot reproduces the fixture hash', () => {
	profiles.registerFromPeet('middlebox-tls12-fp', SAMPLE)
	const { tls } = emitCh('middlebox-tls12-fp')
	// The fixture's ja3_hash is the canonical hash computed by peet.ws's pipeline. If our
	// fingerprint module disagrees, either the JA3 algorithm or the CH bytes diverged.
	// PeetJson types every section optional because a live response can omit one; this
	// checked-in fixture is known to carry both hashes.
	expect(tls.actualFingerprint.ja3).toBe(SAMPLE.tls!.ja3_hash!)
})

it('ja4 over the middlebox parrot reproduces the JA4_a prefix from the fixture', () => {
	const expectedPrefix = SAMPLE.tls!.ja4!.split('_')[0]   // e.g. "t12d1310h2"
	const { tls } = emitCh('middlebox-tls12-fp')
	const actualPrefix = tls.actualFingerprint.ja4.split('_')[0]
	expect(actualPrefix).toBe(expectedPrefix)
})

it('"fingerprint" event fires synchronously during startClientHello', () => {
	const tls = new TLS('tls.peet.ws', 443, null, { profile: 'chrome147-mac' })
	tls.socket = new Writable({ write(_c, _e, cb) { cb() } }) as unknown as net.Socket
	tls.mlkemPk = Buffer.alloc(1184)
	const emitted: EmittedFingerprint[] = []
	tls.on('fingerprint', (fp: EmittedFingerprint) => { emitted.push(fp) })
	tls.startClientHello()
	expect(emitted.length, 'fingerprint event was emitted').toBe(1)
	expect(emitted[0].ja3).toMatch(/^[0-9a-f]{32}$/)
})
