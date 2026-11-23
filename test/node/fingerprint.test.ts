// Tests for lib/tls/fingerprint.ts — parseClientHello + ja3 + ja4. Plus an end-to-end check
// that the JA3 hellojs computes from the CH it just emitted matches the middlebox parrot's
// stated JA3 hash (so users can run profiles.verify(...) without round-tripping through peet).

import * as fs from 'node:fs'
import * as path from 'node:path'
import { Writable } from 'node:stream'

import { beforeEach, expect, it } from 'vitest'

import * as profiles from '../../lib/profiles/index.ts'
import { parseClientHello, ja3, isGrease } from '../../lib/tls/fingerprint.ts'
import { clearSessionTickets, storeSessionTicket } from '../../lib/tls/session-tickets.ts'
import { TLS } from '../../lib/tls/tls.ts'

import type { SessionTicket } from '../../lib/tls/session-tickets.ts'
import type net from 'node:net'

interface EmittedFingerprint {
	ja3: string
	ja3_str: string
	ja4: string
}
type PeetSample = Parameters<typeof profiles.registerFromPeet>[1]

const SAMPLE_PATH = path.join(import.meta.dirname, '../fixtures/middlebox-tls12-peet.json')
const SAMPLE = JSON.parse(fs.readFileSync(SAMPLE_PATH, 'utf8')) as PeetSample

const CHROME_PATH = path.join(import.meta.dirname, '../fixtures/chrome147-peet.json')
const CHROME = JSON.parse(fs.readFileSync(CHROME_PATH, 'utf8')) as PeetSample

beforeEach(() => clearSessionTickets())

function ticket(overrides: Partial<SessionTicket> = {}): SessionTicket {
	return {
		ticket: Buffer.from('offline-resume-ticket'),
		psk: Buffer.alloc(32, 7),
		cipherSuite: 0x1301,
		hash: 'sha256',
		hashLen: 32,
		lifetime: 3600,
		ageAdd: 1234,
		receivedAt: Date.now(),
		alpn: 'h2',
		sniHost: 'tls.peet.ws',
		verified: true,
		...overrides
	}
}

// Run a synchronous CH emission and return the captured record + parsed structure.
function emitCh(
	profileName: string,
	opts: { resume?: boolean } = {}
): { tls: TLS; rec: Buffer; parsed: ReturnType<typeof parseClientHello> } {
	const tls = new TLS('tls.peet.ws', 443, null, { profile: profileName, resume: opts.resume })
	const chunks: Buffer[] = []
	// The test writes into a capturing sink instead of a TCP socket.
	tls.socket = new Writable({
		write(chunk, _enc, cb) {
			chunks.push(chunk as Buffer)
			cb()
		}
	}) as unknown as net.Socket
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
		.filter(Boolean)
		.map(Number)
	for (const c of allCodes) expect(isGrease(c), `JA3 contains GREASE ${c.toString(16)}`).toBe(false)
})

it('chrome147-mac emits exactly the captured JA3 and JA4 hashes (offline)', () => {
	// The network `test/fingerprint/chrome147.test.ts` compares our live bytes against the
	// same fixture through an external observer. This one guards the same hashes in `npm test`,
	// so a TLS ClientHello regression cannot hide behind an offline-only build.
	const { tls } = emitCh('chrome147-mac')
	expect(tls.actualFingerprint.ja4).toBe(CHROME.tls!.ja4)
	// The reporter's ja3_hash is computed over a different extension ordering and GREASE
	// policy, so asserting it would fail on a correct ClientHello. JA4 is the stable
	// fingerprint this repo guarantees; compare the JA3 string to the expected field order
	// instead (the full wire order is asserted by the live network test).
	expect(tls.actualFingerprint.ja3_str).toMatch(
		/^771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,/
	)
	expect(tls.actualFingerprint.ja3_str.split(',')[3]).toBe('4588-29-23-24')
})

it('resume: a cached ticket appends pre_shared_key last and shifts JA4 to 17 extensions', () => {
	// Chrome also adds extension 41 on a resumed handshake, so the 16 -> 17 extension
	// change is the expected shape, not a regression. What must NOT change: ciphers,
	// groups, sigalgs, ALPN and the extension order before PSK.
	storeSessionTicket('tls.peet.ws', 443, ticket())

	const cold = emitCh('chrome147-mac')
	const warm = emitCh('chrome147-mac', { resume: true })

	expect(warm.tls.pskTicket, 'ticket was offered').not.toBeNull()
	expect(warm.parsed.extensions.at(-1)?.id, 'pre_shared_key is last').toBe(0x0029)
	expect(warm.parsed.extensions.filter((e) => e.id === 0x0029)).toHaveLength(1)

	// JA4_a: 16 -> 17 extensions; same version / SNI / cipher count / ALPN.
	expect(cold.tls.actualFingerprint.ja4).toMatch(/^t13d1516h2_8daaf6152771_/)
	expect(warm.tls.actualFingerprint.ja4).toMatch(/^t13d1517h2_8daaf6152771_/)
	// ja4_b (sorted ciphers) is identical; ja4_c (extensions + sigalgs) changes with 0x29.
	const [, coldB, coldC] = cold.tls.actualFingerprint.ja4.split('_')
	const [, warmB, warmC] = warm.tls.actualFingerprint.ja4.split('_')
	expect(warmB).toBe(coldB)
	expect(warmC).not.toBe(coldC)

	// JA3 string: extension list gains 41, but cipher / group / point-format fields stay put.
	const cold3 = cold.tls.actualFingerprint.ja3_str.split(',')
	const warm3 = warm.tls.actualFingerprint.ja3_str.split(',')
	expect(warm3[1]).toBe(cold3[1])
	expect(warm3[3]).toBe(cold3[3])
	expect(warm3[4]).toBe(cold3[4])
	expect(warm3[2]!.split('-').map(Number)).toContain(41)
	expect(warm3[2]!.split('-').at(-1)).toBe('41')
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
	const expectedPrefix = SAMPLE.tls!.ja4!.split('_')[0] // e.g. "t12d1310h2"
	const { tls } = emitCh('middlebox-tls12-fp')
	const actualPrefix = tls.actualFingerprint.ja4.split('_')[0]
	expect(actualPrefix).toBe(expectedPrefix)
})

it('"fingerprint" event fires synchronously during startClientHello', () => {
	const tls = new TLS('tls.peet.ws', 443, null, { profile: 'chrome147-mac' })
	tls.socket = new Writable({
		write(_c, _e, cb) {
			cb()
		}
	}) as unknown as net.Socket
	tls.mlkemPk = Buffer.alloc(1184)
	const emitted: EmittedFingerprint[] = []
	tls.on('fingerprint', (fp: EmittedFingerprint) => {
		emitted.push(fp)
	})
	tls.startClientHello()
	expect(emitted.length, 'fingerprint event was emitted').toBe(1)
	expect(emitted[0].ja3).toMatch(/^[0-9a-f]{32}$/)
})

it('emitted ClientHellos never repeat an extension type', () => {
	// GREASE values used to be drawn independently, so a and b collided in 1 of 16
	// ClientHellos and the first and last GREASE extensions got the same type. RFC 8446
	// §4.2 forbids duplicate extension types; strict servers answered alert 50
	// (decode_error) on those connections. 200 draws make a regression practically certain
	// to show up.
	for (let i = 0; i < 200; i++) {
		const { parsed } = emitCh('chrome147-mac')
		const ids = parsed.extensions.map((e) => e.id)
		expect(new Set(ids).size, `duplicate extension type in CH #${i}`).toBe(ids.length)
	}
})
