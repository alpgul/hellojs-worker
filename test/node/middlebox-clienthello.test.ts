// End-to-end Phase 1-4 regression: register the user's middlebox-tls12 parrot as a profile,
// drive TLS.startClientHello() against a fake socket, parse the captured ClientHello, and
// assert that what hit the wire matches the parrot. No real network.

import * as fs from 'node:fs'
import * as path from 'node:path'
import { Writable } from 'node:stream'

import { expect, it } from 'vitest'

import * as profiles from '../../lib/profiles/index.ts'
import { TLS } from '../../lib/tls/tls.ts'

import type net from 'node:net'

type PeetSample = Parameters<typeof profiles.registerFromPeet>[1]

const SAMPLE_PATH = path.join(import.meta.dirname, '../fixtures/middlebox-tls12-peet.json')
const SAMPLE = JSON.parse(fs.readFileSync(SAMPLE_PATH, 'utf8')) as PeetSample

// Minimal ClientHello parser. Returns { ciphers, extensionIds, extensionMap } where
// extensionMap[id] is the extension body Buffer (without the 4-byte header).
interface ParsedCh { ciphers: number[]; extensionIds: number[]; extensionMap: Record<number, Buffer> }

function parseClientHello(rec: Buffer): ParsedCh {
	// Record header (5) + handshake header (4) → ClientHello body
	expect(rec[0], 'record type should be handshake').toBe(0x16)
	const recLen = rec.readUInt16BE(3)
	expect(5 + recLen, 'record length matches').toBe(rec.length)
	const hs = rec.subarray(5)
	expect(hs[0], 'handshake type should be ClientHello').toBe(0x01)
	const hsLen = (hs[1] << 16) | (hs[2] << 8) | hs[3]
	expect(4 + hsLen, 'handshake length matches').toBe(hs.length)
	let o = 4
	o += 2          // legacy_version
	o += 32         // random
	const sidLen = hs[o]; o += 1 + sidLen
	const csLen = hs.readUInt16BE(o); o += 2
	const ciphers: number[] = []
	for (let i = 0; i < csLen; i += 2) ciphers.push(hs.readUInt16BE(o + i))
	o += csLen
	const cmLen = hs[o]; o += 1 + cmLen   // compression methods
	const extsLen = hs.readUInt16BE(o); o += 2
	const extsEnd = o + extsLen
	const extensionIds: number[] = []
	const extensionMap: Record<number, Buffer> = {}
	while (o < extsEnd) {
		const id = hs.readUInt16BE(o); o += 2
		const len = hs.readUInt16BE(o); o += 2
		extensionIds.push(id)
		extensionMap[id] = hs.subarray(o, o + len)
		o += len
	}
	return { ciphers, extensionIds, extensionMap }
}

function makeTls(profileName: string): { tls: TLS; getCh: () => Buffer } {
	// TLS constructor is (host, port, proxy, opts) — proxy in 3rd arg, opts in 4th.
	const tls = new TLS('tls.peet.ws', 443, null, { profile: profileName })
	// startClientHello writes to this.socket.write — install a buffer-capturing fake.
	const chunks: Buffer[] = []
	tls.socket = new Writable({
		write(chunk, _enc, cb) { chunks.push(chunk as Buffer); cb() },
	}) as unknown as net.Socket
	// In TLS 1.2-only mode startClientHello uses this.mlkemPk only when _profileNeedsMlkem();
	// for TLS 1.3 profiles set a stub here so we don't have to call connect() (which opens TCP).
	tls.mlkemPk = Buffer.alloc(1184)
	return { tls, getCh: () => Buffer.concat(chunks) }
}

it('middlebox parrot composes a valid ClientHello with the right shape', () => {
	const p = profiles.registerFromPeet('middlebox-tls12', SAMPLE)
	// Sanity: profile is configured for no-GREASE + TLS-1.2-only.
	expect(p.tls.useGrease).toBe(false)
	expect(p.tls.supportedVersions).toStrictEqual([0x0303])

	const { tls, getCh } = makeTls('middlebox-tls12')
	tls.startClientHello()
	const { ciphers, extensionIds, extensionMap } = parseClientHello(getCh())

	// (Phase 1) Cipher list: SCSV (0x00ff) present, no GREASE codepoint.
	expect(ciphers.includes(0x00ff), 'SCSV (0x00ff) in cipher list').toBe(true)
	expect(ciphers.every((c) => (c & 0x0f0f) !== 0x0a0a),
		'no GREASE codepoint in cipher list when useGrease=false').toBe(true)

	// (Phase 2) Extensions 17 and 50 emitted (not silently dropped).
	expect(extensionIds.includes(17), 'status_request_v2 (17) in ClientHello').toBe(true)
	expect(extensionIds.includes(50), 'signature_algorithms_cert (50) in ClientHello').toBe(true)

	// (Phase 2) signature_algorithms_cert body must equal the raw bytes captured from peet.
	const expectedRaw = Buffer.from(
		'00260403050306030804080508060809080a080b0401050106010402030303010302020302010202',
		'hex')
	expect(expectedRaw.equals(extensionMap[50]),
		'signature_algorithms_cert body is byte-identical to fixture').toBe(true)

	// (Phase 3) No GREASE extension bookends.
	expect(extensionIds.every((id) => (id & 0x0f0f) !== 0x0a0a),
		'no GREASE extension when useGrease=false').toBe(true)

	// (Phase 4) No key_share (id 51) — the profile is TLS-1.2-only.
	expect(extensionIds.includes(51), 'no key_share for TLS-1.2-only profile').toBe(false)

	// supported_versions body: u8 list length || u16 each. Must be 0x0303 only (no GREASE).
	const sv = extensionMap[43]
	expect(sv[0], 'supported_versions list length = 2 (one TLS version)').toBe(2)
	expect(sv.readUInt16BE(1), 'only TLS 1.2 advertised').toBe(0x0303)

	// supported_groups: u16 list length || u16 each. Five groups, no GREASE.
	const sg = extensionMap[10]
	const sgListLen = sg.readUInt16BE(0)
	expect(sgListLen, '5 groups × 2 bytes = 10').toBe(10)
	const offered: number[] = []
	for (let i = 0; i < sgListLen; i += 2) offered.push(sg.readUInt16BE(2 + i))
	expect(offered).toStrictEqual([0x001d, 0x0017, 0x0018, 0x0019, 0x001e])
})

it('chrome147-mac still emits GREASE everywhere expected', () => {
	const { tls, getCh } = makeTls('chrome147-mac')
	tls.startClientHello()
	const { ciphers, extensionIds, extensionMap } = parseClientHello(getCh())

	// Cipher GREASE at the front (any 0x?a?a where high and low nibbles match the GREASE pattern).
	expect(ciphers[0] & 0x0f0f, 'first cipher is GREASE').toBe(0x0a0a)

	// First and last extension are GREASE.
	expect(extensionIds[0] & 0x0f0f).toBe(0x0a0a)
	expect(extensionIds.at(-1)! & 0x0f0f).toBe(0x0a0a)

	// supported_versions starts with GREASE then 0x0304, 0x0303.
	const sv = extensionMap[43]
	expect(sv[0]).toBe(6)
	expect(sv.readUInt16BE(1) & 0x0f0f).toBe(0x0a0a)
	expect(sv.readUInt16BE(3)).toBe(0x0304)
	expect(sv.readUInt16BE(5)).toBe(0x0303)
})

// Mirrors the runtime profile the Next.js request route registers: keep the selected browser
// profile but advertise TLS 1.2 only and drop the ML-KEM group. chrome147-mac has no
// extensionOrder, so the id-51 filter is a no-op and the legacy extension fallback is used.
function registerTls12RuntimeProfile(sourceName: string, runtimeName: string) {
	const source = profiles.get(sourceName)
	profiles.register(runtimeName, {
		...source,
		tls: {
			...source.tls,
			supportedVersions: [0x0303],
			supportedGroups: Array.isArray(source.tls.supportedGroups)
				? source.tls.supportedGroups.filter((g) => g !== 4588)
				: source.tls.supportedGroups,
			keyShareGroups: Array.isArray(source.tls.keyShareGroups)
				? source.tls.keyShareGroups.filter((g) => g !== 4588)
				: source.tls.keyShareGroups,
			extensionOrder: Array.isArray(source.tls.extensionOrder)
				? source.tls.extensionOrder.filter((e) => e?.id !== 51)
				: source.tls.extensionOrder,
		},
	})
}

it('route.ts TLS-1.2 runtime profili: register sonrası ClientHello key_share üretmeden kurulur', () => {
	registerTls12RuntimeProfile('chrome147-mac', 'runtime-tls12-chrome147-mac')
	const runtime = profiles.get('runtime-tls12-chrome147-mac')
	expect(runtime.tls.supportedVersions).toStrictEqual([0x0303])
	expect(runtime.tls.extensionOrder).toBeUndefined() // chrome147-mac uses the legacy fallback

	const { tls, getCh } = makeTls('runtime-tls12-chrome147-mac')
	expect(() => tls.startClientHello()).not.toThrow()

	const { extensionIds, extensionMap } = parseClientHello(getCh())
	expect(extensionIds).not.toContain(51)
	const sv = extensionMap[43]
	const versions: number[] = []
	for (let i = 1; i < 1 + sv[0]; i += 2) versions.push(sv.readUInt16BE(i))
	expect(versions).toContain(0x0303)
	expect(versions).not.toContain(0x0304)
})
