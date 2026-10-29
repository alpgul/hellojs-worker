// Fingerprint regression test: drive the default profile at the shared fingerprint reporter and
// compare what it observed with the captured Chrome 147 fixture.
//
// The reporter parses the ClientHello we send (ja4, ciphers, extensions, groups, sig algs), so
// these assertions describe our handshake; the host is only the observer. The Akamai HTTP/2
// fingerprint and the HEADERS frame are asserted offline, from the bytes our session emits, in
// test/unit/h2-chrome-headers.test.ts.
//
// Live network: `network` project only. `npm run test:fingerprint`.

import * as fs from 'node:fs'
import * as path from 'node:path'

import { beforeAll, expect, it } from 'vitest'

import request from '../../index.ts'
import { FINGERPRINT_HOST } from '../helpers/hosts.ts'

// Only the fields compared below; the service returns far more.
interface ScrapflyReport {
	ja4?: string
	tls?: {
		ciphers?: string[]
		curves?: string[]
		extensions?: string[]
		signature_algorithms?: number[]
		versions?: string[]
		selected_protocol?: string
		selected_cipher_suite?: number
	}
}

interface FixtureReport {
	http_version?: string
	tls?: {
		ja4?: string
		ja4_r?: string
		tls_version_negotiated?: string
		ciphers?: string[]
		extensions?: Array<{
			name: string
			supported_groups?: string[]
			versions?: string[]
		}>
	}
}

const fixture = JSON.parse(
	fs.readFileSync(path.join(import.meta.dirname, '../fixtures/chrome147-peet.json'), 'utf8'),
) as FixtureReport

let live: ScrapflyReport = {}

beforeAll(async () => {
	live = await request<ScrapflyReport>({
		url: `https://${FINGERPRINT_HOST}/api/fp/ja3?extended=1`,
		json: true,
	})
}, 30_000)

// GREASE codepoints rotate per handshake and every reporter spells them differently
// ("TLS_GREASE (0x4A4A)" vs "0xCACA"), so every comparison drops them entirely first.
function codeOf(name: string): number {
	const hex = name.match(/\(0x([0-9a-f]+)\)/i) ?? name.match(/^(0x[0-9a-f]{4})$/i)
	if (hex) return Number.parseInt(hex[1], 16)
	const dec = name.match(/\((\d+)\)/)
	return dec ? Number(dec[1]) : Number.NaN
}
const isGreaseCode = (code: number): boolean => (code & 0x0f_0f) === 0x0a_0a
const withoutGrease = (names: string[]): string[] =>
	names.filter((n) => !isGreaseCode(codeOf(n)))

const extensionIds = (names: string[]): number[] =>
	withoutGrease(names).map(codeOf).sort((a, b) => a - b)

const fixtureExtension = (prefix: string): { supported_groups?: string[]; versions?: string[] } =>
	fixture.tls?.extensions?.find((e) => e.name.startsWith(prefix)) ?? {}

const toHex = (codes: number[]): string =>
	codes.filter((c) => !isGreaseCode(c)).map((c) => c.toString(16).padStart(4, '0')).join(',')

const VERSION_CODE: Record<string, number> = { 'TLS 1.3': 772, 'TLS 1.2': 771 }
const versionCode = (name: string): number => VERSION_CODE[name] ?? codeOf(name)

it('http_version', () => {
	expect(live.tls?.selected_protocol).toBe(fixture.http_version)
})

it('tls_version_negotiated', () => {
	// The reporter does not repeat the negotiated version, but a TLS 1.3 cipher suite can only
	// be selected under 772 (RFC 8446 §9.2).
	expect(fixture.tls?.tls_version_negotiated).toBe('772')
	expect([0x13_01, 0x13_02, 0x13_03]).toContain(live.tls?.selected_cipher_suite)
})

it('ja4', () => {
	expect(live.ja4).toBe(fixture.tls?.ja4)
})

it('ciphers', () => {
	expect(withoutGrease(live.tls?.ciphers ?? []))
		.toStrictEqual(withoutGrease(fixture.tls?.ciphers ?? []))
})

it('extensions (set)', () => {
	expect(extensionIds(live.tls?.extensions ?? []))
		.toStrictEqual(extensionIds(fixture.tls?.extensions?.map((e) => e.name) ?? []))
})

it('signature_algorithms', () => {
	// The fixture records the list as hex inside ja4_r; compare in the same form.
	const expected = fixture.tls?.ja4_r?.split('_')[3]
	expect(toHex(live.tls?.signature_algorithms ?? [])).toBe(expected)
})

it('supported_groups', () => {
	// The two sides name the same curves differently (P-256 vs secp256r1), so compare codes.
	expect(withoutGrease(live.tls?.curves ?? []).map(codeOf))
		.toStrictEqual(withoutGrease(fixtureExtension('supported_groups').supported_groups ?? []).map(codeOf))
})

it('supported_versions', () => {
	expect((live.tls?.versions ?? []).map(Number).filter((v) => !isGreaseCode(v)))
		.toStrictEqual(
			(fixtureExtension('supported_versions').versions ?? [])
				.map(versionCode)
				.filter((v) => !isGreaseCode(v)),
		)
})
