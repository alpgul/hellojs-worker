// Live fingerprint regression: the browserleaks observer reports both halves of a Chrome
// handshake — the ClientHello (/tls) and the h2 SETTINGS + HEADERS shape (/http2) — from the
// very connection hellojs just opened. A third request against scrapfly verifies the resumed
// ClientHello, because browserleaks does not issue NewSessionTickets.
//
// Live network: `network` project only. `npm run test:fingerprint`.

import { beforeAll, expect, it } from 'vitest'

import request, { clearPool, clearSessionTickets } from '../../index.ts'
import { BROWSERLEAKS_HOST, FINGERPRINT_HOST } from '../helpers/hosts.ts'

interface TlsReport {
	ja4?: string
	ja4_r?: string
	ja3_text?: string
	tls?: { extensions?: string[]; cipher_suites?: string[] }
}

interface H2Report {
	akamai_hash?: string
	akamai_text?: string
}

const COLD_JA4 = 't13d1516h2_8daaf6152771_d8a2da3f94cd'
const AKAMAI_TEXT = '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p'

let cold: TlsReport = {}
let h2: H2Report = {}
let resumed: TlsReport = {}

beforeAll(async () => {
	const get = async <T>(url: string): Promise<T> => {
		const r = await request(url, { profile: 'chrome147-mac' })
		return (await r.json()) as T
	}

	// Fresh observer state: no pooled socket, no ticket. Both /tls and /http2 are read on
	// separate fresh connections so each assertion describes an initial handshake.
	clearSessionTickets()
	clearPool()
	cold = await get<TlsReport>(`https://${BROWSERLEAKS_HOST}/tls`)
	clearPool()
	h2 = await get<H2Report>(`https://${BROWSERLEAKS_HOST}/http2`)

	// browserleaks does not send NewSessionTicket. Scrapfly does, so use it to observe the
	// resumed ClientHello: prime the ticket on one connection, drop the pool (keeping the
	// ticket) and let a fresh handshake offer the PSK.
	clearSessionTickets()
	clearPool()
	await (
		await request(`https://${FINGERPRINT_HOST}/api/fp/ja3?extended=1`, { profile: 'chrome147-mac' })
	).arrayBuffer()
	clearPool()
	resumed = await get<TlsReport>(`https://${FINGERPRINT_HOST}/api/fp/ja3?extended=1`)
}, 120_000)

it('cold ClientHello JA4 still matches the captured Chrome 147 value', () => {
	expect(cold.ja4).toBe(COLD_JA4)
})

it('cold ClientHello ciphers and extension set are unchanged', () => {
	expect(cold.tls?.extensions).toHaveLength(18)
	expect(cold.tls?.cipher_suites).toHaveLength(16)
})

it('h2 SETTINGS + HEADERS fingerprint matches Chrome', () => {
	expect(h2.akamai_text).toBe(AKAMAI_TEXT)
	expect(h2.akamai_hash).toMatch(/^[0-9a-f]{32}$/)
})

it('resumed ClientHello adds pre_shared_key without disturbing ciphers or groups', () => {
	// 16 -> 17 extensions, same cipher count / ALPN; ja4_c changes because 0x0029 joins the
	// sorted extension list. This is Chrome's own resume shape, not a fingerprint regression.
	expect(resumed.ja4).toMatch(/^t13d1517h2_8daaf6152771_(?!d8a2da3f94cd$)[0-9a-f]{12}$/)
	expect(resumed.ja4_r?.split('_')[2]?.split(',')).toContain('0029')
	const names = (resumed.tls?.extensions ?? []).filter((n) => !/GREASE/i.test(n))
	expect(names).toHaveLength(17) // 16 at cold + pre_shared_key
	expect(names.some((n) => /pre_shared_key \(41\)/.test(n))).toBe(true)
})
