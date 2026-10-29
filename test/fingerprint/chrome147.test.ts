// Fingerprint regression test: drives our TLS class directly into its built-in
// http2 session and asserts JA4 / Akamai fingerprint vs the captured Chrome 147 fixture.
//
// Live network (tls.peet.ws): `network` project only. `npm run test:fingerprint`.

import * as fs from 'node:fs'
import * as path from 'node:path'

import { beforeAll, expect, it } from 'vitest'

import { TLS } from '../../lib/tls/tls.ts'

// What peet.ws reports about the handshake it watched. Only the fields compared below.
interface PeetReport {
	http_version?: string
	tls?: {
		ja4?: string
		tls_version_negotiated?: string
		ciphers?: string[]
		extensions?: Array<{
			name: string
			signature_algorithms?: string[]
			supported_groups?: string[]
			versions?: string[]
		}>
	}
	http2?: {
		akamai_fingerprint?: string
		sent_frames?: Array<{ frame_type: string; flags?: string[]; headers?: string[] }>
	}
}

const fixture = JSON.parse(
	fs.readFileSync(path.join(import.meta.dirname, '../fixtures/chrome147-peet.json'), 'utf8'),
) as PeetReport

let json: PeetReport = {}

beforeAll(async () => {
	const tls = new TLS('tls.peet.ws', 443, null)
	json = await new Promise<PeetReport>((resolve, reject) => {
		const t = setTimeout(() => reject(new Error('timeout')), 15_000)
		tls.on('ready', () => {
			const req = tls.h2Session!.request({
				':method': 'GET',
				':authority': 'tls.peet.ws',
				':scheme': 'https',
				':path': '/api/all',
				'sec-ch-ua': '"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
				'sec-ch-ua-mobile': '?0',
				'sec-ch-ua-platform': '"macOS"',
				'upgrade-insecure-requests': '1',
				'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36',
				'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
				'sec-fetch-site': 'none',
				'sec-fetch-mode': 'navigate',
				'sec-fetch-user': '?1',
				'sec-fetch-dest': 'document',
				'accept-encoding': 'gzip, deflate, br, zstd',
				'accept-language': 'en-US,en;q=0.9,es;q=0.8',
				'priority': 'u=0, i',
			}, { endStream: true, weight: 256, exclusive: true, parent: 0 })
			const chunks: Buffer[] = []
			req.on('data', (c: Buffer) => chunks.push(c))
			req.on('end', () => {
				clearTimeout(t)
				tls.h2Session!.close()
				try {
					resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as PeetReport)
				} catch (e) { reject(e) }
			})
			req.on('error', (e: Error) => { clearTimeout(t); reject(e) })
		})
		tls.on('ready-http1', () => reject(new Error('server picked http/1.1 instead of h2')))
		tls.on('error', (e: Error) => { clearTimeout(t); reject(e) })
		void tls.connect()
	})
}, 30_000)

// GREASE codepoints rotate per handshake, so every comparison normalises them away first.
const norm = (s: string): string => s.replace(/0x[0-9a-f]{4}/i, 'GREASE')

// The lists compared below are ASCII names, so a plain bytewise comparator is enough and
// keeps the order identical in both locales the suite can run in.
function byName(a: string, b: string): number {
	if (a === b) return 0
	return a < b ? -1 : 1
}

// peet.ws nests the algorithm/group lists inside the extension that carries them.
const extList = (body: PeetReport, prefix: string, key: string): string[] =>
	(body.tls?.extensions?.find((e) => e.name.startsWith(prefix)) as Record<string, string[]> | undefined)?.[key]
	?? []

const headersFrame = (body: PeetReport) => body.http2?.sent_frames?.find((f) => f.frame_type === 'HEADERS')

it('http_version', () => {
	expect(json.http_version).toBe(fixture.http_version)
})

it('tls_version_negotiated', () => {
	expect(json.tls?.tls_version_negotiated).toBe(fixture.tls?.tls_version_negotiated)
})

it('ja4', () => {
	expect(json.tls?.ja4).toBe(fixture.tls?.ja4)
})

it('akamai_fingerprint', () => {
	expect(json.http2?.akamai_fingerprint).toBe(fixture.http2?.akamai_fingerprint)
})

it('ciphers', () => {
	expect(json.tls?.ciphers?.map(norm)).toStrictEqual(fixture.tls?.ciphers?.map(norm))
})

it('extensions (set)', () => {
	const names = (b: PeetReport) => b.tls?.extensions?.map((e) => norm(e.name)).sort(byName)
	expect(names(json)).toStrictEqual(names(fixture))
})

it('signature_algorithms', () => {
	expect(extList(json, 'signature_algorithms', 'signature_algorithms'))
		.toStrictEqual(extList(fixture, 'signature_algorithms', 'signature_algorithms'))
})

it('supported_groups', () => {
	expect(extList(json, 'supported_groups', 'supported_groups').map(norm))
		.toStrictEqual(extList(fixture, 'supported_groups', 'supported_groups').map(norm))
})

it('supported_versions', () => {
	expect(extList(json, 'supported_versions', 'versions').map(norm))
		.toStrictEqual(extList(fixture, 'supported_versions', 'versions').map(norm))
})

it('h2 HEADERS flags', () => {
	expect(headersFrame(json)?.flags?.slice().sort(byName)).toStrictEqual(headersFrame(fixture)?.flags?.slice().sort(byName))
})

// Header *order* (we expect to send them in a Chrome-matching order). The fixture carries a
// 'referer' from real page navigation that a bare /api/all fetch cannot send, so it is excluded.
it('h2 header order', () => {
	const names = (b: PeetReport) => headersFrame(b)?.headers?.map((h) => h.split(':', 1)[0] || h.split(': ', 1)[0])
	const theirs = names(fixture)?.filter((n) => n !== 'referer')
	expect(names(json)).toStrictEqual(theirs)
})
