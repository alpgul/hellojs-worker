// Micro-benchmarks for the pure hot-path helpers (no sockets, no TLS).
//
//   npm run bench:micro
//   MICRO_FILTER=huffman MICRO_MS=500 npm run bench:micro
//
// Each entry runs a calibration pass, then three measured passes; the median ns/op is reported.
// MICRO_FILTER matches a substring of the bench name. MICRO_MS is the target time per pass.

import { hrtime } from 'node:process'

import { parseSetCookie } from '../../lib/cookies.ts'
import { buildH1Headers, buildH2Headers, mergeProfileHeaders } from '../../lib/headers.ts'
import { DynamicTable as HpackTable, decode as hpackDecode, encode as hpackEncode } from '../../lib/h2/hpack.ts'
import { decode as huffmanDecode, encode as huffmanEncode } from '../../lib/h3/huffman.ts'
import { decodeHeaders as qpackDecode, encodeHeaders as qpackEncode, findStatic } from '../../lib/h3/qpack.ts'
import { decode as varintDecode, encode as varintEncode } from '../../lib/h3/varint.ts'
import * as profiles from '../../lib/profiles/index.ts'

const FILTER = process.env.MICRO_FILTER ?? ''
const TARGET_MS = Number(process.env.MICRO_MS ?? 300)

const profile = profiles.get('chrome147-mac')
const chromeHeaders: Array<[string, string]> = [
	[':method', 'GET'],
	[':authority', 'www.cloudflare.com'],
	[':scheme', 'https'],
	[':path', '/cdn-cgi/trace'],
	['accept', '*/*'],
	['accept-encoding', 'gzip, deflate, br, zstd'],
	['accept-language', 'en-US,en;q=0.9'],
	['cache-control', 'no-cache'],
	['pragma', 'no-cache'],
	['sec-ch-ua', '"Chromium";v="147", "Google Chrome";v="147"'],
	['sec-ch-ua-mobile', '?0'],
	['sec-ch-ua-platform', '"macOS"'],
	['sec-fetch-dest', 'empty'],
	['sec-fetch-mode', 'cors'],
	['sec-fetch-site', 'none'],
	['upgrade-insecure-requests', '1'],
	['user-agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/147.0.0.0 Safari/537.36']
]
// Only caller-controlled headers: profile-fixed ones (sec-ch-*, user-agent, ...) throw by design.
const userHeaders = {
	'x-request-id': 'req-1234567890',
	'x-client-trace': 'trace-abcdef0123456789',
	'cache-control': 'no-cache',
	pragma: 'no-cache'
}
const huffmanInput = chromeHeaders.map(([k, v]) => `${k}: ${v}`).join('\r\n')
const huffmanBytes = huffmanEncode(huffmanInput)
const hpackBytes = hpackEncode(chromeHeaders, new HpackTable(4096))
const qpackBytes = qpackEncode(chromeHeaders)
const varintBytes = varintEncode(1234)
const setCookie =
	'session=abc123; Path=/; Domain=.example.com; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure; SameSite=None'

const hpackTable = new HpackTable(4096)

const benches: Array<{ name: string; fn: () => unknown }> = [
	{ name: 'hpack-encode-17headers', fn: () => hpackEncode(chromeHeaders, new HpackTable(4096)) },
	{ name: 'hpack-decode-17headers', fn: () => hpackDecode(hpackBytes, hpackTable) },
	{ name: 'huffman-encode-600B', fn: () => huffmanEncode(huffmanInput) },
	{ name: 'huffman-decode-600B', fn: () => huffmanDecode(huffmanBytes) },
	{ name: 'qpack-encodeHeaders-17', fn: () => qpackEncode(chromeHeaders) },
	{ name: 'qpack-decodeHeaders-17', fn: () => qpackDecode(qpackBytes) },
	{ name: 'qpack-findStatic-hit', fn: () => findStatic('user-agent', '') },
	{ name: 'qpack-findStatic-miss', fn: () => findStatic('x-not-in-table', 'value') },
	{ name: 'varint-encode-2B', fn: () => varintEncode(1234) },
	{ name: 'varint-decode-2B', fn: () => varintDecode(varintBytes) },
	{
		name: 'headers-buildH2-with-profile',
		fn: () =>
			buildH2Headers({ method: 'GET', host: 'www.cloudflare.com', path: '/cdn-cgi/trace', userHeaders, profile })
	},
	{
		name: 'headers-buildH1-with-profile',
		fn: () => buildH1Headers({ host: 'www.cloudflare.com', userHeaders, profile })
	},
	{ name: 'headers-mergeProfile', fn: () => mergeProfileHeaders(userHeaders, profile) },
	{ name: 'cookies-parseSetCookie', fn: () => parseSetCookie(setCookie) }
]

let sink: unknown

function passes(fn: () => unknown, iterations: number): number {
	const t0 = hrtime.bigint()
	for (let i = 0; i < iterations; i++) sink = fn()
	return Number(hrtime.bigint() - t0) / iterations
}

function measure(fn: () => unknown): { ns: number; iterations: number } {
	passes(fn, 128)
	let iterations = 256
	let elapsed = passes(fn, iterations) * iterations
	while (elapsed < TARGET_MS * 1e6 && iterations < 100_000_000) {
		iterations *= 2
		elapsed = passes(fn, iterations) * iterations
	}
	const samples = [passes(fn, iterations), passes(fn, iterations), passes(fn, iterations)].sort((a, b) => a - b)
	return { ns: samples[1]!, iterations }
}

console.log(`Node ${process.version}  target=${TARGET_MS}ms/pass  filter=${FILTER || '-'}  median of 3 passes`)
console.log('\nbench                              ns/op       Mops/s    iterations')
console.log('-'.repeat(78))
for (const { name, fn } of benches) {
	if (!name.includes(FILTER)) continue
	const { ns, iterations } = measure(fn)
	console.log(
		`${name.padEnd(35)} ${ns.toFixed(1).padStart(10)} ${(1000 / ns).toFixed(2).padStart(11)} ${String(iterations).padStart(12)}`
	)
}

// Keep the optimizer from discarding the benchmark bodies.
if (sink === undefined) console.log('(no results)')
