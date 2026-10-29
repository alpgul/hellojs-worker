// The h2 frames the Chrome 147 profile emits, compared with the capture from the real browser
// (test/fixtures/chrome147-peet.json). The live fingerprint reporter parses the ClientHello
// only; everything observed at the HTTP/2 layer is asserted here, from our own bytes, with no
// network involved.

import { expect, it } from 'vitest'

import * as frame from '../../lib/h2/frame.ts'
import * as hpack from '../../lib/h2/hpack.ts'
import { H2Session } from '../../lib/h2/session.ts'
import { buildH2Headers } from '../../lib/headers.ts'
import profile from '../../lib/profiles/chrome147-mac.ts'

import type { H2Transport } from '../../lib/h2/session.ts'

function capture(): { transport: H2Transport; bytes: () => Buffer } {
	const chunks: Buffer[] = []
	const transport = {
		write(chunk: Buffer) { chunks.push(Buffer.from(chunk)) },
		on() { return transport },
	} as unknown as H2Transport
	return { transport, bytes: () => Buffer.concat(chunks) }
}

// What the browser sent, minus `referer` (a page-navigation header no bare fetch carries).
const EXPECTED_NAMES = [
	':method', ':authority', ':scheme', ':path',
	'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests',
	'user-agent', 'accept', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user',
	'sec-fetch-dest', 'accept-encoding', 'accept-language', 'priority'
]

// Chrome sets END_STREAM (a GET ends with HEADERS), END_HEADERS (block fits one frame) and
// PRIORITY (E=1, weight=256), the last one being the flag the fixture also records.
const EXPECTED_FLAGS = frame.FLAG.END_STREAM | frame.FLAG.END_HEADERS | frame.FLAG.PRIORITY

// The captured Akamai HTTP/2 fingerprint: SETTINGS in wire order | connection WINDOW_UPDATE
// increment | PRIORITY frames | pseudo-header order.
const EXPECTED_AKAMAI = '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p'

const { transport, bytes } = capture()
const session = new H2Session(transport, profile)
session.request(
	buildH2Headers({ method: 'GET', host: 'tls.peet.ws', path: '/api/all', userHeaders: {}, profile }),
	{ endStream: true, weight: 256, exclusive: true, parent: 0 },
)

// Frame stream: 24-byte preface, SETTINGS, WINDOW_UPDATE, HEADERS.
const all = bytes()
const frames: frame.Frame[] = []
let off = 24
while (off < all.length) {
	const f = frame.parse(all.subarray(off))
	if (!f) break
	frames.push(f)
	off += f.consumed
}
const headers = frames.find((f) => f.type === frame.TYPE.HEADERS)!
// 5-byte priority payload precedes the HPACK block when PRIORITY is set (RFC 7540 §6.2).
const names = hpack.decode(headers.payload.subarray(5), new hpack.DynamicTable(4096))
	.map(([name]) => name)

it('HEADERS carries END_STREAM | END_HEADERS | PRIORITY', () => {
	expect(headers.flags).toBe(EXPECTED_FLAGS)
})

it('header names are emitted in Chrome order', () => {
	expect(names).toStrictEqual(EXPECTED_NAMES)
})

it('akamai fingerprint matches', () => {
	const settings = frame.parseSettings(frames.find((f) => f.type === frame.TYPE.SETTINGS)!.payload)
	const windowUpdate = frames.find((f) => f.type === frame.TYPE.WINDOW_UPDATE)!.payload.readUInt32BE(0) & 0x7fff_ffff
	const pseudo = names.filter((n) => n.startsWith(':')).map((n) => n[1]).join(',')
	expect([
		settings.map(([id, value]) => `${id}:${value}`).join(';'),
		windowUpdate,
		0, // no standalone PRIORITY frames; Chrome folds the priority into HEADERS
		pseudo,
	].join('|')).toBe(EXPECTED_AKAMAI)
})
