// Keepalive must not change the HTTP/2 fingerprint. A pooled h2 connection sends no new
// ClientHello, so the only bytes an observer can fingerprint on request #2 are the HEADERS
// frame. This asserts those bytes are identical across two requests on the SAME H2Session.

import { expect, it } from 'vitest'

import * as frame from '../../lib/h2/frame.ts'
import { H2Session } from '../../lib/h2/session.ts'
import { buildH2Headers } from '../../lib/headers.ts'
import profile from '../../lib/profiles/chrome147-mac.ts'

import type { H2Transport } from '../../lib/h2/session.ts'

function capture(): { transport: H2Transport; bytes: () => Buffer } {
	const chunks: Buffer[] = []
	const transport = {
		write(chunk: Buffer) {
			chunks.push(Buffer.from(chunk))
		},
		on() {
			return transport
		}
	} as unknown as H2Transport
	return { transport, bytes: () => Buffer.concat(chunks) }
}

const { transport, bytes } = capture()
const session = new H2Session(transport, profile)
const opts = { endStream: true, weight: 256, exclusive: true, parent: 0 }
const headers = () => buildH2Headers({ method: 'GET', host: 'tls.peet.ws', path: '/api/all', userHeaders: {}, profile })

session.request(headers(), opts)
session.request(headers(), opts)

const all = bytes()
const frames: frame.Frame[] = []
let off = 24 // client preface
while (off < all.length) {
	const f = frame.parse(all.subarray(off))
	if (!f) break
	frames.push(f)
	off += f.consumed
}
const headersFrames = frames.filter((f) => f.type === frame.TYPE.HEADERS)
const flags = headersFrames.map((f) => f.flags)
const payloads = headersFrames.map((f) => Buffer.from(f.payload))

it('two requests on one session emit a HEADERS frame each', () => {
	expect(headersFrames).toHaveLength(2)
})

it('keepalive preserves END_STREAM | END_HEADERS | PRIORITY flags', () => {
	const expected = frame.FLAG.END_STREAM | frame.FLAG.END_HEADERS | frame.FLAG.PRIORITY
	expect(flags).toStrictEqual([expected, expected])
})

it('keepalive preserves the HEADERS payload byte-for-byte', () => {
	// Includes the 5-byte priority payload and the full HPACK block — this is the exact
	// material an on-path Akamai-style observer hashes into its h2 fingerprint.
	expect(payloads[1]).toEqual(payloads[0])
})

it('keepalive emits no extra SETTINGS or WINDOW_UPDATE frames', () => {
	expect(frames.filter((f) => f.type === frame.TYPE.SETTINGS)).toHaveLength(1)
	expect(frames.filter((f) => f.type === frame.TYPE.WINDOW_UPDATE)).toHaveLength(1)
})
