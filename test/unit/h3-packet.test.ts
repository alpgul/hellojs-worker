// Packet builder regression tests — focus on the header-protection sampling
// invariant (RFC 9001 §5.4.2). HP samples 16 bytes starting 4 bytes into the
// packet-number field, so every built packet must carry enough protected bytes;
// short payloads (e.g. a 1-byte PING probe sent on PTO) must be PADDING-padded.

import { expect, it } from 'vitest'

import * as pkt from '../../lib/h3/packet.ts'

import type { PacketKeys } from '../../lib/h3/keys.ts'
import type { ParsedPacket } from '../../lib/h3/packet.ts'

const CK: PacketKeys = { key: Buffer.alloc(16, 1), iv: Buffer.alloc(12, 2), hp: Buffer.alloc(16, 3), secret: Buffer.alloc(32) }
const DST = Buffer.alloc(8, 9)

// The assertions below narrow the discriminated union by hand; a non-1-RTT parse is a real failure.
function oneRtt(parsed: ParsedPacket | null): ParsedPacket & { kind: '1rtt' } {
	if (!parsed || parsed.kind !== '1rtt') throw new Error(`expected a 1-RTT packet, got ${parsed ? parsed.kind : 'null'}`)
	return parsed
}

// Regression for the QUIC PTO crash: _onPtoFire builds a 1-RTT probe carrying a
// single 1-byte PING frame, which previously produced a 15-byte HP sample and threw
// "hp sample must be 16 bytes".
it('1-RTT PING probe builds despite tiny payload (pads for HP sample)', () => {
	for (const pnLen of [1, 2, 3, 4]) {
		const packet = pkt.buildOneRtt({ dstCid: DST, payloadFrames: Buffer.from([0x01]), pn: 5, pnLen, clientKeys: CK })
		// Round-trip: HP removal + decrypt must recover the PING (padding decodes away).
		const parsed = oneRtt(pkt.parsePacket(packet, 0, { oneRtt: { server: CK } }, DST.length))
		const frames = pkt.decodeFrames(parsed.payload)
		expect(frames.some((f) => f.type === 'ping'), `pnLen=${pnLen} ping survives`).toBe(true)
	}
})

it('1-RTT empty-payload packet still builds and round-trips', () => {
	const packet = pkt.buildOneRtt({ dstCid: DST, payloadFrames: Buffer.alloc(0), pn: 1, pnLen: 1, clientKeys: CK })
	oneRtt(pkt.parsePacket(packet, 0, { oneRtt: { server: CK } }, DST.length))
})

it('large 1-RTT payload is not padded (unchanged length)', () => {
	const payload = Buffer.concat([Buffer.from([0x01]), Buffer.alloc(40, 0x02)]) // PING + 40 PADDING
	const packet = pkt.buildOneRtt({ dstCid: DST, payloadFrames: payload, pn: 1, pnLen: 2, clientKeys: CK })
	// header(1 + dstCid + pnLen) + ciphertext(payload + 16 tag)
	expect(packet.length).toBe(1 + DST.length + 2 + payload.length + 16)
})
