// h2 frame codec — 9-byte header + payload.

import { expect, it } from 'vitest'

import * as frame from '../../lib/h2/frame.ts'
import { hex } from '../helpers/bytes.ts'

it('build + parse round-trip preserves type/flags/streamId/payload', () => {
	const payload = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05])
	const built = frame.build(frame.TYPE.DATA, frame.FLAG.END_STREAM, 7, payload)
	const parsed = frame.parse(built)!
	expect(parsed.type).toBe(frame.TYPE.DATA)
	expect(parsed.flags).toBe(frame.FLAG.END_STREAM)
	expect(parsed.streamId).toBe(7)
	expect(parsed.length).toBe(payload.length)
	expect(hex(parsed.payload)).toBe(hex(payload))
	expect(parsed.consumed).toBe(built.length)
})

it('parse returns null for an incomplete header (< 9 bytes)', () => {
	expect(frame.parse(Buffer.from([0]))).toBeNull()
	expect(frame.parse(Buffer.alloc(8))).toBeNull()
})

it('parse returns null when payload is incomplete', () => {
	// Header claims 100-byte payload, supply only 10
	const incomplete = Buffer.alloc(9 + 10)
	incomplete.writeUIntBE(100, 0, 3)
	expect(frame.parse(incomplete)).toBeNull()
})

it('SETTINGS round-trip preserves id/value pairs', () => {
	const pairs: frame.SettingsPair[] = [
		[frame.SETTING.HEADER_TABLE_SIZE, 65536],
		[frame.SETTING.ENABLE_PUSH, 0],
		[frame.SETTING.MAX_HEADER_LIST_SIZE, 262_144]
	]
	const built = frame.buildSettings(pairs)
	expect(frame.parseSettings(built)).toStrictEqual(pairs)
})

it('stream id top bit is always cleared (reserved bit)', () => {
	const built = frame.build(frame.TYPE.HEADERS, 0, 0xffffffff, Buffer.alloc(0))
	expect(frame.parse(built)!.streamId).toBe(0x7fff_ffff)
})

it('WINDOW_UPDATE payload encodes increment as u32', () => {
	const p = frame.buildWindowUpdate(15_663_105)
	expect(p.length).toBe(4)
	expect(p.readUInt32BE(0)).toBe(15_663_105)
})

it('GOAWAY round-trip preserves lastStreamId + errorCode + debugData', () => {
	const debug = Buffer.from('something went wrong', 'utf8')
	const p = frame.buildGoaway(42, frame.ERROR.PROTOCOL_ERROR, debug)
	const parsed = frame.parseGoaway(p)
	expect(parsed.lastStreamId).toBe(42)
	expect(parsed.errorCode).toBe(frame.ERROR.PROTOCOL_ERROR)
	expect(hex(parsed.debugData)).toBe(hex(debug))
})
