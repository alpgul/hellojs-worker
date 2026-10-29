// HTTP/3 layer (RFC 9114) on top of our QUIC connection.
//
// Streams:
//   - Control stream (client-initiated unidirectional, type 0x00) carries SETTINGS
//   - QPACK encoder stream (uni, type 0x02) — we send empty; we never insert into dynamic table
//   - QPACK decoder stream (uni, type 0x03) — we send empty
//   - Request streams (client-initiated bidirectional) carry HEADERS + DATA frames
//
// Frame types (RFC 9114 §7):
//   0x00 DATA       — request/response body bytes
//   0x01 HEADERS    — QPACK-encoded field section
//   0x04 SETTINGS   — connection settings
//   0x07 GOAWAY
//   0x0d MAX_PUSH_ID

import * as qpack from './qpack.ts'
import * as varint from './varint.ts'

import type { QuicConnection, QuicStream } from './connection.ts'
import type { HeaderEntry } from './qpack.ts'
import type { DecodedVarint } from './varint.ts'

type Setting = [id: number, value: number]

const FRAME = {
	DATA: 0x00,
	HEADERS: 0x01,
	SETTINGS: 0x04,
	GOAWAY: 0x07,
	MAX_PUSH_ID: 0x0d,
}

// Chrome 147 h3 SETTINGS — captured/inferred values:
//   QPACK_MAX_TABLE_CAPACITY (0x01) = 65536
//   MAX_FIELD_SECTION_SIZE (0x06) = 65536
//   QPACK_BLOCKED_STREAMS (0x07) = 100
//   plus a GREASE setting (0x1c through 0x21 randomly chosen)
const CHROME_147_SETTINGS: Setting[] = [
	[0x01, 65536],
	[0x06, 65536],
	[0x07, 100],
]

export interface H3RequestOptions {
	method: string
	path: string
	host: string
	// Values reach QPACK as-is; a non-string is the caller's mistake, exactly as before typing.
	headers?: Record<string, unknown>
	body?: Buffer | NodeJS.ReadableStream | null
}

export interface H3Response {
	status: number
	headers: Record<string, string>
	body: Buffer
}

function encodeFrame(type: number, payload: Buffer): Buffer {
	return Buffer.concat([varint.encode(type), varint.encode(payload.length), payload])
}

function encodeSettings(settings: Setting[] = CHROME_147_SETTINGS): Buffer {
	const parts: Buffer[] = []
	for (const [id, value] of settings) {
		parts.push(varint.encode(id))
		parts.push(varint.encode(value))
	}
	return encodeFrame(FRAME.SETTINGS, Buffer.concat(parts))
}

class H3Client {
	declare conn: QuicConnection
	declare controlStream: QuicStream | null
	declare encoderStream: QuicStream | null
	declare decoderStream: QuicStream | null
	declare bootstrapped: boolean

	// QPACK dynamic table replica — populated from server's encoder stream.
	declare peerDynamicTable: qpack.DynamicTable
	declare peerEncoderBuf: Buffer
	declare peerQpackMaxTableCapacity: number   // populated when we see server SETTINGS

	constructor(quicConn: QuicConnection) {
		this.conn = quicConn
		this.controlStream = null
		this.encoderStream = null
		this.decoderStream = null
		this.bootstrapped = false

		this.peerDynamicTable = new qpack.DynamicTable()
		this.peerEncoderBuf = Buffer.alloc(0)
		this.peerQpackMaxTableCapacity = 0

		// Hook server-initiated unidirectional streams (control / encoder / decoder).
		this.conn.onServerStream = (stream: QuicStream) => this._onServerUniStream(stream)
	}

	_onServerUniStream(stream: QuicStream): void {
		let typeBuf: Buffer = Buffer.alloc(0)
		let streamType: number | null = null
		stream.on('data', (chunk: Buffer) => {
			if (streamType == null) {
				typeBuf = Buffer.concat([typeBuf, chunk])
				try {
					const v = varint.decode(typeBuf, 0)
					streamType = Number(v.value)
					const after = typeBuf.subarray(v.length)
					if (streamType === 0x02) {
						this.peerEncoderBuf = Buffer.concat([this.peerEncoderBuf, after])
						this._drainPeerEncoder()
					}
					// 0x00 = control, 0x03 = decoder — we don't use these for anything yet.
					return
				} catch {
					return  // need more bytes for varint
				}
			}
			if (streamType === 0x02) {
				this.peerEncoderBuf = Buffer.concat([this.peerEncoderBuf, chunk])
				this._drainPeerEncoder()
			}
		})
	}

	_drainPeerEncoder(): void {
		try {
			const consumed = qpack.parseEncoderInstructions(this.peerEncoderBuf, this.peerDynamicTable)
			if (consumed > 0) this.peerEncoderBuf = this.peerEncoderBuf.subarray(consumed)
		} catch {
			// Malformed QPACK encoder stream — drop it rather than crash the process.
			this.peerEncoderBuf = Buffer.alloc(0)
		}
	}

	bootstrap(): void {
		// Open the three uni streams: control (type 0x00), encoder (0x02), decoder (0x03).
		this.controlStream = this.conn.openUniStream()
		this.controlStream.send(varint.encode(0x00), false)
		this.controlStream.send(encodeSettings(), false)

		this.encoderStream = this.conn.openUniStream()
		this.encoderStream.send(varint.encode(0x02), false)

		this.decoderStream = this.conn.openUniStream()
		this.decoderStream.send(varint.encode(0x03), false)

		this.bootstrapped = true
	}

	request({ method, path, host, headers = {}, body }: H3RequestOptions): Promise<H3Response> {
		if (!this.bootstrapped) this.bootstrap()
		const stream = this.conn.openBidiStream()

		const ordered: HeaderEntry[] = [
			[':method', method],
			[':authority', host],
			[':scheme', 'https'],
			[':path', path],
			...Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v] as HeaderEntry),
		]
		const fieldSection = qpack.encodeHeaders(ordered)
		const headersFrame = encodeFrame(FRAME.HEADERS, fieldSection)

		const respChunks: Buffer[] = []
		const respHeaders: Record<string, string> = {}
		let respFrameBuf: Buffer = Buffer.alloc(0)
		let respFailed = false

		// Read a QUIC varint only when all its bytes are present (its length is encoded in the top 2
		// bits of the first byte). Returns null = "need more": varint.decode would otherwise THROW on
		// a multi-byte varint split across packet boundaries, which is ordinary traffic.
		const peekVarint = (b: Buffer, o: number): DecodedVarint | null => {
			if (o >= b.length) return null
			const need = 1 << (b[o] >> 6)
			if (o + need > b.length) return null
			return varint.decode(b, o)
		}

		stream.on('data', (data: Buffer) => {
			if (respFailed) return
			respFrameBuf = Buffer.concat([respFrameBuf, data])
			try {
				while (true) {
					if (respFrameBuf.length === 0) break
					let off = 0
					const t = peekVarint(respFrameBuf, off); if (!t) break; off += t.length
					const l = peekVarint(respFrameBuf, off); if (!l) break; off += l.length
					const frameLen = Number(l.value)
					if (off + frameLen > respFrameBuf.length) break
					const payload = respFrameBuf.subarray(off, off + frameLen)
					respFrameBuf = respFrameBuf.subarray(off + frameLen)
					if (t.value === FRAME.HEADERS) {
						// Prefer dynamic-table-aware decode when the peer's table has entries;
						// fall back to static-only decoder for the static-only path (RIC=0, Base=0).
						const maxEntries = Math.floor((this.peerQpackMaxTableCapacity || this.peerDynamicTable.capacity) / 32)
						const decoded = this.peerDynamicTable.entries.length > 0 || (payload[0] !== 0)
							? qpack.decodeHeadersWithTable(payload, this.peerDynamicTable, maxEntries)
							: qpack.decodeHeaders(payload)
						for (const [n, v] of decoded) respHeaders[n] = v
					} else if (t.value === FRAME.DATA) {
						respChunks.push(Buffer.from(payload))
					}
				}
			} catch (e) {
				// Malformed H3 framing / QPACK from the server: fail this request, don't crash.
				respFailed = true
				const err = new Error(`h3 response parse failed: ${(e as Error).message}`) as NodeJS.ErrnoException
				err.code = 'EH3PARSE'
				stream.emit('error', err)
			}
		})

		return new Promise<H3Response>((resolve, reject) => {
			stream.on('end', () => {
				resolve({
					status: parseInt(respHeaders[':status'] || '0', 10),
					headers: respHeaders,
					body: Buffer.concat(respChunks),
				})
			})
			stream.on('error', reject)
			if (body) {
				// One DATA frame holds the whole body — a streaming body has no representation
				// here and fails when the frame is sized.
				const payload = body as Buffer
				stream.send(headersFrame, false)
				stream.send(encodeFrame(FRAME.DATA, payload), true)
			} else {
				stream.send(headersFrame, true)
			}
		})
	}
}

export { H3Client, encodeSettings, encodeFrame, FRAME, CHROME_147_SETTINGS }
