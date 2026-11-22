// QUIC receive-window and H3 consumer-backpressure tests. These stay at the transport seam:
// no UDP server is needed to prove that credit is granted only as bytes are read, that a paused
// consumer stops delivery, and that bodies larger than the old 16 MB client cap stream through.

import * as crypto from 'node:crypto'
import { EventEmitter } from 'node:events'

import { expect, it } from 'vitest'

import { Connection } from '../../lib/connect.ts'
import { QuicConnection, QuicStream } from '../../lib/h3/connection.ts'
import { encodeFrame, FRAME, H3Client } from '../../lib/h3/h3.ts'
import * as keys from '../../lib/h3/keys.ts'
import * as pkt from '../../lib/h3/packet.ts'
import * as qpack from '../../lib/h3/qpack.ts'
import * as tp from '../../lib/h3/transport-params.ts'

import type { H3StreamHandlers } from '../../lib/h3/h3.ts'

function captureFrames(conn: QuicConnection): Buffer[] {
	const frames: Buffer[] = []
	conn._sendFlowControlFrame = (frame: Buffer) => frames.push(frame)
	return frames
}

function maxStreamGrants(frames: Buffer[]): number[] {
	return frames
		.flatMap((frame) => pkt.decodeFrames(frame))
		.filter((f): f is Extract<pkt.QuicFrame, { type: 'max_stream_data' }> => f.type === 'max_stream_data')
		.map((f) => f.value)
}

function maxDataGrants(frames: Buffer[]): number[] {
	return frames
		.flatMap((frame) => pkt.decodeFrames(frame))
		.filter(
			(f): f is Extract<pkt.QuicFrame, { type: 'flow_control' }> =>
				f.type === 'flow_control' && f.subtype === pkt.FRAME_TYPE.MAX_DATA
		)
		.map((f) => f.value)
}

it('grants stream credit as bytes are consumed and withholds it while paused', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const frames = captureFrames(conn)
	const stream = conn.openBidiStream()
	const errors: Error[] = []
	stream.on('error', (e: Error) => errors.push(e))

	const chunk = Buffer.alloc(64 * 1024, 0xab)
	let offset = 0
	// Cross the 3 MiB stream-update threshold but stay below the 7.8 MiB connection threshold.
	for (let i = 0; i < 100; i++) {
		stream._onData(offset, chunk, false)
		offset += chunk.length
	}
	expect(errors).toEqual([])
	expect(maxStreamGrants(frames).length).toBeGreaterThan(0)
	expect(maxStreamGrants(frames).at(-1)).toBeGreaterThan(tp.FLOW_CONTROL.maxStreamDataBidiLocal)
	expect(maxDataGrants(frames)).toEqual([])

	const streamLimit = stream.recvLimit
	const connectionLimit = conn.recvLimit
	const consumed = stream.recvConsumed
	stream.pause()
	stream._onData(offset, chunk, false)
	expect(stream._pendingBytes).toBeGreaterThan(0)
	expect(stream.recvLimit).toBe(streamLimit)
	expect(conn.recvLimit).toBe(connectionLimit)

	stream.resume()
	expect(stream.recvConsumed).toBe(consumed + chunk.length)
	expect(stream._pendingBytes).toBe(0)
	// Keep reading past the half-window connection threshold to force a MAX_DATA grant.
	for (let i = 0; i < 30; i++) {
		stream._onData(offset, chunk, false)
		offset += chunk.length
	}
	expect(maxDataGrants(frames).length).toBeGreaterThan(0)
})

it('starts send-side flow-control limits at zero until the peer grants credit', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	expect(conn.peerMaxData).toBe(0)
	expect(conn.peerMaxStreamDataBidiLocal).toBe(0)
	expect(conn.peerMaxStreamDataBidiRemote).toBe(0)
	expect(conn.peerMaxStreamDataUni).toBe(0)
	expect(conn.openBidiStream().sendLimit).toBe(0)
})

it('encodes per-stream cancel frames', () => {
	const frames = pkt.decodeFrames(
		Buffer.concat([pkt.encodeResetStreamFrame(4, 0x0c, 128), pkt.encodeStopSendingFrame(4, 0x0c)])
	)
	expect(frames.slice(0, 2)).toEqual([
		{ type: 'reset_stream', streamId: 4, errorCode: 0x0c, finalSize: 128 },
		{ type: 'stop_sending', streamId: 4, errorCode: 0x0c }
	])
})

it('keeps queued chunks buffered when a data listener pauses mid-flush', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const stream = conn.openBidiStream()
	const received: string[] = []
	stream.on('data', (chunk: Buffer) => {
		received.push(chunk.toString())
		stream.pause()
	})

	stream.pause()
	stream._onData(0, Buffer.from('a'), false)
	stream._onData(1, Buffer.from('b'), false)
	stream.resume()

	expect(received).toEqual(['a'])
	expect(stream._pendingBytes).toBe(1)
})

it('stops queued and later writes when a stream is cancelled', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	conn.peerMaxData = 1024
	const sent: Buffer[] = []
	conn.sendStreamData = (_id, _offset, data) => sent.push(data)

	const stream = conn.openBidiStream()
	stream.sendLimit = 512
	stream.send(Buffer.alloc(600))
	expect(stream.sendQueue).toHaveLength(1)

	stream.cancel(0x0c)
	expect(stream.sendQueue).toEqual([])
	conn._onPeerMaxStreamData(stream.id, 2048)
	stream.send(Buffer.from('late'))
	expect(sent).toEqual([])
})

it('charges discarded bytes to connection flow control after cancel', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	conn.recvLimit = 100
	const frames = captureFrames(conn)
	const stream = conn.openBidiStream()

	stream.cancel(0x0c)
	stream._onData(0, Buffer.alloc(64), false)

	expect(maxDataGrants(frames).at(-1)).toBeGreaterThan(100)
	expect(conn.recvConsumed).toBe(64)
})

it('tracks cancel frames for PTO and stops replaying them once acknowledged', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	const stream = conn.openBidiStream()

	stream.cancel(0x0c)
	expect(conn.sentPackets.oneRtt.size).toBe(1)
	const cancelKey = [...conn.flowControlFrames.keys()].find((key) => key.startsWith(`cancel:${stream.id}:`))
	expect(cancelKey).toBeDefined()
	const pn = [...conn.sentPackets.oneRtt.keys()][0]
	const info = conn.sentPackets.oneRtt.get(pn)!
	conn._onPacketAcked('oneRtt', pn, info)
	expect(conn.flowControlFrames.has(cancelKey!)).toBe(false)
})

it('keeps the newer cancel replay when an older cancel packet is acknowledged', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	const stream = conn.openBidiStream()

	// Peer STOP_SENDING sends RESET-only first; a local cancel must supersede it.
	stream._resetSend(0x0c, false)
	stream.cancel(0x0c)

	const cancelKeys = [...conn.flowControlFrames.keys()].filter((key) => key.startsWith(`cancel:${stream.id}:`))
	expect(cancelKeys).toHaveLength(1)
	const liveKey = cancelKeys[0]
	const stale = [...conn.sentPackets.oneRtt.entries()].find(([, info]) =>
		info.flowControlKeys?.some((key) => key !== liveKey)
	)
	expect(stale).toBeDefined()
	conn._onPacketAcked('oneRtt', stale![0], stale![1])
	expect(conn.flowControlFrames.has(liveKey)).toBe(true)
})

it('does not charge flow-control packets to the congestion window', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	conn.cc.bytesInFlight = 0

	conn._grantFlowControl('max_data:0', Buffer.from([0x01]))

	expect(conn.sentPackets.oneRtt.size).toBe(1)
	expect(conn.cc.bytesInFlight).toBe(0)
})

it('keeps the newest MAX replay when an older flow-control packet is acknowledged', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram

	try {
		conn._grantFlowControl('connection', Buffer.from([0x01]))
		const oldKey = [...conn.flowControlFrames.keys()][0]!
		const oldPn = [...conn.sentPackets.oneRtt.keys()][0]!

		conn._grantFlowControl('connection', Buffer.from([0x02]))
		const newKey = [...conn.flowControlFrames.keys()][0]!
		expect(newKey).not.toBe(oldKey)

		const oldInfo = conn.sentPackets.oneRtt.get(oldPn)!
		conn._onPacketAcked('oneRtt', oldPn, oldInfo)

		expect(conn.flowControlFrames.has(newKey)).toBe(true)
		expect(conn.flowControlFrames.size).toBe(1)

		const newPn = [...conn.sentPackets.oneRtt.keys()].find((pn) => pn !== oldPn)!
		conn._onPacketAcked('oneRtt', newPn, conn.sentPackets.oneRtt.get(newPn)!)
		expect(conn.flowControlFrames.size).toBe(0)
	} finally {
		conn.close()
	}
})

it('drains queued stream data when a control packet is acknowledged', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	conn.cc.bytesInFlight = 0
	conn.cc.cwnd = 1000
	conn.appSendQueue.push({ packet: Buffer.from([0x01]), size: 10, pn: 4242 })

	try {
		conn._grantFlowControl('max_data:0', Buffer.from([0x01]))
		const control = [...conn.sentPackets.oneRtt.entries()].find(([, info]) => info.size === 0)!
		conn._onPacketAcked('oneRtt', control[0], control[1])

		expect(conn.appSendQueue).toHaveLength(0)
		expect(conn.cc.bytesInFlight).toBe(10)
		expect(conn.sentPackets.oneRtt.has(4242)).toBe(true)
	} finally {
		conn.close()
	}
})

it('does not halve cwnd when PTO declares a control packet lost', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	conn.cc.bytesInFlight = 0
	conn.cc.cwnd = 12000
	conn.cc.ssthresh = 12000

	try {
		conn._grantFlowControl('max_data:0', Buffer.from([0x01]))
		conn._onPtoFire()
		expect(conn.cc.cwnd).toBe(12000)
	} finally {
		conn.close()
	}
})

it('uses a lost data packet for PTO congestion response ahead of older control packets', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	conn.cc.bytesInFlight = 0
	conn.cc.cwnd = 12000
	conn.cc.ssthresh = 12000

	try {
		conn._grantFlowControl('max_data:0', Buffer.from([0x01]))
		const controlPn = [...conn.sentPackets.oneRtt.keys()][0]!
		conn.sentPackets.oneRtt.get(controlPn)!.time = Date.now() - 10_000

		const dataPn = conn.pn.oneRtt++
		conn._send1Rtt(Buffer.from([0x44, 0, 0, 0]), dataPn)
		const dataInfo = conn.sentPackets.oneRtt.get(dataPn)!
		expect(dataInfo.size).toBeGreaterThan(0)
		conn.cc.bytesInFlight = dataInfo.size!

		conn._onPtoFire()

		expect(conn.cc.cwnd).toBe(6000)
		expect(conn.sentPackets.oneRtt.has(dataPn)).toBe(false)
		expect(conn.sentPackets.oneRtt.has(controlPn)).toBe(true)
	} finally {
		conn.close()
	}
})

it('retransmits the lost STREAM frame on PTO', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	const stream = conn.openBidiStream()

	try {
		conn.sendStreamData(stream.id, 0, Buffer.from('hello'), true)
		const originalPn = [...conn.sentPackets.oneRtt.keys()][0]!
		const original = conn.sentPackets.oneRtt.get(originalPn)!
		expect(original.streamFrame).toEqual({
			streamId: stream.id,
			offset: 0,
			data: Buffer.from('hello'),
			fin: true
		})

		conn._onPtoFire()

		expect(conn.sentPackets.oneRtt.has(originalPn)).toBe(false)
		const retransmitted = [...conn.sentPackets.oneRtt.values()].filter((i) => i.streamFrame)
		expect(retransmitted).toHaveLength(1)
		expect(retransmitted[0].streamFrame).toEqual(original.streamFrame)
	} finally {
		conn.close()
	}
})

it('drops retransmittable stream frames when the send direction is cancelled', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	const stream = conn.openBidiStream()

	try {
		conn.sendStreamData(stream.id, 0, Buffer.from('hello'), true)
		expect(conn.cc.bytesInFlight).toBeGreaterThan(0)

		stream.cancel(0x0c)

		const retained = [...conn.sentPackets.oneRtt.values()].filter((i) => i.streamFrame?.streamId === stream.id)
		expect(retained).toHaveLength(0)
		expect(conn.cc.bytesInFlight).toBe(0)
		conn._onPtoFire()
		expect([...conn.sentPackets.oneRtt.values()].some((i) => i.streamFrame?.streamId === stream.id)).toBe(false)
	} finally {
		conn.close()
	}
})

it('drops cwnd-queued stream frames when the send direction is cancelled', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	conn.cc.bytesInFlight = conn.cc.cwnd
	const stream = conn.openBidiStream()

	try {
		conn.sendStreamData(stream.id, 0, Buffer.from('hello'), true)
		expect(conn.appSendQueue).toHaveLength(1)

		stream.cancel(0x0c)

		expect(conn.appSendQueue).toHaveLength(0)
	} finally {
		conn.close()
	}
})

it('drains queued stream data after PTO frees congestion capacity', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const secret = () => crypto.randomBytes(32)
	const epochKeys = () => keys.deriveKeysFromSecret(secret(), 'sha256', 16, 12)
	conn.appKeys = { client: epochKeys(), server: epochKeys() } as unknown as typeof conn.appKeys
	conn._sendDatagram = (() => {}) as unknown as typeof conn._sendDatagram
	conn.cc.cwnd = 2000
	conn.cc.ssthresh = 2000
	conn.cc.bytesInFlight = 1800
	conn.sentPackets.oneRtt.set(1, { time: Date.now(), size: 1800, includesCrypto: false })
	conn.appSendQueue.push({ packet: Buffer.from([0xaa]), size: 300, pn: 2 })

	try {
		conn._onPtoFire()

		expect(conn.appSendQueue).toHaveLength(0)
		expect(conn.sentPackets.oneRtt.has(2)).toBe(true)
		expect(conn.cc.bytesInFlight).toBe(300)
	} finally {
		conn.close()
	}
})

it('charges only unique discarded bytes when a cancelled stream has overlapping frames', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const stream = conn.openBidiStream()
	stream.pause()
	stream._onData(0, Buffer.alloc(100), false)
	stream._onData(0, Buffer.alloc(100), false)
	const before = conn.recvConsumed
	stream.cancel(0x0c)
	expect(conn.recvConsumed - before).toBe(100)
})

it('does not emit end after a synchronous cancel from a data listener', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const stream = conn.openBidiStream()
	let ended = false
	stream.on('data', () => stream.cancel(0x0c))
	stream.on('end', () => {
		ended = true
	})

	stream._onData(0, Buffer.from('ok'), true)

	expect(ended).toBe(false)
	expect(stream.fin).toBe(false)
})

it('defers FIN until a stream paused from a data listener resumes', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const stream = conn.openBidiStream()
	let endCount = 0
	stream.on('data', () => stream.pause())
	stream.on('end', () => {
		endCount++
	})

	stream._onData(0, Buffer.from('ok'), true)
	expect(endCount).toBe(0)
	expect(stream.fin).toBe(false)

	stream.resume()
	expect(endCount).toBe(1)
	expect(stream.fin).toBe(true)
})

it('emits end once when duplicate FIN chunks arrive', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const stream = conn.openBidiStream()
	let endCount = 0
	stream.on('end', () => {
		endCount++
	})

	stream._onData(0, Buffer.from('ok'), true)
	stream._onData(0, Buffer.from('ok'), true)

	expect(endCount).toBe(1)
	expect(stream.fin).toBe(true)
})

it('reports a peer RESET_STREAM once and cancels the whole bidi stream', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const stream = conn.openBidiStream()
	const errors: Error[] = []
	stream.on('error', (e: Error) => errors.push(e))

	conn._handleFrame('oneRtt', { type: 'reset_stream', streamId: stream.id, errorCode: 0x0c, finalSize: 0 })
	conn._handleFrame('oneRtt', { type: 'reset_stream', streamId: stream.id, errorCode: 0x0c, finalSize: 0 })

	expect(stream.cancelled).toBe(true)
	expect(errors).toHaveLength(1)
})

it('treats peer STOP_SENDING on a bidi stream as send-side only', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	conn.appKeys = {} as unknown as typeof conn.appKeys
	const frames = captureFrames(conn)
	const stream = conn.openBidiStream()
	const received: string[] = []
	const errors: Error[] = []
	stream.on('data', (chunk: Buffer) => received.push(chunk.toString()))
	stream.on('error', (e: Error) => errors.push(e))

	conn._handleFrame('oneRtt', { type: 'stop_sending', streamId: stream.id, errorCode: 0x0c })
	const decoded = frames.flatMap((frame) => pkt.decodeFrames(frame))
	expect(decoded.some((f) => f.type === 'reset_stream')).toBe(true)
	expect(decoded.some((f) => f.type === 'stop_sending')).toBe(false)

	stream._onData(0, Buffer.from('ok'), true)
	expect(stream.cancelled).toBe(false)
	expect(received).toEqual(['ok'])
	expect(errors).toEqual([])
})

it('does not echo illegal peer frames on unidirectional streams', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	conn.appKeys = {} as unknown as typeof conn.appKeys
	const frames = captureFrames(conn)
	const serverUni = new QuicStream(conn, 3, 'uni')
	conn.streams.set(serverUni.id, serverUni)
	serverUni.on('error', () => {})

	conn._handleFrame('oneRtt', { type: 'reset_stream', streamId: serverUni.id, errorCode: 0x0c, finalSize: 0 })
	expect(serverUni.cancelled).toBe(true)
	expect(frames).toEqual([])

	const clientUni = new QuicStream(conn, 2, 'uni')
	conn.streams.set(clientUni.id, clientUni)
	conn._handleFrame('oneRtt', { type: 'stop_sending', streamId: clientUni.id, errorCode: 0x0c })
	const decoded = frames.flatMap((frame) => pkt.decodeFrames(frame))
	expect(decoded.some((f) => f.type === 'reset_stream')).toBe(true)
	expect(decoded.some((f) => f.type === 'stop_sending')).toBe(false)
})

it('rejects STREAM data past the connection receive window', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	conn.recvLimit = 64 * 1024
	const stream = conn.openBidiStream()
	const errors: Error[] = []
	stream.on('error', (e: Error) => errors.push(e))
	stream._onData(0, Buffer.alloc(128 * 1024), false)
	expect(errors).toHaveLength(1)
	expect(errors[0].message).toContain('connection')
	expect(stream._pendingBytes ?? 0).toBe(0)
})

it('queues writes past the peer flow-control limit and flushes after MAX_* grants', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	const frames = captureFrames(conn)
	conn.peerMaxData = 1024
	const sent: Buffer[] = []
	conn.sendStreamData = (_id, _offset, data) => sent.push(data)

	const stream = conn.openBidiStream()
	stream.sendLimit = 512
	stream.send(Buffer.alloc(600))
	expect(sent).toEqual([])
	expect(stream.sendQueue).toHaveLength(1)
	expect(frames.flatMap((f) => pkt.decodeFrames(f)).some((f) => f.type === 'stream_data_blocked')).toBe(true)

	conn._onPeerMaxStreamData(stream.id, 1024)
	expect(sent).toHaveLength(1)
	expect(stream.sendOffset).toBe(600)

	// Connection credit is tracked separately from the per-stream limit.
	stream.sendLimit = 4096
	stream.send(Buffer.alloc(600))
	expect(stream.sendQueue).toHaveLength(1)
	expect(frames.flatMap((f) => pkt.decodeFrames(f)).some((f) => f.type === 'data_blocked')).toBe(true)
	conn._onPeerMaxData(4096)
	expect(stream.sendQueue).toHaveLength(0)
	expect(stream.sendOffset).toBe(1200)
})

class FakeQuicStream extends EventEmitter {
	pauseCalls = 0
	resumeCalls = 0
	cancelCalls = 0
	send(_data: Buffer, _fin = false): void {}
	pause(): void {
		this.pauseCalls++
	}
	resume(): void {
		this.resumeCalls++
	}
	cancel(_errorCode = 0x0c): void {
		this.cancelCalls++
	}
}

function fakeH3(): { h3: H3Client; stream: FakeQuicStream } {
	const stream = new FakeQuicStream()
	const conn = {
		onServerStream: undefined,
		openUniStream: () => new FakeQuicStream(),
		openBidiStream: () => stream
	} as unknown as QuicConnection
	return { h3: new H3Client(conn), stream }
}

function responseBytes(data: string[]): Buffer {
	const headers = encodeFrame(FRAME.HEADERS, qpack.encodeHeaders([[':status', '200']]))
	return Buffer.concat([headers, ...data.map((text) => encodeFrame(FRAME.DATA, Buffer.from(text)))])
}

it('keeps the QUIC stream paused while the consumer stays backpressured', () => {
	const { h3, stream } = fakeH3()
	const received: string[] = []
	const handlers: H3StreamHandlers = {
		onHeaders: () => {},
		onData: (chunk) => {
			received.push(chunk.toString())
			return false
		},
		onEnd: () => {},
		onError: (e) => {
			throw e
		},
		onBackpressure: () => {}
	}
	h3.requestStream({ method: 'GET', path: '/', host: 'example.com' }, handlers)
	stream.emit('data', responseBytes(['hello', 'world']))

	expect(received).toEqual(['hello'])
	expect(stream.pauseCalls).toBe(1)
	handlers.onBackpressure!(false)
	expect(stream.resumeCalls).toBe(0)
	expect(received).toEqual(['hello', 'world'])
})

it('drains buffered H3 DATA before a deferred QUIC end on resume', () => {
	const { h3, stream } = fakeH3()
	const received: string[] = []
	let ended = false
	// Real QuicStream.resume() flushes the deferred FIN marker and emits `end` synchronously.
	const fakeResume = stream.resume.bind(stream)
	stream.resume = () => {
		fakeResume()
		stream.emit('end')
	}
	const handlers: H3StreamHandlers = {
		onHeaders: () => {},
		onData: (chunk) => {
			received.push(chunk.toString())
			return received.length === 1 ? false : true
		},
		onEnd: () => {
			ended = true
		},
		onError: (e) => {
			throw e
		},
		onBackpressure: () => {}
	}
	h3.requestStream({ method: 'GET', path: '/', host: 'example.com' }, handlers)
	stream.emit('data', responseBytes(['hello', 'world']))

	expect(received).toEqual(['hello'])
	handlers.onBackpressure!(false)

	expect(received).toEqual(['hello', 'world'])
	expect(ended).toBe(true)
})

it('cancels one H3 request without closing the QUIC session', () => {
	const { h3, stream } = fakeH3()
	let ended = false
	const handle = h3.requestStream(
		{ method: 'GET', path: '/', host: 'example.com' },
		{
			onHeaders: () => {},
			onData: () => true,
			onEnd: () => {
				ended = true
			},
			onError: () => {}
		}
	)

	handle.cancel()
	expect(stream.cancelCalls).toBe(1)
	expect(ended).toBe(false)
})

it('cancels a stream when a fatal H3 error arrives after headers', () => {
	const { h3, stream } = fakeH3()
	let handle: ReturnType<H3Client['requestStream']> | null = null
	const errors: Error[] = []
	handle = h3.requestStream(
		{ method: 'GET', path: '/', host: 'example.com' },
		{
			onHeaders: () => {},
			onData: () => true,
			onEnd: () => {},
			onError: (e) => {
				errors.push(e)
				handle!.cancel()
			}
		}
	)
	stream.emit('data', responseBytes([]))
	stream.emit('error', new Error('peer reset'))

	expect(errors).toHaveLength(1)
	expect(stream.cancelCalls).toBe(1)
})

it('reports a protocol error when an H3 stream ends before HEADERS', () => {
	const { h3, stream } = fakeH3()
	const errors: Error[] = []
	let ended = false
	const handle = h3.requestStream(
		{ method: 'GET', path: '/', host: 'example.com' },
		{
			onHeaders: () => {},
			onData: () => true,
			onEnd: () => {
				ended = true
			},
			onError: (e) => {
				errors.push(e)
				handle.cancel()
			}
		}
	)

	stream.emit('end')
	expect(ended).toBe(false)
	expect(errors).toHaveLength(1)
	expect(errors[0].message).toContain('before HEADERS')
	expect(stream.cancelCalls).toBe(1)
})

it('waits for final HEADERS after a 1xx response', () => {
	const { h3, stream } = fakeH3()
	const statuses: number[] = []
	let ended = false
	h3.requestStream(
		{ method: 'GET', path: '/', host: 'example.com' },
		{
			onHeaders: (status) => statuses.push(status),
			onData: () => true,
			onEnd: () => {
				ended = true
			},
			onError: () => {}
		}
	)

	stream.emit('data', encodeFrame(FRAME.HEADERS, qpack.encodeHeaders([[':status', '103']])))
	expect(statuses).toEqual([])
	stream.emit('data', encodeFrame(FRAME.HEADERS, qpack.encodeHeaders([[':status', '200']])))
	stream.emit('end')
	expect(statuses).toEqual([200])
	expect(ended).toBe(true)
})

it('keeps final headers intact when trailer HEADERS arrive', async () => {
	const { h3, stream } = fakeH3()
	const pending = h3.request({ method: 'GET', path: '/', host: 'example.com' })

	stream.emit(
		'data',
		encodeFrame(
			FRAME.HEADERS,
			qpack.encodeHeaders([
				[':status', '200'],
				['content-type', 'text/plain']
			])
		)
	)
	stream.emit('data', encodeFrame(FRAME.HEADERS, qpack.encodeHeaders([['x-trailer', 'done']])))
	stream.emit('end')

	const response = await pending
	expect(response.status).toBe(200)
	expect(response.headers).toMatchObject({ ':status': '200', 'content-type': 'text/plain' })
	expect(response.headers['x-trailer']).toBeUndefined()
})

it('stops draining buffered frames when onData cancels the stream', () => {
	const { h3, stream } = fakeH3()
	const received: string[] = []
	const handle = h3.requestStream(
		{ method: 'GET', path: '/', host: 'example.com' },
		{
			onHeaders: () => {},
			onData: (chunk) => {
				received.push(chunk.toString())
				handle.cancel()
				return true
			},
			onEnd: () => {},
			onError: () => {}
		}
	)

	stream.emit(
		'data',
		Buffer.concat([
			encodeFrame(FRAME.HEADERS, qpack.encodeHeaders([[':status', '200']])),
			encodeFrame(FRAME.DATA, Buffer.from('first')),
			encodeFrame(FRAME.DATA, Buffer.from('second'))
		])
	)

	expect(received).toEqual(['first'])
	expect(stream.cancelCalls).toBe(1)
})

it('fails when a 1xx is followed by HEADERS without a final status', () => {
	const { h3, stream } = fakeH3()
	const errors: Error[] = []
	let ended = false
	h3.requestStream(
		{ method: 'GET', path: '/', host: 'example.com' },
		{
			onHeaders: () => {},
			onData: () => true,
			onEnd: () => {
				ended = true
			},
			onError: (e) => errors.push(e)
		}
	)

	stream.emit('data', encodeFrame(FRAME.HEADERS, qpack.encodeHeaders([[':status', '103']])))
	stream.emit('data', encodeFrame(FRAME.HEADERS, qpack.encodeHeaders([['x-invalid', '1']])))
	stream.emit('end')

	expect(ended).toBe(false)
	expect(errors).toHaveLength(1)
	expect(errors[0].message).toContain('before HEADERS')
})

it('fails sibling H3 requests when the shared connection closes', () => {
	const qc = new QuicConnection('127.0.0.1', 443)
	const conn = new Connection(null)
	conn.alpn = 'h3'
	conn.quicConn = qc
	conn.h3Client = new H3Client(qc)
	const errors: Error[] = []
	for (let i = 0; i < 2; i++) {
		conn.h3Client.requestStream(
			{ method: 'GET', path: `/${i}`, host: 'example.com' },
			{
				onHeaders: () => {},
				onData: () => true,
				onEnd: () => {},
				onError: (e) => errors.push(e)
			}
		)
	}

	conn.close('test')
	expect(errors).toHaveLength(2)
})

it('streams response bodies past the former 16 MB buffered cap', () => {
	const { h3, stream } = fakeH3()
	let total = 0
	let ended = false
	h3.requestStream(
		{ method: 'GET', path: '/', host: 'example.com' },
		{
			onHeaders: () => {},
			onData: (chunk) => {
				total += chunk.length
			},
			onEnd: () => {
				ended = true
			},
			onError: (e) => {
				throw e
			}
		}
	)
	const mb = Buffer.alloc(1024 * 1024, 0x5a)
	stream.emit('data', encodeFrame(FRAME.HEADERS, qpack.encodeHeaders([[':status', '200']])))
	for (let i = 0; i < 18; i++) stream.emit('data', encodeFrame(FRAME.DATA, mb))
	stream.emit('end')

	expect(ended).toBe(true)
	expect(total).toBe(18 * 1024 * 1024)
})
