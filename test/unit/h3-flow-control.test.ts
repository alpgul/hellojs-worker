// QUIC receive-window and H3 consumer-backpressure tests. These stay at the transport seam:
// no UDP server is needed to prove that credit is granted only as bytes are read, that a paused
// consumer stops delivery, and that bodies larger than the old 16 MB client cap stream through.

import { EventEmitter } from 'node:events'

import { expect, it } from 'vitest'

import { QuicConnection } from '../../lib/h3/connection.ts'
import { encodeFrame, FRAME, H3Client } from '../../lib/h3/h3.ts'
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

it('pauses H3 delivery when the consumer returns false and resumes on drain', () => {
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
	expect(stream.resumeCalls).toBe(1)
	expect(received).toEqual(['hello', 'world'])
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
	for (let i = 0; i < 18; i++) stream.emit('data', encodeFrame(FRAME.DATA, mb))
	stream.emit('end')

	expect(ended).toBe(true)
	expect(total).toBe(18 * 1024 * 1024)
})
