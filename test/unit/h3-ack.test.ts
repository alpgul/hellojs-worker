// Regressions for two QUIC transport stalls found against live h3 hosts:
//
//   - Initial and Handshake packets were never ACKed on their own epoch ("bundled with the next
//     outgoing CRYPTO"), so a server whose flight outgrows the 3x anti-amplification budget — a
//     large certificate chain — stopped mid-flight waiting for an ACK that never came;
//   - every send() took the hostname, so a multi-A-record host answered from one address while our
//     replies resolved to another, and the handshake never completed.
//
// Both are exercised through the UDP seam, so this stays offline.

import * as crypto from 'node:crypto'

import { expect, it } from 'vitest'

import { QuicConnection } from '../../lib/h3/connection.ts'
import * as keys from '../../lib/h3/keys.ts'
import * as udp from '../../lib/h3/udp.ts'

import type { UdpRinfo, UdpSocket } from '../../lib/h3/udp.ts'

interface Sent {
	buf: Buffer
	port: number
	host: string
}

// A socket that records what the client sends and can deliver an inbound datagram on demand.
function recordingSocket(sent: Sent[]) {
	const listeners: { message?: (buf: Buffer, rinfo: UdpRinfo) => void } = {}
	const socket = {
		destroyed: false,
		on(event: string, listener: never) {
			if (event === 'message') listeners.message = listener
		},
		bind(_port: number, callback: () => void) {
			queueMicrotask(callback)
		},
		send(buf: Buffer, port: number, host: string) {
			sent.push({ buf: Buffer.from(buf), port, host })
		},
		close() {
			socket.destroyed = true
		},
		deliver(buf: Buffer, rinfo: UdpRinfo) {
			listeners.message?.(buf, rinfo)
		}
	}
	return socket
}

async function connected() {
	const sent: Sent[] = []
	const socket = recordingSocket(sent)
	udp.setUdpProvider(() => socket as unknown as UdpSocket)
	const conn = new QuicConnection('example.invalid', 443)
	conn.on('error', () => {})
	await conn.connect()
	return { conn, socket, sent }
}

it('acks Initial and Handshake packets on their own epoch', async () => {
	try {
		const { conn, sent } = await connected()
		expect(sent.length, 'the ClientHello is the only flight so far').toBe(1)

		conn.largestRecv.initial = 0
		conn.needAck.initial = true
		conn._maybeSendAcks('initial')
		expect(sent.length).toBe(2)
		const initialAck = sent[1].buf
		expect((initialAck[0] & 0x30) >> 4, 'Initial packet type').toBe(0)
		expect(initialAck.length, 'client Initial datagrams are padded to 1200 bytes').toBeGreaterThanOrEqual(1200)

		conn.handshakeKeys = {
			client: keys.deriveKeysFromSecret(crypto.randomBytes(32), 'sha256', 16, 12),
			server: keys.deriveKeysFromSecret(crypto.randomBytes(32), 'sha256', 16, 12)
		}
		conn.largestRecv.handshake = 1
		conn.needAck.handshake = true
		conn._maybeSendAcks('handshake')
		expect(sent.length).toBe(3)
		expect((sent[2].buf[0] & 0x30) >> 4, 'Handshake packet type').toBe(2)
	} finally {
		udp.setUdpProvider(null)
	}
})

it('sends to the address that answered instead of re-resolving the hostname', async () => {
	try {
		const { conn, socket, sent } = await connected()
		expect(sent[0].host, 'the first flight still goes to the configured host').toBe('example.invalid')

		socket.deliver(Buffer.alloc(0), { address: '203.0.113.9', family: 'IPv4', port: 443 })

		conn.largestRecv.initial = 0
		conn.needAck.initial = true
		conn._maybeSendAcks('initial')
		expect(sent.at(-1)).toStrictEqual({
			buf: expect.any(Buffer) as unknown as Buffer,
			port: 443,
			host: '203.0.113.9'
		})
	} finally {
		udp.setUdpProvider(null)
	}
})

it('CRYPTO reassembly keeps the stream contiguous across duplicates, gaps and overlaps', () => {
	const conn = new QuicConnection('127.0.0.1', 443)
	conn.on('error', () => {})
	const frames = (...pairs: [number, number[]][]) => {
		for (const [offset, bytes] of pairs) {
			conn._handleFrame('handshake', { type: 'crypto', offset, data: Buffer.from(bytes) })
		}
	}

	frames([0, [1, 2, 3, 4]])
	frames([0, [1, 2, 3, 4]]) // verbatim duplicate
	expect([...conn.cryptoBufIn.handshake]).toStrictEqual([1, 2, 3, 4])

	frames([10, [9, 9]]) // starts past a gap: dropped, not spliced in
	expect([...conn.cryptoBufIn.handshake]).toStrictEqual([1, 2, 3, 4])

	frames([4, [5, 6]])
	expect([...conn.cryptoBufIn.handshake]).toStrictEqual([1, 2, 3, 4, 5, 6])

	frames([4, [5, 6, 7, 8]]) // retransmission overlapping what we already have
	expect([...conn.cryptoBufIn.handshake]).toStrictEqual([1, 2, 3, 4, 5, 6, 7, 8])
})
