// ALPS (draft-vvv-tls-alps-01) regression: when the server negotiates application_settings in
// EncryptedExtensions the client MUST answer with a client EncryptedExtensions (CEE) before its
// Finished. Google's frontends send a fatal `unexpected_message` alert otherwise, which used to
// leave request() hanging because connect() had already resolved.

import { EventEmitter, once } from 'node:events'
import { PassThrough } from 'node:stream'

import { expect, it, vi } from 'vitest'

import * as frame from '../../lib/h2/frame.ts'
import { H2Session } from '../../lib/h2/session.ts'
import * as profileRegistry from '../../lib/profiles/index.ts'
import { TLS } from '../../lib/tls/tls.ts'

type Probe = {
	offeredAlpsTypes: number[]
	negotiatedAlpsType: number | null
	cipher: { hash: string; hashLen: number }
	cHsTraffic: Buffer
	clientHandshakeKey: Buffer
	clientHandshakeIV: Buffer
	transcript: Buffer[]
	alpsServerSettings: frame.SettingsPair[]
	alpn: string
	socket: { write(chunk: Buffer): void; destroy(): void } | null
	h2Session: { closed: boolean; _fatalError(err: Error): void } | null
	h2Transport: unknown
	encrypt(key: Buffer, iv: Buffer, plain: Buffer, innerType: number, seq: number): Buffer
	_onEncryptedExtensions(body: Buffer): void
	_parseAlpsSettings(data: Buffer): frame.SettingsPair[]
	_sendClientFinished(): void
	_handleAlert(level: number, desc: number, where: string): void
}

function encryptedExtensions(entries: { type: number; data?: Buffer }[]): Buffer {
	const exts = entries.map(({ type, data }) => {
		const body = data ?? Buffer.alloc(0)
		const ext = Buffer.alloc(4 + body.length)
		ext.writeUInt16BE(type, 0)
		ext.writeUInt16BE(body.length, 2)
		body.copy(ext, 4)
		return ext
	})
	const list = Buffer.concat(exts)
	const len = Buffer.alloc(2)
	len.writeUInt16BE(list.length, 0)
	return Buffer.concat([len, list])
}

function runHandshake(offered: number[], negotiated: { type: number; data?: Buffer }[]) {
	const t = new TLS('example.com', 443, null, { verifyTLS: false })
	const p = t as unknown as Probe
	const plaintext: Buffer[] = []
	const seqs: number[] = []

	p.offeredAlpsTypes = offered
	p.negotiatedAlpsType = null
	p.cipher = { hash: 'sha256', hashLen: 32 }
	p.cHsTraffic = Buffer.alloc(32, 7)
	p.clientHandshakeKey = Buffer.alloc(16)
	p.clientHandshakeIV = Buffer.alloc(12)
	p.transcript = [Buffer.from('client hello')]
	p.alpsServerSettings = []
	p.alpn = 'http/1.1' // avoids constructing a live h2 session in this unit test
	p.socket = {
		write: (chunk: Buffer) => plaintext.push(chunk),
		destroy: vi.fn()
	}
	// Record the plaintext handshake messages and their record sequence numbers; no real crypto.
	p.encrypt = (_key, _iv, plain, _type, seq) => {
		seqs.push(seq)
		plaintext.push(Buffer.from([0x17])) // record header marker
		return plain
	}

	p._onEncryptedExtensions(encryptedExtensions(negotiated))
	p._sendClientFinished()
	return { t, p, plaintext, seqs }
}

it('sends CEE (seq 0) before Finished (seq 1) when ALPS is negotiated', () => {
	const { p, plaintext, seqs } = runHandshake([0x44cd], [{ type: 0x44cd }])
	expect(p.negotiatedAlpsType).toBe(0x44cd)
	expect(seqs).toStrictEqual([0, 1])

	const messages = plaintext.filter((b) => b[0] !== 0x17)
	expect(messages).toHaveLength(2)
	expect(messages[0]).toStrictEqual(Buffer.from([0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x44, 0xcd, 0x00, 0x00]))
	expect(messages[1][0]).toBe(0x14) // Finished

	// The CEE is in the Client Handshake Context before the Finished MAC is computed.
	expect(p.transcript).toHaveLength(2)
	expect(p.transcript[1]).toStrictEqual(messages[0])
})

it('does not send CEE when the server did not negotiate ALPS', () => {
	const { p, plaintext, seqs } = runHandshake([0x44cd], [])
	expect(p.negotiatedAlpsType).toBeNull()
	expect(seqs).toStrictEqual([0])
	expect(plaintext.filter((b) => b[0] !== 0x17)).toHaveLength(1)
	expect(p.transcript).toHaveLength(1)
})

it('ignores an ALPS codepoint that was not offered', () => {
	const { p, seqs } = runHandshake([0x44cd], [{ type: 0x446d }])
	expect(p.negotiatedAlpsType).toBeNull()
	expect(seqs).toStrictEqual([0])
})

it('echoes the ALPS v2 codepoint when that is what was negotiated', () => {
	const { p, plaintext } = runHandshake([0x446d], [{ type: 0x446d }])
	expect(p.negotiatedAlpsType).toBe(0x446d)
	const cee = plaintext.find((b) => b[0] !== 0x17)
	expect(cee?.subarray(6, 8)).toStrictEqual(Buffer.from([0x44, 0x6d]))
})

it('tracks the legacy ALPS 17513 (0x4469) codepoint from the built ClientHello', () => {
	const profile = structuredClone(profileRegistry.get('chrome147-mac'))
	profile.tls!.extensionOrder = [{ id: 17513 }]
	profile.tls!.rawExtensionBodies = { 17513: Buffer.from([0, 3, 2, 0x68, 0x32]) }
	const t = new TLS('example.com', 443, null, { profile, verifyTLS: false })
	const p = t as unknown as Probe
	const chunks: Buffer[] = []
	p.socket = { write: (chunk) => chunks.push(chunk), destroy: vi.fn() }
	;(t as unknown as { mlkemPk: Buffer }).mlkemPk = Buffer.alloc(1184)

	t.startClientHello()

	expect(p.offeredAlpsTypes).toStrictEqual([0x4469])
	expect(Buffer.concat(chunks).includes(Buffer.from([0x44, 0x69]))).toBe(true)
	const negotiated = runHandshake([0x4469], [{ type: 0x4469 }])
	expect(negotiated.p.negotiatedAlpsType).toBe(0x4469)
})

it('emits legacy ALPS from protocols alone (parrot capture without a raw body)', () => {
	const profile = structuredClone(profileRegistry.get('chrome147-mac'))
	profile.tls!.extensionOrder = [{ id: 17513 }]
	const t = new TLS('example.com', 443, null, { profile, verifyTLS: false })
	const p = t as unknown as Probe
	const chunks: Buffer[] = []
	p.socket = { write: (chunk) => chunks.push(chunk), destroy: vi.fn() }
	;(t as unknown as { mlkemPk: Buffer }).mlkemPk = Buffer.alloc(1184)

	t.startClientHello()

	expect(p.offeredAlpsTypes).toStrictEqual([0x4469])
	expect(Buffer.concat(chunks).includes(Buffer.from([0x44, 0x69]))).toBe(true)
})

it('extracts SETTINGS frames from the server ALPS blob and applies them before h2 starts', () => {
	const settings = frame.build(
		frame.TYPE.SETTINGS,
		0,
		0,
		frame.buildSettings([[frame.SETTING.INITIAL_WINDOW_SIZE, 0]])
	)
	const { p } = runHandshake([0x44cd], [{ type: 0x44cd, data: settings }])
	expect(p.alpsServerSettings).toStrictEqual([[frame.SETTING.INITIAL_WINDOW_SIZE, 0]])

	const transport = Object.assign(new EventEmitter(), { write: vi.fn(), destroy: vi.fn() })
	const h2 = new H2Session(transport as never, null, p.alpsServerSettings)
	expect(h2.peerSettings[frame.SETTING.INITIAL_WINDOW_SIZE]).toBe(0)
	// The ALPS settings must not produce an ACK frame; only the normal preface is written.
	expect(transport.write).toHaveBeenCalledOnce()
	h2.close()
})

it('restarts a queued upload when SETTINGS raises the window set by ALPS', () => {
	const transport = Object.assign(new EventEmitter(), { write: vi.fn(), destroy: vi.fn() })
	const h2 = new H2Session(transport as never, null, [[frame.SETTING.INITIAL_WINDOW_SIZE, 0]])
	const s = h2.request({ ':method': 'POST', ':path': '/' })
	transport.write.mockClear() // preface + HEADERS
	s.write(Buffer.alloc(64, 0x61))
	expect(transport.write).not.toHaveBeenCalled() // body is window-blocked by ALPS
	transport.write.mockClear()

	h2._onData(frame.build(frame.TYPE.SETTINGS, 0, 0, frame.buildSettings([[frame.SETTING.INITIAL_WINDOW_SIZE, 64]])))

	const written = transport.write.mock.calls.map(([b]) => b as Buffer)
	expect(written.some((b) => b[3] === frame.TYPE.DATA)).toBe(true)
	h2.close()
})

it('signals an ALPS header-table reduction at the head of the first HPACK block', () => {
	const transport = Object.assign(new EventEmitter(), { write: vi.fn(), destroy: vi.fn() })
	const h2 = new H2Session(transport as never, null, [[frame.SETTING.HEADER_TABLE_SIZE, 0]])
	h2.request({ ':method': 'GET', ':path': '/' })

	const written = transport.write.mock.calls.map(([b]) => b as Buffer)
	const headers = written.find((b) => b[3] === frame.TYPE.HEADERS)
	// RFC 7541 §6.3: 001xxxxx is a Dynamic Table Size Update; 0x20 means "size 0".
	expect(headers?.[9]).toBe(0x20)
	h2.close()
})

it('keeps the pending HPACK update in sync when wire SETTINGS lower an ALPS limit', () => {
	const transport = Object.assign(new EventEmitter(), { write: vi.fn(), destroy: vi.fn() })
	const h2 = new H2Session(transport as never, null, [[frame.SETTING.HEADER_TABLE_SIZE, 65536]])
	h2._onData(frame.build(frame.TYPE.SETTINGS, 0, 0, frame.buildSettings([[frame.SETTING.HEADER_TABLE_SIZE, 0]])))
	h2.request({ ':method': 'GET', ':path': '/' })

	const written = transport.write.mock.calls.map(([b]) => b as Buffer)
	const headers = written.find((b) => b[3] === frame.TYPE.HEADERS)
	// The first update must honour the final (zero) limit, not the stale ALPS value.
	expect(headers?.[9]).toBe(0x20)
	h2.close()
})

it('fails live h2 streams when a fatal alert arrives after the handshake', () => {
	const t = new TLS('example.com', 443, null)
	const p = t as unknown as Probe
	const fatal = vi.fn()
	const order: string[] = []
	const emitted: Error[] = []
	t.on('error', (e: Error) => {
		order.push('error')
		emitted.push(e)
	})
	p.h2Session = {
		closed: false,
		_fatalError: (e: Error) => {
			order.push('fatal')
			fatal(e)
		}
	}
	p.h2Transport = null
	p.socket = { write: () => {}, destroy: vi.fn() }

	p._handleAlert(2, 10, 'encrypted')

	expect(fatal).toHaveBeenCalledOnce()
	expect((fatal.mock.calls[0][0] as Error & { code?: string }).code).toBe('ETLS_ALERT')
	expect(order).toStrictEqual(['fatal', 'error'])
	expect(emitted).toHaveLength(1)
	expect(p.socket.destroy).toHaveBeenCalledOnce()
})

it('also fails streams in a draining (GOAWAY-closed) h2 session', () => {
	const t = new TLS('example.com', 443, null)
	const p = t as unknown as Probe
	const fatal = vi.fn()
	t.on('error', () => {})
	p.h2Session = { closed: true, _fatalError: fatal }
	p.h2Transport = null
	p.socket = { write: () => {}, destroy: vi.fn() }

	p._handleAlert(2, 10, 'encrypted')
	expect(fatal).toHaveBeenCalledOnce()
})

it('delivers a fatal alert on an idle h1 transport to the permanent pool listener', async () => {
	const t = new TLS('example.com', 443, null)
	const p = t as unknown as Probe
	const transport = new PassThrough()
	const seen: Error[] = []
	// connect.ts installs this once at ready-http1 and never removes it. Per-request
	// listeners come and go, but a pooled idle socket must stay observable.
	transport.on('error', (e: Error) => seen.push(e))
	t.on('error', () => {}) // connect's already-settled fail() handler
	p.h2Transport = transport
	p.socket = { write: () => {}, destroy: vi.fn() }

	const alerted = once(transport, 'error')
	p._handleAlert(2, 10, 'encrypted')
	const [err] = await alerted

	expect((err as Error & { code?: string }).code).toBe('ETLS_ALERT')
	expect(seen).toStrictEqual([err])
	expect(transport.destroyed).toBe(true)
})

it('keeps a baseline error listener on TLSTransports for idle proxy hops', () => {
	// runHandshake completes an h1 handshake, which creates the real TLSTransport. A pooled
	// HTTPS-proxy hop has no inner session to listen on it, so the baseline listener is what
	// keeps destroy(err) on a fatal proxy alert from becoming an uncaught exception.
	const { p } = runHandshake([0x44cd], [])
	const transport = p.h2Transport as EventEmitter
	expect(transport.listenerCount('error')).toBeGreaterThanOrEqual(1)
})

function clientHelloExtensionIds(bytes: Buffer): number[] {
	// TLS record header + handshake header, then the fixed ClientHello prefix.
	let off = 5 + 4 + 2 + 32
	const sessionIdLen = bytes[off++]!
	off += sessionIdLen
	const cipherLen = bytes.readUInt16BE(off)
	off += 2 + cipherLen
	const compressionLen = bytes[off++]!
	off += compressionLen
	const extensionsLen = bytes.readUInt16BE(off)
	off += 2
	const end = off + extensionsLen
	const ids: number[] = []
	while (off < end) {
		ids.push(bytes.readUInt16BE(off))
		off += 4 + bytes.readUInt16BE(off + 2)
	}
	return ids
}

it('emits each ALPS codepoint once when a capture lists both', () => {
	const profile = structuredClone(profileRegistry.get('chrome147-mac'))
	profile.tls!.extensionOrder = [{ id: 17513 }, { id: 17613 }]
	// An older first ALPS label makes the shared override point at the legacy codepoint.
	profile.tls!.alpsExtensionType = 17513
	const t = new TLS('example.com', 443, null, { profile, verifyTLS: false })
	const p = t as unknown as Probe
	const chunks: Buffer[] = []
	p.socket = { write: (chunk) => chunks.push(chunk), destroy: vi.fn() }
	;(t as unknown as { mlkemPk: Buffer }).mlkemPk = Buffer.alloc(1184)

	t.startClientHello()

	const ids = clientHelloExtensionIds(Buffer.concat(chunks))
	expect(ids.filter((id) => id === 0x4469)).toHaveLength(1)
	expect(ids.filter((id) => id === 0x44cd)).toHaveLength(1)
	expect(p.offeredAlpsTypes).toStrictEqual([0x4469, 0x44cd])
})

