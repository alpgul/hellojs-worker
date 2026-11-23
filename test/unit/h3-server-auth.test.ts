// Regression proof: QUIC/TLS 1.3 Finished must not be accepted on a verification-required
// handshake unless the server's Certificate/CertificateVerify were authenticated (or the PSK
// used for resumption has verified ancestry).

import { expect, it, vi } from 'vitest'

import { QuicConnection } from '../../lib/h3/connection.ts'

type Probe = {
	verifyTLS: boolean
	serverAuthenticated: boolean
	pskAccepted: boolean
	pskTicket: { verified: boolean } | null
	transcript: Buffer[]
	cipher: { hash: string; hashLen: number }
	_onTlsHandshakeMessage(epoch: 'handshake', type: number, body: Buffer, full: Buffer): void
	_processEncryptedExtensions(body: Buffer): void
	_validateServerFinished(body: Buffer): void
	_deriveApplicationKeys(): void
	_sendClientFinished(): void
	_deriveResumptionMasterSecret(): void
	close(code?: number, reason?: string): void
}

function hs(type: number, body: Buffer): Buffer {
	const len = Buffer.alloc(3)
	len.writeUIntBE(body.length, 0, 3)
	return Buffer.concat([Buffer.from([type]), len, body])
}

function runHandshake(opts: {
	verifyTLS?: boolean
	authenticated?: boolean
	pskAccepted?: boolean
	pskVerified?: boolean
}) {
	const c = new QuicConnection('good.example', 443, undefined, opts.verifyTLS !== false)
	const p = c as unknown as Probe
	const finish = vi.fn()
	const close = vi.fn()
	let emitted: (Error & { code?: string }) | undefined

	c.on('error', (e) => {
		emitted = e as Error & { code?: string }
	})
	p._processEncryptedExtensions = () => {}
	p._validateServerFinished = () => {}
	p._deriveApplicationKeys = () => {}
	p._sendClientFinished = finish
	p._deriveResumptionMasterSecret = () => {}
	p.close = close
	p.serverAuthenticated = opts.authenticated === true
	p.pskAccepted = opts.pskAccepted === true
	p.pskTicket = opts.pskVerified === undefined ? null : { verified: opts.pskVerified }
	p.transcript = []
	p.cipher = { hash: 'sha256', hashLen: 32 }

	// EncryptedExtensions then Finished: no Certificate or CertificateVerify on the wire.
	for (const message of [hs(0x08, Buffer.alloc(0)), hs(0x14, Buffer.alloc(32))]) {
		p._onTlsHandshakeMessage('handshake', message[0], message.subarray(4), message)
	}
	return { emitted, finish, close }
}

it('verifyTLS QUIC handshake without certificate authentication is rejected before Finished', () => {
	const { emitted, finish, close } = runHandshake({})
	expect(emitted?.code).toBe('ECERTVALIDATION')
	expect(close).toHaveBeenCalledOnce()
	expect(finish).not.toHaveBeenCalled()
})

it('default QuicConnection requires verification', () => {
	const c = new QuicConnection('good.example', 443)
	expect((c as unknown as Probe).verifyTLS).toBe(true)
})

it('authenticated QUIC handshake still reaches Finished', () => {
	const { emitted, finish, close } = runHandshake({ authenticated: true })
	expect(emitted).toBeUndefined()
	expect(close).not.toHaveBeenCalled()
	expect(finish).toHaveBeenCalledOnce()
})

it('verified PSK resumption still reaches Finished without a Certificate', () => {
	const { emitted, finish } = runHandshake({ pskAccepted: true, pskVerified: true })
	expect(emitted).toBeUndefined()
	expect(finish).toHaveBeenCalledOnce()
})

it('unverified PSK ancestry is not enough when verification is required', () => {
	const { emitted, finish } = runHandshake({ pskAccepted: true, pskVerified: false })
	expect(emitted?.code).toBe('ECERTVALIDATION')
	expect(finish).not.toHaveBeenCalled()
})

it('verifyTLS:false keeps the old QUIC behaviour and does not gate on certificate auth', () => {
	const { emitted, finish } = runHandshake({ verifyTLS: false })
	expect(emitted).toBeUndefined()
	expect(finish).toHaveBeenCalledOnce()
})
