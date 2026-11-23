// Regression proof: TLS 1.3 Finished must not be accepted on a verified full handshake
// unless the server's Certificate and CertificateVerify were both processed successfully.

import { expect, it, vi } from 'vitest'

import { TLS } from '../../lib/tls/tls.ts'

// Only the fields/methods the state machine under test touches are modelled here; crypto and
// socket I/O are stubbed so the test isolates the authentication gate itself.
type Probe = {
	encHsBuf: Buffer
	serverAuthenticated: boolean
	pskAccepted: boolean
	pskTicket: { verified: boolean } | null
	socket: { destroy(): void } | null
	_onEncryptedExtensions(body: Buffer): void
	_validateServerFinished(body: Buffer): void
	_deriveApplicationKeys(): void
	_sendClientFinished(): void
	_parseDecryptedHandshake(): void
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
	const t = new TLS('good.example', 443, null, { verifyTLS: opts.verifyTLS !== false })
	const p = t as unknown as Probe
	const finish = vi.fn()
	const destroy = vi.fn()
	let emitted: (Error & { code?: string }) | undefined

	t.on('error', (e) => {
		emitted = e as Error & { code?: string }
	})
	p._onEncryptedExtensions = () => {}
	p._validateServerFinished = () => {}
	p._deriveApplicationKeys = () => {}
	p._sendClientFinished = finish
	p.socket = { destroy }
	p.serverAuthenticated = opts.authenticated === true
	p.pskAccepted = opts.pskAccepted === true
	p.pskTicket = opts.pskVerified === undefined ? null : { verified: opts.pskVerified }
	// EncryptedExtensions then Finished: no Certificate or CertificateVerify on the wire.
	p.encHsBuf = Buffer.concat([hs(0x08, Buffer.alloc(0)), hs(0x14, Buffer.alloc(32))])

	p._parseDecryptedHandshake()
	return { emitted, finish, destroy }
}

it('verifyTLS full handshake without Certificate/CertificateVerify is rejected before Finished', () => {
	const { emitted, finish, destroy } = runHandshake({})
	expect(emitted?.code).toBe('ECERTVALIDATION')
	expect(destroy).toHaveBeenCalledOnce()
	expect(finish).not.toHaveBeenCalled()
})

it('authenticated full handshake still reaches Finished', () => {
	const { emitted, finish, destroy } = runHandshake({ authenticated: true })
	expect(emitted).toBeUndefined()
	expect(destroy).not.toHaveBeenCalled()
	expect(finish).toHaveBeenCalledOnce()
})

it('verified PSK resumption still reaches Finished without a Certificate', () => {
	const { emitted, finish, destroy } = runHandshake({ pskAccepted: true, pskVerified: true })
	expect(emitted).toBeUndefined()
	expect(destroy).not.toHaveBeenCalled()
	expect(finish).toHaveBeenCalledOnce()
})

it('unverified PSK ancestry is not enough when verification is required', () => {
	const { emitted, finish } = runHandshake({ pskAccepted: true, pskVerified: false })
	expect(emitted?.code).toBe('ECERTVALIDATION')
	expect(finish).not.toHaveBeenCalled()
})

it('verifyTLS:false keeps its old behaviour and does not gate on certificate auth', () => {
	const { emitted, finish } = runHandshake({ verifyTLS: false })
	expect(emitted).toBeUndefined()
	expect(finish).toHaveBeenCalledOnce()
})
