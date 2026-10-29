// OCSP stapled-response parser tests. We don't have a stable test vector library, so we
// build minimal hand-rolled DER for the happy paths.

import { expect, it } from 'vitest'

import { parseOcspResponse } from '../../lib/tls/ocsp.ts'

// Build a SEQUENCE prefixed with tag 0x30 + length.
function seq(content: Buffer[]): Buffer {
	const c = Buffer.concat(content)
	return Buffer.concat([Buffer.from([0x30, c.length]), c])
}
const enumerated = (v: number): Buffer => Buffer.from([0x0a, 1, v])
const expl0 = (content: Buffer): Buffer => Buffer.concat([Buffer.from([0xa0, content.length]), content])
const expl1 = (content: Buffer): Buffer => Buffer.concat([Buffer.from([0xa1, content.length]), content])
const octStr = (content: Buffer): Buffer => Buffer.concat([Buffer.from([0x04, content.length]), content])
const oid = (b: Buffer): Buffer => Buffer.concat([Buffer.from([0x06, b.length]), b])
const genTime = (s: string): Buffer => Buffer.concat([Buffer.from([0x18, s.length]), Buffer.from(s)])
const ctxImplicit = (tag: number, content: Buffer): Buffer => Buffer.concat([Buffer.from([tag, content.length]), content])

// Construct a minimal SuccessfulOcspResponse with one SingleResponse whose certStatus is `tag`.
// tag: 0x80 (good), 0xa1 (revoked), 0x82 (unknown).
function buildResp(certStatusTag: number): Buffer {
	const singleResp = seq([
		seq([Buffer.alloc(0)]),                       // certID (empty SEQUENCE placeholder)
		ctxImplicit(certStatusTag, Buffer.alloc(0)),  // certStatus
		genTime('20260513120000Z'),                   // thisUpdate
	])
	const responses = seq([singleResp])
	const responderIdName = expl1(seq([Buffer.alloc(0)]))     // [1] EXPLICIT Name
	const producedAt = genTime('20260513120000Z')
	const tbs = seq([responderIdName, producedAt, responses])

	const basicOCSP = seq([
		tbs,
		seq([oid(Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]))]),  // signatureAlgorithm (faked)
		Buffer.from([0x03, 0x01, 0x00]),              // signature BIT STRING (empty)
	])

	const responseBytes = expl0(seq([
		oid(Buffer.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01])),  // basic OCSP OID
		octStr(basicOCSP),
	]))

	return seq([
		enumerated(0),     // successful
		responseBytes,
	])
}

it('parses OCSP responseStatus=successful + cert status=good', () => {
	const r = parseOcspResponse(buildResp(0x80))
	expect(r.responseStatus).toBe('successful')
	expect(r.statuses).toStrictEqual(['good'])
})

it('parses cert status=revoked', () => {
	const r = parseOcspResponse(buildResp(0xa1))
	expect(r.responseStatus).toBe('successful')
	expect(r.statuses).toStrictEqual(['revoked'])
})

it('parses cert status=unknown', () => {
	const r = parseOcspResponse(buildResp(0x82))
	expect(r.responseStatus).toBe('successful')
	expect(r.statuses).toStrictEqual(['unknown'])
})

it('handles malformedRequest (non-successful) without crashing', () => {
	const der = Buffer.concat([
		Buffer.from([0x30, 0x03]),
		Buffer.from([0x0a, 0x01, 0x01]),  // ENUMERATED 1 = malformedRequest
	])
	const r = parseOcspResponse(der)
	expect(r.responseStatus).toBe('malformedRequest')
	expect(r.statuses).toStrictEqual([])
})

it('handles empty buffer', () => {
	const r = parseOcspResponse(Buffer.alloc(0))
	expect(r.responseStatus).toBeNull()
})
