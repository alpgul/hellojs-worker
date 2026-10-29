// Wire-format tests for the extension builders that Phase 2 added.

import { expect, it } from 'vitest'

import {
	CreateStatusRequestExtension,
	CreateStatusRequestV2Extension,
	CreateSignatureAlgorithmsCertExtension,
	CreateSupportedGroupsExtension,
	CreateSupportedVersionsExtension,
	pickGreaseTriple
} from '../../lib/extensions/index.ts'

it('status_request (5): default (Chrome) shape — type=1, 0/0', () => {
	const ext = CreateStatusRequestExtension()
	expect(ext.readUInt16BE(0)).toBe(0x0005)
	expect(ext.readUInt16BE(2) + 4).toBe(ext.length)
	expect(ext.readUInt8(4)).toBe(0x01) // certificate_status_type = ocsp(1)
	expect(ext.readUInt16BE(5)).toBe(0) // responder_id_list_length
	expect(ext.readUInt16BE(7)).toBe(0) // request_extensions_length
})

it('status_request (5): honours non-zero shape from profile', () => {
	const ext = CreateStatusRequestExtension({
		certificateStatusType: 1,
		responderIdListLength: 0,
		requestExtensionsLength: 2
	})
	// 1 byte type + 2 byte ridLen + 0 bytes responder list + 2 byte reqLen + 2 bytes ext data
	expect(ext.readUInt16BE(2)).toBe(1 + 2 + 0 + 2 + 2)
	expect(ext.readUInt16BE(7)).toBe(2)
})

it('status_request_v2 (17): default shape', () => {
	const ext = CreateStatusRequestV2Extension()
	expect(ext.readUInt16BE(0)).toBe(0x0011)
	const bodyLen = ext.readUInt16BE(2)
	expect(ext.readUInt16BE(4) + 2).toBe(bodyLen)
	// Inside the list: type(1) + ridLen(2) + reqLen(2) = 5 bytes
	expect(ext.readUInt8(6)).toBe(0x02)
	expect(ext.readUInt16BE(7)).toBe(0)
	expect(ext.readUInt16BE(9)).toBe(0)
})

it('status_request_v2 (17): non-zero responder/request lengths', () => {
	const ext = CreateStatusRequestV2Extension({
		certificateStatusType: 0,
		responderIdListLength: 7,
		requestExtensionsLength: 2
	})
	// list_len + item(type + ridLen + 7 padding + reqLen + 2 padding)
	expect(ext.readUInt16BE(2)).toBe(2 + 1 + 2 + 7 + 2 + 2)
	expect(ext.readUInt8(6)).toBe(0)
	expect(ext.readUInt16BE(7)).toBe(7)
})

it('signature_algorithms_cert (50): emits raw body verbatim', () => {
	const raw = Buffer.from('00040403080a', 'hex') // 2 sigalgs: 0x0403, 0x080a
	const ext = CreateSignatureAlgorithmsCertExtension({ raw })
	expect(ext.readUInt16BE(0)).toBe(0x0032)
	expect(ext.readUInt16BE(2)).toBe(raw.length)
	expect(ext.subarray(4).equals(raw)).toBe(true)
})

it('signature_algorithms_cert (50): builds from sigalgs array', () => {
	const ext = CreateSignatureAlgorithmsCertExtension({ sigalgs: [0x0403, 0x0809] })
	expect(ext.readUInt16BE(0)).toBe(0x0032)
	expect(ext.readUInt16BE(2)).toBe(2 + 4)
	expect(ext.readUInt16BE(4)).toBe(4) // inner list length
	expect(ext.readUInt16BE(6)).toBe(0x0403)
	expect(ext.readUInt16BE(8)).toBe(0x0809)
})

it('signature_algorithms_cert (50): throws without raw or sigalgs', () => {
	expect(() => CreateSignatureAlgorithmsCertExtension({})).toThrow(/raw \(Buffer\) or opts\.sigalgs/)
})

it('supported_groups (10): useGrease=true prepends GREASE codepoint', () => {
	const ext = CreateSupportedGroupsExtension(0xAA, [0x001d, 0x0017])
	// hdr(2) + extLen(2) + listLen(2) + entries(3*2=6)
	expect(ext.length).toBe(12)
	expect(ext.readUInt16BE(6)).toBe(0xAAAA) // GREASE
	expect(ext.readUInt16BE(8)).toBe(0x001d)
	expect(ext.readUInt16BE(10)).toBe(0x0017)
})

it('supported_groups (10): useGrease=false omits GREASE', () => {
	const ext = CreateSupportedGroupsExtension(0xAA, [0x001d, 0x0017], { useGrease: false })
	// hdr(2) + extLen(2) + listLen(2) + entries(2*2=4)
	expect(ext.length).toBe(10)
	expect(ext.readUInt16BE(6)).toBe(0x001d)
	expect(ext.readUInt16BE(8)).toBe(0x0017)
})

it('supported_versions (43): useGrease=true prepends GREASE codepoint', () => {
	const ext = CreateSupportedVersionsExtension(0xBB, [0x0304, 0x0303])
	// hdr(2) + extLen(2) + listLen(1) + entries(3*2=6)
	expect(ext.length).toBe(11)
	expect(ext.readUInt16BE(5)).toBe(0xBBBB)
	expect(ext.readUInt16BE(7)).toBe(0x0304)
})

it('supported_versions (43): useGrease=false emits only the requested versions', () => {
	const ext = CreateSupportedVersionsExtension(0xBB, [0x0303], { useGrease: false })
	// hdr(2) + extLen(2) + listLen(1) + entries(1*2=2)
	expect(ext.length).toBe(7)
	expect(ext.readUInt16BE(5)).toBe(0x0303)
})

it('pickGreaseTriple: values are valid GREASE bytes and pairwise distinct', () => {
	// The triple stores the 0x?a byte; the wire value is that byte doubled (0x?a?a).
	const allowed = new Set([0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a, 0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa])
	for (let i = 0; i < 2_000; i++) {
		const { a, b, c } = pickGreaseTriple()
		for (const v of [a, b, c]) expect(allowed.has(v), `0x${v.toString(16)} is a GREASE byte`).toBe(true)
		// a and b type the first and last extensions: a collision puts two extensions of the
		// same type in one ClientHello, which strict servers reject with alert 50.
		expect(new Set([a, b, c]).size).toBe(3)
	}
})
