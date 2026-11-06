// CONNECT request validation for `proxyAuthorization` / `proxyHeaders`.
//
// Both options are written straight into the hand-framed CONNECT request (lib/tls/tls.ts's
// sendConnectRequest), so any byte that could end that request early or add a line to it has to
// be rejected at the option boundary, before a proxy is dialled. The rules live in lib/headers.ts.

import { describe, expect, it } from 'vitest'

import { assertProxyConnectHeaders } from '../../lib/headers.ts'

// Names the CONNECT builder emits itself or that reframe the request.
const CONNECT_MANAGED = [
	'host',
	'connection',
	'proxy-connection',
	'te',
	'trailer',
	'transfer-encoding',
	'upgrade',
	'keep-alive'
]

function codeOf(fn: () => void): string | undefined {
	try {
		fn()
	} catch (err) {
		return (err as Error & { code?: string }).code
	}
	return undefined
}

describe('assertProxyConnectHeaders', () => {
	it('accepts the schemes the option exists for', () => {
		for (const value of ['Basic c2FkOnBhc3M=', 'Bearer eyJhbGciOiJIUzI1NiJ9.x.y', '', '   ', null, undefined]) {
			expect(codeOf(() => assertProxyConnectHeaders(value, null)), JSON.stringify(value)).toBeUndefined()
		}
	})

	it('rejects proxyAuthorization bytes that could break out of the CONNECT request', () => {
		for (const value of [
			'Bearer x\r\nX-Injected: 1',
			'Bearer x\nX-Injected: 1',
			'Bearer x\rX-Injected: 1',
			'Bearer\tx',
			'Bearer ünïcode',
			'Bearer \u2028sep',
			'Bearer \u007f',
			'Bearer \u0080'
		]) {
			expect(codeOf(() => assertProxyConnectHeaders(value, null)), JSON.stringify(value)).toBe('EBADOPTS')
		}
	})

	it('rejects proxyHeaders values exactly as strictly', () => {
		expect(codeOf(() => assertProxyConnectHeaders(null, { 'x-a': 'ok' }))).toBeUndefined()
		for (const value of ['v\r\n\r\nGET /evil', 'v\nY: 1', 'ünïcode', 'v\tx']) {
			expect(codeOf(() => assertProxyConnectHeaders(null, { 'x-a': value })), JSON.stringify(value)).toBe('EBADOPTS')
		}
	})

	it('rejects field names that are not HTTP tokens', () => {
		for (const name of ['bad name', '', 'x:y', 'x\r\nY', 'ünïcode-name', 'x;a']) {
			expect(codeOf(() => assertProxyConnectHeaders(null, { [name]: 'v' })), JSON.stringify(name)).toBe('EBADOPTS')
		}
	})

	it('rejects names the CONNECT builder owns, in any casing', () => {
		for (const name of CONNECT_MANAGED) {
			expect(codeOf(() => assertProxyConnectHeaders(null, { [name]: 'x' })), name).toBe('EBADOPTS')
			expect(codeOf(() => assertProxyConnectHeaders(null, { [name.toUpperCase()]: 'x' })), name).toBe('EBADOPTS')
		}
		// proxy-authorization is routed into the auth slot, so it stays legal.
		expect(codeOf(() => assertProxyConnectHeaders(null, { 'Proxy-Authorization': 'Bearer x' }))).toBeUndefined()
	})

	it('accepts a computed __proto__ key as a plain field name', () => {
		// A computed key really does create an own property (the literal `__proto__:` form sets the
		// prototype instead), so this is the shape that reaches the CONNECT builder's accumulator —
		// which is null-prototype for exactly that reason.
		expect(codeOf(() => assertProxyConnectHeaders(null, { ['__proto__']: 'x' }))).toBeUndefined()
		expect(codeOf(() => assertProxyConnectHeaders(null, { ['constructor']: 'x' }))).toBeUndefined()
	})

	it('skips absent entries and absent options', () => {
		expect(codeOf(() => assertProxyConnectHeaders())).toBeUndefined()
		expect(codeOf(() => assertProxyConnectHeaders(undefined, undefined))).toBeUndefined()
		expect(codeOf(() => assertProxyConnectHeaders(null, {}))).toBeUndefined()
		expect(codeOf(() => assertProxyConnectHeaders(null, { 'x-a': undefined as unknown as string }))).toBeUndefined()
	})
})
