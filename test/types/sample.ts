// Strict-TS validation of @unreleased/hellojs's index.d.ts.
//
// This file is compiled via `tsc --noEmit --strict` in CI. Any drift between the .d.ts
// and the real export shape will surface as a compile error here. Importing through the
// package's own name resolves via package.json "exports" -> "types" -> index.d.ts, so this
// program sees exactly what a consumer's `tsc` sees and never the .ts sources behind it.

import request, { HellojsError, TLS, setPoolConfig } from '@unreleased/hellojs'

import type {
	HellojsErrorCode,
	HellojsErrorCategory,
	Response,
	RequestOptions,
	FetchInit,
	RedirectMode,
	DefaultsFn,
	PerPhaseTimeouts
} from '@unreleased/hellojs'

async function smoke(): Promise<void> {
	// Basic GET: fetch semantics, a real Response.
	const res: Response = await request('https://example.com')
	const ok: boolean = res.ok
	const status: number = res.status
	const statusText: string = res.statusText
	const headers: Headers = res.headers
	const url: string = res.url
	const redirected: boolean = res.redirected
	const clone: Response = res.clone()
	const text: string = await res.text()
	const json: unknown = await res.json()
	void ok
	void status
	void statusText
	void headers
	void url
	void redirected
	void clone
	void text
	void json

	// Fetch-style signature: (input, init). Request.js options may be mixed into init.
	const init: FetchInit = {
		method: 'POST',
		headers: { authorization: 'Bearer x' },
		body: JSON.stringify({ name: 'foo' }),
		signal: new AbortController().signal,
		redirect: 'follow',
		timeout: 5000,
		retry: { limit: 2 }
	}
	const posted: Response = await request('https://example.com/api', init)
	void posted

	// Full request opts (object form).
	const r = await request({
		url: 'https://example.com/api',
		method: 'POST',
		headers: { authorization: 'Bearer x' },
		json: { name: 'foo' },
		jar: request.jar(),
		gzip: true,
		timeout: 5000,
		timeouts: { connect: 1000, tlsHandshake: 2000, response: 3000, bodyIdle: 30_000 },
		proxy: {
			url: 'https://user:pass@127.0.0.1:8443',
			authorization: 'Bearer token',
			headers: { 'x-tenant': 'acme' },
			keepAlive: true
		},
		retry: { limit: 2, methods: ['GET'], statusCodes: [503], baseDelayMs: 100 },
		profile: 'chrome147-mac',
		verifyTLS: true
	})
	{
		const code: number = r.status
		const h: Headers = r.headers
		void code
		void h
	}

	// Inherited RequestInit fields (shared by the DOM and Workers spellings) remain accepted.
	await request({
		url: 'https://example.com',
		method: 'POST',
		headers: { 'x-a': '1' },
		body: 'hello',
		redirect: 'follow',
		cache: 'no-store',
		integrity: 'sha256-abc',
		signal: new AbortController().signal
	})

	// hellojs-only fields are additive to RequestInit.
	const allHellojsFields: RequestOptions = {
		url: 'https://example.com',
		json: { a: 1 },
		form: { a: '1' },
		qs: { page: 2 },
		jar: request.jar(),
		gzip: true,
		maxRedirects: 3,
		timeout: 5000,
		timeouts: { connect: 1000 },
		proxy: { url: 'http://127.0.0.1:8080' },
		retry: { limit: 1 },
		verifyTLS: false,
		resume: true,
		h3: true,
		profile: 'default'
	}
	void allHellojsFields
	await request({ url: 'https://example.com', proxy: null })

	// Pool caps are process-wide: one static call, never a request option.
	request.setPoolConfig({ maxSockets: 2, idleMs: 1000 })
	setPoolConfig()
	// @ts-expect-error pool caps are not a per-request option
	await request({ url: 'https://example.com', pool: { maxSockets: 2 } })

	// The proxy object is now the only place for CONNECT settings, and fetch's `keepalive` is
	// the only spelling for the connection pool switch.
	// @ts-expect-error proxy is an object, not a flat URL string
	await request({ url: 'https://example.com', proxy: 'http://127.0.0.1:8080' })
	// @ts-expect-error flat proxy options were removed
	await request({ url: 'https://example.com', proxyAuthorization: 'Bearer x' })
	// @ts-expect-error flat proxy options were removed
	await request({ url: 'https://example.com', proxyHeaders: { 'x-a': '1' } })
	// @ts-expect-error camelCase `keepAlive` was removed
	await request({ url: 'https://example.com', keepAlive: true })
	// @ts-expect-error proxy.url is required
	await request({ url: 'https://example.com', proxy: {} })
	// @ts-expect-error proxy.url must be a string
	await request({ url: 'https://example.com', proxy: { url: 123 } })

	// Removed request.js response options are rejected at the type level.
	// @ts-expect-error bodyOnly was removed
	await request({ url: 'https://example.com', bodyOnly: true })
	// @ts-expect-error simple was removed
	await request({ url: 'https://example.com', simple: true })

	// HeaderInit spellings all work.
	await request('https://example.com', { headers: [['x-a', '1']] })
	await request('https://example.com', { headers: new Headers({ 'x-b': '2' }) })
	await request('https://example.com', { headers: { 'x-c': '3' } })

	// Request object input.
	const req = new Request('https://example.com')
	await request(req)
	// @ts-expect-error callbacks were removed
	await request('https://example.com', (err: unknown) => void err)

	// Method shortcuts.
	await request.get('https://example.com')
	await request.post({ url: 'https://example.com', json: {} })
	await request.del({ url: 'https://example.com' })

	// Cookie jar.
	const jar = request.jar()
	jar.setCookie('SID=x', 'https://example.com')
	const _ck: string = jar.getCookieString('https://example.com')
	jar.setPublicSuffixList(new Set(['co.uk']))
	jar.setPublicSuffixList((host) => host.endsWith('.invalid'))
	jar.setPublicSuffixList(null)
	jar.gc()
	void _ck

	// Error narrowing.
	try {
		await request('https://example.com')
	} catch (e) {
		if (e instanceof HellojsError) {
			const code: HellojsErrorCode | string = e.code
			const cat: HellojsErrorCategory = e.category
			void code
			void cat
		}
	}

	// TLS low-level surface.
	const t = new TLS('example.com', 443, null, { verifyTLS: true })
	t.on('ready', () => {})
	t.on('error', (_err: Error) => {})

	// Streaming response: the promise resolves at headers; `body` is a web ReadableStream,
	// for H1, H2 and H3 alike.
	const streamed = await request({ url: 'https://example.com' })
	const reader = streamed.body?.getReader()
	if (reader) {
		const { done, value } = await reader.read()
		void done
		if (value) {
			const bytes: Uint8Array = value
			void bytes
		}
		await reader.cancel()
	}

	// Streaming request body: any BodyInit, including a web stream.
	const streamingReq: RequestOptions = {
		url: 'https://example.com',
		method: 'POST',
		body: new ReadableStream<Uint8Array>()
	}
	void streamingReq

	// Per-phase timeouts type.
	const ts: PerPhaseTimeouts = { connect: 1000, bodyIdle: 30_000 }
	void ts

	// Values with a standard are validated, not left as free strings/numbers.
	// Each @ts-expect-error below MUST fail to compile; if the .d.ts loosens again, tsc
	// reports the directive as unused and this file breaks.
	await request({ url: 'https://example.com', method: 'get' }) // any case is fine
	await request({ url: 'https://example.com', method: 'PURGE' }) // extension methods allowed
	await request({ url: 'https://example.com', redirect: 'manual' })
	await request({ url: 'https://example.com', redirect: 'error' })
	// @ts-expect-error redirect is a mode token, not a number
	await request({ url: 'https://example.com', redirect: 123 })
	await request({ url: 'https://example.com', qs: { tag: ['a', 'b'], page: 2 } })
	await request({ url: 'https://example.com', headers: { authorization: 'Bearer x', 'x-trace': '1' } })
	await request({ url: 'https://example.com', retry: { statusCodes: [408, 429, 503], methods: ['GET'] } })
	const mode: RedirectMode = 'manual'
	void mode
	// @ts-expect-error a method is a token, not a number
	await request({ url: 'https://example.com', method: 123 })
	// @ts-expect-error a timeout is milliseconds, not a numeric string
	await request({ url: 'https://example.com', timeout: '5000' })
	// @ts-expect-error header values are strings or string arrays
	await request({ url: 'https://example.com', headers: { 'x-count': 42 } })
	// @ts-expect-error query values may not be nested objects
	await request({ url: 'https://example.com', qs: { filter: { a: 1 } } })
	// @ts-expect-error status codes are numbers (the IANA set autocompletes)
	await request({ url: 'https://example.com', retry: { statusCodes: ['503'] } })
	// @ts-expect-error json must be an RFC 8259 value; a Date is not
	await request({ url: 'https://example.com', json: { at: new Date() } })
	// @ts-expect-error observability events are the documented lifecycle set
	request.observability.on('request:bogus', () => {})

	// Statuses and codes carry the registry/taxonomy types.
	const statusNum: number = (await request({ url: 'https://example.com' })).status
	const code: HellojsErrorCode = 'ETLS_HANDSHAKE'
	const bodyIdle: HellojsErrorCode = 'EBODYIDLE'
	const bodyBackpressure: HellojsErrorCode = 'EBODYBACKPRESSURE'
	const cat: HellojsErrorCategory = 'protocol'
	void statusNum
	void code
	void bodyIdle
	void bodyBackpressure
	void cat
	// @ts-expect-error codes outside the documented taxonomy do not narrow to HellojsErrorCode
	const badCode: HellojsErrorCode = 'ENOPE'
	void badCode

	// defaults() carries the callable, its shortcuts and a further defaults() — and nothing
	// else, since only the root export is decorated with TLS/udp/profiles helpers.
	const api: DefaultsFn = request.defaults({ headers: { 'x-default': 'yes' } })
	const apiRes: Response = await api.get('https://example.com')
	void apiRes
	await api.post({ url: 'https://example.com', json: {} })
	void api.jar().getCookieString('https://example.com')
	void api.defaults({ timeout: 1000 })

	// The root export is decorated with the lower-level surfaces.
	const TlsCtor: typeof TLS = request.TLS
	request.setTrustedRoots([])
	void request.observability.on('request:headersSent', (_p: unknown) => {})
	void request.profiles.list()
	void request.udp.udpAvailable()
	void TlsCtor
}

void smoke
