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
	HttpMethod,
	RegisteredHttpMethod,
	RedirectMode,
	DefaultsFn,
	RequestBodyValue
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

	// Fetch-style init: body is a strict BodyInit; callers serialize JSON themselves.
	const init: FetchInit = {
		method: 'POST',
		headers: { authorization: 'Bearer x', 'content-type': 'application/json' },
		body: JSON.stringify({ name: 'foo' }),
		signal: new AbortController().signal,
		redirect: 'follow',
		retry: { limit: 2 }
	}
	const posted: Response = await request('https://example.com/api', init)
	void posted

	// Every supported init field in one place.
	const allHellojsFields: RequestOptions = {
		method: 'POST',
		headers: { 'x-a': '1' },
		body: new URLSearchParams({ a: '1' }),
		jar: request.jar(),
		proxy: { url: 'http://127.0.0.1:8080' },
		retry: { limit: 1, methods: ['GET'], statusCodes: [503], baseDelayMs: 100 },
		verifyTLS: false,
		keepalive: false,
		profile: 'default'
	}
	void allHellojsFields
	await request('https://example.com', { proxy: null })

	// Pool caps are process-wide: one static call, never a request option.
	request.setPoolConfig({ maxSockets: 2, idleMs: 1000 })
	setPoolConfig()
	// @ts-expect-error pool caps are not a per-request option
	await request('https://example.com', { pool: { maxSockets: 2 } })

	// The proxy object is the only place for CONNECT settings.
	// @ts-expect-error proxy is an object, not a flat URL string
	await request('https://example.com', { proxy: 'http://127.0.0.1:8080' })
	// @ts-expect-error flat proxy options were removed
	await request('https://example.com', { proxyAuthorization: 'Bearer x' })
	// @ts-expect-error flat proxy options were removed
	await request('https://example.com', { proxyHeaders: { 'x-a': '1' } })
	// @ts-expect-error camelCase `keepAlive` was removed
	await request('https://example.com', { keepAlive: true })
	// @ts-expect-error proxy.url is required
	await request('https://example.com', { proxy: {} })
	// @ts-expect-error proxy.url must be a string
	await request('https://example.com', { proxy: { url: 123 } })

	// Removed request.js response options are rejected at the type level.
	// @ts-expect-error bodyOnly was removed
	await request('https://example.com', { bodyOnly: true })
	// @ts-expect-error simple was removed
	await request('https://example.com', { simple: true })

	// The whole request.js option family is gone. Each directive must stay rejected.
	// @ts-expect-error url comes from input, never init
	await request('https://example.com', { url: 'https://example.com' })
	// @ts-expect-error uri was removed
	await request('https://example.com', { uri: 'https://example.com' })
	// @ts-expect-error json was removed; serialize with JSON.stringify
	await request('https://example.com', { json: { a: 1 } })
	// @ts-expect-error form was removed; use URLSearchParams
	await request('https://example.com', { form: { a: '1' } })
	// @ts-expect-error qs was removed; put the query in the input URL
	await request('https://example.com', { qs: { page: 2 } })
	// @ts-expect-error gzip was removed; decoding is automatic
	await request('https://example.com', { gzip: true })
	// @ts-expect-error maxRedirects was removed; the browser limit is fixed at 20
	await request('https://example.com', { maxRedirects: 3 })
	// @ts-expect-error timeout was removed; use signal
	await request('https://example.com', { timeout: 5000 })
	// @ts-expect-error timeouts was removed; use signal
	await request('https://example.com', { timeouts: { connect: 1000 } })
	// @ts-expect-error resume was removed; resumption is internal
	await request('https://example.com', { resume: false })
	// @ts-expect-error h3 was removed; transport is selected automatically
	await request('https://example.com', { h3: true })

	// The object call form is gone too.
	// @ts-expect-error request({ url, ... }) was replaced by request(input, init)
	await request({ url: 'https://example.com' })
	// @ts-expect-error shortcuts take an input URL, not an options object
	await request.post({ url: 'https://example.com', json: {} })
	// @ts-expect-error defaults init cannot carry a url
	await request.defaults({ url: 'https://example.com' })
	// @ts-expect-error defaults init cannot carry a timeout
	await request.defaults({ timeout: 1000 })

	// Headers have the three fetch spellings.
	await request('https://example.com', { headers: [['x-a', '1']] })
	await request('https://example.com', { headers: new Headers({ 'x-b': '2' }) })
	await request('https://example.com', { headers: { 'x-c': '3' } })
	// @ts-expect-error header values are strings or string arrays
	await request('https://example.com', { headers: { 'x-count': 42 } })

	// Request object input.
	const req = new Request('https://example.com')
	await request(req)
	// @ts-expect-error callbacks were removed
	await request('https://example.com', (err: unknown) => void err)

	// Method shortcuts.
	await request.get('https://example.com')
	await request.post('https://example.com', { body: JSON.stringify({}) })
	await request.del('https://example.com')

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

	// TLS low-level surface: `resume` is internal-only and not part of public TLSOptions.
	const t = new TLS('example.com', 443, null, { verifyTLS: true })
	t.on('ready', () => {})
	t.on('error', (_err: Error) => {})
	// @ts-expect-error resume is not a public TLS option
	const _badTlsOptions: ConstructorParameters<typeof TLS>[3] = { resume: false }
	void _badTlsOptions

	// Streaming response: the promise resolves at headers; `body` is a web ReadableStream.
	const streamed = await request('https://example.com')
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

	// Streaming request body: a web stream is a valid BodyInit.
	const streamingReq: RequestOptions = {
		method: 'POST',
		body: new ReadableStream<Uint8Array>()
	}
	void streamingReq
	// Node's DOM typings count async iterables as BodyInit, but the runtime only accepts
	// web ReadableStream — use Readable.toWeb(stream) for Node streams (see README).
	// @ts-expect-error plain objects are not serialized automatically
	await request('https://example.com', { method: 'POST', body: { a: 1 } })

	// Strict method union: registered methods (either case) only; runtime is still permissive.
	const upper: HttpMethod = 'GET'
	const lower: RegisteredHttpMethod | HttpMethod = 'patch'
	void upper
	void lower
	await request('https://example.com', { method: 'get' })
	// @ts-expect-error extension methods are not in the public union
	await request('https://example.com', { method: 'PURGE' })
	// @ts-expect-error a method is a token, not a number
	await request('https://example.com', { method: 123 })
	await request('https://example.com', { redirect: 'manual' })
	await request('https://example.com', { redirect: 'error' })
	// @ts-expect-error redirect is a mode token, not a number
	await request('https://example.com', { redirect: 123 })
	await request('https://example.com', { headers: { authorization: 'Bearer x', 'x-trace': '1' } })
	await request('https://example.com', { retry: { statusCodes: [408, 429, 503], methods: ['GET'] } })
	const mode: RedirectMode = 'manual'
	void mode
	// @ts-expect-error status codes are numbers
	await request('https://example.com', { retry: { statusCodes: ['503'] } })
	// @ts-expect-error observability events are the documented lifecycle set
	request.observability.on('request:bogus', () => {})

	// Statuses and codes carry the registry/taxonomy types.
	const statusNum: number = (await request('https://example.com')).status
	const code: HellojsErrorCode = 'ETLS_HANDSHAKE'
	const redirectCode: HellojsErrorCode = 'ETOOMANYREDIRECTS'
	const bodyBackpressure: HellojsErrorCode = 'EBODYBACKPRESSURE'
	const cat: HellojsErrorCategory = 'protocol'
	void statusNum
	void code
	void redirectCode
	void bodyBackpressure
	void cat
	// @ts-expect-error EBODYIDLE was removed with the body-idle watchdog
	const bodyIdle: HellojsErrorCode = 'EBODYIDLE'
	void bodyIdle
	// @ts-expect-error codes outside the documented taxonomy do not narrow to HellojsErrorCode
	const badCode: HellojsErrorCode = 'ENOPE'
	void badCode

	// BodyInit is strict; RequestBodyValue is the alias consumers see.
	const textBody: RequestBodyValue = 'hello'
	const formBody: RequestBodyValue = new URLSearchParams({ a: '1' })
	void textBody
	void formBody
	// @ts-expect-error PerPhaseTimeouts was removed with the public timeout options
	const ts = {} as import('@unreleased/hellojs').PerPhaseTimeouts
	void ts

	// defaults() carries the callable, its shortcuts and a further defaults() — and nothing
	// else, since only the root export is decorated with TLS/udp/profiles helpers.
	const api: DefaultsFn = request.defaults({ headers: { 'x-default': 'yes' } })
	const apiRes: Response = await api.get('https://example.com')
	void apiRes
	await api.post('https://example.com', { body: JSON.stringify({}) })
	void api.jar().getCookieString('https://example.com')

	// The root export is decorated with the lower-level surfaces.
	const TlsCtor: typeof TLS = request.TLS
	request.setTrustedRoots([])
	void request.observability.on('request:headersSent', (_p: unknown) => {})
	void request.profiles.list()
	void request.udp.udpAvailable()
	void TlsCtor
}

void smoke
