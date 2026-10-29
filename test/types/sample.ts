// Strict-TS validation of @unreleased/hellojs's index.d.ts.
//
// This file is compiled via `tsc --noEmit --strict` in CI. Any drift between the .d.ts
// and the real export shape will surface as a compile error here. Importing through the
// package's own name resolves via package.json "exports" -> "types" -> index.d.ts, so this
// program sees exactly what a consumer's `tsc` sees and never the .ts sources behind it.

import request, {
	HellojsError,
	TLS
} from '@unreleased/hellojs'

import type {
	HellojsErrorCode,
	HellojsErrorCategory,
	Response,
	RequestOptions,
	DefaultsFn,
	PerPhaseTimeouts,
} from '@unreleased/hellojs'
import type { Readable, Writable } from 'node:stream'

async function smoke(): Promise<void> {
	// Basic GET, promise form.
	const body: unknown = await request('https://example.com')

	// Full request opts.
	const r = await request({
		url: 'https://example.com/api',
		method: 'POST',
		headers: { authorization: 'Bearer x' },
		json: { name: 'foo' },
		jar: request.jar(),
		gzip: true,
		timeout: 5000,
		timeouts: { connect: 1000, tlsHandshake: 2000, response: 3000 },
		proxy: 'http://127.0.0.1:8080',
		retry: { limit: 2, methods: ['GET'], statusCodes: [503], baseDelayMs: 100 },
		profile: 'chrome147-mac',
		verifyTLS: true,
		resolveWithFullResponse: true,
	})
	// `resolveWithFullResponse: true` as a literal types the result as the full Response.
	{
		const code: number = r.statusCode
		const headers: Record<string, string | string[]> = r.headers
		const _b: unknown = r.body
		const _raw: unknown = r.rawBody
		void code; void headers; void _b; void _raw
	}

	// The README's TypeScript example, verbatim — docs snippets get compiled here.
	const opts: RequestOptions = {
		url: 'https://api.example.com',
		json: true,
		timeouts: { connect: 2000, tlsHandshake: 5000, response: 10_000 },
	}
	{
		const res: Response<{ name: string }> = await request<{ name: string }>({ ...opts, resolveWithFullResponse: true })
		const code: number = res.statusCode
		const name: string = res.body.name
		void code; void name
	}

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
			void code; void cat
		}
	}

	// TLS low-level surface.
	const t = new TLS('example.com', 443, null, { verifyTLS: true })
	t.on('ready', () => {})
	t.on('error', (_err: Error) => {})

	// Streaming response: when stream:true, body is a Readable.
	const stream = await request({ url: 'https://example.com', stream: true }) as Readable
	const sinks: Writable[] = []
	stream.pipe(sinks[0])

	// Streaming request body: Readable as body.
	const streamingReq: RequestOptions = {
		url: 'https://example.com',
		method: 'POST',
		body: process.stdin,   // any Readable
	}
	void streamingReq

	// Per-phase timeouts type.
	const ts: PerPhaseTimeouts = { connect: 1000 }
	void ts

	// defaults() carries the callable, its shortcuts and a further defaults() — and nothing
	// else, since only the root export is decorated with TLS/udp/profiles helpers.
	const api: DefaultsFn = request.defaults({ headers: { 'x-default': 'yes' } })
	await api.get('https://example.com')
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

	void body
}

void smoke
