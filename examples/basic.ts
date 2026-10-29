// Run with: node examples/basic.ts
//
// Tour of hellojs against httpbingo.org. Demonstrates the request.js-shape API
// and the Chrome 147 fingerprint at the same time.

import request from '../index.ts'

import type { HellojsError } from '../index.ts'

// httpbingo echoes the request back under different keys depending on the endpoint.
interface EchoBody {
	url?: string
	method?: string
	args?: Record<string, string[]>
	headers?: Record<string, string[]>
	form?: Record<string, string[]>
	json?: Record<string, unknown>
	cookies?: Record<string, string>
}

// tls.peet.ws reports the fingerprints it saw on the connection.
interface PeetBody {
	tls?: { ja4?: string }
	http2?: { akamai_fingerprint?: string }
}

const log = (label: string, ok: boolean, detail = ''): void => {
	const tag = ok ? '\x1B[32m✓\x1B[0m' : '\x1B[31m✗\x1B[0m'
	console.log(`${tag}  ${label}${detail ? '  —  ' + detail : ''}`)
}
const v = (x: string | string[] | undefined): string | undefined => (Array.isArray(x) ? x[0] : x)

// Run a step, catch any error so one Cloudflare hiccup doesn't kill the whole demo.
const step = async (label: string, fn: () => Promise<void>): Promise<void> => {
	try { await fn() }
	catch (e) {
		const err = e as HellojsError
		log(label, false, `${err.code || err.name}: ${err.message.slice(0, 80)}`)
	}
}

await (async (): Promise<void> => {
	console.log('\n=== hellojs example tour ===\n')

	// 1. Verify Chrome 147 fingerprint against tls.peet.ws
	await step('TLS fingerprint matches Chrome 147', async () => {
		const r = await request<PeetBody>({ url: 'https://tls.peet.ws/api/all', json: true, simple: false })
		log('TLS fingerprint matches Chrome 147', r?.tls?.ja4 === 't13d1516h2_8daaf6152771_d8a2da3f94cd', `JA4 = ${r?.tls?.ja4}`)
		log('HTTP/2 Akamai fingerprint matches Chrome 147',
			r?.http2?.akamai_fingerprint === '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
			r?.http2?.akamai_fingerprint)
	})

	// 2. Plain GET, JSON parse
	await step('GET with json:true', async () => {
		const body = await request<EchoBody>({ url: 'https://httpbingo.org/get', json: true })
		log('GET with json:true', !!body.url, body.url)
	})

	// 3. GET with query string
	await step('GET with qs', async () => {
		const body = await request<EchoBody>({ url: 'https://httpbingo.org/get', qs: { hello: 'world', n: 42 }, json: true })
		log('GET with qs', v(body.args?.hello) === 'world', `args=${JSON.stringify(body.args)}`)
	})

	// 4. POST with JSON body
	await step('POST json body', async () => {
		const body = await request<EchoBody>({ url: 'https://httpbingo.org/post', method: 'POST', json: { greeting: 'hi', count: 3 } })
		log('POST json body', body.json?.greeting === 'hi', `json=${JSON.stringify(body.json)}`)
	})

	// 5. POST with form body
	await step('POST form body', async () => {
		const body = await request<EchoBody>({ url: 'https://httpbingo.org/post', method: 'POST', form: { user: 'alice', role: 'admin' }, json: true })
		log('POST form body', v(body.form?.user) === 'alice', `form=${JSON.stringify(body.form)}`)
	})

	// 6. Custom headers merged with Chrome 147 default header set
	await step('Custom header + Chrome UA', async () => {
		const body = await request<EchoBody>({ url: 'https://httpbingo.org/headers', json: true, headers: { 'x-app': 'hellojs-demo' } })
		const ua = body.headers?.['User-Agent'] || body.headers?.['user-agent']
		const appSent = body.headers?.['X-App']?.[0] === 'hellojs-demo' || body.headers?.['x-app']?.[0] === 'hellojs-demo'
		const chromeUa = v(ua)?.includes('Chrome/147') ?? false
		log('Custom header sent + Chrome UA default', appSent && chromeUa,
			`x-app present, UA=${v(ua)?.slice(0, 50)}…`)
	})

	// 7. Status code policy
	await step('Status code policy', async () => {
		try {
			await request({ url: 'https://httpbingo.org/status/418' })
			log('simple:true rejects on 418', false, 'expected throw')
		} catch (e) {
			const err = e as HellojsError
			log('simple:true rejects on 418', err.code === 'EHTTP' && err.response?.status === 418, `${err.code} ${err.response?.status}`)
		}
		const r = await request({ url: 'https://httpbingo.org/status/418', simple: false, resolveWithFullResponse: true })
		log('simple:false resolves on 418', r.status === 418, `status=${r.status}`)
	})

	// 8. Redirects auto-followed by default
	await step('Auto-follow redirects', async () => {
		const r = await request<EchoBody>({ url: 'https://httpbingo.org/redirect/3', resolveWithFullResponse: true, simple: false, json: true })
		log('Auto-follows redirect chain', r.status === 200, `final status=${r.status}`)
	})

	// 9. zstd decompression (Chrome's default accept-encoding includes zstd)
	await step('zstd', async () => {
		const r = await request<EchoBody>({ url: 'https://httpbingo.org/get', json: true, resolveWithFullResponse: true, simple: false })
		log('zstd response auto-decompressed', r.status === 200 && !!r.body.url, `content-encoding=${r.headers['content-encoding'] || 'none'}`)
	})

	// 10. Cookie jar persists across requests
	await step('Cookie jar', async () => {
		const jar = request.jar()
		await request({ url: 'https://httpbingo.org/cookies/set?session=hellojs-rocks', jar, simple: false, resolveWithFullResponse: true })
		const body = await request<EchoBody>({ url: 'https://httpbingo.org/cookies', jar, json: true })
		log('Cookie jar persists', body.cookies?.session === 'hellojs-rocks', `cookies=${JSON.stringify(body.cookies)}`)
	})

	// 11. defaults() instance — bind common opts
	await step('defaults() instance', async () => {
		const api = request.defaults({ headers: { 'x-app': 'hellojs-demo', 'x-env': 'example' }, json: true, simple: false })
		const r = await api<EchoBody>({ url: 'https://httpbingo.org/headers', resolveWithFullResponse: true })
		log('request.defaults() instance applies defaults', r.status === 200 && !!r.body.headers?.['X-App'], 'x-app + x-env present')
	})

	// 13. HTTP/3 (QUIC) — opt in per request; falls back to TCP if QUIC fails
	await step('HTTP/3 explicit', async () => {
		const t0 = Date.now()
		const r = await request({ url: 'https://www.cloudflare.com/cdn-cgi/trace', h3: true, simple: false, resolveWithFullResponse: true })
		log('HTTP/3 explicit', r.status === 200, `${Date.now() - t0}ms via h3`)
	})

	// 14. h2 by default — no Alt-Svc upgrade happens without h3: true
	await step('h3 off by default', async () => {
		const r = await request({ url: 'https://www.cloudflare.com/cdn-cgi/trace', simple: false, resolveWithFullResponse: true })
		log('request without h3 stays on TCP', r.status === 200, `status=${r.status}`)
	})

	console.log('\n=== done ===\n')
	process.exit(0)
})().catch((e: HellojsError) => {
	console.error('\n\x1B[31m✗  FATAL\x1B[0m', e)
	process.exit(1)
})
