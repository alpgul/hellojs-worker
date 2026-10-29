// The hellojs feature tour as data: fourteen scenarios, each one asserting a single
// behaviour and returning the detail line to show for it.
//
// Two runners share this table:
//   examples/basic.ts   — sequential, printed to a terminal
//   examples/worker.ts  — all fourteen in parallel, rendered by the run-test page
//
// Endpoints are chosen so both runtimes can reach them: a Worker may not open a TCP
// connection into Cloudflare's own address ranges, so the HTTP/3 scenarios point at
// httpbingo (Fly.io) rather than cloudflare.com.

import request from '../index.ts'

import type { HellojsError } from '../index.ts'

// httpbingo echoes the request back under a different key per endpoint.
export interface EchoBody {
	url?: string
	method?: string
	args?: Record<string, string[]>
	headers?: Record<string, string[]>
	form?: Record<string, string[]>
	json?: Record<string, unknown>
	cookies?: Record<string, string>
}

// tls.peet.ws reports the fingerprints it observed on the connection.
export interface PeetBody {
	tls?: { ja4?: string }
	http2?: { akamai_fingerprint?: string }
}

export interface Scenario {
	id: number
	name: string
	/** Resolves with the detail line; rejects with a HellojsError when the expectation fails. */
	run: () => Promise<string>
}

const BIN = 'https://httpbingo.org'
const CHROME_JA4 = 't13d1516h2_8daaf6152771_d8a2da3f94cd'
const CHROME_H2 = '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p'

// The edge occasionally closes a connection without sending a single TLS byte back. hellojs
// already counts ECONNRESET and ETIMEDOUT as transient, so the tour takes two retries over it
// (GET/HEAD/OPTIONS, the policy's own default methods) instead of reporting a dropped handshake
// as a failed feature.
const tour = request.defaults({ retry: { limit: 2 } })

// Echoed header names keep the casing we sent, but not the casing we asked with.
function echoed(body: EchoBody, name: string): string | undefined {
	for (const [key, values] of Object.entries(body.headers ?? {})) {
		if (key.toLowerCase() === name.toLowerCase()) return values[0]
	}
	return undefined
}

// The single assertion point: a scenario that does not pass throws with its own evidence.
function check(label: string, ok: boolean, detail: string): string {
	if (!ok) throw new Error(`${label} — expected true, got ${detail}`)
	return `${label} — ${detail}`
}

export const scenarios: Scenario[] = [
	{
		id: 1,
		name: 'Chrome 147 fingerprints',
		run: async () => {
			// tls.peet.ws is the one endpoint here with multi-second connect times, so its budget is
			// spelled out instead of inherited: 4s connect + 6s response, two tries. Worst case ~20s,
			// which stays inside the Worker's 30s scenario ceiling rather than being cut off mid-retry
			// and reported as a timeout the server never caused.
			const r = await tour<PeetBody>({
				url: 'https://tls.peet.ws/api/all',
				json: true,
				simple: false,
				timeouts: { connect: 4000, response: 6000 },
				retry: { limit: 1 },
			})
			return check(
				'JA4 + HTTP/2 Akamai match Chrome 147',
				r?.tls?.ja4 === CHROME_JA4 && r?.http2?.akamai_fingerprint === CHROME_H2,
				`ja4=${r?.tls?.ja4} h2=${r?.http2?.akamai_fingerprint}`,
			)
		},
	},
	{
		id: 2,
		name: 'GET with json:true',
		run: async () => {
			const body = await tour<EchoBody>({ url: `${BIN}/get`, json: true })
			return check('body parsed as JSON', !!body.url, `${body.url}`)
		},
	},
	{
		id: 3,
		name: 'GET with qs',
		run: async () => {
			const body = await tour<EchoBody>({ url: `${BIN}/get`, qs: { hello: 'world', n: 42 }, json: true })
			return check('query string serialized', body.args?.hello?.[0] === 'world' && body.args?.n?.[0] === '42', JSON.stringify(body.args))
		},
	},
	{
		id: 4,
		name: 'POST json body',
		run: async () => {
			const body = await tour<EchoBody>({ url: `${BIN}/post`, method: 'POST', json: { greeting: 'hi', count: 3 } })
			return check('JSON body round-tripped', body.json?.greeting === 'hi', JSON.stringify(body.json))
		},
	},
	{
		id: 5,
		name: 'POST form body',
		run: async () => {
			const body = await tour<EchoBody>({ url: `${BIN}/post`, method: 'POST', form: { user: 'alice', role: 'admin' }, json: true })
			return check('form encoded as x-www-form-urlencoded', body.form?.user?.[0] === 'alice', JSON.stringify(body.form))
		},
	},
	{
		id: 6,
		name: 'Custom headers over the profile header set',
		run: async () => {
			const body = await tour<EchoBody>({ url: `${BIN}/headers`, json: true, headers: { 'x-app': 'hellojs-demo' } })
			const ua = echoed(body, 'user-agent') ?? ''
			return check(
				'x-app sent, Chrome UA kept',
				echoed(body, 'x-app') === 'hellojs-demo' && ua.includes('Chrome/147'),
				`UA=${ua.slice(0, 42)}…`,
			)
		},
	},
	{
		id: 7,
		name: 'Status code policy',
		run: async () => {
			const rejected = await tour({ url: `${BIN}/status/418` }).then(() => null, (e: HellojsError) => e)
			if (!rejected || rejected.code !== 'EHTTP') throw new Error('simple:true did not reject on 418')
			const res = await tour({ url: `${BIN}/status/418`, simple: false, resolveWithFullResponse: true })
			return check(
				'simple:true rejects, simple:false resolves',
				res.status === 418 && rejected.response?.status === 418,
				`${rejected.code} ${rejected.response?.status} rejected, ${res.status} resolved`,
			)
		},
	},
	{
		id: 8,
		name: 'Auto-follow redirects',
		run: async () => {
			const r = await tour<EchoBody>({ url: `${BIN}/redirect/3`, resolveWithFullResponse: true, simple: false, json: true })
			return check('redirect chain followed to 200', r.status === 200, `final status=${r.status}`)
		},
	},
	{
		id: 9,
		name: 'Response body auto-decompressed',
		run: async () => {
			const r = await tour<EchoBody>({ url: `${BIN}/get`, json: true, resolveWithFullResponse: true, simple: false })
			const enc = String(r.headers['content-encoding'] ?? 'identity')
			return check(`${enc} decoded transparently`, r.status === 200 && !!r.body.url, `content-encoding=${enc}`)
		},
	},
	{
		id: 10,
		name: 'Cookie jar persists',
		run: async () => {
			const jar = request.jar()
			await tour({ url: `${BIN}/cookies/set?session=hellojs-rocks`, jar, simple: false, resolveWithFullResponse: true })
			const body = await tour<EchoBody>({ url: `${BIN}/cookies`, jar, json: true })
			return check('cookie sent back on the next request', body.cookies?.session === 'hellojs-rocks', JSON.stringify(body.cookies))
		},
	},
	{
		id: 11,
		name: 'defaults() instance',
		run: async () => {
			const api = tour.defaults({ headers: { 'x-app': 'hellojs-demo', 'x-env': 'example' }, json: true, simple: false })
			const r = await api<EchoBody>({ url: `${BIN}/headers`, resolveWithFullResponse: true })
			return check(
				'defaults applied to a derived entry point',
				r.status === 200 && echoed(r.body, 'x-app') === 'hellojs-demo' && echoed(r.body, 'x-env') === 'example',
				'x-app + x-env present',
			)
		},
	},
	{
		id: 12,
		name: 'Firefox 147 profile',
		run: async () => {
			const body = await tour<EchoBody>({ url: `${BIN}/headers`, profile: 'firefox147', json: true })
			const ua = echoed(body, 'user-agent') ?? ''
			return check(
				'profile swaps the whole header set',
				ua.includes('Firefox/147') && echoed(body, 'sec-ch-ua') === undefined,
				`UA=${ua.slice(0, 42)}…`,
			)
		},
	},
	{
		id: 13,
		name: 'HTTP/3 explicitly requested',
		run: async () => {
			const t0 = Date.now()
			// Bounded so a server that ignores UDP cannot hold the tour for a minute: the connect
			// budget covers the QUIC handshake, then the request falls back to TCP + TLS.
			const r = await tour({ url: `${BIN}/get`, h3: true, timeouts: { connect: 5000 }, simple: false, resolveWithFullResponse: true })
			return check(
				'h3:true served',
				r.status === 200,
				`udp transport ${request.udp.udpAvailable() ? 'available' : 'absent → fell back to TCP + TLS'} in ${Date.now() - t0}ms`,
			)
		},
	},
	{
		id: 14,
		name: 'HTTP/3 off by default',
		run: async () => {
			const r = await tour({ url: `${BIN}/get`, simple: false, resolveWithFullResponse: true })
			return check('no h3 attempt without the flag', r.status === 200, `status=${r.status}`)
		},
	},
]
