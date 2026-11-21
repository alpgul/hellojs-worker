// The hellojs feature tour as data: fourteen scenarios, each one asserting a single
// behaviour and returning the detail line to show for it.
//
// examples/worker.ts runs all fourteen concurrently and the run-test page renders the
// report; the scenarios themselves stay runtime-agnostic so the table reads as a
// checklist rather than as test plumbing.
//
// Endpoints are chosen so a Worker can reach them: a Worker may not open a TCP
// connection into Cloudflare's own address ranges, so the HTTP/3 scenarios point at
// httpbingo (Fly.io) rather than cloudflare.com.

import request from '../index.ts'

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

// Read the typed JSON body of a fetch-style response, draining it exactly once.
async function jsonBody<T>(p: Promise<Response>): Promise<T> {
	const res = await p
	if (!res.ok) throw new Error(`HTTP ${res.status}`)
	return (await res.json()) as T
}

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
			// tls.peet.ws is the one endpoint here with multi-second connect times, so its deadline
			// is spelled out instead of inherited: one 20s AbortSignal covers two ~10s attempts,
			// leaving the Worker's 30s scenario ceiling intact. Each phase no longer has its own
			// configurable budget — the signal is the caller-controlled deadline.
			const r = await jsonBody<PeetBody>(
				tour('https://tls.peet.ws/api/all', {
					signal: AbortSignal.timeout(20_000),
					retry: { limit: 1 }
				})
			)
			return check(
				'JA4 + HTTP/2 Akamai match Chrome 147',
				r?.tls?.ja4 === CHROME_JA4 && r?.http2?.akamai_fingerprint === CHROME_H2,
				`ja4=${r?.tls?.ja4} h2=${r?.http2?.akamai_fingerprint}`
			)
		}
	},
	{
		id: 2,
		name: 'GET response parsed as JSON',
		run: async () => {
			const body = await jsonBody<EchoBody>(tour(`${BIN}/get`))
			return check('body parsed as JSON', !!body.url, `${body.url}`)
		}
	},
	{
		id: 3,
		name: 'GET with query string',
		run: async () => {
			const query = new URLSearchParams({ hello: 'world', n: '42' })
			const body = await jsonBody<EchoBody>(tour(`${BIN}/get?${query}`))
			return check(
				'query string serialized',
				body.args?.hello?.[0] === 'world' && body.args?.n?.[0] === '42',
				JSON.stringify(body.args)
			)
		}
	},
	{
		id: 4,
		name: 'POST json body',
		run: async () => {
			const body = await jsonBody<EchoBody>(
				tour(`${BIN}/post`, {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ greeting: 'hi', count: 3 })
				})
			)
			return check('JSON body round-tripped', body.json?.greeting === 'hi', JSON.stringify(body.json))
		}
	},
	{
		id: 5,
		name: 'POST form body',
		run: async () => {
			const body = await jsonBody<EchoBody>(
				tour(`${BIN}/post`, {
					method: 'POST',
					body: new URLSearchParams({ user: 'alice', role: 'admin' })
				})
			)
			return check(
				'form encoded as x-www-form-urlencoded',
				body.form?.user?.[0] === 'alice',
				JSON.stringify(body.form)
			)
		}
	},
	{
		id: 6,
		name: 'Custom headers over the profile header set',
		run: async () => {
			const body = await jsonBody<EchoBody>(tour(`${BIN}/headers`, { headers: { 'x-app': 'hellojs-demo' } }))
			const ua = echoed(body, 'user-agent') ?? ''
			return check(
				'x-app sent, Chrome UA kept',
				echoed(body, 'x-app') === 'hellojs-demo' && ua.includes('Chrome/147'),
				`UA=${ua.slice(0, 42)}…`
			)
		}
	},
	{
		id: 7,
		name: 'Status code policy',
		run: async () => {
			const res = await tour(`${BIN}/status/418`)
			// Streaming is the default, so drain the body we only inspect for status.
			await res.text()
			return check(
				'4xx resolves like fetch',
				res.status === 418 && !res.ok,
				`${res.status} resolved, ok=${res.ok}`
			)
		}
	},
	{
		id: 8,
		name: 'Auto-follow redirects',
		run: async () => {
			const r = await tour(`${BIN}/redirect/3`)
			// Redirects are followed before resolution; drain the final body.
			await r.text()
			return check('redirect chain followed to 200', r.status === 200, `final status=${r.status}`)
		}
	},
	{
		id: 9,
		name: 'Response body auto-decompressed',
		run: async () => {
			const r = await tour(`${BIN}/get`)
			const enc = String(r.headers.get('content-encoding') ?? 'identity')
			const body = (await r.json()) as EchoBody
			return check(`${enc} decoded transparently`, r.status === 200 && !!body.url, `content-encoding=${enc}`)
		}
	},
	{
		id: 10,
		name: 'Cookie jar persists',
		run: async () => {
			const jar = request.jar()
			// Drain the set-cookie response so its socket closes before the next request.
			await (await tour(`${BIN}/cookies/set?session=hellojs-rocks`, { jar })).text()
			const body = await jsonBody<EchoBody>(tour(`${BIN}/cookies`, { jar }))
			return check(
				'cookie sent back on the next request',
				body.cookies?.session === 'hellojs-rocks',
				JSON.stringify(body.cookies)
			)
		}
	},
	{
		id: 11,
		name: 'defaults() instance',
		run: async () => {
			const api = tour.defaults({ headers: { 'x-app': 'hellojs-demo', 'x-env': 'example' } })
			const r = await api(`${BIN}/headers`)
			const body = (await r.json()) as EchoBody
			return check(
				'defaults applied to a derived entry point',
				r.status === 200 && echoed(body, 'x-app') === 'hellojs-demo' && echoed(body, 'x-env') === 'example',
				'x-app + x-env present'
			)
		}
	},
	{
		id: 12,
		name: 'Firefox 147 profile',
		run: async () => {
			const body = await jsonBody<EchoBody>(tour(`${BIN}/headers`, { profile: 'firefox147' }))
			const ua = echoed(body, 'user-agent') ?? ''
			return check(
				'profile swaps the whole header set',
				ua.includes('Firefox/147') && echoed(body, 'sec-ch-ua') === undefined,
				`UA=${ua.slice(0, 42)}…`
			)
		}
	},
	{
		id: 13,
		name: 'Automatic transport selection',
		run: async () => {
			const t0 = Date.now()
			// The client selects its transport (QUIC when a UDP provider exists, otherwise
			// TCP + TLS); there is no public h3 option. A caller deadline still bounds a
			// request when a server ignores UDP.
			const r = await tour(`${BIN}/get`, { signal: AbortSignal.timeout(20_000) })
			await r.text()
			return check(
				'auto-selected transport served the request',
				r.status === 200,
				`udp transport ${request.udp.udpAvailable() ? 'available' : 'absent → fell back to TCP + TLS'} in ${Date.now() - t0}ms`
			)
		}
	},
	{
		id: 14,
		name: 'Transport-neutral request',
		run: async () => {
			const r = await tour(`${BIN}/get`)
			await r.text()
			return check('plain GET needs no transport flags', r.status === 200, `status=${r.status}`)
		}
	}
]
