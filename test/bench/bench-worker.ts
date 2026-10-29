// Subprocess worker: run one client through cold + warm + concurrent + memory phases.
// Reads BENCH_CLIENT, BENCH_TARGET, BENCH_PORT, BENCH_WARM_REPS and BENCH_CONCURRENT from
// the environment and prints one JSON result line on success. Spawned by clients.ts so each
// client starts from a clean module cache.

import * as http2 from 'node:http2'
import * as https from 'node:https'

interface Adapter {
	// Returns the response body size in bytes; the harness only needs the request to complete.
	fn: (url: string) => Promise<number>
	cleanup: () => void | Promise<void>
}

const CLIENT = process.env.BENCH_CLIENT
const TARGET = process.env.BENCH_TARGET
const PORT = Number(process.env.BENCH_PORT ?? 443)
const WARM_REPS = Number(process.env.BENCH_WARM_REPS ?? 30)
const CONCURRENT = Number(process.env.BENCH_CONCURRENT ?? 50)

function errMsg(e: unknown): string {
	if (e instanceof Error) {
		// fetch and node:http2 hide the useful part in `cause`.
		const cause = (e as { cause?: unknown }).cause
		return cause ? `${e.message}: ${cause instanceof Error ? cause.message : String(cause)}` : e.message
	}
	return String(e)
}

async function makeAdapter(name: string | undefined): Promise<Adapter> {
	if (name === 'hellojs') {
		const { default: request } = await import('../../index.ts')
		return {
			fn: async (url) => {
				const r = (await request({ url, verifyTLS: false, resolveWithFullResponse: true })) as {
					body?: Buffer
					rawBody?: Buffer
				}
				return r.body?.length || r.rawBody?.length || 0
			},
			cleanup: () => {},
		}
	}
	if (name === 'node-https') {
		const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false })
		return {
			fn: (url) =>
				new Promise<number>((resolve, reject) => {
					const req = https.get(url, { agent, rejectUnauthorized: false }, (res) => {
						let total = 0
						res.on('data', (c: Buffer) => (total += c.length))
						res.on('end', () => resolve(total))
					})
					req.on('error', reject)
				}),
			cleanup: () => agent.destroy(),
		}
	}
	if (name === 'node-http2') {
		// Pool sessions by origin so multiple requests reuse the same connection.
		const sessions = new Map<string, http2.ClientHttp2Session>()
		const getSession = (url: string): http2.ClientHttp2Session => {
			const origin = new URL(url).origin
			let s = sessions.get(origin)
			if (s && !s.destroyed && !s.closed) return s
			s = http2.connect(origin, { rejectUnauthorized: false })
			sessions.set(origin, s)
			s.on('error', () => {})
			return s
		}
		return {
			fn: (url) =>
				new Promise<number>((resolve, reject) => {
					const u = new URL(url)
					const req = getSession(url).request({
						':method': 'GET',
						':path': u.pathname + u.search,
						':authority': u.host,
						':scheme': 'https',
					})
					let total = 0
					req.on('data', (c: Buffer) => (total += c.length))
					req.on('end', () => resolve(total))
					req.on('error', reject)
					req.end()
				}),
			cleanup: () => {
				for (const s of sessions.values()) s.destroy()
			},
		}
	}
	if (name === 'undici') {
		const { Agent, request } = await import('undici')
		const agent = new Agent({ connect: { rejectUnauthorized: false }, allowH2: true })
		return {
			fn: async (url) => {
				const { body } = await request(url, { dispatcher: agent })
				let total = 0
				for await (const chunk of body) total += chunk.length
				return total
			},
			cleanup: () => agent.close(),
		}
	}
	if (name === 'got') {
		const { default: got } = await import('got')
		const client = got.extend({ https: { rejectUnauthorized: false }, http2: true })
		return {
			fn: async (url) => {
				const r = await client(url, { responseType: 'buffer' })
				return r.body.length
			},
			cleanup: () => {},
		}
	}
	if (name === 'axios') {
		const { default: axios } = await import('axios')
		const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false })
		const inst = axios.create({ httpsAgent: agent, responseType: 'arraybuffer', validateStatus: () => true })
		return {
			fn: async (url) => {
				const r = await inst.get<ArrayBuffer>(url)
				return Buffer.from(r.data).length
			},
			cleanup: () => agent.destroy(),
		}
	}
	if (name === 'node-fetch') {
		const { default: fetch } = await import('node-fetch')
		const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false })
		return {
			fn: async (url) => {
				const r = await fetch(url, { agent })
				const b = await r.arrayBuffer()
				return b.byteLength
			},
			cleanup: () => agent.destroy(),
		}
	}
	if (name === 'fetch-native') {
		// Node's built-in undici-backed fetch ignores NODE_TLS_REJECT_UNAUTHORIZED, so the
		// self-signed local server needs a permissive global dispatcher. No allowH2: fetch over
		// h2 with an npm undici Agent hangs against the local server, and h1 is what a stock
		// fetch user gets anyway.
		const { Agent, setGlobalDispatcher } = await import('undici')
		setGlobalDispatcher(new Agent({ connect: { rejectUnauthorized: false } }))
		return {
			fn: async (url) => {
				const r = await fetch(url)
				const b = await r.arrayBuffer()
				return b.byteLength
			},
			cleanup: () => {},
		}
	}
	throw new Error(`unknown client: ${name}`)
}

function percentile(arr: number[], p: number): number {
	const a = arr.slice().sort((x, y) => x - y)
	const idx = Math.floor((p / 100) * (a.length - 1))
	return a[idx]!
}

async function run(): Promise<void> {
	if (!CLIENT || !TARGET) throw new Error('BENCH_CLIENT and BENCH_TARGET are required')
	const url =
		TARGET === 'local'
			? `https://127.0.0.1:${PORT}/`
			: TARGET.includes('/')
				? `https://${TARGET}`
				: `https://${TARGET}/`

	const ad = await makeAdapter(CLIENT)
	const rssBefore = process.memoryUsage().rss

	// COLD: first request through this client. Includes TLS handshake.
	const tCold = process.hrtime.bigint()
	try {
		await ad.fn(url)
	} catch (e) {
		process.stderr.write(`cold failed: ${errMsg(e)}\n`)
		process.exit(2)
	}
	const coldMs = Number(process.hrtime.bigint() - tCold) / 1e6

	// WARM-SERIAL
	const warmTimes: number[] = []
	for (let i = 0; i < WARM_REPS; i++) {
		const t = process.hrtime.bigint()
		await ad.fn(url)
		warmTimes.push(Number(process.hrtime.bigint() - t) / 1e6)
	}

	// CONCURRENT
	const tConc = process.hrtime.bigint()
	await Promise.all(Array.from({ length: CONCURRENT }, () => ad.fn(url)))
	const concWallMs = Number(process.hrtime.bigint() - tConc) / 1e6

	const rssAfter = process.memoryUsage().rss
	await ad.cleanup()

	const result = {
		coldMs,
		warmP50: percentile(warmTimes, 50),
		warmP99: percentile(warmTimes, 99),
		concWallMs,
		concRps: (CONCURRENT * 1000) / concWallMs,
		rssDeltaMB: (rssAfter - rssBefore) / 1024 / 1024,
	}
	process.stdout.write(JSON.stringify(result) + '\n')
	process.exit(0)
}

run().catch((e: unknown) => {
	process.stderr.write(`${errMsg(e)}\n`)
	process.exit(2)
})
