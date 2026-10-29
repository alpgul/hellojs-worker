// Sustained-load soak: open many connections against a local h2 server and check that
// neither heap nor OS handles grow with the request count. Runs in the node project, so
// `npm test` and CI execute it on every change; raise the load with the SOAK_* knobs:
//
//   SOAK_REQUESTS=200000 SOAK_CONCURRENCY=200 npm run test:soak
//
// Each request opens its own connection (the client does not pool), so this exercises the
// full handshake + teardown path. Heap growth is measured after an explicit GC, comparing
// the idle baseline with the post-load state; a leak shows up as growth that survives GC.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

import { afterAll, beforeAll, expect, it } from 'vitest'

import request from '../../index.ts'

const TOTAL_REQUESTS = Number(process.env.SOAK_REQUESTS ?? 300)
const CONCURRENCY = Number(process.env.SOAK_CONCURRENCY ?? 25)
const HEAP_BUDGET_MB = Number(process.env.SOAK_HEAP_BUDGET_MB ?? 40)
const HANDLE_BUDGET = Number(process.env.SOAK_HANDLE_BUDGET ?? 20)
const TIMEOUT_MS = Number(process.env.SOAK_TIMEOUT_MS ?? 120_000)

function genCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'soak-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	try {
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

// process._getActiveHandles is the only leak signal Node exposes; it is undocumented, so it
// is missing from the typings and may be absent at runtime.
function activeHandles(): number {
	const proc = process as unknown as { _getActiveHandles?: () => unknown[] }
	return proc._getActiveHandles?.().length ?? -1
}

function heapUsedMB(): number {
	return process.memoryUsage().heapUsed / 1024 / 1024
}

async function collectGarbage(): Promise<void> {
	const gc = (globalThis as { gc?: () => void }).gc
	if (!gc) return
	for (let i = 0; i < 3; i++) {
		gc()
		// Let finalizers and pending I/O callbacks run before measuring.
		await new Promise((resolve) => setTimeout(resolve, 50))
	}
}

let server: http2.Http2SecureServer
let port = 0

beforeAll(async () => {
	const { key, cert } = genCert()
	server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-type': 'application/json' })
		stream.end(JSON.stringify({ ts: Date.now(), payload: 'x'.repeat(512) }))
	})
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
	const address = server.address()
	if (!address || typeof address === 'string') throw new Error('expected a bound TCP port')
	port = address.port
})

afterAll(() => {
	server?.close()
})

it(
	'sustained load does not leak heap or sockets',
	async () => {
		const url = `https://127.0.0.1:${port}/`
		const send = () => request({ url, verifyTLS: false, json: true })

		// Warm up once so the baseline excludes first-request allocations.
		await send()
		await collectGarbage()
		const baselineHeap = heapUsedMB()
		const baselineHandles = activeHandles()

		let issued = 0
		let completed = 0
		const started = Date.now()

		async function worker(): Promise<void> {
			while (issued < TOTAL_REQUESTS) {
				issued++
				await send()
				completed++
			}
		}

		await Promise.all(Array.from({ length: Math.min(CONCURRENCY, TOTAL_REQUESTS) }, worker))

		const elapsedSec = (Date.now() - started) / 1000
		await collectGarbage()
		const finalHeap = heapUsedMB()
		const finalHandles = activeHandles()

		const heapGrowthMB = finalHeap - baselineHeap
		const handleGrowth = finalHandles - baselineHandles
		const rps = completed / elapsedSec
		process.stdout.write(
			`    soak: ${completed} requests in ${elapsedSec.toFixed(2)}s (${rps.toFixed(0)} rps), ` +
			`heap ${heapGrowthMB.toFixed(2)} MB, handles ${baselineHandles} -> ${finalHandles}\n`
		)

		expect(completed).toBe(TOTAL_REQUESTS)

		const gc = (globalThis as { gc?: () => void }).gc
		if (gc) {
			expect(heapGrowthMB, `heap grew ${heapGrowthMB.toFixed(2)} MB after GC (budget ${HEAP_BUDGET_MB} MB)`)
				.toBeLessThan(HEAP_BUDGET_MB)
		}

		if (baselineHandles >= 0 && finalHandles >= 0) {
			expect(handleGrowth, `active handles grew by ${handleGrowth} (budget +${HANDLE_BUDGET}) — possible socket leak`)
				.toBeLessThanOrEqual(HANDLE_BUDGET)
		}
	},
	TIMEOUT_MS
)
