// Benchmark hellojs against the major Node.js HTTP clients.
//
// TWO scenarios:
//   1. LOCAL h2 server — deterministic, measures the client's own overhead (default)
//   2. Real internet target — representative, measures end-to-end (opt in; see below)
//
// For each scenario, we measure:
//   - Cold connect: time to first byte on the FIRST request (includes TLS handshake)
//   - Warm-serial: sequential reqs on a reused connection (median + p99)
//   - Concurrent:   wall time for N parallel reqs
//   - RSS delta:    memory growth during the run
//
// Each client runs in its own subprocess (bench-worker.ts) so module-level caches don't
// bleed across runs. Numbers are MS unless noted otherwise.
//
//   npm run bench                 # local h2 server only
//   npm run bench -- --remote     # local + real internet
//   npm run bench -- --remote-only
//
// Env: WARM_REPS (30), CONCURRENT (50), REMOTE_TARGET, REMOTE_WARM_REPS (10),
// REMOTE_CONCURRENT (8).

import { execSync, spawn } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

const WARM_REPS = Number(process.env.WARM_REPS ?? 30)
const CONCURRENT = Number(process.env.CONCURRENT ?? 50)
const REMOTE_TARGET = process.env.REMOTE_TARGET ?? 'www.cloudflare.com/cdn-cgi/trace'
const REMOTE_WARM_REPS = Number(process.env.REMOTE_WARM_REPS ?? 10)
const REMOTE_CONCURRENT = Number(process.env.REMOTE_CONCURRENT ?? 8)

const CLIENTS = ['hellojs', 'node-https', 'node-http2', 'undici', 'got', 'axios', 'node-fetch', 'fetch-native']

interface RunOptions {
	timeoutMs?: number
	warmReps?: number
	concurrent?: number
}

interface WorkerResult {
	client: string
	coldMs?: number
	warmP50?: number
	warmP99?: number
	concWallMs?: number
	concRps?: number
	rssDeltaMB?: number
	error?: string
}

function genCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-'))
	const k = path.join(dir, 'k'), c = path.join(dir, 'c')
	try {
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

const WORKER = path.join(import.meta.dirname, 'bench-worker.ts')

function runWorker(client: string, target: string, port: number | null, opts: RunOptions = {}): Promise<WorkerResult> {
	const perRunTimeoutMs = opts.timeoutMs ?? 90_000
	return new Promise((resolve) => {
		const env: NodeJS.ProcessEnv = {
			...process.env,
			BENCH_CLIENT: client,
			BENCH_TARGET: target,
			BENCH_PORT: String(port ?? ''),
			BENCH_WARM_REPS: String(opts.warmReps ?? WARM_REPS),
			BENCH_CONCURRENT: String(opts.concurrent ?? CONCURRENT),
		}
		const child = spawn(process.execPath, [WORKER], { env, stdio: ['ignore', 'pipe', 'pipe'] })
		let out = ''
		let err = ''
		const timer = setTimeout(() => {
			try {
				child.kill('SIGKILL')
			} catch {}
		}, perRunTimeoutMs)
		child.stdout.on('data', (d: Buffer) => (out += d.toString()))
		child.stderr.on('data', (d: Buffer) => (err += d.toString()))
		child.on('exit', (code, signal) => {
			clearTimeout(timer)
			if (signal === 'SIGKILL') {
				resolve({ client, error: `timeout >${perRunTimeoutMs / 1000}s` })
			} else if (code !== 0) {
				// Skip Node warnings/banners and blank lines so the captured error is the actual
				// failure cause, not a deprecation notice.
				const firstErrorLine = err.trim().split('\n').find((l) => {
					const t = l.trim()
					if (!t) return false
					if (/^\(node:\d+\)/.test(t)) return false // (node:1234) Warning: ...
					if (/^Node\.js v/i.test(t)) return false // version footer
					if (/^(\(Use|Use) `node --trace-/i.test(t)) return false // trace hints
					return true
				})
				resolve({ client, error: (firstErrorLine ?? `exit ${code}`).slice(0, 80) })
			} else {
				try {
					resolve({ client, ...(JSON.parse(out.trim()) as Omit<WorkerResult, 'client'>) })
				} catch {
					resolve({ client, error: 'parse failed: ' + out.slice(0, 100) })
				}
			}
		})
		process.stderr.write(
			`  · ${client} → ${target}${port ? ':' + port : ''} (warm=${opts.warmReps ?? WARM_REPS}, conc=${opts.concurrent ?? CONCURRENT})\n`
		)
	})
}

function pad(s: string | number, n: number): string {
	return String(s).padEnd(n)
}

function fmt(n: number | undefined): string {
	return n == null ? '-' : typeof n === 'number' ? n.toFixed(1) : String(n)
}

function printTable(rows: WorkerResult[], scenario: string): void {
	console.log(`\n--- ${scenario} ---`)
	console.log(`${pad('client', 14)} ${pad('cold', 10)} ${pad('p50/warm', 10)} ${pad('p99/warm', 10)} ${pad('conc', 10)} ${pad('rss Δ', 10)}`)
	console.log('-'.repeat(70))
	for (const r of rows) {
		if (r.error) {
			console.log(`${pad(r.client, 14)} ERROR: ${r.error.slice(0, 50)}`)
		} else {
			console.log(`${pad(r.client, 14)} ${pad(fmt(r.coldMs), 10)} ${pad(fmt(r.warmP50), 10)} ${pad(fmt(r.warmP99), 10)} ${pad(fmt(r.concWallMs), 10)} ${pad(fmt(r.rssDeltaMB) + ' MB', 10)}`)
		}
	}
}

async function runLocalScenario(clients: string[]): Promise<WorkerResult[]> {
	console.log('## Scenario 1: local h2 server (loopback, fixed-size response)')
	const { key, cert } = genCert()
	// allowHTTP1: without it Node's h2 server answers every HTTP/1.1 client with 403, and the
	// h1 rows would measure error pages instead of responses.
	const server = http2.createSecureServer({ key, cert, allowHTTP1: true })
	// One 'request' handler serves both protocols: allowHTTP1 delivers HTTP/1.1 requests here,
	// and the h2 compat layer routes h2 streams here too. (Listening to 'stream' as well would
	// answer every h2 request twice.)
	server.on('request', (_req, res) => {
		res.writeHead(200, { 'content-type': 'application/octet-stream' })
		res.end(Buffer.alloc(1024, 0x41))
	})
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
	const address = server.address()
	if (!address || typeof address === 'string') throw new Error('expected a bound TCP port')
	const port = address.port

	try {
		const results: WorkerResult[] = []
		for (const c of clients) results.push(await runWorker(c, 'local', port))
		printTable(results, 'local h2 server (127.0.0.1, 1KB body)')
		return results
	} finally {
		server.close()
	}
}

async function runRemoteScenario(clients: string[]): Promise<WorkerResult[]> {
	console.log(`\n\n## Scenario 2: ${REMOTE_TARGET} (real internet, warm=${REMOTE_WARM_REPS} conc=${REMOTE_CONCURRENT})`)
	const results: WorkerResult[] = []
	for (const c of clients) {
		results.push(await runWorker(c, REMOTE_TARGET, 443, { warmReps: REMOTE_WARM_REPS, concurrent: REMOTE_CONCURRENT }))
		// Cooldown between clients so the target's per-IP rate limit cools off.
		await new Promise((r) => setTimeout(r, 3000))
	}
	printTable(results, `${REMOTE_TARGET} (real internet)`)
	return results
}

async function main(): Promise<void> {
	const args = new Set(process.argv.slice(2))
	const remoteOnly = args.has('--remote-only')
	const withRemote = remoteOnly || args.has('--remote') || process.env.BENCH_REMOTE === '1'

	console.log('# Node HTTP-client benchmark\n')
	console.log(`Node ${process.version}  WARM_REPS=${WARM_REPS}  CONCURRENT=${CONCURRENT}`)
	if (!withRemote) console.log('(local only — pass --remote for the real-internet scenario)\n')

	const results: WorkerResult[] = []
	if (!remoteOnly) results.push(...(await runLocalScenario(CLIENTS)))
	if (withRemote) results.push(...(await runRemoteScenario(CLIENTS)))

	console.log('\nNotes:')
	console.log('  cold      = time to first byte on the FIRST request, including TLS handshake')
	console.log(`  p50/warm  = median of ${WARM_REPS} sequential reused-connection requests`)
	console.log(`  p99/warm  = 99th percentile of those ${WARM_REPS} reqs`)
	console.log(`  conc      = wall time for ${CONCURRENT} parallel requests (h2 multiplexes; h1 serializes per conn)`)
	console.log('  rss Δ     = process.memoryUsage().rss before vs after the run')
	console.log('\n  hellojs is the ONLY client whose JA4 matches a real Chrome 147 browser.')

	const failed = results.filter((r) => r.error)
	if (failed.length) {
		console.error(`\nFAIL ${failed.length}/${results.length} clients: ${failed.map((r) => r.client).join(', ')}`)
		process.exitCode = 1
	}
}

await main()
