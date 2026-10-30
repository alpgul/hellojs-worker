// hellojs on Node — the same fourteen scenarios as examples/worker.ts, run from the terminal.
//
//   npm run example:node
//
// What differs from the Worker (examples/worker.ts does none of the Worker's setup here):
//
//   1. UDP is real. The library's UDP seam resolves to node:dgram on its own, so scenario 13
//      actually attempts QUIC; a network that blocks UDP makes it fall back to TCP + TLS.
//   2. The trust store is real. Certificate validation reads node:tls's bundled roots, so the
//      generated Mozilla bundle the Worker installs is not needed.
//   3. ML-KEM is native. Node 24.7+ supplies ML-KEM-768 through node:crypto.webcrypto, and
//      WebCrypto is resolved there even if the globalThis.crypto global is absent.
//
// Network access is required; this is a manual tour, not part of `npm test`.

import request from '../index.ts'

import { runScenario } from './scenario-runner.ts'
import { scenarios } from './scenarios.ts'

const t0 = Date.now()
const results = await Promise.all(scenarios.map(runScenario))
const passed = results.filter((row) => row.ok).length

for (const row of results) {
	const mark = row.ok ? 'ok  ' : 'FAIL'
	console.log(`${mark} #${row.id} ${row.name} — ${row.detail} (${row.ms}ms)`)
}
console.log(
	`\n${passed}/${results.length} passed in ${Date.now() - t0}ms` +
		` · UDP transport: ${request.udp.udpAvailable() ? 'available' : 'absent'}`,
)

process.exitCode = passed === results.length ? 0 : 1
