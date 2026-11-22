// Shared, local-only harness helpers for the benchmark and profiling scripts in this folder.
// No network access is needed: the TLS server is a throwaway self-signed h2 server on loopback.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'
import { gzipSync } from 'node:zlib'

import type { Socket } from 'node:net'

export interface LocalServer {
	/** The `https://127.0.0.1:<port>` origin to request. */
	url: string
	port: number
	close: () => Promise<void>
}

export interface Stats {
	min: number
	p50: number
	p95: number
	p99: number
	mean: number
	total: number
}

/** Throwaway SAN certificate for `localhost` / `127.0.0.1`. Callers must keep verifyTLS off. */
export function generateCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-'))
	const keyPath = path.join(dir, 'k')
	const certPath = path.join(dir, 'c')
	try {
		execSync(
			`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`
		)
		return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

/**
 * Start an h2 server on an ephemeral loopback port. `/large` serves 1 MB so the large-body
 * scenario can share the same server as the small-body scenarios.
 */
export function startLocalH2Server(): Promise<LocalServer> {
	const { key, cert } = generateCert()
	const server = http2.createSecureServer({ key, cert, allowHTTP1: true })
	const sockets = new Set<Socket>()
	server.on('connection', (socket) => {
		sockets.add(socket)
		socket.on('close', () => sockets.delete(socket))
	})
	server.on('request', (_req, res) => {
		const large = _req.url === '/large' || _req.url === '/large.gz'
		const body = Buffer.alloc(large ? 1024 * 1024 : 1024, 0x41)
		if (_req.url === '/large.gz') {
			// Same 1 MB payload, sent encoded: lets the profiler isolate the zlib decode path.
			res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-encoding': 'gzip' })
			res.end(gzipSync(body))
		} else {
			res.writeHead(200, { 'content-type': 'application/octet-stream' })
			res.end(body)
		}
	})
	return new Promise((resolve, reject) => {
		server.once('error', reject)
		server.listen(0, '127.0.0.1', () => {
			const address = server.address()
			if (!address || typeof address === 'string') {
				reject(new Error('expected a bound TCP port'))
				return
			}
			resolve({
				port: address.port,
				url: `https://127.0.0.1:${address.port}`,
				close: () =>
					new Promise<void>((done) => {
						server.close(() => done())
						for (const socket of sockets) socket.destroy()
					})
			})
		})
	})
}

export function stats(values: number[]): Stats {
	const sorted = [...values].sort((a, b) => a - b)
	const sum = values.reduce((a, b) => a + b, 0)
	const at = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))]!
	return { min: sorted[0]!, p50: at(0.5), p95: at(0.95), p99: at(0.99), mean: sum / values.length, total: sum }
}

export function fmt(value: number | undefined, digits = 2): string {
	return value == null ? '-' : value.toFixed(digits)
}
