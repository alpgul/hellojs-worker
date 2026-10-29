// opts.stream returns a Readable that delivers chunks as they arrive (no buffer).

import { execSync } from 'node:child_process'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as os from 'node:os'
import * as path from 'node:path'

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type { Readable } from 'node:stream'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjsrv-'))
	const k = path.join(dir, 'k.pem'), c = path.join(dir, 'c.pem')
	try {
		// Fixed tmpdir paths, no user input reaches the shell string.
		execSync(`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

it('opts.stream resolves with a Readable that yields chunks progressively', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert, allowHTTP1: false })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 200, 'content-type': 'application/octet-stream' })
		// Write 16 chunks of 8KB so the client receives them piecewise.
		let n = 0
		const tick = () => {
			if (n >= 16) { stream.end(); return }
			stream.write(crypto.randomBytes(8192))
			n++
			setImmediate(tick)
		}
		tick()
	})
	const port = await listenOnLoopback(server)

	try {
		// localhost cert is not in trust store, so we must disable cert validation.
		const stream = await request({
			url: `https://127.0.0.1:${port}/`,
			stream: true,
			verifyTLS: false,
		}) as unknown as Readable

		let bytes = 0
		let chunkCount = 0
		await new Promise<void>((resolve, reject) => {
			stream.on('data', (c: Buffer) => { bytes += c.length; chunkCount++ })
			stream.on('end', resolve)
			stream.on('error', reject)
		})

		expect(bytes, 'all bytes received').toBe(16 * 8192)
		expect(chunkCount, `expected multiple progressive chunks, got ${chunkCount}`).toBeGreaterThanOrEqual(2)
	} finally {
		server.close()
	}
}, 10_000)

it('opts.stream + resolveWithFullResponse exposes status, headers, body Readable', async () => {
	const { key, cert } = genServerCert()
	const server = http2.createSecureServer({ key, cert })
	server.on('stream', (stream) => {
		stream.respond({ ':status': 201, 'x-hello': 'world' })
		stream.end('payload')
	})
	const port = await listenOnLoopback(server)

	try {
		const res = await request({
			url: `https://127.0.0.1:${port}/`,
			stream: true,
			resolveWithFullResponse: true,
			verifyTLS: false,
		})
		expect(res.statusCode).toBe(201)
		expect(res.headers['x-hello']).toBe('world')
		// opts.stream puts a Readable in body, which the Response<TBody> default cannot know.
		const body = res.body as Readable
		expect(typeof body.pipe).toBe('function')
		const chunks: Buffer[] = []
		for await (const c of body) chunks.push(c)
		expect(Buffer.concat(chunks).toString()).toBe('payload')
	} finally {
		server.close()
	}
}, 10_000)
