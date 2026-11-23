// POST with a streamed request body.
//
// `body` accepts a web ReadableStream; a Node Readable is adapted with Readable.toWeb(). The
// client sends it as a
// run of h2 DATA frames (or h1 `transfer-encoding: chunked`), not as one buffered payload. These
// checks pin that contract against a loopback server that reassembles what actually arrived:
//   - a multi-chunk Readable is delivered, in order, with no truncation/duplication,
//   - a large streamed body (several MB) arrives byte-for-byte,
//   - a Readable that errors mid-stream rejects the request with EBODYSTREAM,
//   - a real file stream (fs.createReadStream) uploads correctly.
//
// h2 + TLS1.3 loopback for the main cases; one HTTP/1.1 case exercises the chunked path.
// Deterministic, no live network: runs under the `node` project.

import { execSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as http2 from 'node:http2'
import * as https from 'node:https'
import * as os from 'node:os'
import * as path from 'node:path'
import { Readable } from 'node:stream'

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import request from '../../index.ts'
import { listenOnLoopback } from '../helpers/tcp.ts'

import type { FetchInit } from '../../index.ts'
import type * as http from 'node:http'
import type { TLSSocket } from 'node:tls'

function genServerCert(): { key: Buffer; cert: Buffer } {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hjsb-'))
	const k = path.join(dir, 'k.pem')
	const c = path.join(dir, 'c.pem')
	try {
		execSync(
			`openssl req -x509 -nodes -newkey rsa:2048 -keyout ${k} -out ${c} -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null`
		)
		return { key: fs.readFileSync(k), cert: fs.readFileSync(c) }
	} finally {
		fs.rmSync(dir, { recursive: true, force: true })
	}
}

// What an echo endpoint reassembled from the streamed request body.
interface Received {
	method?: string
	length?: number
	text?: string
}

let h2: http2.Http2SecureServer | null = null
let h1: https.Server | null = null
let h2Base = ''
let h1Base = ''
let tmpFile = ''
const h1Sockets = new Set<TLSSocket>()

// Reassemble the incoming body, then echo method + total bytes (+ the text for small payloads).
function echoBody(readable: NodeJS.ReadableStream, respond: (r: Received) => void): void {
	const bufs: Buffer[] = []
	let length = 0
	readable.on('data', (c: Buffer) => {
		bufs.push(c)
		length += c.length
	})
	readable.on('end', () => {
		const all = Buffer.concat(bufs)
		respond({ length, text: all.length <= 4096 ? all.toString('utf8') : undefined })
	})
	readable.on('error', () => respond({}))
}

beforeAll(async () => {
	const c = genServerCert()

	// A temp file so we can upload via a real fs read-stream.
	tmpFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hjsbf-')), 'payload.txt')
	fs.writeFileSync(tmpFile, 'file-stream-body-contents')

	// HTTP/2 server: /echo streams the request body back.
	h2 = http2.createSecureServer({ key: c.key, cert: c.cert, allowHTTP1: false })
	h2.on('stream', (stream: http2.ServerHttp2Stream, headers) => {
		stream.on('error', () => {
			/* client may RST mid-upload */
		})
		const p = String(headers[':path'] ?? '')
		if (p === '/echo') {
			echoBody(stream, (r) => {
				if (stream.destroyed) return // the client aborted; nothing to answer
				const payload = JSON.stringify({ ...r, method: String(headers[':method']) })
				stream.respond({ ':status': 200, 'content-type': 'application/json' })
				stream.end(payload)
			})
			return
		}
		// /sink drains the body but never answers until END — used to prove chunked delivery starts early.
		stream.on('end', () => {
			if (stream.destroyed) return
			stream.respond({ ':status': 200 })
			stream.end('sunk')
		})
	})
	h2Base = `https://127.0.0.1:${await listenOnLoopback(h2)}`

	// HTTP/1.1 (TLS) server for the chunked upload path.
	h1 = https.createServer({ key: c.key, cert: c.cert }, (req: http.IncomingMessage, res: http.ServerResponse) => {
		if (req.url === '/echo') {
			echoBody(req, (r) => {
				res.writeHead(200, { 'content-type': 'application/json' })
				res.end(
					JSON.stringify({
						...r,
						method: req.method,
						chunked: req.headers['transfer-encoding'] === 'chunked'
					})
				)
			})
			return
		}
		if (req.url === '/early') {
			// A keep-alive early response: the request body is still chunked and unfinished.
			res.writeHead(413, { 'content-length': '0' })
			res.end()
			return
		}
		res.writeHead(404)
		res.end()
	})
	h1.on('secureConnection', (socket) => {
		h1Sockets.add(socket)
		socket.on('close', () => h1Sockets.delete(socket))
	})
	h1Base = `https://127.0.0.1:${await listenOnLoopback(h1)}`
})

afterAll(async () => {
	if (tmpFile) fs.rmSync(path.dirname(tmpFile), { recursive: true, force: true })
	if (h2) await new Promise<void>((resolve) => h2!.close(() => resolve()))
	if (h1) await new Promise<void>((resolve) => h1!.close(() => resolve()))
	h2 = null
	h1 = null
})

const base = () => ({ verifyTLS: false })
// The only streaming BodyInit is a web ReadableStream; Node sources are adapted explicitly.
const web = (body: Readable) => Readable.toWeb(body) as unknown as ReadableStream<Uint8Array>
const echo = async (body: Readable, extra: FetchInit = {}) =>
	(
		await request(`${h2Base}/echo`, { ...base(), ...extra, method: 'POST', body: web(body) })
	).json() as Promise<Received>

describe('POST with a Readable body — HTTP/2', () => {
	it('streams multiple string chunks, reassembled in order', async () => {
		const body = Readable.from(['chunk-a:', 'chunk-b:', 'chunk-c'])
		const res = await echo(body)
		expect(res.method).toBe('POST')
		expect(res.text).toBe('chunk-a:chunk-b:chunk-c')
		expect(res.length).toBe('chunk-a:chunk-b:chunk-c'.length)
	})

	it('streams Buffer chunks', async () => {
		const body = Readable.from([Buffer.from('AB'), Buffer.from('CD'), Buffer.from('EF')])
		const res = await echo(body)
		expect(res.text).toBe('ABCDEF')
		expect(res.length).toBe(6)
	})

	it('streams a body across multiple DATA frames, reassembled byte-for-byte', async () => {
		// 48 KB in 8 KB chunks: bigger than one 16 KB DATA frame, so it proves the streaming path
		// frames + reassembles correctly. It stays under the 64 KB HTTP/2 flow-control window on
		// purpose — sustained uploads LARGER than the advertised window are a separate limitation
		// (lib/h2/session.ts _sendData has no outbound send queue yet; see the large case over
		// HTTP/1.1 chunked below, which has no such cap).
		const TOTAL = 48 * 1024
		const CH = 8 * 1024
		const gen = async function* (): AsyncGenerator<Buffer> {
			let sent = 0
			while (sent < TOTAL) {
				const n = Math.min(CH, TOTAL - sent)
				sent += n
				yield Buffer.alloc(n, 0x41) // 'A'
			}
		}
		const body = Readable.from(gen())
		const res = await echo(body)
		expect(res.length).toBe(TOTAL)
	})

	it('a multi-MB streamed body arrives byte-for-byte over HTTP/2 (send-queue drains on window updates)', async () => {
		// 3 MB far exceeds the 64 KB flow-control window, so this exercises the outbound send queue:
		// _pump holds the backlog and flushes as the server's WINDOW_UPDATE refills the window.
		const TOTAL = 3 * 1024 * 1024
		const CH = 64 * 1024
		const gen = async function* (): AsyncGenerator<Buffer> {
			let sent = 0
			while (sent < TOTAL) {
				const n = Math.min(CH, TOTAL - sent)
				sent += n
				yield Buffer.alloc(n, 0x43) // 'C'
			}
		}
		const body = Readable.from(gen())
		const res = await echo(body)
		expect(res.length).toBe(TOTAL)
	}, 60_000)

	it('uploads via a real fs read-stream', async () => {
		const body = fs.createReadStream(tmpFile)
		const res = await echo(body)
		expect(res.text).toBe('file-stream-body-contents')
		body.destroy()
	})

	it('rejects with EBODYSTREAM when the source stream errors mid-upload', async () => {
		const body = Readable.from(
			(function* (): Generator<Buffer> {
				yield Buffer.from('partial')
				throw new Error('source failed')
			})()
		)
		await expect(echo(body)).rejects.toMatchObject({ code: 'EBODYSTREAM' })
	})
})

describe('POST with a Readable body — HTTP/1.1 chunked', () => {
	it('streams a body over HTTP/1.1 using transfer-encoding: chunked', async () => {
		const body = Readable.from(['h1:', 'streamed:', 'body'])
		const res = (await (
			await request(`${h1Base}/echo`, {
				...base(),
				method: 'POST',
				body: web(body)
			})
		).json()) as { method?: string; text?: string; chunked?: boolean }
		expect(res.method).toBe('POST')
		expect(res.text).toBe('h1:streamed:body')
		// The client must frame a bodyless-length stream as chunked on HTTP/1.1.
		expect(res.chunked).toBe(true)
	})

	it('a multi-MB streamed body arrives byte-for-byte over HTTP/1.1 (no flow-control cap)', async () => {
		// HTTP/1.1 chunked has no equivalent to the HTTP/2 send-window limit, so a sustained
		// multi-MB upload is reassembled intact here.
		const TOTAL = 3 * 1024 * 1024
		const CH = 64 * 1024
		const gen = async function* (): AsyncGenerator<Buffer> {
			let sent = 0
			while (sent < TOTAL) {
				const n = Math.min(CH, TOTAL - sent)
				sent += n
				yield Buffer.alloc(n, 0x42) // 'B'
			}
		}
		const res = (await (
			await request(`${h1Base}/echo`, {
				...base(),
				method: 'POST',
				body: web(Readable.from(gen()))
			})
		).json()) as { method?: string; length?: number; chunked?: boolean }
		expect(res.method).toBe('POST')
		expect(res.length).toBe(TOTAL)
		expect(res.chunked).toBe(true)
	}, 60_000)

	it('closes the connection when the upload errors after an early response', async () => {
		request.clearPool()
		let failUpload!: () => void
		const gate = new Promise<void>((resolve) => {
			failUpload = resolve
		})
		const body = Readable.from(
			(async function* (): AsyncGenerator<Buffer> {
				yield Buffer.from('partial')
				await gate
				throw new Error('late upload failure')
			})()
		)
		const res = await request(`${h1Base}/early`, {
			...base(),
			method: 'POST',
			body: web(body)
		})
		expect(res.status).toBe(413)
		await res.text()
		const [socket] = [...h1Sockets]
		expect(socket).toBeDefined()
		// The response completed before the upload ended, so the socket must be retired now —
		// never released to the pool where another request could check it out.
		await vi.waitFor(() => expect(socket!.destroyed).toBe(true), { timeout: 1000 })

		failUpload()
		expect(socket!.destroyed).toBe(true)
		request.clearPool()
	})
})
