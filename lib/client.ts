// Public request.js-shape API.
//
//   import request from 'hellojs'
//   request({ url, method, headers, body, json, qs, jar, gzip, followRedirect, timeout, proxy }, (err, res, body) => {})
//   request({...}).then(res => {})            // promise form
//   request.get/post/put/del/patch/head/options
//   request.defaults(opts)
//   request.jar()
//
// Notes:
// - Driven by lib/connect.ts and lib/tls/tls.ts for TLS+HTTP/2. Every request opens
//   a fresh connection and closes it when the response completes.
// - HTTP/1.1 fallback is hand-rolled (chunked, content-length).
// - Auto-decompresses gzip / br / deflate / zstd response bodies based on the response's
//   Content-Encoding header — no opt-in needed. To receive raw compressed bytes, override
//   Accept-Encoding to `identity` in headers; servers will then respond uncompressed.

import * as querystring from 'node:querystring'
import { PassThrough } from 'node:stream'
import { URL } from 'node:url'
import * as zlib from 'node:zlib'

import { connect, connectPreferred } from './connect.ts'
import { Jar } from './cookies.ts'
import { HellojsError, wrap as wrapError } from './errors.ts'
import { buildH2Headers, buildH1Headers, mergeProfileHeaders } from './headers.ts'
import { observability, nextRequestId } from './observability.ts'
import * as profileRegistry from './profiles/index.ts'
import { summarizeConn } from './tls-summary.ts'

import type { Connection, PerPhaseTimeouts } from './connect.ts'
import type { ErrorCode } from './errors.ts'
import type { H2Stream } from './h2/session.ts'
import type { HeaderMap } from './headers.ts'
import type { Profile } from './profiles/types.ts'
import type { Readable, Transform } from 'node:stream'

// RFC 6265-compliant cookie jar lives in lib/cookies.ts.

// Default response-phase timeout applied when neither `opts.timeouts.response` nor the
// legacy `opts.timeout` is provided. 60s is generous enough for slow APIs but ends the
// old "hang forever" default. Callers can opt OUT by passing 0 or null explicitly:
//   { timeouts: { response: 0 } }         — no timer, request runs until conn closes
// Any positive number overrides the default.
const DEFAULT_RESPONSE_TIMEOUT_MS = 60_000

export type RequestBodyValue = string | Buffer | Uint8Array | Readable | Record<string, unknown> | unknown[]

export interface RetryPolicy {
	limit?: number
	methods?: string[]
	statusCodes?: number[]
	baseDelayMs?: number
}

export interface RequestOptions {
	url?: string
	uri?: string
	method?: string
	headers?: Record<string, string | string[]>
	body?: RequestBodyValue | null
	json?: boolean | unknown
	form?: Record<string, string | number>
	qs?: Record<string, string | number | (string | number)[]>
	jar?: Jar | null
	gzip?: boolean
	followRedirect?: boolean
	maxRedirects?: number
	timeout?: number
	timeouts?: PerPhaseTimeouts | null
	proxy?: string | null
	resolveWithFullResponse?: boolean
	simple?: boolean
	retry?: RetryPolicy

	/** TLS-only: turn on cert chain validation (default `true`). */
	verifyTLS?: boolean
	/**
	 * TLS-only: reuse a TLS 1.3 session ticket from an earlier request to the same host
	 * (default `false`). Resumed handshakes skip the certificate flight and its validation,
	 * but add `pre_shared_key` to the ClientHello, so JA3/JA4 differ from a fresh handshake.
	 */
	resume?: boolean
	/** Opt in to HTTP/3 (QUIC) for this request. Off unless explicitly `true`. */
	h3?: boolean
	/** When true, resolve as soon as headers arrive and expose the body as a Node Readable. */
	stream?: boolean
	/** Profile name, or an inline profile object. */
	profile?: string | Profile
	// Carried across redirects so every attempt shares one observability id.
	_reqId?: number
}

export interface Response<TBody = unknown> {
	statusCode: number
	status: number
	headers: Record<string, string | string[]>
	body: TBody
	rawBody: TBody | Buffer
}

export type Callback<TBody = unknown> = (
	err: HellojsError | null,
	res: Response<TBody> | undefined,
	body: TBody | undefined,
) => void

type MethodFn = (urlOrOpts: RequestOptions | string, cb?: Callback) => Promise<unknown>

// The public call shape, mirrored by index.d.ts: `resolveWithFullResponse: true` written as a
// literal resolves the full Response, anything else resolves just the body.
export interface Invokable {
	<TBody = unknown>(opts: RequestOptions & { resolveWithFullResponse: true }, cb?: Callback<TBody>): Promise<Response<TBody>>
	<TBody = unknown>(opts: RequestOptions | string, cb?: Callback<TBody>): Promise<TBody>
}

interface Shortcuts {
	get: Invokable
	post: Invokable
	put: Invokable
	del: Invokable
	delete: Invokable
	patch: Invokable
	head: Invokable
	options: Invokable
	jar(): Jar
}

export interface RequestFn extends Invokable, Shortcuts {
	defaults(defaults?: Partial<RequestOptions>): DefaultsFn
	HellojsError: typeof HellojsError
}

export interface DefaultsFn extends Invokable, Shortcuts {
	defaults(more?: Partial<RequestOptions>): DefaultsFn
}

// Everything a transport needs to put one request on the wire.
interface RequestContext {
	method: string
	url: URL
	host: string
	body: Buffer | Readable | null
	userHeaders: HeaderMap
	opts: RequestOptions
	profileObj: Profile | null
}

type HeadMode = 'none' | 'chunked' | 'length' | 'eof'
type HeadResult = 'need-more' | 'error' | 'interim' | 'ok'
type H1Headers = Record<string, string | string[]>

const isReadable = (b: unknown): b is Readable =>
	!!b && typeof b === 'object' && typeof (b as { pipe?: unknown }).pipe === 'function'

function decompressIfNeeded(buf: Buffer, encoding: string): Buffer {
	const e = (encoding || '').toLowerCase()
	if (!e || e === 'identity') return buf
	if (e.includes('gzip')) return zlib.gunzipSync(buf)
	if (e.includes('br')) return zlib.brotliDecompressSync(buf)
	if (e.includes('deflate')) {
		try { return zlib.inflateSync(buf) } catch { return zlib.inflateRawSync(buf) }
	}
	if (e.includes('zstd')) return zlib.zstdDecompressSync(buf)
	return buf
}

// Streaming counterpart: return a Transform that the response body can be piped through.
// `null` means "no decoding needed — caller can read the body as-is."
function decompressStreamForEncoding(encoding: string): Transform | null {
	const e = (encoding || '').toLowerCase()
	if (!e || e === 'identity') return null
	if (e.includes('gzip')) return zlib.createGunzip()
	if (e.includes('br'))   return zlib.createBrotliDecompress()
	if (e.includes('deflate')) {
		// Some servers send raw deflate; createInflate auto-detects, but to match the sync path
		// we use createInflate and rely on Node's auto-fallback to raw.
		return zlib.createInflate()
	}
	if (e.includes('zstd')) return zlib.createZstdDecompress()
	return null  // unknown encoding — caller reads the body as-is
}

function buildUrl(opts: RequestOptions): URL {
	const url = opts.url || opts.uri
	if (!url) throw new HellojsError('missing url', 'EBADOPTS')
	if (opts.qs) {
		const qs = querystring.stringify(opts.qs)
		return new URL(url + (url.includes('?') ? '&' : '?') + qs)
	}
	return new URL(url)
}

function prepareBody(opts: RequestOptions): Buffer | Readable | null {
	if (opts.body !== undefined) {
		// Streaming bodies: pass the Readable through; we'll send it as h2 DATA frames or h1 chunked.
		if (isReadable(opts.body)) return opts.body
		if (typeof opts.body === 'string' || Buffer.isBuffer(opts.body)) return Buffer.from(opts.body)
		if (opts.json && typeof opts.body === 'object') return Buffer.from(JSON.stringify(opts.body))
		if (typeof opts.body === 'object') return Buffer.from(JSON.stringify(opts.body))
	}
	if (opts.json && typeof opts.json !== 'boolean') {
		return Buffer.from(JSON.stringify(opts.json))
	}
	if (opts.form) {
		return Buffer.from(querystring.stringify(opts.form))
	}
	return null
}

function shouldDoJsonContentType(opts: RequestOptions, body: Buffer | Readable | null): boolean {
	if (!body) return false
	if (opts.json && (typeof opts.json === 'object' || (opts.json === true && typeof opts.body === 'object'))) return true
	return false
}

async function performRequest(opts: RequestOptions): Promise<unknown> {
	const url = buildUrl(opts)
	const method = (opts.method || 'GET').toUpperCase()
	const host = url.hostname
	const port = url.port ? parseInt(url.port, 10) : 443
	const _reqId = opts._reqId || (opts._reqId = nextRequestId())
	const _t0 = Date.now()
	observability.safeEmit('request:start', {
		id: _reqId, method, url: url.toString(), headers: opts.headers,
		// The request body (if any) as a Buffer, for observability / mitm-style capture.
		// Streams aren't captured here — they'd force us to tee/replay. Callers who need
		// the body for streamed uploads should buffer it themselves upstream.
		requestBody: (opts.body != null && typeof opts.body !== 'object')
			? Buffer.from(String(opts.body))
			: (Buffer.isBuffer(opts.body) ? opts.body : null),
	})
	const profile = opts.profile || 'chrome147-mac'
	// Resolve to the actual profile object for header / pseudo-header / priority building.
	// Tolerate unknown names (caller may have a custom profile registered elsewhere) — the TLS
	// layer will throw a clearer error if the name truly isn't valid.
	let profileObj: Profile | null = null
	if (typeof profile === 'string') {
		try { profileObj = profileRegistry.get(profile) } catch {}
	}

	// Transport: HTTP/3 is opt-in per request (`h3: true`). Every other request uses
	// TCP + TLS, regardless of any `alt-svc` response headers. An h3 request tries QUIC
	// first and falls back to TCP when the handshake cannot complete, so an origin without
	// a QUIC endpoint answers over TCP instead of sitting in QUIC Initial retransmits.
	const conn: Connection = opts.h3 === true
		? await connectPreferred({
			host, port, profile, proxy: opts.proxy,
			verifyTLS: opts.verifyTLS !== false,
			resume: opts.resume === true,
			timeouts: opts.timeouts,
		})
		: await connect({
			host, port, profile, proxy: opts.proxy,
			transport: 'tcp',
			verifyTLS: opts.verifyTLS !== false,
			resume: opts.resume === true,
			timeouts: opts.timeouts,
		})

	// Build headers
	const userHeaders: HeaderMap = { ...opts.headers }
	// Case-insensitive header presence check. Callers may Title-Case headers (e.g.
	// `Content-Length`, `Content-Type`) to match Chrome's HTTP/1.1 casing, which is a
	// DataDome fingerprint. The auto-adds below must NOT inject a lowercase DUPLICATE
	// (two Content-Length headers is illegal / ambiguous and gets the request rejected).
	const _hasHeader = (name: string) => Object.keys(userHeaders).some((k) => k.toLowerCase() === name)
	if (opts.jar) {
		const cookie = opts.jar.getCookieString(url.toString())
		// Title-Case `Cookie` matches real Chrome (H1 header case is a DataDome/Akamai
		// fingerprint — hellojs's default lowercase `cookie` is a tell). Chrome (H2) sends
		// Cookie BEFORE a trailing `priority` header on navigations (browser-verified:
		// /as/authorize is `…, cookie, priority`). If the caller placed a `priority` header,
		// splice Cookie in JUST BEFORE it while preserving every other header's relative
		// order; otherwise append last.
		if (cookie) {
			const priKey = Object.keys(userHeaders).find((k) => k.toLowerCase() === 'priority')
			if (priKey) {
				const keys = Object.keys(userHeaders)
				const values = keys.map((k) => userHeaders[k])
				for (const k of keys) delete userHeaders[k]
				for (let i = 0; i < keys.length; i++) {
					if (keys[i] === priKey) userHeaders['Cookie'] = cookie
					userHeaders[keys[i]] = values[i]
				}
			} else {
				userHeaders['Cookie'] = cookie
			}
		}
	}
	const body = prepareBody(opts)
	if (body && !_hasHeader('content-type')) {
		if (shouldDoJsonContentType(opts, body)) userHeaders['content-type'] = 'application/json'
		else if (opts.form) userHeaders['content-type'] = 'application/x-www-form-urlencoded'
	}
	const isStream = isReadable(body)
	if (body && !isStream) {
		// Always compute Content-Length from the buffered body — but if the caller placed the
		// header (typically as a fingerprint-order placeholder), update its VALUE in-place
		// while preserving the caller's key spelling and insertion position. Reassigning an
		// existing key in a JS object doesn't move it; a new key appends. Result: the caller
		// controls where Content-Length appears in the header block, we control the number.
		const clKey = Object.keys(userHeaders).find((k) => k.toLowerCase() === 'content-length')
		if (clKey) userHeaders[clKey] = String(body.length)
		else userHeaders['content-length'] = String(body.length)
	}
	// h2 doesn't need either header (frame length is implicit); for h1 we'll use chunked.
	if (isStream && !_hasHeader('content-length') && !_hasHeader('transfer-encoding') && conn.alpn === 'http/1.1') userHeaders['transfer-encoding'] = 'chunked'

	const ctx: RequestContext = { method, url, host, body, userHeaders, opts, profileObj }
	try {
		if (conn.alpn === 'h3') return await performH3(conn, ctx)
		if (conn.alpn === 'h2') return await performH2(conn, ctx)
		return await performH1(conn, ctx)
	} catch (e) {
		// Synchronous setup failures (e.g. a header builder throwing) must not leak the socket.
		// Individual transports close on their own completion paths, and close() is idempotent.
		conn.close('error')
		throw e
	}
}

async function performH3(conn: Connection, { method, url, host, body, userHeaders, opts, profileObj }: RequestContext): Promise<unknown> {
	const headers = mergeProfileHeaders(userHeaders, profileObj)
	let res
	try {
		res = await conn.h3Client!.request({
			method,
			path: url.pathname + url.search,
			host,
			headers,
			body,
		})
	} catch (e) {
		conn.close('h3-error')
		throw e
	}
	conn.close('h3-response-complete')
	const raw: Buffer = decompressIfNeeded(res.body, res.headers['content-encoding'])
	if (opts.jar && res.headers['set-cookie']) opts.jar.setCookie(res.headers['set-cookie'], url.toString())
	let bodyOut: unknown = raw
	if (opts.json && raw.length) { try { bodyOut = JSON.parse(raw.toString('utf8')) } catch {} }
	else if (raw.length && res.headers['content-type']?.includes('text')) bodyOut = raw.toString('utf8')
	return new Promise((resolve, reject) => handleResponse({ status: res.status, headers: res.headers, body: bodyOut, raw, opts, resolve, reject }))
}

function performH2(conn: Connection, { method, url, host, body, userHeaders, opts, profileObj }: RequestContext): Promise<unknown> {
	return new Promise((resolve, reject) => {
		const headers = buildH2Headers({ method, host, path: url.pathname + url.search, userHeaders, profile: profileObj })
		const streamingBody = isReadable(body) ? body : null
		// A non-stream body is the only thing that can go into a DATA frame directly.
		const bufferedBody = streamingBody ? null : (body as Buffer | null)
		const reqId = opts._reqId
		const reqT0 = Date.now()
		// PRIORITY-on-HEADERS values default to the profile when present; otherwise H2Session
		// falls back to Chrome's exclusive/weight=256. Passing `null` here lets H2Session pick.
		const reqOpts = { endStream: !body }
		const req: H2Stream = conn.h2Session!.request(headers, reqOpts)
		observability.safeEmit('request:headersSent', { id: reqId, method, path: url.pathname + url.search })
		const respMs = opts.timeouts?.response ?? opts.timeout ?? DEFAULT_RESPONSE_TIMEOUT_MS
		const timer = respMs ? setTimeout(() => {
			req.close(0x8 /*CANCEL*/)
			conn.close('h2-timeout')
			const e = new HellojsError(`request timed out after ${respMs}ms`, 'ETIMEDOUT')
			observability.safeEmit('request:error', { id: reqId, code: 'ETIMEDOUT', message: e.message, durationMs: Date.now() - reqT0 })
			reject(e)
		}, respMs) : null
		let firstByteEmitted = false

		// Streaming response path: when opts.stream is true, resolve as soon as headers arrive
		// with the body exposed as a Readable that callers can `.pipe()` into a Writable.
		if (opts.stream) {
			let settled = false
			req.on('response', (h: H1Headers) => {
				if (settled) return
				settled = true
				if (timer) clearTimeout(timer)
				const status = parseInt(String(h[':status'] ?? 0), 10)
				if (opts.jar && h['set-cookie']) opts.jar.setCookie(h['set-cookie'], url.toString())

				const pt = new PassThrough()
				const decoder = decompressStreamForEncoding(h['content-encoding'] as string)
				const userStream: Readable = decoder ? pt.pipe(decoder) : pt

				req.on('data', (c: Buffer) => pt.write(c))
				req.on('end', () => {
					pt.end()
					conn.close('h2-stream-end')
				})
				req.on('error', (e: Error) => { conn.close('h2-stream-error'); pt.destroy(new HellojsError(e.message, 'EH2STREAM', e)) })

				const res: Response<Readable> = { statusCode: status, status, headers: h, body: userStream, rawBody: userStream }
				if (opts.simple !== false && status >= 400) {
					const err = new HellojsError(`HTTP ${status}`, 'EHTTP')
					err.response = res
					req.close(0x8); conn.close('h2-http-error'); pt.destroy(err)
					return reject(err)
				}
				resolve(opts.resolveWithFullResponse ? res : userStream)
			})
			req.on('error', (e: Error) => { if (settled) return; settled = true; if (timer) clearTimeout(timer); conn.close('h2-stream-error'); reject(new HellojsError(e.message, 'EH2STREAM', e)) })
			if (streamingBody) {
				streamingBody.on('data', (c: Buffer) => req.write(Buffer.isBuffer(c) ? c : Buffer.from(c)))
				streamingBody.on('end', () => req.end())
				streamingBody.on('error', (e: Error) => { try { req.close(0x8) } catch {}; conn.close('h2-body-error'); reject(new HellojsError(e.message, 'EBODYSTREAM', e)) })
			} else if (bufferedBody) req.end(bufferedBody)
			else req.end()
			return
		}

		const chunks: Buffer[] = []
		let resHeaders: H1Headers | undefined
		let totalBytes = 0
		req.on('response', (h: H1Headers) => { resHeaders = h })
		req.on('data', (c: Buffer) => {
			chunks.push(c); totalBytes += c.length
			if (!firstByteEmitted) {
				firstByteEmitted = true
				observability.safeEmit('request:firstByte', { id: reqId, durationMs: Date.now() - reqT0 })
			}
		})
		req.on('end', () => {
			if (timer) clearTimeout(timer)
			conn.close('h2-response-complete')
			let raw: Buffer = Buffer.concat(chunks)
			try { raw = decompressIfNeeded(raw, resHeaders?.['content-encoding'] as string) }
			catch (e) { return reject(new HellojsError((e as Error).message, 'EDECOMPRESS', e)) }
			const status = parseInt(String(resHeaders?.[':status'] ?? 0), 10)
			// responseBody is the DECODED bytes (post-gzip/brotli/zstd) as a Buffer, for
			// observability consumers. Consumers that need the raw wire bytes can sum from
			// the request:firstByte + subsequent hooks. `tls` carries the negotiated
			// protocol / cipher / cert / server-IP summary.
			observability.safeEmit('request:end', {
				id: reqId, status, headers: resHeaders, totalBytes,
				durationMs: Date.now() - reqT0, responseBody: raw,
				tls: summarizeConn(conn),
			})
			if (opts.jar && resHeaders?.['set-cookie']) opts.jar.setCookie(resHeaders['set-cookie'], url.toString())
			let bodyOut: unknown = raw
			if (opts.json && raw.length) {
				try { bodyOut = JSON.parse(raw.toString('utf8')) } catch { /* leave as buffer */ }
			} else if (raw.length && (resHeaders?.['content-type'] as string)?.includes('utf-8')) {
				bodyOut = raw.toString('utf8')
			}
			handleResponse({ status, headers: resHeaders!, body: bodyOut, raw, opts, resolve, reject })
		})
		req.on('error', (e: Error) => { if (timer) clearTimeout(timer); conn.close('h2-error'); reject(new HellojsError(e.message, 'EH2STREAM', e)) })
		if (streamingBody) {
			streamingBody.on('data', (c: Buffer) => req.write(Buffer.isBuffer(c) ? c : Buffer.from(c)))
			streamingBody.on('end', () => req.end())
			streamingBody.on('error', (e: Error) => { try { req.close(0x8) } catch {}; reject(new HellojsError(e.message, 'EBODYSTREAM', e)) })
		} else if (bufferedBody) req.end(bufferedBody)
		else req.end()
	})
}

// CRLF markers for the incremental HTTP/1.1 response parser below.
const CRLF = Buffer.from('\r\n')
const CRLFCRLF = Buffer.from('\r\n\r\n')

// Hand-rolled HTTP/1.1 over the raw TLS Duplex. Framing is parsed INCREMENTALLY on every 'data'
// chunk and the request resolves the moment the body is fully delimited — Content-Length satisfied,
// terminal 0-chunk seen, or a bodyless status — WITHOUT waiting for the socket to close. The old
// code did all parsing inside `transport.once('end', onEnd)`, but 'end' only fires when the peer
// closes the connection (TLSTransport.endReadable -> push(null), called solely from the socket
// 'close' handler). HTTP/1.1 defaults to keep-alive (we send no Connection header), so the server
// holds the socket open and 'end' never fired -> every keep-alive request hung until the timeout.
// The only mode that legitimately waits for 'end' is a connection-close-delimited body.
function performH1(conn: Connection, { method, url, host, body, userHeaders, opts, profileObj }: RequestContext): Promise<unknown> {
	const transport = conn.h2Transport!  // misnomer: this is the raw TLS Duplex
	const requestLine = `${method} ${url.pathname + url.search} HTTP/1.1\r\n`
	const headerBlock = buildH1Headers({ host, userHeaders, profile: profileObj })
	const head = Buffer.from(requestLine + headerBlock + '\r\n\r\n', 'utf8')
	const h1T0 = Date.now()
	transport.write(head)
	if (body) transport.write(body)

	return new Promise((resolve, reject) => {
		// The connection is fresh and dedicated to this request, so no leftover bytes
		// from a prior response exist.
		let buf: Buffer = Buffer.alloc(0)
		let settled = false, headersParsed = false
		let status = 0
		let headers: H1Headers = {}
		let mode: HeadMode | null = null
		let contentLength = 0
		let bodyStart = 0

		const respMs = opts.timeouts?.response ?? opts.timeout ?? DEFAULT_RESPONSE_TIMEOUT_MS
		let timer: ReturnType<typeof setTimeout> | null = respMs ? setTimeout(() => {
			done(() => { try { conn.close('h1-timeout') } catch {}; reject(new HellojsError(`request timed out after ${respMs}ms`, 'ETIMEDOUT')) })
		}, respMs) : null

		const coerce = (v: string | string[] | undefined) => Array.isArray(v) ? v.join(', ') : v

		function cleanup() {
			transport.removeListener('data', onData)
			transport.removeListener('end', onEnd)
			if (timer) { clearTimeout(timer); timer = null }
		}
		function done(fn: () => void) {
			if (settled) return
			settled = true
			cleanup()
			fn()
		}
		function fail(msg: string, code: ErrorCode | string) {
			done(() => { try { conn.close('h1-error') } catch {}; reject(new HellojsError(msg, code)) })
		}

		// Parse one response head (status line + headers) at the front of buf.
		function parseHead(): HeadResult {
			const he = buf.indexOf(CRLFCRLF)
			if (he < 0) return 'need-more'  // a partial head is NOT an error — wait for more bytes
			const lines = buf.subarray(0, he).toString('latin1').split('\r\n')
			const m = lines.shift()!.match(/^HTTP\/1\.(\d) (\d{3})(?: (.*))?$/)
			if (!m) { fail('bad status line', 'EBADRESP'); return 'error' }
			const st = parseInt(m[2], 10)
			// 1xx informational responses carry no body; discard the interim head and parse the
			// next one from the stream (RFC 7230 3.3.3 rule 1 — e.g. 100 Continue, 103 Early Hints).
			if (st >= 100 && st < 200) { buf = buf.subarray(he + 4); return 'interim' }
			status = st
			headers = {}
			for (const ln of lines) {
				const idx = ln.indexOf(':')
				if (idx < 0) continue
				const k = ln.slice(0, idx).trim().toLowerCase()
				const v = ln.slice(idx + 1).trim()
				if (headers[k] !== undefined) headers[k] = ([] as string[]).concat(headers[k], v); else headers[k] = v
			}
			bodyStart = he + 4
			const te = (coerce(headers['transfer-encoding']) || '').trim()
			const cl = coerce(headers['content-length'])
			// RFC 7230 3.3.3: HEAD responses and 204/304 never have a body, regardless of CL/TE.
			if (method === 'HEAD' || status === 204 || status === 304) {
				mode = 'none'
			} else if (/(^|,)\s*chunked\s*$/i.test(te)) {
				// chunked is the final transfer-coding -> chunked framing. Transfer-Encoding overrides
				// any Content-Length (which we ignore rather than mis-frame / risk smuggling).
				mode = 'chunked'
			} else if (cl !== undefined && cl !== '') {
				const s = String(cl).trim()
				if (!/^\d+$/.test(s)) { fail('invalid content-length', 'EBADRESP'); return 'error' }
				mode = 'length'; contentLength = parseInt(s, 10)
			} else {
				mode = 'eof'  // body delimited by connection close
			}
			headersParsed = true
			return 'ok'
		}

		// Returns true if the request settled (resolved/failed), false if more bytes are needed.
		function tryComplete(): boolean {
			if (mode === 'none') { finish(bodyStart); return true }
			if (mode === 'length') {
				if (buf.length - bodyStart >= contentLength) { finish(bodyStart + contentLength); return true }
				return false
			}
			if (mode === 'chunked') {
				let off = bodyStart
				for (;;) {
					const nl = buf.indexOf(CRLF, off)
					if (nl < 0) return false
					const token = buf.subarray(off, nl).toString('ascii').split(';')[0].trim()  // strip chunk extensions
					if (!/^[0-9a-fA-F]+$/.test(token)) { fail('bad chunk size', 'EBADRESP'); return true }
					const sz = Number.parseInt(token, 16)
					if (sz === 0) {
						const end = findTrailerEnd(buf, nl + 2)
						if (end < 0) return false  // trailer section not fully arrived
						finish(end); return true
					}
					const dataEnd = nl + 2 + sz
					if (buf.length < dataEnd + 2) return false  // chunk data + trailing CRLF not all here
					off = dataEnd + 2
				}
			}
			return false  // 'eof' -> wait for onEnd / socket close
		}

		function finish(bodyEndIdx: number) {
			let entity: Buffer = buf.subarray(bodyStart, bodyEndIdx)
			if (mode === 'chunked') entity = dechunk(entity)
			done(() => {
				try { conn.close('h1-response-complete') } catch {}
				let raw: Buffer = entity
				if (raw.length) {
					try { raw = decompressIfNeeded(raw, coerce(headers['content-encoding']) || '') }
					catch (e) { return reject(new HellojsError((e as Error).message, 'EDECOMPRESS', e)) }
				}
				if (opts.jar && headers['set-cookie']) opts.jar.setCookie(headers['set-cookie'], url.toString())
				// Observability event so hooks / metrics can capture H1 traffic too. Payload
				// mirrors the H2 request:end shape.
				observability.safeEmit('request:end', {
					id: opts._reqId, status, headers,
					totalBytes: raw.length, durationMs: Date.now() - h1T0, responseBody: raw,
					tls: summarizeConn(conn),
				})
				let bodyOut: unknown = raw
				if (opts.json && raw.length) { try { bodyOut = JSON.parse(raw.toString('utf8')) } catch {} }
				else if (raw.length) bodyOut = raw.toString('utf8')
				handleResponse({ status, headers, body: bodyOut, raw, opts, resolve, reject })
			})
		}

		const onData = (c: Buffer) => {
			if (settled) return
			if (c.length) buf = buf.length ? Buffer.concat([buf, c]) : c
			while (!settled) {
				if (!headersParsed) {
					const r = parseHead()
					if (r === 'need-more' || r === 'error') return
					if (r === 'interim') continue  // 1xx consumed; parse the next head
				}
				tryComplete()
				return
			}
		}
		const onEnd = () => {
			if (settled) return
			if (!headersParsed) return fail('incomplete h1 response', 'EBADRESP')
			if (mode === 'eof') return finish(buf.length)  // close-delimited body: end == complete
			fail('connection closed before response complete', 'EBADRESP')  // truncated CL/chunked body
		}

		transport.on('data', onData)
		transport.once('end', onEnd)
		try { transport.resume() } catch {}
	})
}

// Walk trailer lines after a terminal 0-length chunk; return the index just past the closing empty
// line, or -1 if the trailer section hasn't fully arrived.
function findTrailerEnd(b: Buffer, start: number): number {
	let off = start
	for (;;) {
		const nl = b.indexOf(CRLF, off)
		if (nl < 0) return -1
		if (nl === off) return off + 2  // empty line terminates the trailers
		off = nl + 2
	}
}

// Decode a chunked body that is already delimited up to and including the terminal 0-chunk.
// Tolerant of chunk extensions (`size;ext=val`) and bounded so a short final slice can't read past
// the buffer.
function dechunk(buf: Buffer): Buffer {
	const out: Buffer[] = []
	let off = 0
	while (off < buf.length) {
		const nl = buf.indexOf(CRLF, off)
		if (nl < 0) break
		const sz = Number.parseInt(buf.subarray(off, nl).toString('ascii').split(';')[0].trim(), 16)
		if (Number.isNaN(sz)) break
		const start = nl + 2, end = start + sz
		if (end > buf.length) break
		out.push(buf.subarray(start, end))
		off = end + 2
		if (sz === 0) break
	}
	return Buffer.concat(out)
}

// Return a copy of opts with the named request headers removed (case-insensitively). Used on
// redirects to avoid leaking credentials across origins and to drop body-framing headers when a
// POST is downgraded to GET. Creates a fresh headers object so the caller's opts is untouched.
function withoutHeaders(opts: RequestOptions, names: string[]): RequestOptions {
	if (!opts.headers) return opts
	const drop = new Set(names.map((n) => n.toLowerCase()))
	const next: Record<string, string | string[]> = {}
	for (const [k, v] of Object.entries(opts.headers)) {
		if (!drop.has(k.toLowerCase())) next[k] = v
	}
	opts.headers = next
	return opts
}

interface HandleResponseInput {
	status: number
	headers: H1Headers
	body: unknown
	raw: Buffer
	opts: RequestOptions
	resolve: (value: unknown) => void
	reject: (reason: unknown) => void
}

function handleResponse({ status, headers, body, raw, opts, resolve, reject }: HandleResponseInput): void {
	const res: Response = { statusCode: status, status, headers, body, rawBody: raw }
	if (opts.simple !== false && status >= 400) {
		const err = new HellojsError(`HTTP ${status}`, 'EHTTP')
		err.response = res
		return reject(err)
	}
	if (opts.followRedirect !== false && status >= 300 && status < 400 && headers.location && (opts.maxRedirects ?? 10) > 0) {
		const location = Array.isArray(headers.location) ? headers.location[0] : headers.location
		const currentUrl = new URL(opts.url ?? opts.uri ?? '')
		const target = new URL(location, currentUrl)
		let newOpts: RequestOptions = { ...opts, url: target.toString(), maxRedirects: (opts.maxRedirects ?? 10) - 1 }
		// The Location URL carries its own query string; don't re-append opts.qs to it.
		delete newOpts.qs
		const method = (opts.method || 'GET').toUpperCase()
		// RFC 9110 §15.4: 303 → GET. Browsers (and the request library) also downgrade a POST to GET
		// on 301/302. 307/308 preserve method and body. On downgrade, drop the request body and its
		// framing headers so the redirected GET is bodyless.
		if (status === 303 || ((status === 301 || status === 302) && method === 'POST')) {
			newOpts.method = 'GET'
			delete newOpts.body
			delete newOpts.form
			if (newOpts.json && typeof newOpts.json !== 'boolean') delete newOpts.json
			newOpts = withoutHeaders(newOpts, ['content-type', 'content-length', 'transfer-encoding'])
		}
		// Never carry credentials across an origin boundary (scheme://host:port). Mirrors browser /
		// request-library behavior, and matters more here since verifyTLS is off by default.
		if (target.origin !== currentUrl.origin) {
			newOpts = withoutHeaders(newOpts, ['authorization', 'cookie', 'proxy-authorization'])
		}
		return resolve(performRequest(newOpts))
	}
	if (opts.resolveWithFullResponse) return resolve(res)
	resolve(opts.json ? body : (typeof body === 'string' ? body : raw))
}

// Public API ------------------------------------------------------------

async function performWithRetry(opts: RequestOptions): Promise<unknown> {
	const policy = opts.retry || {}
	const limit = policy.limit ?? 0
	const methods = policy.methods ?? ['GET', 'HEAD', 'OPTIONS']
	const statusCodes = policy.statusCodes ?? [408, 429, 500, 502, 503, 504]
	const baseDelay = policy.baseDelayMs ?? 200
	const upper = (opts.method || 'GET').toUpperCase()
	const retriable = methods.includes(upper)
	let lastErr: HellojsError | undefined
	for (let attempt = 0; attempt <= limit; attempt++) {
		try {
			return await performRequest(opts)
		} catch (e) {
			// Normalize: every error leaving this function is a HellojsError with a stable .code.
			lastErr = wrapError(e)
			const status = lastErr.response?.status
			const transient = (!!status && statusCodes.includes(status)) ||
				['ETIMEDOUT', 'ECONNRESET', 'EH2STREAM', 'EH3STREAM'].includes(lastErr.code)
			if (!retriable || !transient || attempt === limit) throw lastErr
			const delay = baseDelay * Math.pow(2, attempt)
			await new Promise((r) => setTimeout(r, delay))
		}
	}
	throw lastErr
}

function requestImpl(opts: RequestOptions | string, cb?: Callback): Promise<unknown> {
	const o = typeof opts === 'string' ? { url: opts } : opts
	const p = performWithRetry(o)
	if (cb) {
		p.then(
			(r) => cb(null, r as Response, o.resolveWithFullResponse ? (r as Response).body : r),
			(e: HellojsError) => cb(e, e?.response, e?.response?.body)
		)
	}
	return p
}

function method(m: string, dispatch: MethodFn = requestImpl): MethodFn {
	return (urlOrOpts, cb) => {
		const opts = typeof urlOrOpts === 'string' ? { url: urlOrOpts } : { ...urlOrOpts }
		opts.method = m
		return dispatch(opts, cb)
	}
}

// Deep-merge defaults + per-call opts, with `headers` lowercased and merged (later wins).
function mergeOpts(base: Partial<RequestOptions>, over: RequestOptions): RequestOptions {
	const out: RequestOptions = { ...base, ...over }
	const lowerCaseHeaders = (h?: Record<string, string | string[]>) => {
		const o: Record<string, string | string[]> = {}
		if (!h) return o
		for (const [k, v] of Object.entries(h)) o[k.toLowerCase()] = v
		return o
	}
	out.headers = { ...lowerCaseHeaders(base.headers), ...lowerCaseHeaders(over.headers) }
	return out
}

const SHORTCUTS = {
	get: 'GET',
	post: 'POST',
	put: 'PUT',
	del: 'DELETE',
	delete: 'DELETE',
	patch: 'PATCH',
	head: 'HEAD',
	options: 'OPTIONS',
} as const

// Shortcuts dispatch through `dispatch`, so a defaults-derived entry point keeps merging
// its defaults when called as `.get(...)` / `.post(...)`.
function withShortcuts<T extends object>(fn: T, dispatch: MethodFn): T {
	const shortcuts: Record<string, MethodFn> = {}
	for (const [name, verb] of Object.entries(SHORTCUTS)) shortcuts[name] = method(verb, dispatch)
	return Object.assign(fn, shortcuts)
}

const request = withShortcuts(
	Object.assign(requestImpl, {
		defaults: (defaults: Partial<RequestOptions> = {}) => {
			const wrapped: MethodFn = (urlOrOpts, cb) => {
				const opts = typeof urlOrOpts === 'string' ? { url: urlOrOpts } : urlOrOpts
				return requestImpl(mergeOpts(defaults, opts), cb)
			}
			return withShortcuts(
				Object.assign(wrapped, {
					defaults: (more?: Partial<RequestOptions>) => request.defaults(mergeOpts(defaults, more || {})),
					jar: request.jar,
				}),
				wrapped
			)
		},
		jar: () => new Jar(),
		HellojsError,
	}),
	requestImpl
) as unknown as RequestFn

export default request
