// Public fetch-compatible API with request.js-style request options.
//
//   import request from 'hellojs'
//   request({ url, method, headers, body, json, qs, jar, gzip, redirect, timeout, proxy })
//   const res = await request({...})          // fetch Response, streamed body
//   request.get/post/put/del/patch/head/options
//   request.defaults(opts)
//   request.jar()
//
// Notes:
// - Driven by lib/connect.ts and lib/tls/tls.ts for TLS+HTTP/2. Requests open a fresh
//   connection and close it when the response completes, unless `keepAlive: true` opts the
//   caller into the bounded per-origin pool (lib/pool.ts).
// - HTTP/1.1 fallback is hand-rolled (chunked, content-length).
// - Auto-decompresses gzip / br / deflate / zstd response bodies based on the response's
//   Content-Encoding header — no opt-in needed. To receive raw compressed bytes, override
//   Accept-Encoding to `identity` in headers; servers will then respond uncompressed.

import * as querystring from 'node:querystring'
import { URL } from 'node:url'
import * as zlib from 'node:zlib'

import { connect, connectPreferred } from './connect.ts'
import { Jar } from './cookies.ts'
import { HellojsError, wrap as wrapError } from './errors.ts'
import { buildH2Headers, buildH1Headers, mergeProfileHeaders } from './headers.ts'
import { observability, nextRequestId } from './observability.ts'
import * as pool from './pool.ts'
import * as profileRegistry from './profiles/index.ts'
import { startProgressiveResponse, type ProgressiveStream } from './response-stream.ts'
import { statusTextFor } from './status-text.ts'
import { summarizeConn } from './tls-summary.ts'
import { buildResponse, isWebReadableStream, webToNodeStream } from './web-response.ts'

import type { Connection, PerPhaseTimeouts } from './connect.ts'
import type { ErrorCode } from './errors.ts'
import type { H2Stream } from './h2/session.ts'
import type { HeaderMap } from './headers.ts'
import type { PoolConfig } from './pool.ts'
import type { Profile } from './profiles/types.ts'
import type { Readable } from 'node:stream'

// RFC 6265-compliant cookie jar lives in lib/cookies.ts.

// Default response-phase timeout applied when neither `opts.timeouts.response` nor the
// legacy `opts.timeout` is provided. 60s is generous enough for slow APIs but ends the
// old "hang forever" default. Callers can opt OUT by passing 0 or null explicitly:
//   { timeouts: { response: 0 } }         — no timer, request runs until conn closes
// Any positive number overrides the default.
const DEFAULT_RESPONSE_TIMEOUT_MS = 60_000

// H3 does not implement QUIC receive flow control yet, so a consumer that stops reading
// cannot make the peer pause. Bound the in-process buffer and fail the body instead of
// growing without limit.
const MAX_H3_BUFFERED_BODY = 16 * 1024 * 1024

export type RequestBodyValue = BodyInit | Buffer | Readable | Record<string, unknown> | unknown[]

export type RedirectMode = 'follow' | 'manual' | 'error'

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
	headers?: HeadersInit | Record<string, string | string[]>
	body?: RequestBodyValue | null
	/** Object values are serialized as the JSON request body; `true` does the same for an object `body`. */
	json?: boolean | unknown
	form?: Record<string, string | number>
	qs?: Record<string, string | number | (string | number)[]>
	jar?: Jar | null
	gzip?: boolean
	/** Redirect handling: 'follow' (default) auto-follows 3xx; 'manual' stops and returns the 3xx response; 'error' rejects on any redirect. */
	redirect?: RedirectMode
	maxRedirects?: number
	timeout?: number
	timeouts?: PerPhaseTimeouts | null
	proxy?: string | null
	/**
	 * Full CONNECT `Proxy-Authorization` value (e.g. `Bearer <jwt>`). Overrides URL Basic auth;
	 * `''` sends no header. Validated at construction, and unused by `socks5://`.
	 */
	proxyAuthorization?: string | null
	/**
	 * Extra headers sent on the CONNECT request to the proxy. CONNECT-owned names and values
	 * outside printable ASCII reject with `EBADOPTS`; unused by `socks5://`.
	 */
	proxyHeaders?: Record<string, string> | null
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
	/**
	 * Reuse live HTTP/2 connections across requests (default `false`). Each pooled origin holds
	 * at most one multiplexed socket; caps and idle lifetime come from `pool`. A request that
	 * finds no pool capacity opens a one-shot connection and closes it after the response, so
	 * enabling this can never hold more sockets than the caps allow.
	 */
	keepAlive?: boolean
	/** Keep-alive pool caps: process-wide sockets, sockets per origin, idle socket lifetime. */
	pool?: Partial<PoolConfig>
	/** Profile name, or an inline profile object. */
	profile?: string | Profile

	/** Fetch `RequestInit` fields accepted for drop-in compatibility (ignored by this client). */
	credentials?: 'omit' | 'same-origin' | 'include'
	mode?: 'cors' | 'no-cors' | 'same-origin' | 'navigate'
	cache?: string
	integrity?: string
	keepalive?: boolean
	referrer?: string
	referrerPolicy?: string
	/** Present for fetch signature compatibility; a streaming request body is always half-duplex here. */
	duplex?: 'half'
	/** Abort the request (or an in-flight response body) when this signal fires. */
	signal?: AbortSignal | null
	// Carried across redirects so every attempt shares one observability id.
	_reqId?: number
	// Internal: set once a redirect has been followed, so `Response.redirected` is accurate.
	_redirected?: boolean
}

/**
 * The result of `request()`: the platform's own fetch `Response`, so every consumer —
 * DOM, Node's undici, or Workers — understands it without a cast.
 */
export type Response = globalThis.Response

/** Fetch-style init accepted as the second argument; request.js options may be mixed in. */
export type FetchInit = Omit<RequestInit, 'body' | 'headers' | 'method' | 'redirect' | 'signal'> & RequestOptions

type MethodFn = (input: string | URL | Request | RequestOptions, init?: FetchInit) => Promise<Response>

/**
 * The public call shape, mirrored by index.d.ts: every call resolves the fetch-compatible
 * `Response` (unless redirect: 'error' rejects).
 */
export interface Invokable {
	(input: string | URL | Request, init?: FetchInit): Promise<Response>
	(opts: RequestOptions): Promise<Response>
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

// Normalize the three `HeadersInit` spellings (Headers, tuple list, record) into the plain
// record the transports already build from. Repeated fields stay repeated so `set-cookie`
// arrays survive; every name is lowercased the way the wire layer expects.
function headersToRecord(input?: HeadersInit | HeaderMap | null): Record<string, string | string[]> {
	const out: Record<string, string | string[]> = {}
	if (!input) return out
	const maybeHeaders = input as Headers
	if (typeof maybeHeaders.forEach === 'function') {
		maybeHeaders.forEach((value, name) => {
			const key = name.toLowerCase()
			const prev = out[key]
			out[key] = prev === undefined ? value : Array.isArray(prev) ? [...prev, value] : [String(prev), value]
		})
		// Undici and Workers expose combined set-cookie values through getSetCookie; forEach
		// collapses them into one comma-joined string, which cookies must not do.
		const getSetCookie = (input as { getSetCookie?: () => string[] }).getSetCookie
		if (typeof getSetCookie === 'function') {
			const cookies = getSetCookie.call(input)
			if (cookies.length) out['set-cookie'] = cookies
		}
		return out
	}
	if (Array.isArray(input)) {
		for (const [name, value] of input) {
			const key = String(name).toLowerCase()
			const prev = out[key]
			out[key] = prev === undefined ? String(value) : Array.isArray(prev) ? [...prev, String(value)] : [String(prev), String(value)]
		}
		return out
	}
	for (const [name, value] of Object.entries(input as HeaderMap)) {
		if (value === undefined || value === null) continue
		out[name.toLowerCase()] = Array.isArray(value) ? value.map(String) : String(value)
	}
	return out
}

function isBlob(value: unknown): value is Blob {
	return typeof Blob !== 'undefined' && value instanceof Blob
}

function isFormData(value: unknown): value is FormData {
	return typeof FormData !== 'undefined' && value instanceof FormData
}

function isUrlSearchParams(value: unknown): value is URLSearchParams {
	return typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams
}

function abortReason(signal?: AbortSignal | null): unknown {
	const reason = signal?.reason
	return reason !== undefined ? reason : new DOMException('The operation was aborted.', 'AbortError')
}

function errorCodeOf(error: unknown, fallback: ErrorCode | string): string {
	const code = (error as { code?: unknown } | null)?.code
	if (typeof code === 'string') return code
	const name = (error as { name?: unknown } | null)?.name
	return typeof name === 'string' && name ? name : fallback
}

function messageOf(error: unknown): string {
	return error instanceof Error ? error.message : String(error)
}

function throwIfAborted(signal?: AbortSignal | null): void {
	if (signal?.aborted) throw abortReason(signal)
}

// Register a fetch-style abort hook and return the cleanup. `{ once: true }` plus the
// explicit removal keeps a long-lived signal from retaining closed requests.
function onAbort(signal: AbortSignal | null | undefined, handler: () => void): () => void {
	if (!signal) return () => {}
	if (signal.aborted) { handler(); return () => {} }
	signal.addEventListener('abort', handler, { once: true })
	return () => signal.removeEventListener('abort', handler)
}

function decompressIfNeeded(buf: Buffer, encoding: string): Buffer {
	const e = (encoding || '').toLowerCase()
	// HEAD/204/304 responses carry content-encoding but no body; decompressing
	// zero bytes would fail with a spurious truncated-input error.
	if (!buf || buf.length === 0) return buf
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

function buildUrl(opts: RequestOptions): URL {
	const url = opts.url || opts.uri
	if (!url) throw new HellojsError('missing url', 'EBADOPTS')
	if (opts.qs) {
		const qs = querystring.stringify(opts.qs)
		return new URL(url + (url.includes('?') ? '&' : '?') + qs)
	}
	return new URL(url)
}

interface PreparedBody {
	body: Buffer | Readable | null
	/** Content type computed by the BodyInit serializer (FormData boundary, URLSearchParams). */
	contentType: string | null
}

async function prepareBody(opts: RequestOptions): Promise<PreparedBody> {
	const raw = opts.body
	if (raw !== undefined && raw !== null) {
		// Streaming bodies: pass the Readable through; we'll send it as h2 DATA frames or h1 chunked.
		if (isReadable(raw)) return { body: raw, contentType: null }
		if (isWebReadableStream(raw)) return { body: webToNodeStream(raw), contentType: null }
		if (typeof raw === 'string') return { body: Buffer.from(raw), contentType: null }
		if (Buffer.isBuffer(raw)) return { body: raw, contentType: null }
		if (raw instanceof ArrayBuffer) return { body: Buffer.from(raw), contentType: null }
		if (ArrayBuffer.isView(raw)) return { body: Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength), contentType: null }
		// BodyInit types that need serialization rules (multipart boundary, form encoding).
		// A real Response performs exactly the encoding fetch would, so reuse it.
		if (isBlob(raw) || isFormData(raw) || isUrlSearchParams(raw)) {
			const wrapped = new Response(raw as BodyInit)
			return {
				body: Buffer.from(await wrapped.arrayBuffer()),
				contentType: wrapped.headers.get('content-type'),
			}
		}
		if (typeof raw === 'object') return { body: Buffer.from(JSON.stringify(raw)), contentType: null }
	}
	if (opts.json && typeof opts.json !== 'boolean') {
		return { body: Buffer.from(JSON.stringify(opts.json)), contentType: null }
	}
	if (opts.form) {
		return { body: Buffer.from(querystring.stringify(opts.form)), contentType: null }
	}
	return { body: null, contentType: null }
}

function shouldDoJsonContentType(opts: RequestOptions, body: Buffer | Readable | null): boolean {
	if (!body) return false
	if (opts.json && (typeof opts.json === 'object' || (opts.json === true && typeof opts.body === 'object'))) return true
	return false
}

async function performRequest(opts: RequestOptions): Promise<Response> {
	throwIfAborted(opts.signal)
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
	// With `keepAlive: true` a live pooled h2 socket for this origin+profile is taken first;
	// otherwise (and whenever the pool has no capacity) the request handshakes a fresh one,
	// which is registered for reuse when it lands on a healthy h2 session.
	const poolConfig: PoolConfig | null = opts.keepAlive === true && opts.h3 !== true
		? { ...pool.DEFAULT_CONFIG, ...opts.pool }
		: null
	const poolKey = poolConfig
		? pool.poolKey(host, port, opts.profile, opts.proxy, opts.verifyTLS !== false, opts.proxyAuthorization, opts.proxyHeaders)
		: null
	let conn: Connection | null = poolConfig && poolKey ? pool.take(poolKey) : null
	if (!conn) {
		conn = opts.h3 === true
			? await connectPreferred({
				host, port, profile, proxy: opts.proxy,
				proxyAuthorization: opts.proxyAuthorization,
				proxyHeaders: opts.proxyHeaders,
				verifyTLS: opts.verifyTLS !== false,
				resume: opts.resume === true,
				timeouts: opts.timeouts,
			})
			: await connect({
				host, port, profile, proxy: opts.proxy,
				proxyAuthorization: opts.proxyAuthorization,
				proxyHeaders: opts.proxyHeaders,
				transport: 'tcp',
				verifyTLS: opts.verifyTLS !== false,
				resume: opts.resume === true,
				timeouts: opts.timeouts,
			})
		if (poolConfig && poolKey) pool.register(conn, poolKey, poolConfig)
	}

	// Build headers
	const userHeaders: HeaderMap = headersToRecord(opts.headers)
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
	const prepared = await prepareBody(opts)
	const body = prepared.body
	if (body && !_hasHeader('content-type')) {
		if (prepared.contentType) userHeaders['content-type'] = prepared.contentType
		else if (shouldDoJsonContentType(opts, body)) userHeaders['content-type'] = 'application/json'
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
	const transport = (async () => {
		if (conn.alpn === 'h3') return performH3(conn, ctx)
		if (conn.alpn === 'h2') return performH2(conn, ctx)
		return performH1(conn, ctx)
	})()
	let removeAbort = () => {}
	try {
		if (opts.signal) {
			let rejectAbort: (reason: unknown) => void = () => {}
			const aborted = new Promise<never>((_, reject) => { rejectAbort = reject })
			removeAbort = onAbort(opts.signal, () => {
				try { conn.close('abort') } catch {}
				rejectAbort(abortReason(opts.signal))
			})
			return await Promise.race([transport, aborted])
		}
		return await transport
	} catch (e) {
		// Synchronous setup failures (e.g. a header builder throwing) must not leak the socket.
		// A pooled socket survives with its slot returned so sibling streams are unaffected;
		// one-shot sockets close. close() is idempotent.
		if (!pool.release(conn)) conn.close('error')
		throw e
	} finally {
		removeAbort()
	}
}

function performH3(conn: Connection, { method, url, host, body, userHeaders, opts, profileObj }: RequestContext): Promise<Response> {
	const headers = mergeProfileHeaders(userHeaders, profileObj)
	const path = url.pathname + url.search
	const reqId = opts._reqId
	const reqT0 = Date.now()
	const close = () => { try { conn.close('h3-response-complete') } catch { /* already closed */ } }

	// Resolve at HEADERS and stream DATA frames as they arrive. Redirects are buffered so the
	// normal handleResponse policy still applies to them.
	return new Promise((resolve, reject) => {
		let stream: ProgressiveStream | null = null
		let buffering = false
		const buffered: Buffer[] = []
		let status = 0
		let resHeaders: Record<string, string> = {}
		let resolved = false

		conn.h3Client!.requestStream({ method, path, host, headers, body }, {
			onHeaders: (s, h) => {
				// 1xx informational responses are not final; wait for the real HEADERS.
				if (s >= 100 && s < 200) return
				status = s
				resHeaders = h
				if (opts.jar && h['set-cookie']) opts.jar.setCookie(h['set-cookie'], url.toString())
				const isRedirect = opts.redirect !== 'manual' && s >= 300 && s < 400 && !!h.location
				if (isRedirect) {
					buffering = true
					return
				}
				stream = startProgressiveResponse({
					status: s,
					headers: h,
					...responseMeta(opts),
					signal: opts.signal,
					idleTimeoutMs: opts.timeouts?.bodyIdle ?? 0,
					errorCode: 'EH3STREAM',
					onCancel: () => { try { conn.close('h3-stream-cancel') } catch { /* already closed */ } },
					onFirstByte: () => observability.safeEmit('request:firstByte', { id: reqId, durationMs: Date.now() - reqT0 }),
					onEnd: (bytes) => {
						observability.safeEmit('request:end', {
							id: reqId, status: s, headers: h, totalBytes: bytes,
							durationMs: Date.now() - reqT0, tls: summarizeConn(conn),
						})
						close()
					},
					onError: (error, bytes) => {
						observability.safeEmit('request:error', {
							id: reqId, code: errorCodeOf(error, 'EH3STREAM'),
							message: messageOf(error), durationMs: Date.now() - reqT0,
						})
						void bytes
						close()
					},
				})
				resolved = true
				resolve(stream.result)
			},
			onData: (chunk) => {
				if (buffering) { buffered.push(chunk); return }
				if (!stream) return
				stream.write(chunk)
				// QUIC receive flow control is not wired yet, so a consumer that stops
				// reading would otherwise let the peer fill memory without bound.
				if (stream.bufferedBytes() > MAX_H3_BUFFERED_BODY) {
					stream.fail(new HellojsError(
						`h3 response body exceeded ${MAX_H3_BUFFERED_BODY} buffered bytes`,
						'EBODYBACKPRESSURE',
					))
				}
			},
			onEnd: () => {
				if (buffering) {
					close()
					let raw: Buffer = Buffer.concat(buffered)
					try { raw = decompressIfNeeded(raw, resHeaders['content-encoding']) }
					catch (e) { reject(new HellojsError((e as Error).message, 'EDECOMPRESS', e)); return }
					observability.safeEmit('request:end', {
						id: reqId, status, headers: resHeaders, totalBytes: raw.length,
						durationMs: Date.now() - reqT0, responseBody: raw, tls: summarizeConn(conn),
					})
					handleResponse({ status, statusText: statusTextFor(status), headers: resHeaders, raw, opts, resolve, reject })
					return
				}
				stream?.end()
			},
			onError: (e) => {
				if (stream) {
					stream.fail(new HellojsError(e.message, 'EH3STREAM', e))
					return
				}
				close()
				if (!resolved) reject(new HellojsError(e.message, 'EH3STREAM', e))
			},
		})
	})
}

function performH2(conn: Connection, { method, url, host, body, userHeaders, opts, profileObj }: RequestContext): Promise<Response> {
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

		// Resolve as soon as headers arrive and expose the rest as a web ReadableStream.
		// Redirects need their (small) body to apply the normal policy, so those are buffered
		// and handed to handleResponse.
		let settled = false
		let buffering = false
		const buffered: Buffer[] = []
		let bufferedStatus = 0
		let bufferedHeaders: H1Headers | undefined
		let stream: ProgressiveStream | null = null

		req.on('response', (h: H1Headers) => {
			const status = parseInt(String(h[':status'] ?? 0), 10)
			// 1xx informational responses (100 Continue, 103 Early Hints) are not final.
			// Keep waiting for the real HEADERS instead of resolving a clamped 200.
			if (status >= 100 && status < 200) return
			if (settled) return
			settled = true
			if (timer) clearTimeout(timer)
			if (opts.jar && h['set-cookie']) opts.jar.setCookie(h['set-cookie'], url.toString())
			const isRedirect = opts.redirect !== 'manual' && status >= 300 && status < 400 && !!h.location
			if (isRedirect) {
				buffering = true
				bufferedStatus = status
				bufferedHeaders = h
				return
			}
			stream = startProgressiveResponse({
				status,
				headers: h,
				...responseMeta(opts),
				signal: opts.signal,
				idleTimeoutMs: opts.timeouts?.bodyIdle ?? 0,
				errorCode: 'EH2STREAM',
				onCancel: () => {
					try { req.close(0x8) } catch { /* already closed */ }
					if (!pool.release(conn)) conn.close('h2-stream-cancel')
				},
				onBackpressure: (paused) => {
					if (paused) req.pauseInbound()
					else req.resumeInbound()
				},
				onFirstByte: () => {
					firstByteEmitted = true
					observability.safeEmit('request:firstByte', { id: reqId, durationMs: Date.now() - reqT0 })
				},
				onEnd: (bytes) => {
					observability.safeEmit('request:end', {
						id: reqId, status, headers: h, totalBytes: bytes,
						durationMs: Date.now() - reqT0, tls: summarizeConn(conn),
					})
					if (!pool.release(conn)) conn.close('h2-stream-end')
				},
				onError: (error) => {
					observability.safeEmit('request:error', {
						id: reqId, code: errorCodeOf(error, 'EH2STREAM'),
						message: messageOf(error), durationMs: Date.now() - reqT0,
					})
				},
			})
			resolve(stream.result)
		})
		req.on('data', (c: Buffer) => {
			if (buffering) {
				buffered.push(c)
				if (!firstByteEmitted) {
					firstByteEmitted = true
					observability.safeEmit('request:firstByte', { id: reqId, durationMs: Date.now() - reqT0 })
				}
				return
			}
			stream?.write(c)
		})
		req.on('end', () => {
			if (!buffering) {
				stream?.end()
				return
			}
			if (timer) clearTimeout(timer)
			if (!pool.release(conn)) conn.close('h2-response-complete')
			let raw: Buffer = Buffer.concat(buffered)
			try { raw = decompressIfNeeded(raw, bufferedHeaders?.['content-encoding'] as string) }
			catch (e) { return reject(new HellojsError((e as Error).message, 'EDECOMPRESS', e)) }
			observability.safeEmit('request:end', {
				id: reqId, status: bufferedStatus, headers: bufferedHeaders ?? {}, totalBytes: raw.length,
				durationMs: Date.now() - reqT0, responseBody: raw, tls: summarizeConn(conn),
			})
			handleResponse({
				status: bufferedStatus, statusText: statusTextFor(bufferedStatus),
				headers: bufferedHeaders ?? {}, raw, opts, resolve, reject,
			})
		})
		req.on('error', (e: Error) => {
			if (stream) {
				conn.close('h2-stream-error')
				stream.fail(new HellojsError(e.message, 'EH2STREAM', e))
				return
			}
			if (settled && !buffering) return
			settled = true
			if (timer) clearTimeout(timer)
			conn.close('h2-stream-error')
			reject(new HellojsError(e.message, 'EH2STREAM', e))
		})
		if (streamingBody) {
			// req.write returns false when the peer's flow-control window is full and the chunk
			// is queued; pause the source until the session drains it (emits 'drain').
			streamingBody.on('data', (c: Buffer) => {
				if (!req.write(Buffer.isBuffer(c) ? c : Buffer.from(c))) { streamingBody.pause(); req.once('drain', () => streamingBody.resume()) }
			})
			streamingBody.on('end', () => req.end())
			streamingBody.on('error', (e: Error) => { try { req.close(0x8) } catch {}; conn.close('h2-body-error'); reject(new HellojsError(e.message, 'EBODYSTREAM', e)) })
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
function performH1(conn: Connection, { method, url, host, body, userHeaders, opts, profileObj }: RequestContext): Promise<Response> {
	const transport = conn.h2Transport!  // misnomer: this is the raw TLS Duplex
	const requestLine = `${method} ${url.pathname + url.search} HTTP/1.1\r\n`
	const headerBlock = buildH1Headers({ host, userHeaders, profile: profileObj })
	const head = Buffer.from(requestLine + headerBlock + '\r\n\r\n', 'utf8')
	const h1T0 = Date.now()
	transport.write(head)

	return new Promise((resolve, reject) => {
		// The connection is fresh and dedicated to this request, so no leftover bytes
		// from a prior response exist.
		let buf: Buffer = Buffer.alloc(0)
		let settled = false, headersParsed = false
		let status = 0
		let statusText = ''
		let headers: H1Headers = {}
		let mode: HeadMode | null = null
		let contentLength = 0
		let bodyStart = 0
		// Progressive-response state. `streamingStarted` means headers have been handed off to
		// the body parser (or to the redirect buffer), so later chunks bypass `buf`.
		let streamingStarted = false
		let buffering = false
		let streamDone = false
		const buffered: Buffer[] = []
		let stream: ProgressiveStream | null = null
		// Incremental framing state for the streaming chunked parser.
		let frameBuf: Buffer = Buffer.alloc(0)
		let chunkRemaining = 0
		let chunkState: 'size' | 'data' | 'data-crlf' | 'trailers' = 'size'
		let received = 0

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

		// Send the request body. A Readable streams as HTTP/1.1 chunks when the header layer
		// selected chunked framing (unknown length); with a caller Content-Length it streams raw.
		// A buffered body is written in one shot. Mirrors the h2/h3 streaming-body paths.
		const streamBody = isReadable(body) ? body : null
		if (streamBody) {
			const chunked = Object.keys(userHeaders).some(
				(k) => k.toLowerCase() === 'transfer-encoding' && String(userHeaders[k]).toLowerCase().includes('chunked'),
			)
			const CRLF = Buffer.from('\r\n', 'utf8')
			streamBody.on('data', (c: Buffer | string) => {
				const data = Buffer.isBuffer(c) ? c : Buffer.from(c)
				const frame = chunked
					? Buffer.concat([Buffer.from(data.length.toString(16), 'utf8'), CRLF, data, CRLF])
					: data
				if (!transport.write(frame)) { streamBody.pause(); transport.once('drain', () => streamBody.resume()) }
			})
			streamBody.on('end', () => { if (chunked) transport.write('0\r\n\r\n', 'utf8') })
			streamBody.on('error', (e: Error) => done(() => { try { conn.close('h1-body-error') } catch {}; reject(new HellojsError(e.message, 'EBODYSTREAM', e)) }))
		} else if (body) {
			transport.write(body)
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
			statusText = m[3] ?? ''
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

		// Write decoded entity bytes into the progressive stream, or collect them while a
		// redirect response is being buffered.
		function writeOut(data: Buffer): void {
			if (data.length === 0) return
			received += data.length
			if (buffering) { buffered.push(data); return }
			if (!stream) return
			stream.write(data)
		}

		// Incremental chunked decoder: never retains more than partial framing.
		function feedChunked(chunk: Buffer): void {
			frameBuf = frameBuf.length ? Buffer.concat([frameBuf, chunk]) : chunk
			for (;;) {
				if (chunkState === 'size') {
					const nl = frameBuf.indexOf(CRLF)
					if (nl < 0) return
					const token = frameBuf.subarray(0, nl).toString('ascii').split(';')[0].trim()
					if (!/^[0-9a-fA-F]+$/.test(token)) { failStream('bad chunk size', 'EBADRESP'); return }
					const size = Number.parseInt(token, 16)
					frameBuf = frameBuf.subarray(nl + 2)
					if (size === 0) { chunkState = 'trailers'; continue }
					chunkRemaining = size
					chunkState = 'data'
				}
				if (chunkState === 'data') {
					if (frameBuf.length === 0) return
					const take = Math.min(chunkRemaining, frameBuf.length)
					writeOut(frameBuf.subarray(0, take))
					frameBuf = frameBuf.subarray(take)
					chunkRemaining -= take
					if (chunkRemaining > 0) return
					chunkState = 'data-crlf'
				}
				if (chunkState === 'data-crlf') {
					if (frameBuf.length < 2) return
					frameBuf = frameBuf.subarray(2)
					chunkState = 'size'
				}
				if (chunkState === 'trailers') {
					const end = findTrailerEnd(frameBuf, 0)
					if (end < 0) return
					completeStream()
					return
				}
			}
		}

		function feedStream(chunk: Buffer): void {
			if (streamDone) return
			if (mode === 'none') return
			if (mode === 'length') {
				const take = Math.min(chunk.length, contentLength - received)
				if (take > 0) writeOut(chunk.subarray(0, take))
				if (received >= contentLength) completeStream()
				return
			}
			if (mode === 'eof') { writeOut(chunk); return }
			if (mode === 'chunked') feedChunked(chunk)
		}

		function failStream(message: string, code: ErrorCode | string): void {
			if (streamDone) return
			streamDone = true
			settled = true
			cleanup()
			try { conn.close('h1-stream-error') } catch { /* closed */ }
			// A buffered response has not resolved yet, so the failure belongs on the promise.
			if (buffering) { reject(new HellojsError(message, code)); return }
			stream?.fail(new HellojsError(message, code))
		}

		function completeStream(): void {
			if (streamDone) return
			streamDone = true
			settled = true
			cleanup()
			if (buffering) {
				try { conn.close('h1-response-complete') } catch { /* closed */ }
				let raw: Buffer = Buffer.concat(buffered)
				if (raw.length) {
					try { raw = decompressIfNeeded(raw, coerce(headers['content-encoding']) || '') }
					catch (e) { reject(new HellojsError((e as Error).message, 'EDECOMPRESS', e)); return }
				}
				if (opts.jar && headers['set-cookie']) opts.jar.setCookie(headers['set-cookie'], url.toString())
				observability.safeEmit('request:end', {
					id: opts._reqId, status, headers, totalBytes: raw.length,
					durationMs: Date.now() - h1T0, responseBody: raw, tls: summarizeConn(conn),
				})
				handleResponse({ status, statusText, headers, raw, opts, resolve, reject })
				return
			}
			stream?.end()
		}

		// Hand the response off as soon as its headers are complete. Redirects are buffered
		// because their (small) body decides what handleResponse must do; everything else
		// becomes a progressive web stream.
		function startStreaming(): void {
			streamingStarted = true
			const isRedirect = opts.redirect !== 'manual' && status >= 300 && status < 400 && !!headers.location
			if (isRedirect) { buffering = true; return }
			stream = startProgressiveResponse({
				status,
				statusText,
				headers,
				...responseMeta(opts),
				signal: opts.signal,
				idleTimeoutMs: opts.timeouts?.bodyIdle ?? 0,
				errorCode: 'EBADRESP',
				onCancel: () => {
					streamDone = true
					settled = true
					cleanup()
					try { conn.close('h1-stream-cancel') } catch { /* closed */ }
				},
				onBackpressure: (paused) => {
					try {
						if (paused) transport.pause()
						else transport.resume()
					} catch { /* not a Node stream */ }
				},
				onFirstByte: () => observability.safeEmit('request:firstByte', { id: opts._reqId, durationMs: Date.now() - h1T0 }),
				onEnd: (bytes) => {
					observability.safeEmit('request:end', {
						id: opts._reqId, status, headers, totalBytes: bytes,
						durationMs: Date.now() - h1T0, tls: summarizeConn(conn),
					})
					try { conn.close('h1-response-complete') } catch { /* closed */ }
				},
				onError: (error) => {
					observability.safeEmit('request:error', {
						id: opts._reqId, code: errorCodeOf(error, 'EBADRESP'),
						message: messageOf(error), durationMs: Date.now() - h1T0,
					})
				},
			})
			if (timer) { clearTimeout(timer); timer = null }
			resolve(stream.result)
		}

		const onData = (c: Buffer) => {
			if (settled) return
			// After the header hand-off every chunk is body bytes; `buf` only ever holds the
			// unparsed head, so the two paths never compete for the same offset.
			if (streamingStarted) { if (c.length) feedStream(c); return }
			if (c.length) buf = buf.length ? Buffer.concat([buf, c]) : c
			while (!settled) {
				if (!headersParsed) {
					const r = parseHead()
					if (r === 'need-more' || r === 'error') return
					if (r === 'interim') continue  // 1xx consumed; parse the next head
				}
				startStreaming()
				if (mode === 'none' || (mode === 'length' && contentLength === 0)) { completeStream(); return }
				const leftover = buf.subarray(bodyStart)
				buf = Buffer.alloc(0)
				if (leftover.length) feedStream(leftover)
				return
			}
		}
		const onEnd = () => {
			if (settled) return
			if (!headersParsed) return fail('incomplete h1 response', 'EBADRESP')
			// Close-delimited bodies complete on EOF. A length/chunked close before its frame
			// (streaming or buffered) is truncation.
			if (mode === 'eof') { completeStream(); return }
			failStream('connection closed before response complete', 'EBADRESP')
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
	statusText?: string
	headers: H1Headers
	/** Fully decoded response bytes. */
	raw: Buffer
	opts: RequestOptions
	resolve: (value: Response) => void
	reject: (reason: unknown) => void
}

function responseMeta(opts: RequestOptions): { url: string; redirected: boolean; method: string } {
	return {
		url: opts.url ?? opts.uri ?? '',
		redirected: opts._redirected === true,
		method: (opts.method || 'GET').toUpperCase(),
	}
}

function handleResponse({ status, statusText, headers, raw, opts, resolve, reject }: HandleResponseInput): void {
	const res = buildResponse({ status, statusText, headers, body: raw, ...responseMeta(opts) })

	if (opts.redirect === 'error' && status >= 300 && status < 400 && headers.location) {
		return reject(new HellojsError(`redirect not allowed with redirect: 'error' (HTTP ${status})`, 'EHTTP'))
	}
	if (opts.redirect !== 'manual' && status >= 300 && status < 400 && headers.location && (opts.maxRedirects ?? 10) > 0) {
		const location = Array.isArray(headers.location) ? headers.location[0] : headers.location
		const currentUrl = new URL(opts.url ?? opts.uri ?? '')
		const target = new URL(location, currentUrl)
		// `_redirected` survives the recursive call so the final Response reports it.
		let newOpts: RequestOptions = { ...opts, url: target.toString(), maxRedirects: (opts.maxRedirects ?? 10) - 1, _redirected: true }
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
		void performRequest(newOpts).then(resolve, reject)
		return
	}
	resolve(res)
}

// Public API ------------------------------------------------------------

function retryDelay(ms: number, signal?: AbortSignal | null): Promise<void> {
	return new Promise((resolve, reject) => {
		if (signal?.aborted) { reject(abortReason(signal)); return }
		let timer: ReturnType<typeof setTimeout> | null = null
		const onAbort = () => {
			if (timer) clearTimeout(timer)
			signal?.removeEventListener('abort', onAbort)
			reject(abortReason(signal))
		}
		timer = setTimeout(() => {
			signal?.removeEventListener('abort', onAbort)
			resolve()
		}, ms)
		timer.unref?.()
		signal?.addEventListener('abort', onAbort, { once: true })
	})
}

// The request.js response shims are gone. Fail loudly instead of silently ignoring them:
// `simple: true` / `bodyOnly: true` would promise behavior the fetch-shaped API no longer
// has. Explicit `false` is harmless and stays accepted.
function assertNoLegacyResponseOptions(opts: RequestOptions): void {
	const legacy = opts as RequestOptions & { simple?: unknown; bodyOnly?: unknown }
	if (legacy.simple === true) {
		throw new HellojsError('simple was removed; inspect res.ok instead', 'EBADOPTS')
	}
	if (legacy.bodyOnly === true) {
		throw new HellojsError('bodyOnly was removed; await res.json()/text()/arrayBuffer() instead', 'EBADOPTS')
	}
}

async function performWithRetry(opts: RequestOptions): Promise<Response> {
	assertNoLegacyResponseOptions(opts)
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
			const res = await performRequest(opts)
			// A retryable status is already visible at the header stage. Cancel the unread
			// body to release the stream/socket before the next attempt.
			if (retriable && attempt < limit && statusCodes.includes(res.status)) {
				if (res.body) { try { await res.body.cancel() } catch { /* already closed */ } }
				await retryDelay(baseDelay * Math.pow(2, attempt), opts.signal)
				continue
			}
			return res
		} catch (e) {
			// Abort is not a retryable transport failure, and fetch rejects with the signal's
			// reason (a DOMException by default), not a HellojsError.
			if (opts.signal?.aborted) throw abortReason(opts.signal)
			if (typeof DOMException !== 'undefined' && e instanceof DOMException && e.name === 'AbortError') throw e
			// Normalize: every error leaving this function is a HellojsError with a stable .code.
			lastErr = wrapError(e)
			const transient = ['ETIMEDOUT', 'ECONNRESET', 'EH2STREAM', 'EH3STREAM'].includes(lastErr.code)
			if (!retriable || !transient || attempt === limit) throw lastErr
			await retryDelay(baseDelay * Math.pow(2, attempt), opts.signal)
		}
	}
	throw lastErr
}

function inputToOptions(input: RequestOptions | string | URL | Request, init?: FetchInit): RequestOptions {
	if (typeof init === 'function') {
		throw new HellojsError('callbacks were removed; use await request(...) instead', 'EBADOPTS')
	}
	let opts: RequestOptions
	if (typeof input === 'string' || input instanceof URL) {
		opts = { ...(init ?? {}), url: input.toString() }
	} else if (typeof Request !== 'undefined' && input instanceof Request) {
		const headers = headersToRecord(input.headers)
		opts = {
			...inputToRequestOptions(input),
			...(init ?? {}),
			url: init?.url ?? input.url,
			method: init?.method ?? input.method,
			headers: init?.headers ? headersToRecord(init.headers) : headers,
			body: init?.body !== undefined ? init.body : (input.body as ReadableStream<Uint8Array> | null),
			redirect: (init?.redirect ?? input.redirect) as RedirectMode,
			signal: init?.signal ?? input.signal,
		}
	} else {
		opts = { ...(input as RequestOptions), ...(init ?? {}) }
	}
	opts.headers = headersToRecord(opts.headers)
	return opts
}

// Pull the fetch fields off a `Request` without copying its (already consumed) body twice.
function inputToRequestOptions(input: Request): Partial<RequestOptions> {
	return {
		method: input.method,
		redirect: input.redirect as RedirectMode,
		signal: input.signal,
	}
}

async function requestImpl(input: RequestOptions | string | URL | Request, init?: FetchInit): Promise<Response> {
	return performWithRetry(inputToOptions(input, init))
}

function method(m: string, dispatch: MethodFn = requestImpl): MethodFn {
	return async (input, init) => {
		const opts = inputToOptions(input, init)
		opts.method = m
		return dispatch(opts)
	}
}

// Deep-merge defaults + per-call opts, with `headers` lowercased and merged (later wins).
function mergeOpts(base: Partial<RequestOptions>, over: RequestOptions): RequestOptions {
	const out: RequestOptions = { ...base, ...over }
	out.headers = { ...headersToRecord(base.headers), ...headersToRecord(over.headers) }
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
			const wrapped: MethodFn = async (input, init) =>
				requestImpl(mergeOpts(defaults, inputToOptions(input, init)))
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
