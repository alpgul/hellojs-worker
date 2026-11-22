// Public fetch-compatible API: request(input, init) with a real fetch Response.
//
//   import request from 'hellojs'
//   request('https://example.com', { method, headers, body, redirect, proxy })
//   const res = await request(url, { ... })   // fetch Response, streamed body
//   request.get/post/put/del/patch/head/options
//   request.defaults(init)
//   request.jar()
//
// Notes:
// - Driven by lib/connect.ts and lib/tls/tls.ts for TLS+HTTP/2. Requests reuse a bounded
//   per-origin h2 pool (lib/pool.ts) unless `keepalive: false` opts out.
// - HTTP/1.1 fallback is hand-rolled (chunked, content-length).
// - Auto-decompresses gzip / br / deflate / zstd response bodies based on the response's
//   Content-Encoding header — no opt-in needed. To receive raw compressed bytes, override
//   Accept-Encoding to `identity` in headers; servers will then respond uncompressed.

import { URL } from 'node:url'
import * as zlib from 'node:zlib'

import {
	authorizedAltsvcOrigin,
	forgetAltSvc,
	markAltSvcBroken,
	originKey,
	rememberAltSvc,
	selectAltSvc
} from './alt-svc.ts'
import { Jar } from './cookies.ts'
import { HellojsError, wrap as wrapError } from './errors.ts'
import { udpAvailable } from './h3/udp.ts'
import { assertProxyConnectHeaders, buildH2Headers, buildH1Headers, mergeProfileHeaders } from './headers.ts'
import { observability, nextRequestId } from './observability.ts'
import * as pool from './pool.ts'
import * as profileRegistry from './profiles/index.ts'
import { startProgressiveResponse, type ProgressiveStream } from './response-stream.ts'
import { statusTextFor } from './status-text.ts'
import { summarizeConn } from './tls-summary.ts'
import { canUseQuic, connectWithTransport, type TransportHint } from './transport-race.ts'
import { buildResponse, isWebReadableStream, webToNodeStream } from './web-response.ts'

import type { Alpn, Connection } from './connect.ts'
import type { ErrorCode } from './errors.ts'
import type { H2Session, H2Stream } from './h2/session.ts'
import type { H3StreamHandlers } from './h3/h3.ts'
import type { HeaderMap } from './headers.ts'
import type { Profile } from './profiles/types.ts'
import type { Readable } from 'node:stream'

// RFC 6265-compliant cookie jar lives in lib/cookies.ts.

/** Request bodies are exactly fetch's `BodyInit` — serialize JSON/forms before calling. */
export type RequestBodyValue = BodyInit

/** Methods registered with IANA (RFC 9110 §9, RFC 5789). */
export type RegisteredHttpMethod =
	'GET' | 'HEAD' | 'POST' | 'PUT' | 'DELETE' | 'CONNECT' | 'OPTIONS' | 'TRACE' | 'PATCH'

/**
 * The method may be given in either case; `request()` uppercases it before use. The type
 * is deliberately closed to the registered set; the runtime still accepts any HTTP token.
 */
export type HttpMethod = RegisteredHttpMethod | Lowercase<RegisteredHttpMethod>

export type RedirectMode = 'follow' | 'manual' | 'error'

export interface RetryPolicy {
	limit?: number
	methods?: HttpMethod[]
	statusCodes?: number[]
	baseDelayMs?: number
}

/** Per-request proxy configuration. Every CONNECT detail lives under `proxy`, not at the top level. */
export interface ProxyOptions {
	/** Proxy URL (`http://`, `https://`, `socks5://`, …). Required when `proxy` is present. */
	url: string
	/**
	 * Full CONNECT `Proxy-Authorization` value (e.g. `Bearer <jwt>`). Overrides URL Basic auth;
	 * `''` sends no header. Validated before any socket is opened; unused by `socks5://`.
	 */
	authorization?: string | null
	/**
	 * Extra headers sent on the CONNECT request to the proxy. CONNECT-owned names and values
	 * outside printable ASCII reject with `EBADOPTS`; unused by `socks5://`.
	 */
	headers?: Record<string, string> | null
	/**
	 * Keep the connection to an `http(s)`/`ws(s)` proxy alive and reuse it for later CONNECTs
	 * (default `true`; pass `false` for one-shot hops). No-op for `socks5://` and h3. Shares the
	 * process-wide pool caps.
	 */
	keepAlive?: boolean
}

/**
 * Options accepted as the second argument of `request(input, init)`. Deliberately not an
 * extension of `RequestInit`: inherited fields such as `cache`, `integrity`, `mode`,
 * `credentials` and `priority` are never consulted by the transports, so accepting them
 * would promise behavior that does not exist. The URL always comes from `input`.
 */
export interface RequestOptions {
	method?: HttpMethod
	/** `Headers`, tuple lists and plain records are normalized to a lowercase record internally. */
	headers?: HeadersInit | Record<string, string | string[]> | null
	body?: RequestBodyValue | null
	redirect?: RedirectMode
	signal?: AbortSignal | null
	jar?: Jar | null
	proxy?: ProxyOptions | null
	/** TLS-only: turn on cert chain validation (default `true`). */
	verifyTLS?: boolean
	/** Hellojs-specific: reuse a pooled h2 socket (default `true`); `false` forces a fresh connection. Unrelated to fetch's same-named flag. */
	keepalive?: boolean
	retry?: RetryPolicy
	/** Profile name, or an inline profile object. */
	profile?: string | Profile
}

/**
 * Internal: what the transports actually receive. `headers` is always a lowercase map,
 * the URL comes from `input`, and redirect/observability bookkeeping stays private.
 */
type NormalizedRequestOptions = Omit<RequestOptions, 'headers'> & {
	headers: HeaderMap
	url: string
	_reqId?: number
	_redirected?: boolean
	_redirectCount?: number
}

// `HeaderMap` is intentionally richer than the cross-runtime `HeadersInit`. Only the internals
// consume it; casting back at the public boundary keeps the declared option shape independent
// of which runtime's ambient types are in scope.
function toPublicOptions(opts: NormalizedRequestOptions): RequestOptions {
	return opts as unknown as RequestOptions
}

/**
 * The result of `request()`: the platform's own fetch `Response`, so every consumer —
 * DOM, Node's undici, or Workers — understands it without a cast.
 */
export type Response = globalThis.Response

/** Fetch-style init accepted as the second argument. */
export type FetchInit = RequestOptions

type MethodFn = (input: string | URL | Request, init?: FetchInit) => Promise<Response>

/**
 * The public call shape, mirrored by index.d.ts: every call resolves the fetch-compatible
 * `Response` (unless redirect: 'error' rejects).
 */
export interface Invokable {
	(input: string | URL | Request, init?: FetchInit): Promise<Response>
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
	opts: NormalizedRequestOptions
	profileObj: Profile | null
	/** h1 sockets are registered only after a reusable response, so the key travels with the request. */
	h1PoolKey: string | null
	/** h2/h3 register a per-stream cancel so abort never kills a pooled sibling stream. */
	registerCancel?: (cancel: () => void) => void
	/** Return this request's pool slot exactly once, even if abort and stream teardown race. */
	release: () => boolean
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
			out[key] =
				prev === undefined
					? String(value)
					: Array.isArray(prev)
						? [...prev, String(value)]
						: [String(prev), String(value)]
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
	if (signal.aborted) {
		handler()
		return () => {}
	}
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
		try {
			return zlib.inflateSync(buf)
		} catch {
			return zlib.inflateRawSync(buf)
		}
	}
	if (e.includes('zstd')) return zlib.zstdDecompressSync(buf)
	return buf
}

// Streaming counterpart: return a Transform that the response body can be piped through.
// `null` means "no decoding needed — caller can read the body as-is."

function buildUrl(opts: NormalizedRequestOptions): URL {
	// The query string is part of `input`; there is no `qs` option to append.
	return new URL(opts.url)
}

interface PreparedBody {
	body: Buffer | Readable | null
	/** Content type computed by the BodyInit serializer (FormData boundary, URLSearchParams). */
	contentType: string | null
}

async function prepareBody(opts: NormalizedRequestOptions): Promise<PreparedBody> {
	const raw = opts.body
	if (raw === undefined || raw === null) return { body: null, contentType: null }
	// A web ReadableStream is the only streaming BodyInit; convert it to the Node stream the
	// transports already use for h2 DATA frames / h1 chunked encoding.
	if (isWebReadableStream(raw)) return { body: webToNodeStream(raw), contentType: null }
	if (typeof raw === 'string') return { body: Buffer.from(raw), contentType: null }
	// Buffer is a Uint8Array, so it arrives here as an ArrayBufferView like any other typed array.
	if (raw instanceof ArrayBuffer) return { body: Buffer.from(raw), contentType: null }
	if (ArrayBuffer.isView(raw))
		return { body: Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength), contentType: null }
	// BodyInit types with their own serialization rules (multipart boundary, form encoding).
	// A real Response performs exactly the encoding fetch would, so reuse it.
	if (isBlob(raw) || isFormData(raw) || isUrlSearchParams(raw)) {
		const wrapped = new Response(raw as BodyInit)
		return {
			body: Buffer.from(await wrapped.arrayBuffer()),
			contentType: wrapped.headers.get('content-type')
		}
	}
	return { body: null, contentType: null }
}

/** Learn Alt-Svc from final response headers; HTTP 421 invalidates the cached origin. */
function observeAltSvc(headers: H1Headers, opts: NormalizedRequestOptions, status: number): void {
	if (opts.proxy) return
	if (status === 421) {
		forgetAltSvc(opts.url)
		return
	}
	rememberAltSvc(headers['alt-svc'], opts.url)
}

interface PoolIdentity {
	originHost: string
	originPort: number
	dialHost: string
	dialPort: number
	profile: string | Profile | undefined
	proxy: ProxyOptions | null | undefined
	verifyTLS: boolean
}

/** The full bucket identity: origin, actual dial target and negotiated protocol. */
function keyFor(identity: PoolIdentity, kind: Alpn): string {
	return pool.poolKey(
		identity.originHost,
		identity.originPort,
		identity.profile,
		identity.proxy,
		identity.verifyTLS,
		{ host: identity.dialHost, port: identity.dialPort },
		kind
	)
}

/**
 * Buckets to try, best first. An h3 Alt-Svc hint only matches a QUIC session; with no hint a
 * pooled h3 session wins over h2, and an h1 socket is the last resort (it cannot multiplex).
 */
function candidatePoolKeys(identity: PoolIdentity, hint: TransportHint): string[] {
	let kinds: Alpn[]
	if (hint === 'h3') kinds = ['h3']
	else if (hint === 'h1') kinds = ['http/1.1']
	else if (hint === 'h2') kinds = ['h2', 'http/1.1']
	else kinds = canUseQuic(identity.proxy) ? ['h3', 'h2', 'http/1.1'] : ['h2', 'http/1.1']
	return kinds.map((kind) => keyFor(identity, kind))
}

const altsvcWired = new WeakSet<H2Session>()

/** Listen for RFC 7838 ALTSVC frames once per h2 session. */
function wireAltSvcFrame(conn: Connection, origin: string): void {
	const session = conn.h2Session
	if (!session || altsvcWired.has(session)) return
	altsvcWired.add(session)
	session.on?.('altsvc', (frameOrigin: string | null, value: string, streamId: number) => {
		const authorized = authorizedAltsvcOrigin(frameOrigin, origin, streamId)
		if (authorized) rememberAltSvc(value, authorized)
	})
}

async function performRequest(opts: NormalizedRequestOptions): Promise<Response> {
	throwIfAborted(opts.signal)
	const url = buildUrl(opts)
	const method = (opts.method || 'GET').toUpperCase()
	const host = url.hostname
	const port = url.port ? parseInt(url.port, 10) : 443
	const _reqId = opts._reqId || (opts._reqId = nextRequestId())
	const _t0 = Date.now()
	observability.safeEmit('request:start', {
		id: _reqId,
		method,
		url: url.toString(),
		headers: opts.headers,
		// The request body (if any) as a Buffer, for observability / mitm-style capture.
		// Streams aren't captured here — they'd force us to tee/replay. Callers who need
		// the body for streamed uploads should buffer it themselves upstream.
		requestBody:
			opts.body != null && typeof opts.body !== 'object'
				? Buffer.from(String(opts.body))
				: Buffer.isBuffer(opts.body)
					? opts.body
					: null
	})
	const profile = opts.profile || 'chrome147-mac'
	// Resolve to the actual profile object for header / pseudo-header / priority building.
	// Tolerate unknown names (caller may have a custom profile registered elsewhere) — the TLS
	// layer will throw a clearer error if the name truly isn't valid.
	let profileObj: Profile | null = null
	if (typeof profile === 'string') {
		try {
			profileObj = profileRegistry.get(profile)
		} catch {}
	}

	// Transport is selected automatically, like a browser. A cached h3 Alt-Svc skips the race;
	// otherwise a live pooled session wins first, then lib/transport-race.ts races QUIC against a
	// 300ms-delayed TCP handshake (or goes straight to TCP when UDP is unavailable or a proxy is
	// configured). h2, h3 and reusable h1 connections all enter the bounded pool.
	const origin = originKey(url)
	let alt = opts.proxy ? null : selectAltSvc(origin, host, port)
	// An h3 alternative is useless without a datagram socket; fall back to the normal race.
	if (alt?.hint === 'h3' && !udpAvailable()) alt = null
	const dialHost = alt?.host ?? host
	const dialPort = alt?.port ?? port
	const identityFor = (targetHost: string, targetPort: number): PoolIdentity => ({
		originHost: host,
		originPort: port,
		dialHost: targetHost,
		dialPort: targetPort,
		profile: opts.profile,
		proxy: opts.proxy,
		verifyTLS: opts.verifyTLS !== false
	})
	let identity = identityFor(dialHost, dialPort)
	let usedAlternative = alt !== null
	let conn: Connection | null = null
	let h1PoolKey: string | null = null
	if (opts.keepalive !== false) {
		for (const key of candidatePoolKeys(identity, alt?.hint ?? null)) {
			conn = pool.take(key)
			if (conn) break
		}
	}
	if (!conn) {
		try {
			const result = await connectWithTransport(
				{
					host: dialHost,
					port: dialPort,
					sniHost: host,
					profile,
					proxy: opts.proxy,
					verifyTLS: opts.verifyTLS !== false,
					signal: opts.signal
				},
				alt?.hint ?? null,
				origin,
				{ host, port }
			)
			conn = result.conn
			usedAlternative = result.usedAlternative
			// A failed h3 hint falls back to the origin, so the socket must be pooled under
			// the origin dial target rather than the dead alternative's key.
			if (!usedAlternative) identity = identityFor(host, port)
		} catch (e) {
			// A cached alternative may have gone away: mark it broken and let the retry use TCP.
			// An explicit abort says nothing about the endpoint's health.
			if (alt?.hint === 'h3' && !opts.signal?.aborted) markAltSvcBroken(origin, 'h3')
			throw e
		}
		if (opts.keepalive !== false && conn.alpn && conn.alpn !== 'http/1.1') {
			pool.register(conn, keyFor(identity, conn.alpn))
		}
	}
	// h1 cannot multiplex: register only once a reusable response proves the socket can serve
	// another request (no `Connection: close`, no eof-delimited body). A freshly dialed h1
	// socket has no slot yet; one taken from the pool already does.
	if (opts.keepalive !== false && conn.alpn === 'http/1.1') h1PoolKey = keyFor(identity, 'http/1.1')

	// h2 ALTSVC frames (RFC 7838 §4) carry the same information as the response header. Wire
	// once per session; stream-level frames with an empty Origin use this connection's origin
	// (the h2 pool is per-origin).
	if (conn.alpn === 'h2' && conn.h2Session && !opts.proxy) wireAltSvcFrame(conn, origin)

	// Build headers
	const userHeaders: HeaderMap = headersToRecord(opts.headers)
	// RFC 7838 §5: only a request actually sent to an alternative names that authority. An
	// h3 handshake that failed and fell back to the origin must NOT claim `Alt-Used`.
	if (usedAlternative && alt?.altUsed && !Object.keys(userHeaders).some((k) => k.toLowerCase() === 'alt-used')) {
		userHeaders['Alt-Used'] = alt.altUsed
	}
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
	// Only BodyInit values that carry their own media type (FormData, URLSearchParams, typed
	// Blobs) get an automatic content-type. Strings/buffers are opaque; the caller labels them.
	if (body && prepared.contentType && !_hasHeader('content-type')) {
		userHeaders['content-type'] = prepared.contentType
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
	if (isStream && !_hasHeader('content-length') && !_hasHeader('transfer-encoding') && conn.alpn === 'http/1.1')
		userHeaders['transfer-encoding'] = 'chunked'

	// h1 has no per-stream cancel (its socket is exclusive), so abort still closes it. h2/h3
	// override this with a stream-scoped cancel that keeps their pooled session alive.
	let cancelRequest = () => {
		if (conn.alpn === 'http/1.1') conn.close('abort')
	}
	let releasedSlot = false
	const release = (): boolean => {
		if (releasedSlot) return true
		releasedSlot = true
		return pool.release(conn)
	}
	const ctx: RequestContext = {
		method,
		url,
		host,
		body,
		userHeaders,
		opts,
		profileObj,
		h1PoolKey,
		registerCancel: (cancel) => {
			cancelRequest = cancel
		},
		release
	}
	const transport = (async () => {
		if (conn.alpn === 'h3') return performH3(conn, ctx)
		if (conn.alpn === 'h2') return performH2(conn, ctx)
		return performH1(conn, ctx)
	})()
	let removeAbort = () => {}
	try {
		if (opts.signal) {
			let rejectAbort: (reason: unknown) => void = () => {}
			const aborted = new Promise<never>((_, reject) => {
				rejectAbort = reject
			})
			removeAbort = onAbort(opts.signal, () => {
				try {
					cancelRequest()
				} catch {}
				rejectAbort(abortReason(opts.signal))
			})
			return await Promise.race([transport, aborted])
		}
		return await transport
	} catch (e) {
		// Synchronous setup failures (e.g. a header builder throwing) must not leak the socket.
		// A pooled socket survives with its slot returned so sibling streams are unaffected;
		// one-shot sockets close. close() is idempotent.
		if (!release()) conn.close('error')
		throw e
	} finally {
		removeAbort()
	}
}

function performH3(
	conn: Connection,
	{ method, url, host, body, userHeaders, opts, profileObj, registerCancel, release }: RequestContext
): Promise<Response> {
	const headers = mergeProfileHeaders(userHeaders, profileObj)
	const path = url.pathname + url.search
	const reqId = opts._reqId
	const reqT0 = Date.now()
	const close = () => {
		// A healthy QUIC session stays pooled; unpooled or poisoned sessions close as before.
		if (!release()) {
			try {
				conn.close('h3-response-complete')
			} catch {
				/* already closed */
			}
		}
	}

	// Resolve at HEADERS and stream DATA frames as they arrive. Redirects are buffered so the
	// normal handleResponse policy still applies to them.
	return new Promise((resolve, reject) => {
		let stream: ProgressiveStream | null = null
		let buffering = false
		const buffered: Buffer[] = []
		let status = 0
		let resHeaders: Record<string, string> = {}
		let resolved = false
		let cancelStream = () => {}

		const handlers: H3StreamHandlers = {
			onHeaders: (s, h) => {
				// 1xx informational responses are not final; wait for the real HEADERS.
				if (s >= 100 && s < 200) return
				status = s
				resHeaders = h
				observeAltSvc(h, opts, s)
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
					errorCode: 'EH3STREAM',
					// H3Client wraps this handler to pause/resume the QUIC stream; drain
					// events from the web body must travel back through that wrapper.
					onBackpressure: (paused) => handlers.onBackpressure!(paused),
					onCancel: () => {
						cancelStream()
						close()
					},
					onFirstByte: () =>
						observability.safeEmit('request:firstByte', { id: reqId, durationMs: Date.now() - reqT0 }),
					onEnd: (bytes) => {
						observability.safeEmit('request:end', {
							id: reqId,
							status: s,
							headers: h,
							totalBytes: bytes,
							durationMs: Date.now() - reqT0,
							tls: summarizeConn(conn)
						})
						close()
					},
					onError: (error, bytes) => {
						observability.safeEmit('request:error', {
							id: reqId,
							code: errorCodeOf(error, 'EH3STREAM'),
							message: messageOf(error),
							durationMs: Date.now() - reqT0
						})
						void bytes
						close()
					}
				})
				resolved = true
				resolve(stream.result)
			},
			onData: (chunk) => {
				if (buffering) {
					buffered.push(chunk)
					return true
				}
				// false pauses QuicStream delivery and withholds MAX_DATA/MAX_STREAM_DATA
				// until response-stream signals drain through onBackpressure.
				return stream ? stream.write(chunk) : true
			},
			onBackpressure: (paused) => {
				observability.safeEmit('request:backpressure', { id: reqId, paused })
			},
			onEnd: () => {
				if (buffering) {
					close()
					let raw: Buffer = Buffer.concat(buffered)
					try {
						raw = decompressIfNeeded(raw, resHeaders['content-encoding'])
					} catch (e) {
						reject(new HellojsError((e as Error).message, 'EDECOMPRESS', e))
						return
					}
					observability.safeEmit('request:end', {
						id: reqId,
						status,
						headers: resHeaders,
						totalBytes: raw.length,
						durationMs: Date.now() - reqT0,
						responseBody: raw,
						tls: summarizeConn(conn)
					})
					handleResponse({
						status,
						statusText: statusTextFor(status),
						headers: resHeaders,
						raw,
						opts,
						resolve,
						reject
					})
					return
				}
				if (!stream) {
					close()
					if (!resolved) {
						resolved = true
						reject(new HellojsError('h3 response ended before headers', 'EBADRESP'))
					}
					return
				}
				stream.end()
			},
			onError: (e) => {
				if (stream) {
					stream.fail(new HellojsError(e.message, 'EH3STREAM', e))
					return
				}
				// H3 parse/stream errors are request-scoped. Release this slot without tearing
				// down a pooled QUIC session that sibling requests are still using.
				close()
				if (!resolved) {
					resolved = true
					reject(new HellojsError(e.message, 'EH3STREAM', e))
				}
			}
		}
		const handle = conn.h3Client!.requestStream({ method, path, host, headers, body }, handlers)
		cancelStream = () => handle.cancel()
		registerCancel?.(cancelStream)
	})
}

function performH2(
	conn: Connection,
	{ method, url, host, body, userHeaders, opts, profileObj, registerCancel, release }: RequestContext
): Promise<Response> {
	return new Promise((resolve, reject) => {
		const headers = buildH2Headers({
			method,
			host,
			path: url.pathname + url.search,
			userHeaders,
			profile: profileObj
		})
		const streamingBody = isReadable(body) ? body : null
		// A non-stream body is the only thing that can go into a DATA frame directly.
		const bufferedBody = streamingBody ? null : (body as Buffer | null)
		const reqId = opts._reqId
		const reqT0 = Date.now()
		// PRIORITY-on-HEADERS values default to the profile when present; otherwise H2Session
		// falls back to Chrome's exclusive/weight=256. Passing `null` here lets H2Session pick.
		const reqOpts = { endStream: !body }
		const req: H2Stream = conn.h2Session!.request(headers, reqOpts)
		registerCancel?.(() => {
			try {
				req.close(0x8)
			} catch {
				/* already closed */
			}
		})
		observability.safeEmit('request:headersSent', { id: reqId, method, path: url.pathname + url.search })
		// Browsers impose no response-header timeout; the caller's `signal` is the only
		// deadline here. A stalled server is bounded by transport-level TCP/QUIC budgets.
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
			observeAltSvc(h, opts, status)
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
				errorCode: 'EH2STREAM',
				onCancel: () => {
					try {
						req.close(0x8)
					} catch {
						/* already closed */
					}
					if (!release()) conn.close('h2-stream-cancel')
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
						id: reqId,
						status,
						headers: h,
						totalBytes: bytes,
						durationMs: Date.now() - reqT0,
						tls: summarizeConn(conn)
					})
					if (!release()) conn.close('h2-stream-end')
				},
				onError: (error) => {
					observability.safeEmit('request:error', {
						id: reqId,
						code: errorCodeOf(error, 'EH2STREAM'),
						message: messageOf(error),
						durationMs: Date.now() - reqT0
					})
				}
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
				if (!stream) {
					if (settled) return
					settled = true
					if (!release()) conn.close('h2-response-complete')
					reject(new HellojsError('h2 response ended before headers', 'EBADRESP'))
					return
				}
				stream.end()
				return
			}
			if (!release()) conn.close('h2-response-complete')
			let raw: Buffer = Buffer.concat(buffered)
			try {
				raw = decompressIfNeeded(raw, bufferedHeaders?.['content-encoding'] as string)
			} catch (e) {
				return reject(new HellojsError((e as Error).message, 'EDECOMPRESS', e))
			}
			observability.safeEmit('request:end', {
				id: reqId,
				status: bufferedStatus,
				headers: bufferedHeaders ?? {},
				totalBytes: raw.length,
				durationMs: Date.now() - reqT0,
				responseBody: raw,
				tls: summarizeConn(conn)
			})
			handleResponse({
				status: bufferedStatus,
				statusText: statusTextFor(bufferedStatus),
				headers: bufferedHeaders ?? {},
				raw,
				opts,
				resolve,
				reject
			})
		})
		req.on('error', (e: Error & { code?: string; errorCode?: number }) => {
			// RST_STREAM / REFUSED_STREAM are per-stream: only session-level failures
			// (EH2PROTOCOL, transport errors) may tear down a socket shared by siblings.
			const perStream = e.code === 'EH2STREAM' && typeof e.errorCode === 'number'
			const h2Error = new HellojsError(e.message, 'EH2STREAM', e)
			if (stream) {
				if (!perStream) conn.close('h2-session-error')
				stream.fail(h2Error)
				return
			}
			if (settled && !buffering) return
			settled = true
			if (perStream) {
				if (!release()) conn.close('h2-stream-error')
			} else {
				conn.close('h2-session-error')
			}
			reject(h2Error)
		})
		if (streamingBody) {
			// req.write returns false when the peer's flow-control window is full and the chunk
			// is queued; pause the source until the session drains it (emits 'drain').
			streamingBody.on('data', (c: Buffer) => {
				if (!req.write(Buffer.isBuffer(c) ? c : Buffer.from(c))) {
					streamingBody.pause()
					req.once('drain', () => streamingBody.resume())
				}
			})
			streamingBody.on('end', () => req.end())
			streamingBody.on('error', (e: Error) => {
				try {
					req.close(0x8)
				} catch {}
				conn.close('h2-body-error')
				reject(new HellojsError(e.message, 'EBODYSTREAM', e))
			})
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
function performH1(
	conn: Connection,
	{ method, url, host, body, userHeaders, opts, profileObj, h1PoolKey }: RequestContext
): Promise<Response> {
	const transport = conn.h2Transport! // misnomer: this is the raw TLS Duplex
	const requestLine = `${method} ${url.pathname + url.search} HTTP/1.1\r\n`
	const headerBlock = buildH1Headers({ host, userHeaders, profile: profileObj })
	const head = Buffer.from(requestLine + headerBlock + '\r\n\r\n', 'utf8')
	const h1T0 = Date.now()
	transport.write(head)

	return new Promise((resolve, reject) => {
		// The connection is fresh and dedicated to this request, so no leftover bytes
		// from a prior response exist.
		let buf: Buffer = Buffer.alloc(0)
		let settled = false,
			headersParsed = false
		let status = 0
		let statusText = ''
		let httpVersion = '1.1'
		// A socket may only be pooled when the peer agreed to keep it alive and the body was
		// framed (length/chunked/none) — an eof-delimited body means the peer already closed it.
		let reusable = false
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

		// No response-header watchdog (browsers have none here); `signal` is the sole deadline.

		const coerce = (v: string | string[] | undefined) => (Array.isArray(v) ? v.join(', ') : v)

		function cleanup() {
			transport.removeListener('data', onData)
			transport.removeListener('end', onEnd)
		}
		function done(fn: () => void) {
			if (settled) return
			settled = true
			cleanup()
			fn()
		}
		function fail(msg: string, code: ErrorCode | string) {
			done(() => {
				try {
					conn.close('h1-error')
				} catch {}
				reject(new HellojsError(msg, code))
			})
		}

		// Successful completion: park a reusable socket in the pool, otherwise tear it down.
		function finishH1(reason: string) {
			if (!h1PoolKey || !reusable) {
				conn.close(reason)
				return
			}
			if (pool.isPooled(conn)) {
				pool.release(conn) // return this request's exclusive slot and start the idle timer
				return
			}
			if (pool.register(conn, h1PoolKey)) {
				pool.release(conn) // the creating request's slot becomes the idle reservation
				return
			}
			conn.close('h1-pool-full')
		}

		// Send the request body. A Readable streams as HTTP/1.1 chunks when the header layer
		// selected chunked framing (unknown length); with a caller Content-Length it streams raw.
		// A buffered body is written in one shot. Mirrors the h2/h3 streaming-body paths.
		const streamBody = isReadable(body) ? body : null
		if (streamBody) {
			const chunked = Object.keys(userHeaders).some(
				(k) =>
					k.toLowerCase() === 'transfer-encoding' && String(userHeaders[k]).toLowerCase().includes('chunked')
			)
			const CRLF = Buffer.from('\r\n', 'utf8')
			streamBody.on('data', (c: Buffer | string) => {
				const data = Buffer.isBuffer(c) ? c : Buffer.from(c)
				const frame = chunked
					? Buffer.concat([Buffer.from(data.length.toString(16), 'utf8'), CRLF, data, CRLF])
					: data
				if (!transport.write(frame)) {
					streamBody.pause()
					transport.once('drain', () => streamBody.resume())
				}
			})
			streamBody.on('end', () => {
				if (chunked) transport.write('0\r\n\r\n', 'utf8')
			})
			streamBody.on('error', (e: Error) =>
				done(() => {
					try {
						conn.close('h1-body-error')
					} catch {}
					reject(new HellojsError(e.message, 'EBODYSTREAM', e))
				})
			)
		} else if (body) {
			transport.write(body)
		}

		// Parse one response head (status line + headers) at the front of buf.
		function parseHead(): HeadResult {
			const he = buf.indexOf(CRLFCRLF)
			if (he < 0) return 'need-more' // a partial head is NOT an error — wait for more bytes
			const lines = buf.subarray(0, he).toString('latin1').split('\r\n')
			const m = lines.shift()!.match(/^HTTP\/1\.(\d) (\d{3})(?: (.*))?$/)
			if (!m) {
				fail('bad status line', 'EBADRESP')
				return 'error'
			}
			const st = parseInt(m[2], 10)
			// 1xx informational responses carry no body; discard the interim head and parse the
			// next one from the stream (RFC 7230 3.3.3 rule 1 — e.g. 100 Continue, 103 Early Hints).
			if (st >= 100 && st < 200) {
				buf = buf.subarray(he + 4)
				return 'interim'
			}
			status = st
			statusText = m[3] ?? ''
			httpVersion = m[1] === '1' ? '1.1' : '1.0'
			headers = {}
			for (const ln of lines) {
				const idx = ln.indexOf(':')
				if (idx < 0) continue
				const k = ln.slice(0, idx).trim().toLowerCase()
				const v = ln.slice(idx + 1).trim()
				if (headers[k] !== undefined) headers[k] = ([] as string[]).concat(headers[k], v)
				else headers[k] = v
			}
			bodyStart = he + 4
			observeAltSvc(headers, opts, status)
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
				if (!/^\d+$/.test(s)) {
					fail('invalid content-length', 'EBADRESP')
					return 'error'
				}
				mode = 'length'
				contentLength = parseInt(s, 10)
			} else {
				mode = 'eof' // body delimited by connection close
			}
			const connectionTokens = new Set(
				`${coerce(headers['connection']) ?? ''},${coerce(headers['proxy-connection']) ?? ''}`
					.toLowerCase()
					.split(',')
					.map((t) => t.trim())
			)
			reusable =
				mode !== 'eof' &&
				!connectionTokens.has('close') &&
				(httpVersion !== '1.0' || connectionTokens.has('keep-alive'))
			headersParsed = true
			return 'ok'
		}

		// Write decoded entity bytes into the progressive stream, or collect them while a
		// redirect response is being buffered.
		function writeOut(data: Buffer): void {
			if (data.length === 0) return
			received += data.length
			if (buffering) {
				buffered.push(data)
				return
			}
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
					if (!/^[0-9a-fA-F]+$/.test(token)) {
						failStream('bad chunk size', 'EBADRESP')
						return
					}
					const size = Number.parseInt(token, 16)
					frameBuf = frameBuf.subarray(nl + 2)
					if (size === 0) {
						chunkState = 'trailers'
						continue
					}
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
			if (mode === 'eof') {
				writeOut(chunk)
				return
			}
			if (mode === 'chunked') feedChunked(chunk)
		}

		function failStream(message: string, code: ErrorCode | string): void {
			if (streamDone) return
			streamDone = true
			settled = true
			cleanup()
			try {
				conn.close('h1-stream-error')
			} catch {
				/* closed */
			}
			// A buffered response has not resolved yet, so the failure belongs on the promise.
			if (buffering) {
				reject(new HellojsError(message, code))
				return
			}
			stream?.fail(new HellojsError(message, code))
		}

		function completeStream(): void {
			if (streamDone) return
			streamDone = true
			settled = true
			cleanup()
			if (buffering) {
				try {
					finishH1('h1-response-complete')
				} catch {
					/* closed */
				}
				let raw: Buffer = Buffer.concat(buffered)
				if (raw.length) {
					try {
						raw = decompressIfNeeded(raw, coerce(headers['content-encoding']) || '')
					} catch (e) {
						reject(new HellojsError((e as Error).message, 'EDECOMPRESS', e))
						return
					}
				}
				if (opts.jar && headers['set-cookie']) opts.jar.setCookie(headers['set-cookie'], url.toString())
				observability.safeEmit('request:end', {
					id: opts._reqId,
					status,
					headers,
					totalBytes: raw.length,
					durationMs: Date.now() - h1T0,
					responseBody: raw,
					tls: summarizeConn(conn)
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
			if (isRedirect) {
				buffering = true
				return
			}
			stream = startProgressiveResponse({
				status,
				statusText,
				headers,
				...responseMeta(opts),
				signal: opts.signal,
				errorCode: 'EBADRESP',
				onCancel: () => {
					streamDone = true
					settled = true
					cleanup()
					try {
						conn.close('h1-stream-cancel')
					} catch {
						/* closed */
					}
				},
				onBackpressure: (paused) => {
					try {
						if (paused) transport.pause()
						else transport.resume()
					} catch {
						/* not a Node stream */
					}
				},
				onFirstByte: () =>
					observability.safeEmit('request:firstByte', { id: opts._reqId, durationMs: Date.now() - h1T0 }),
				onEnd: (bytes) => {
					observability.safeEmit('request:end', {
						id: opts._reqId,
						status,
						headers,
						totalBytes: bytes,
						durationMs: Date.now() - h1T0,
						tls: summarizeConn(conn)
					})
					try {
						finishH1('h1-response-complete')
					} catch {
						/* closed */
					}
				},
				onError: (error) => {
					observability.safeEmit('request:error', {
						id: opts._reqId,
						code: errorCodeOf(error, 'EBADRESP'),
						message: messageOf(error),
						durationMs: Date.now() - h1T0
					})
				}
			})
			resolve(stream.result)
		}

		const onData = (c: Buffer) => {
			if (settled) return
			// After the header hand-off every chunk is body bytes; `buf` only ever holds the
			// unparsed head, so the two paths never compete for the same offset.
			if (streamingStarted) {
				if (c.length) feedStream(c)
				return
			}
			if (c.length) buf = buf.length ? Buffer.concat([buf, c]) : c
			while (!settled) {
				if (!headersParsed) {
					const r = parseHead()
					if (r === 'need-more' || r === 'error') return
					if (r === 'interim') continue // 1xx consumed; parse the next head
				}
				startStreaming()
				if (mode === 'none' || (mode === 'length' && contentLength === 0)) {
					completeStream()
					return
				}
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
			if (mode === 'eof') {
				completeStream()
				return
			}
			failStream('connection closed before response complete', 'EBADRESP')
		}

		transport.on('data', onData)
		transport.once('end', onEnd)
		try {
			transport.resume()
		} catch {}
	})
}

// Walk trailer lines after a terminal 0-length chunk; return the index just past the closing empty
// line, or -1 if the trailer section hasn't fully arrived.
function findTrailerEnd(b: Buffer, start: number): number {
	let off = start
	for (;;) {
		const nl = b.indexOf(CRLF, off)
		if (nl < 0) return -1
		if (nl === off) return off + 2 // empty line terminates the trailers
		off = nl + 2
	}
}

// Return a copy of opts with the named request headers removed (case-insensitively). Used on
// redirects to avoid leaking credentials across origins and to drop body-framing headers when a
// POST is downgraded to GET. Creates a fresh headers object so the caller's opts is untouched.
function withoutHeaders(opts: NormalizedRequestOptions, names: string[]): NormalizedRequestOptions {
	if (!opts.headers) return opts
	const drop = new Set(names.map((n) => n.toLowerCase()))
	const next: HeaderMap = {}
	for (const [k, v] of Object.entries(opts.headers)) {
		if (!drop.has(k.toLowerCase()) && v !== undefined) next[k] = v
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
	opts: NormalizedRequestOptions
	resolve: (value: Response) => void
	reject: (reason: unknown) => void
}

function responseMeta(opts: NormalizedRequestOptions): { url: string; redirected: boolean; method: string } {
	return {
		url: opts.url,
		redirected: opts._redirected === true,
		method: (opts.method || 'GET').toUpperCase()
	}
}

function handleResponse({ status, statusText, headers, raw, opts, resolve, reject }: HandleResponseInput): void {
	const res = buildResponse({ status, statusText, headers, body: raw, ...responseMeta(opts) })

	if (opts.redirect === 'error' && status >= 300 && status < 400 && headers.location) {
		return reject(new HellojsError(`redirect not allowed with redirect: 'error' (HTTP ${status})`, 'EHTTP'))
	}
	if (opts.redirect !== 'manual' && status >= 300 && status < 400 && headers.location) {
		const count = opts._redirectCount ?? 0
		// Fetch's HTTP-redirect-fetch: if the redirect count is 20, return a network error,
		// then increment. So 20 hops are followed and the 21st is rejected.
		if (count >= 20) {
			return reject(new HellojsError('redirect count exceeded the 20-hop browser limit', 'ETOOMANYREDIRECTS'))
		}
		const location = Array.isArray(headers.location) ? headers.location[0] : headers.location
		const currentUrl = new URL(opts.url)
		const target = new URL(location, currentUrl)
		// Internal bookkeeping survives the recursive call: `_redirected` makes the final
		// Response redirect-aware, `_redirectCount` enforces the fixed 20-hop browser limit.
		let newOpts: NormalizedRequestOptions = {
			...opts,
			headers: opts.headers,
			url: target.toString(),
			_redirectCount: count + 1,
			_redirected: true
		}
		const method = (opts.method || 'GET').toUpperCase()
		// RFC 9110 §15.4: 303 → GET. Browsers also downgrade a POST to GET on 301/302.
		// 307/308 preserve method and body. On downgrade, drop the body and its framing headers
		// so the redirected GET is bodyless.
		if (status === 303 || ((status === 301 || status === 302) && method === 'POST')) {
			newOpts.method = 'GET'
			delete newOpts.body
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
		if (signal?.aborted) {
			reject(abortReason(signal))
			return
		}
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
function assertProxyOptions(proxy: ProxyOptions | null | undefined): void {
	if (proxy == null) return
	if (typeof proxy !== 'object' || typeof proxy.url !== 'string' || !proxy.url.trim()) {
		throw new HellojsError('proxy.url must be a non-empty string', 'EBADOPTS')
	}
	assertProxyConnectHeaders(proxy.authorization, proxy.headers)
}

function assertNoLegacyResponseOptions(opts: RequestOptions): void {
	const legacy = opts as RequestOptions & { simple?: unknown; bodyOnly?: unknown }
	if (legacy.simple === true) {
		throw new HellojsError('simple was removed; inspect res.ok instead', 'EBADOPTS')
	}
	if (legacy.bodyOnly === true) {
		throw new HellojsError('bodyOnly was removed; await res.json()/text()/arrayBuffer() instead', 'EBADOPTS')
	}
}

async function performWithRetry(opts: NormalizedRequestOptions): Promise<Response> {
	assertNoLegacyResponseOptions(toPublicOptions(opts))
	assertProxyOptions(opts.proxy)
	const policy = opts.retry || {}
	const limit = policy.limit ?? 0
	const methods = policy.methods ?? ['GET', 'HEAD', 'OPTIONS']
	const statusCodes = policy.statusCodes ?? [408, 429, 500, 502, 503, 504]
	const baseDelay = policy.baseDelayMs ?? 200
	// The public type is closed to registered methods, but the runtime still accepts any
	// HTTP token, so compare case-insensitively on the raw string.
	const upper = (opts.method || 'GET').toUpperCase() as HttpMethod
	const retriable = methods.includes(upper)
	let lastErr: HellojsError | undefined
	for (let attempt = 0; attempt <= limit; attempt++) {
		try {
			const res = await performRequest(opts)
			// A retryable status is already visible at the header stage. Cancel the unread
			// body to release the stream/socket before the next attempt.
			if (retriable && attempt < limit && statusCodes.includes(res.status)) {
				if (res.body) {
					try {
						await res.body.cancel()
					} catch {
						/* already closed */
					}
				}
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

// Removed request.js knobs get a precise error instead of being silently ignored by JS callers.
const REMOVED_INIT_OPTIONS: Record<string, string> = {
	url: 'pass the URL as request(input, init)',
	uri: 'pass the URL as request(input, init)',
	json: 'serialize with JSON.stringify and pass it as body',
	form: 'use URLSearchParams as body',
	qs: 'put the query string in the input URL',
	gzip: 'response decoding is automatic',
	maxRedirects: 'browsers follow up to 20 redirects',
	timeout: 'use signal (AbortSignal.timeout())',
	timeouts: 'use signal (AbortSignal.timeout())',
	resume: 'TLS session resumption is managed internally',
	h3: 'transport is selected automatically'
}

function assertNoRemovedInitOptions(init?: FetchInit | Partial<RequestOptions>): void {
	if (!init) return
	for (const [key, hint] of Object.entries(REMOVED_INIT_OPTIONS)) {
		if (key in init) throw new HellojsError(`${key} was removed; ${hint}`, 'EBADOPTS')
	}
}

function inputToOptions(input: string | URL | Request, init?: FetchInit): NormalizedRequestOptions {
	if (typeof init === 'function') {
		throw new HellojsError('callbacks were removed; use await request(...) instead', 'EBADOPTS')
	}
	assertNoRemovedInitOptions(init)
	let opts: NormalizedRequestOptions
	if (typeof input === 'string' || input instanceof URL) {
		opts = { ...(init ?? {}), url: input.toString() } as unknown as NormalizedRequestOptions
	} else {
		const headers = headersToRecord(input.headers)
		opts = {
			...inputToRequestOptions(input),
			...(init ?? {}),
			url: input.url,
			method: init?.method ?? input.method,
			headers: init?.headers ? headersToRecord(init.headers) : headers,
			body: init?.body !== undefined ? init.body : (input.body as ReadableStream<Uint8Array> | null),
			redirect: (init?.redirect ?? input.redirect) as RedirectMode,
			signal: init?.signal ?? input.signal
		} as unknown as NormalizedRequestOptions
	}
	opts.headers = headersToRecord(opts.headers)
	return opts
}

// Pull the fetch fields off a `Request` without copying its (already consumed) body twice.
function inputToRequestOptions(input: Request): Partial<RequestOptions> {
	return {
		method: input.method as HttpMethod,
		redirect: input.redirect as RedirectMode,
		signal: input.signal
	}
}

// Internal entry point: everything below this line receives normalized options.
type InternalDispatch = (opts: NormalizedRequestOptions) => Promise<Response>

const requestImpl: MethodFn = (input, init) => performWithRetry(inputToOptions(input, init))

function method(m: HttpMethod, dispatch: InternalDispatch = performWithRetry): MethodFn {
	return async (input, init) => {
		const opts = inputToOptions(input, init)
		opts.method = m
		return dispatch(opts)
	}
}

// Deep-merge defaults + per-call opts: `headers` is lowercased and merged (later wins), and
// `proxy` is merged field by field so a per-call override need not repeat authorization/headers.
// An explicit `proxy: null` clears the default entirely.
function mergeProxy(
	base: ProxyOptions | null | undefined,
	over: ProxyOptions | null | undefined
): ProxyOptions | null | undefined {
	if (over === null) return null
	if (over === undefined) return base ?? undefined
	if (base == null) return over
	return { ...base, ...over }
}

function mergeOpts(base: Partial<RequestOptions>, over: Partial<NormalizedRequestOptions>): NormalizedRequestOptions {
	const out = { ...base, ...over } as unknown as NormalizedRequestOptions
	out.headers = { ...headersToRecord(base.headers), ...headersToRecord(over.headers) }
	const proxy = mergeProxy(base.proxy, over.proxy)
	if (proxy === undefined) delete out.proxy
	else out.proxy = proxy
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
	options: 'OPTIONS'
} as const

// Shortcuts dispatch through `dispatch`, so a defaults-derived entry point keeps merging
// its defaults when called as `.get(...)` / `.post(...)`.
function withShortcuts<T extends object>(fn: T, dispatch: InternalDispatch): T {
	const shortcuts: Record<string, MethodFn> = {}
	for (const [name, verb] of Object.entries(SHORTCUTS)) shortcuts[name] = method(verb, dispatch)
	return Object.assign(fn, shortcuts)
}

const request = withShortcuts(
	Object.assign(requestImpl, {
		defaults: (defaults: Partial<RequestOptions> = {}) => {
			assertNoRemovedInitOptions(defaults)
			const dispatch: InternalDispatch = (opts) => performWithRetry(mergeOpts(defaults, opts))
			const wrapped: MethodFn = (input, init) => dispatch(inputToOptions(input, init))
			return withShortcuts(
				Object.assign(wrapped, {
					defaults: (more?: Partial<RequestOptions>) =>
						request.defaults(
							toPublicOptions(mergeOpts(defaults, (more || {}) as Partial<NormalizedRequestOptions>))
						),
					jar: request.jar
				}),
				dispatch
			)
		},
		jar: () => new Jar(),
		HellojsError
	}),
	performWithRetry
) as unknown as RequestFn

export default request
