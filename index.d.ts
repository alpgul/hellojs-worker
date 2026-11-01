// TypeScript declarations for @unreleased/hellojs.
//
// Public surface: a request.js-shape `request()` function plus the lower-level
// `TLS` export.

/// <reference types="node" />

import { EventEmitter } from 'node:events'

import type { Duplex } from 'node:stream'

/**
 * Methods registered with IANA (RFC 9110 §9, RFC 5789). The protocol allows extension
 * methods, so any token is accepted at runtime — the literals exist for autocomplete,
 * not to close the set.
 */
export type RegisteredHttpMethod =
	| 'GET' | 'HEAD' | 'POST' | 'PUT' | 'DELETE' | 'CONNECT' | 'OPTIONS' | 'TRACE' | 'PATCH'

/** The method may be given in either case; `request()` uppercases it before use. */
export type HttpMethod = RegisteredHttpMethod | Lowercase<RegisteredHttpMethod> | (string & {})

/** Status codes registered with IANA. Unknown codes are accepted (servers invent them). */
export type RegisteredHttpStatusCode =
	| 100 | 101 | 102 | 103
	| 200 | 201 | 202 | 203 | 204 | 205 | 206 | 207 | 208 | 226
	| 300 | 301 | 302 | 303 | 304 | 305 | 307 | 308
	| 400 | 401 | 402 | 403 | 404 | 405 | 406 | 407 | 408 | 409
	| 410 | 411 | 412 | 413 | 414 | 415 | 416 | 417 | 418 | 421
	| 422 | 423 | 424 | 425 | 426 | 428 | 429 | 431 | 451
	| 500 | 501 | 502 | 503 | 504 | 505 | 506 | 507 | 508 | 509 | 510 | 511

export type HttpStatusCode = RegisteredHttpStatusCode | (number & {})

/**
 * Redirect handling, as the Fetch standard defines the mode. Only the two modes this client
 * implements are accepted: `'follow'` (default) follows 3xx with a `Location` up to
 * `maxRedirects`; `'manual'` stops and returns the 3xx response itself. Fetch's `'error'` is
 * deliberately not offered until the client rejects on it.
 */
export type RedirectMode = 'follow' | 'manual'

/** ALPN identifiers this client can negotiate. */
export type AlpnProtocol = 'h2' | 'http/1.1'

/** RFC 8259 JSON — the shape `json` and a serialized `body` are restricted to. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

/** A percent-encoded `key=value` pair set, as `application/x-www-form-urlencoded` defines it. */
export type QueryValue = string | number | ReadonlyArray<string | number>
export type QueryParams = Record<string, QueryValue>

/**
 * Header field names registered for HTTP requests (RFC 9110 + the IANA registry, plus the
 * `sec-*` set the fingerprint profiles send). Field names are case-insensitive; the library
 * lowercases them on the wire.
 */
export type KnownHttpRequestHeader =
	| 'accept' | 'accept-charset' | 'accept-encoding' | 'accept-language' | 'accept-ranges'
	| 'authorization' | 'cache-control' | 'connection' | 'content-encoding' | 'content-language'
	| 'content-length' | 'content-location' | 'content-range' | 'content-type' | 'cookie'
	| 'date' | 'expect' | 'forwarded' | 'from' | 'host' | 'if-match' | 'if-modified-since'
	| 'if-none-match' | 'if-range' | 'if-unmodified-since' | 'max-forwards' | 'pragma'
	| 'proxy-authorization' | 'range' | 'referer' | 'te' | 'trailer' | 'transfer-encoding'
	| 'upgrade' | 'upgrade-insecure-requests' | 'user-agent' | 'via' | 'warning'
	| 'x-forwarded-for' | 'x-forwarded-host'
	| 'sec-ch-ua' | 'sec-ch-ua-mobile' | 'sec-ch-ua-platform'
	| 'sec-fetch-dest' | 'sec-fetch-mode' | 'sec-fetch-site' | 'sec-fetch-user'
	| 'sec-websocket-accept' | 'sec-websocket-extensions' | 'sec-websocket-key' | 'sec-websocket-version'

/** Known names autocomplete; any other field name is allowed, since HTTP defines extensions. */
export type HttpRequestHeaders =
	& { [name: string]: string | string[] }
	& Partial<Record<KnownHttpRequestHeader, string | string[]>>

/** Profiles this build ships with. `default` aliases `chrome147-mac`; `register()` adds more. */
export type BuiltInProfileName = 'default' | 'chrome147-mac' | 'firefox147'
export type ProfileName = BuiltInProfileName | (string & {})

export interface CookieJar {
	getCookieString(requestUrlOrHost: string): string
	setCookie(setCookieHeader: string | string[], requestUrlOrHost: string): void
}

/** `request.jar()`'s own jar: the CookieJar seam plus the maintenance hooks it exposes. */
export interface Jar extends CookieJar {
	/** Narrow which hosts count as public suffixes; `null` restores the bundled list. */
	setPublicSuffixList(list: Set<string> | ((host: string) => boolean) | null): void
	/** Drop expired cookies — call periodically on a long-lived jar. */
	gc(): void
}

export interface RetryPolicy {
	limit?: number
	methods?: HttpMethod[]
	statusCodes?: HttpStatusCode[]
	baseDelayMs?: number
}

export interface PerPhaseTimeouts {
	connect?: number
	tlsHandshake?: number
	response?: number
}

export interface RequestOptions {
	url?: string
	uri?: string
	method?: HttpMethod
	headers?: HttpRequestHeaders
	body?: string | Buffer | Uint8Array | NodeJS.ReadableStream | JsonValue | null
	/** `true` parses the response as JSON; an RFC 8259 value is serialized and sent as the body. */
	json?: boolean | JsonValue
	form?: QueryParams
	qs?: QueryParams
	jar?: CookieJar | null
	gzip?: boolean
	redirect?: RedirectMode
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
	 * (default `false`). Resumed handshakes skip the certificate flight, but add
	 * `pre_shared_key` to the ClientHello, so JA3/JA4 differ from a fresh handshake.
	 */
	resume?: boolean
	/** Opt in to HTTP/3 (QUIC) for this request. Off unless explicitly `true`; QUIC is tried first with a bounded TCP fallback. */
	h3?: boolean
	/** When true, resolve as soon as headers arrive and expose the body as a Node Readable. */
	stream?: boolean
	/** Profile name, or an inline profile object shaped like lib/profiles/types.ts `Profile`. */
	profile?: ProfileName | Record<string, unknown>
}

export interface Response<TBody = unknown> {
	statusCode: HttpStatusCode
	status: HttpStatusCode
	headers: Record<string, string | string[]>
	body: TBody
	/** Wire bytes as read; with `stream: true` this is the same Readable as `body`. */
	rawBody: TBody | Buffer
}

export type HellojsErrorCategory =
	| 'usage' | 'transport' | 'tls' | 'protocol' | 'http' | 'body' | 'timeout'

/**
 * The stable taxonomy in `lib/errors.ts`. `code` is typed with a `(string & {})` escape so
 * a newer runtime can introduce codes without breaking compilation, while the known set still
 * autocompletes and narrows.
 */
export type HellojsErrorCode =
	| 'EBADOPTS' | 'EBADARG' | 'EHEADERFIXED'
	| 'ECONNREFUSED' | 'ECONNRESET' | 'ENOTFOUND' | 'EPROXY' | 'EUDPUNAVAILABLE'
	| 'ETLS_ALERT' | 'ETLS_HANDSHAKE' | 'ETLS_CERT_VERIFY' | 'ETLS_VERSION'
	| 'ECERTPARSE' | 'ECERTVALIDATION' | 'ECERTVERIFY' | 'ETLSPSK' | 'ETLS12' | 'EHRR'
	| 'EH2STREAM' | 'EH2GOAWAY' | 'EH2COMPRESS' | 'EH2KEEPALIVE'
	| 'EH3STREAM' | 'EH3CONN' | 'EH3PARSE' | 'EPROTO'
	| 'EHTTP' | 'EBADRESP' | 'EDECOMPRESS'
	| 'EBODYSTREAM'
	| 'ETIMEDOUT'

/**
 * Codes the low-level `TLS` class puts on the `Error` it emits for its `'error'` event. Every
 * one of them is also a `HellojsErrorCode`, so `request()` preserves the specific diagnosis
 * instead of collapsing it to `EPROTO`.
 */
export type TLSErrorCode =
	| 'ETLS_ALERT' | 'ETLS_HANDSHAKE' | 'ETLS_VERSION'
	| 'ETLS_CERT_VERIFY' | 'ECERTPARSE' | 'ECERTVALIDATION' | 'ECERTVERIFY'
	| 'ETLSPSK' | 'ETLS12' | 'EHRR'
	| 'ECONNRESET' | 'ECONNREFUSED' | 'ETIMEDOUT'

export interface TLSError extends Error {
	code?: TLSErrorCode | (string & {})
}

export class HellojsError extends Error {
	code: HellojsErrorCode | (string & {})
	category: HellojsErrorCategory
	cause?: unknown
	response?: Response
}

export type Callback<TBody = unknown> = (
	err: HellojsError | null,
	res: Response<TBody> | undefined,
	body: TBody | undefined,
) => void

// Both the root export and the `defaults()`-derived entry point (and every shortcut) resolve
// the same way: the full Response when `resolveWithFullResponse: true` is passed as a literal,
// otherwise the body — a string, the raw Buffer, or the parsed value for `json: true`.
interface Invokable {
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

/** What `request.defaults(...)` returns: the callable, its shortcuts and a further `defaults()`. */
export interface DefaultsFn extends Invokable, Shortcuts {
	defaults(more?: Partial<RequestOptions>): DefaultsFn
}

export interface RequestFn extends Invokable, Shortcuts {
	defaults(defaults?: Partial<RequestOptions>): DefaultsFn

	HellojsError: typeof HellojsError

	/** Exported for advanced users. */
	TLS: typeof TLS

	/** Install a Mozilla/NSS PEM bundle when the runtime has no built-in roots. */
	setTrustedRoots(pems: string[]): void

	/** Drop every cached TLS 1.3 session ticket (used only with `resume: true`). */
	clearSessionTickets(): void

	/** Request lifecycle events — see [Observability](README.md#observability). */
	observability: Observability

	/** Fingerprint profile registry. */
	profiles: ProfileRegistry

	/** QUIC's UDP seam — see [UDP transport](README.md#udp-transport). */
	udp: UdpTransport
}

declare const request: RequestFn
export default request

/** Lifecycle events the library emits — see README → Observability. */
export type ObservabilityEvent =
	| 'request:start'
	| 'request:headersSent'
	| 'request:firstByte'
	| 'request:end'
	| 'request:error'

export interface ProfileRegistry {
	get(name?: ProfileName): unknown
	list(): string[]
	register(name: string, profile: unknown): void
	registerFromPeet(name: string, peet: unknown): unknown
	fromPeet(peet: unknown, opts?: unknown): unknown
	profiles: Record<string, unknown>
}

export interface Observability {
	safeEmit(event: ObservabilityEvent, payload?: unknown): void
	on(event: ObservabilityEvent, listener: (...args: unknown[]) => void): unknown
	off(event: ObservabilityEvent, listener: (...args: unknown[]) => void): unknown
}

export const observability: Observability
export const profiles: ProfileRegistry
export const udp: UdpTransport
export function setTrustedRoots(pems: string[]): void
export function clearSessionTickets(): void

export interface TLSOptions {
	verifyTLS?: boolean
	resume?: boolean
}

/** The subset of `node:dgram.Socket` that the QUIC client depends on. */
export interface UdpSocket {
	on(event: 'message', listener: (buf: Buffer, rinfo: { address: string; family: string; port: number }) => void): unknown
	on(event: 'error', listener: (err: Error) => void): unknown
	bind(port: number, callback: () => void): unknown
	send(buf: Buffer, port: number, host: string, callback?: () => void): unknown
	close(): unknown
	readonly destroyed: boolean
}

export interface UdpTransport {
	/** Open a datagram socket; throws `code === 'EUDPUNAVAILABLE'` when no provider is set. */
	createSocket(type?: 'udp4' | 'udp6'): UdpSocket
	/** Install a provider, or pass `null` to take HTTP/3 out of reach (requests fall back to TCP). */
	setUdpProvider(factory: ((type: 'udp4' | 'udp6') => UdpSocket) | null): void
	udpAvailable(): boolean
}

export class TLS extends EventEmitter {
	constructor(host: string, port?: number, proxy?: string | null, options?: TLSOptions)
	host: string
	port: number
	alpn: AlpnProtocol | null
	h2Transport: Duplex | null
	h2Session: unknown | null
	server: {
		legacyVersion: number
		sessionId: Buffer
		cipherSuite: number
		selVersion: number | null
		serverKShare?: { group: number; key: Buffer }
	} | null
	connect(): Promise<void>

	on(event: 'ready', listener: () => void): this
	on(event: 'ready-http1', listener: () => void): this
	on(event: 'error', listener: (err: TLSError) => void): this
}
