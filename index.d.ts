// TypeScript declarations for @unreleased/hellojs.
//
// Public surface: a request.js-shape `request()` function plus the lower-level
// `TLS` export.

/// <reference types="node" />

import { EventEmitter } from 'node:events'

import type { Duplex } from 'node:stream'

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
	methods?: string[]
	statusCodes?: number[]
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
	method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS' | string
	headers?: Record<string, string | string[]>
	body?: string | Buffer | Uint8Array | NodeJS.ReadableStream | null
	json?: boolean | unknown
	form?: Record<string, string | number>
	qs?: Record<string, string | number | (string | number)[]>
	jar?: CookieJar | null
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
	/** Opt in to HTTP/3 (QUIC) for this request. Off unless explicitly `true`. */
	h3?: boolean
	/** When true, resolve as soon as headers arrive and expose the body as a Node Readable. */
	stream?: boolean
	/** Profile name, or an inline profile object shaped like lib/profiles/types.ts `Profile`. */
	profile?: string | Record<string, unknown>
}

export interface Response<TBody = unknown> {
	statusCode: number
	status: number
	headers: Record<string, string | string[]>
	body: TBody
	/** Wire bytes as read; with `stream: true` this is the same Readable as `body`. */
	rawBody: TBody | Buffer
}

export type HellojsErrorCategory =
	| 'usage' | 'transport' | 'tls' | 'protocol' | 'http' | 'body' | 'timeout'

export type HellojsErrorCode =
	| 'EBADOPTS' | 'EBADARG' | 'EHEADERFIXED'
	| 'ECONNREFUSED' | 'ECONNRESET' | 'ENOTFOUND' | 'EPROXY'
	| 'ETLS_ALERT' | 'ETLS_HANDSHAKE' | 'ETLS_CERT_VERIFY' | 'ETLS_VERSION'
	| 'EH2STREAM' | 'EH2GOAWAY' | 'EH3STREAM' | 'EH3CONN' | 'EPROTO'
	| 'EHTTP' | 'EBADRESP' | 'EDECOMPRESS'
	| 'EBODYSTREAM'
	| 'ETIMEDOUT'

export class HellojsError extends Error {
	code: HellojsErrorCode | string
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

	/** Request lifecycle events — see [Observability](README.md#observability). */
	observability: Observability

	/** Fingerprint profile registry. */
	profiles: ProfileRegistry

	/** QUIC's UDP seam — see [UDP transport](README.md#udp-transport). */
	udp: UdpTransport
}

declare const request: RequestFn
export default request

export interface ProfileRegistry {
	get(name?: string): unknown
	list(): string[]
	register(name: string, profile: unknown): void
	registerFromPeet(name: string, peet: unknown): unknown
	fromPeet(peet: unknown, opts?: unknown): unknown
	profiles: Record<string, unknown>
}

export interface Observability {
	safeEmit(event: string, payload?: unknown): void
	on(event: string, listener: (...args: unknown[]) => void): unknown
	off(event: string, listener: (...args: unknown[]) => void): unknown
}

export const observability: Observability
export const profiles: ProfileRegistry
export const udp: UdpTransport
export function setTrustedRoots(pems: string[]): void

export interface TLSOptions {
	verifyTLS?: boolean
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
	alpn: 'h2' | 'http/1.1' | null
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
	on(event: 'error', listener: (err: Error) => void): this
}
