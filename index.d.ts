// TypeScript declarations for @unreleased/hellojs.
//
// Public surface: a request.js-shape `request()` function plus the lower-level
// `TLS` export.

/// <reference types="node" />

import { EventEmitter } from 'node:events'
import { Duplex } from 'node:stream'

export interface CookieJar {
	getCookieString(host: string): string
	setCookie(setCookieHeader: string | string[], host: string): void
}

export interface RetryPolicy {
	limit?: number
	methods?: string[]
	statusCodes?: number[]
	baseDelay?: number
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
	jar?: CookieJar | true
	gzip?: boolean
	followRedirect?: boolean
	maxRedirects?: number
	timeout?: number
	timeouts?: PerPhaseTimeouts
	proxy?: string
	resolveWithFullResponse?: boolean
	simple?: boolean
	retry?: RetryPolicy

	/** TLS-only: turn on cert chain validation (default `true`). */
	verifyTLS?: boolean
	/** Opt in to HTTP/3 (QUIC) for this request. Off unless explicitly `true`. */
	h3?: boolean
	/** When true, resolve as soon as headers arrive and expose the body as a Node Readable. */
	stream?: boolean
}

export interface Response<TBody = unknown> {
	statusCode: number
	status: number
	headers: Record<string, string | string[]>
	body: TBody
	rawBody: Buffer
}

export type HellojsErrorCategory =
	| 'usage' | 'transport' | 'tls' | 'protocol' | 'http' | 'body' | 'timeout'

export type HellojsErrorCode =
	| 'EBADOPTS' | 'EBADARG'
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

export interface RequestFn {
	<TBody = unknown>(opts: RequestOptions, cb?: Callback<TBody>): Promise<Response<TBody> | TBody>
	(url: string, cb?: Callback): Promise<unknown>
	get<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	post<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	put<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	del<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	delete<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	patch<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	head<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>
	options<T = unknown>(opts: RequestOptions | string, cb?: Callback<T>): Promise<Response<T> | T>

	defaults(defaults: Partial<RequestOptions>): RequestFn
	jar(): CookieJar
	HellojsError: typeof HellojsError

	/** Exported for advanced users. */
	TLS: typeof TLS

	/** QUIC's UDP seam — see [UDP transport](README.md#udp-transport). */
	udp: UdpTransport
}

declare const request: RequestFn
export default request
export = request

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
