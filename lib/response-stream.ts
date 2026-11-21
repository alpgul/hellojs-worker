// Shared progressive-response hand-off.
//
// Every transport (H1, H2, H3) reaches the same point: headers are known, body bytes will
// arrive over time, and the caller expects a fetch `Response` whose `body` is a web
// `ReadableStream`. The details that must not drift between transports live here:
//
//   - decoding (gzip / br / deflate / zstd) with errors propagated end to end
//   - backpressure signalling so the source can pause
//   - abort / cancel teardown (`signal` is the only deadline; browsers have no body-idle timer)

import { PassThrough, pipeline, type Readable, type Transform } from 'node:stream'
import * as zlib from 'node:zlib'

import { HellojsError, type ErrorCode } from './errors.ts'
import { statusTextFor } from './status-text.ts'
import { buildResponse, nodeToWebStream } from './web-response.ts'

type HeaderRecord = Record<string, string | string[]>

interface ProgressiveStreamOptions {
	status: number
	statusText?: string
	headers: HeaderRecord
	url: string
	redirected: boolean
	method: string
	signal?: AbortSignal | null
	/** Fallback code when the source itself errors without a stable Hellojs code. */
	errorCode: ErrorCode | string
	/** Tear down the transport side (close socket, RST stream, release pool slot). */
	onCancel?: (reason: unknown) => void
	/** True when the consumer is behind; false once it drains. */
	onBackpressure?: (paused: boolean) => void
	onFirstByte?: () => void
	/** Wire bytes written, fired when the source signals end. */
	onEnd?: (bytes: number) => void
	onError?: (error: unknown, bytes: number) => void
}

export interface ProgressiveStream {
	/** The fetch `Response` handed to the caller. */
	readonly result: Response
	/** Write wire bytes. Returns false when the consumer is applying backpressure. */
	write(chunk: Buffer): boolean
	/** Source reached its natural end. */
	end(): void
	/** Source failed (protocol, decoder, transport). */
	fail(error: unknown): void
	/** Bytes currently buffered between the wire and the consumer. */
	bufferedBytes(): number
}

function abortReason(signal?: AbortSignal | null): unknown {
	const reason = signal?.reason
	return reason !== undefined ? reason : new DOMException('The operation was aborted.', 'AbortError')
}

function onAbort(signal: AbortSignal | null | undefined, handler: () => void): () => void {
	if (!signal) return () => {}
	if (signal.aborted) {
		handler()
		return () => {}
	}
	signal.addEventListener('abort', handler, { once: true })
	return () => signal.removeEventListener('abort', handler)
}

/** Streaming counterpart of the sync decoder: `null` means "no decoding needed". */
function decompressStreamForEncoding(encoding: string): Transform | null {
	const e = (encoding || '').toLowerCase()
	if (!e || e === 'identity') return null
	if (e.includes('gzip')) return zlib.createGunzip()
	if (e.includes('br')) return zlib.createBrotliDecompress()
	if (e.includes('deflate')) return zlib.createInflate()
	if (e.includes('zstd')) return zlib.createZstdDecompress()
	return null
}

/**
 * Start a progressive response for one request. The transport keeps feeding `write()`
 * and finishes with `end()`; redirect responses are buffered by the caller and never
 * reach this helper.
 */
export function startProgressiveResponse(opts: ProgressiveStreamOptions): ProgressiveStream {
	const pass = new PassThrough()
	// No body means no decoder: a gzip/brotli stream over zero bytes reports a spurious
	// truncated-input error. The buffered path has the same guard.
	const emptyBody =
		opts.method === 'HEAD' ||
		opts.status === 204 ||
		opts.status === 205 ||
		opts.status === 304 ||
		headerValue(opts.headers['content-length']) === '0'
	const decoder = emptyBody ? null : decompressStreamForEncoding(headerValue(opts.headers['content-encoding']) || '')
	const source: Readable = decoder ?? pass

	let finished = false
	let canceled = false
	let firstByte = false
	let bytes = 0
	let pausedNotified = false
	let removeAbort = () => {}

	const cleanup = () => {
		removeAbort()
		removeAbort = () => {}
	}

	if (decoder) {
		pipeline(pass, decoder, (error) => {
			if (error && !finished && !canceled) {
				fail(new HellojsError(error.message, opts.errorCode, error))
			}
		})
	}

	const destroySource = (error: unknown) => {
		const err = error instanceof Error ? error : new Error(String(error))
		if (!pass.destroyed) pass.destroy(err)
		if (decoder && !decoder.destroyed) decoder.destroy(err)
	}

	const fail = (error: unknown): void => {
		if (finished || canceled) return
		finished = true
		cleanup()
		destroySource(error)
		opts.onError?.(error, bytes)
		opts.onCancel?.(error)
	}

	const cancel = (reason: unknown): void => {
		if (finished || canceled) return
		canceled = true
		finished = true
		cleanup()
		destroySource(reason)
		opts.onCancel?.(reason)
	}

	// The caller always gets a fetch `Response` over a web `ReadableStream`; redirect
	// responses are buffered by the transport before reaching this helper.
	const web = nodeToWebStream(source, (reason) => cancel(reason))
	const result = buildResponse({
		status: opts.status,
		statusText: opts.statusText ?? statusTextFor(opts.status),
		headers: opts.headers,
		body: web,
		url: opts.url,
		redirected: opts.redirected,
		method: opts.method
	})

	// Destroying the source must still close the transport instead of leaving a pooled
	// socket pinned.
	source.once('close', () => {
		if (!finished && !canceled) cancel(new Error('response body closed'))
	})
	// `destroy(error)` emits 'error'. The bridge listens, but this additive listener makes
	// sure an early teardown can never crash the process before the consumer attaches.
	source.on('error', () => {})

	removeAbort = onAbort(opts.signal, () => fail(abortReason(opts.signal)))

	return {
		result,
		write(chunk: Buffer): boolean {
			if (finished || canceled || chunk.length === 0) return !finished && !canceled
			if (!firstByte) {
				firstByte = true
				opts.onFirstByte?.()
			}
			bytes += chunk.length
			const ok = pass.write(chunk)
			if (!ok && !pausedNotified) {
				pausedNotified = true
				opts.onBackpressure?.(true)
				pass.once('drain', () => {
					pausedNotified = false
					if (!finished && !canceled) opts.onBackpressure?.(false)
				})
			}
			return ok
		},
		end(): void {
			if (finished || canceled) return
			finished = true
			cleanup()
			opts.onEnd?.(bytes)
			if (decoder && bytes === 0) {
				// A decoder over zero bytes reports a truncated stream. The response is
				// legitimately empty (e.g. chunked with no chunks), so close without
				// running it rather than surfacing a bogus EDECOMPRESS.
				if (!pass.destroyed) pass.destroy()
				if (!decoder.destroyed) decoder.destroy()
				return
			}
			pass.end()
		},
		fail,
		bufferedBytes(): number {
			return (
				pass.readableLength +
				pass.writableLength +
				(decoder?.readableLength ?? 0) +
				(decoder?.writableLength ?? 0)
			)
		}
	}
}

function headerValue(value: string | string[] | undefined): string | undefined {
	return Array.isArray(value) ? value[0] : value
}
