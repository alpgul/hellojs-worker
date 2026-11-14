// Fetch-compatible response construction.
//
// `request()` resolves a real WHATWG `Response`, exactly like `fetch()`. The transports
// hand this module either a fully buffered body or a progressive source, and it produces
// one object regardless of ALPN (H1/H2/H3) and regardless of runtime (Node or workerd):
//
//   - headers move from the internal `Record<string, string | string[]>` into `Headers`
//   - `body` is a `ReadableStream<Uint8Array>` (or `null` for bodies HTTP forbids)
//   - `url`, `redirected` and `type` are filled in because the `Response` constructor has
//     no way to set them (they are normally set by the fetch network layer)
//   - a Node `Readable` can be bridged to the web stream the Response needs

import { Readable } from 'node:stream'

import { statusTextFor } from './status-text.ts'

// RFC 9110: these statuses never carry a body, and neither does a HEAD response.
const EMPTY_BODY_STATUS = new Set([101, 204, 205, 304])

export interface ResponseInput {
	status: number
	statusText?: string
	headers: Record<string, string | string[]>
	body: Uint8Array | ReadableStream<Uint8Array> | null
	url?: string
	redirected?: boolean
	method?: string
}

/** Narrow a header record into a `Headers` instance, preserving repeated fields. Pseudo-headers (`:status` and friends, present on H2/H3 responses) are skipped because the Fetch `Headers` API only accepts field names. */
export function toHeaders(input: Record<string, string | string[]>): Headers {
	const headers = new Headers()
	for (const [name, value] of Object.entries(input)) {
		if (name.startsWith(':')) continue
		if (Array.isArray(value)) {
			for (const item of value) headers.append(name, item)
		} else if (value !== undefined && value !== null) {
			headers.append(name, String(value))
		}
	}
	return headers
}

// The Response constructor gives no way to set these; fetch sets them from the network
// response. Defining an own property shadows the prototype getter without changing the
// body semantics. Wrapped in try/catch because a non-extensible implementation would
// otherwise turn a cosmetic gap into a request failure.
function defineOwn(target: object, key: string, value: unknown): void {
	try {
		Object.defineProperty(target, key, { value, enumerable: false, configurable: true })
	} catch {
		/* keep the constructor's value */
	}
}

/** Build a fetch-compatible `Response` from the transports' internal result shape. */
export function buildResponse(input: ResponseInput): Response {
	const status = input.status >= 200 && input.status <= 599 ? input.status : 200
	const emptyBody = input.method === 'HEAD' || EMPTY_BODY_STATUS.has(status)
	const body = emptyBody ? null : input.body
	const res = new Response(body, {
		status,
		statusText: input.statusText ?? statusTextFor(status),
		headers: toHeaders(input.headers),
	})
	defineOwn(res, 'url', input.url ?? '')
	defineOwn(res, 'redirected', input.redirected === true)
	defineOwn(res, 'type', 'basic')
	return res
}

// A push-based web stream: transports write as bytes arrive, the Response reads them.
// Callers that can pause their source (H1) may inspect `closed`/`desiredSize` themselves;
// the controller queues when they cannot (H2/H3, where flow control is owned by the layer).
export interface PushStream {
	readonly stream: ReadableStream<Uint8Array>
	readonly closed: boolean
	write(chunk: Uint8Array | Buffer): boolean
	end(): void
	fail(error: unknown): void
}

export function createPushStream(): PushStream {
	let controller!: ReadableStreamDefaultController<Uint8Array>
	let closed = false
	const stream = new ReadableStream<Uint8Array>({
		start(c) {
			controller = c
		},
		cancel() {
			closed = true
		},
	})
	return {
		stream,
		get closed() {
			return closed
		},
		write(chunk) {
			if (closed) return false
			try {
				controller.enqueue(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk))
			} catch {
				closed = true
				return false
			}
			return (controller.desiredSize ?? 1) > 0
		},
		end() {
			if (closed) return
			closed = true
			try { controller.close() } catch { /* already closed */ }
		},
		fail(error) {
			if (closed) return
			closed = true
			try { controller.error(error) } catch { /* already closed */ }
		},
	}
}

/**
 * Bridge a Node `Readable` (the shape every transport already produces, including the
 * decompression transforms) to the `ReadableStream` a `Response` needs. Pausing the
 * source when the consumer stops reading gives backpressure end to end; `cancel` tears
 * the source down and runs the caller's cleanup (closing the request/connection).
 */
export function nodeToWebStream(
	source: Readable,
	onCancel?: (reason: unknown) => void,
): ReadableStream<Uint8Array> {
	let controller!: ReadableStreamDefaultController<Uint8Array>
	let closed = false

	const finish = () => {
		if (closed) return
		closed = true
		try { controller.close() } catch { /* canceled */ }
	}
	const fail = (error: unknown) => {
		if (closed) return
		closed = true
		try { controller.error(error) } catch { /* canceled */ }
	}

	return new ReadableStream<Uint8Array>({
		start(c) {
			controller = c
			source.on('data', (chunk: Buffer | string) => {
				if (closed) return
				try {
					controller.enqueue(typeof chunk === 'string' ? new TextEncoder().encode(chunk) : new Uint8Array(chunk))
				} catch {
					closed = true
					return
				}
				if ((controller.desiredSize ?? 1) <= 0) {
					try { source.pause() } catch { /* not a Node stream */ }
				}
			})
			source.on('end', finish)
			source.on('close', finish)
			source.on('error', fail)
		},
		pull() {
			try { source.resume() } catch { /* not a Node stream */ }
		},
		cancel(reason) {
			closed = true
			try { source.destroy() } catch { /* already closed */ }
			onCancel?.(reason)
		},
	})
}

/**
 * Convert a web `ReadableStream` request body into the Node `Readable` the transport
 * writers consume. `Readable.fromWeb` exists in Node and in workerd's nodejs_compat, but
 * the manual reader below keeps the client working on polyfills that lack it.
 */
export function webToNodeStream(source: ReadableStream<Uint8Array>): Readable {
	const fromWeb = (Readable as unknown as { fromWeb?: (s: ReadableStream<Uint8Array>) => Readable }).fromWeb
	if (typeof fromWeb === 'function') return fromWeb.call(Readable, source)

	const reader = source.getReader()
	return new Readable({
		async read() {
			try {
				const { done, value } = await reader.read()
				if (done) { this.push(null); return }
				this.push(Buffer.from(value))
			} catch (error) {
				this.destroy(error as Error)
			}
		},
		destroy(error, callback) {
			reader.cancel(error).catch(() => { /* already closed */ })
			callback(error)
		},
	})
}

/** True for anything that is a web `ReadableStream`, without depending on the global. */
export function isWebReadableStream(value: unknown): value is ReadableStream<Uint8Array> {
	return !!value && typeof value === 'object' && typeof (value as { getReader?: unknown }).getReader === 'function'
}
