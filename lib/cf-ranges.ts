// Cloudflare's published IP ranges, with a bundled fallback.
//
// The list is public and stable but not immutable: Cloudflare has added prefixes over the years.
// Fetching it daily keeps routing correct without a build step, and the module-scope cache keeps a
// warm isolate from paying for it on every request. Two subrequests per isolate per day is the
// whole cost.
//
// Resolution order is live fetch, then the bundled snapshot. This function never throws and never
// returns an empty set: an unreachable list endpoint, a non-200, an HTML error page or a range
// list that parsed to nothing all fall back to the snapshot. Routing decisions depend on this,
// so "unknown" is not an allowed answer.

import { CF_RANGES_SNAPSHOT_V4, CF_RANGES_SNAPSHOT_V6 } from './cf-ranges.snapshot.ts'
import { parseCidrList } from './cidr.ts'

import type { Cidr } from './cidr.ts'

const LIST_V4 = 'https://www.cloudflare.com/ips-v4'
const LIST_V6 = 'https://www.cloudflare.com/ips-v6'

const DEFAULT_TTL_MS = 86_400_000
/** A broken feed is retried after this backoff instead of hammering the endpoint. */
const FAILURE_TTL_MS = 5 * 60_000
/** Fewer prefixes than this means the feed is broken, not that Cloudflare shrank. */
const MIN_PLAUSIBLE_PREFIXES = 8
const MIN_PLAUSIBLE_V4 = 4
const MIN_PLAUSIBLE_V6 = 1

interface CfRangesOptions {
	/** How long a successful fetch is reused. Defaults to one day. */
	ttlMs?: number
	/** Injection seam for tests and for runtimes with a non-global fetch. */
	fetchImpl?: typeof fetch
	/** Bypass the cache and fetch again. */
	force?: boolean
	/** Abort the wait for a refresh. The shared in-flight fetch is not cancelled. */
	signal?: AbortSignal | null
}

let cached: { ranges: readonly Cidr[]; expiresAt: number } | null = null
let inflight: Promise<readonly Cidr[]> | null = null
let snapshot: readonly Cidr[] | null = null
let generation = 0

/** Parse the two feeds into one list. Non-CIDR tokens are dropped by `parseCidrList`. */
function parseCfRanges(v4Text: string, v6Text: string): Cidr[] {
	const v4 = parseCidrList(v4Text).filter((cidr) => cidr.family === 4)
	const v6 = parseCidrList(v6Text).filter((cidr) => cidr.family === 6)
	return [...v4, ...v6]
}

function snapshotRanges(): readonly Cidr[] {
	snapshot ??= parseCfRanges(CF_RANGES_SNAPSHOT_V4, CF_RANGES_SNAPSHOT_V6)
	return snapshot
}

function unrefTimer(timer: ReturnType<typeof setTimeout>): void {
	;(timer as unknown as { unref?: () => void }).unref?.()
}

async function fetchList(url: string, fetchImpl: typeof fetch): Promise<string> {
	const controller = new AbortController()
	const timer = setTimeout(() => controller.abort(new Error('cloudflare ip list fetch timed out')), 5_000)
	unrefTimer(timer)
	try {
		const res = await fetchImpl(url, { headers: { accept: 'text/plain' }, signal: controller.signal })
		if (!res.ok) {
			try {
				await res.body?.cancel()
			} catch {
				/* ignore body cancel failure */
			}
			throw new Error(`${url} returned ${res.status}`)
		}
		return await res.text()
	} finally {
		clearTimeout(timer)
	}
}

async function loadRanges(fetchImpl: typeof fetch): Promise<readonly Cidr[]> {
	const [v4Text, v6Text] = await Promise.all([fetchList(LIST_V4, fetchImpl), fetchList(LIST_V6, fetchImpl)])
	const v4 = parseCidrList(v4Text).filter((cidr) => cidr.family === 4)
	const v6 = parseCidrList(v6Text).filter((cidr) => cidr.family === 6)
	if (v4.length < MIN_PLAUSIBLE_V4 || v6.length < MIN_PLAUSIBLE_V6) {
		throw new Error('cloudflare ip list parsed to too few prefixes')
	}
	const ranges = [...v4, ...v6]
	if (ranges.length < MIN_PLAUSIBLE_PREFIXES) throw new Error('cloudflare ip list parsed to too few prefixes')
	return ranges
}

const INFLIGHT_WAIT_MS = 6_000

function waitForInflight(
	inflightPromise: Promise<readonly Cidr[]>,
	signal?: AbortSignal | null
): Promise<readonly Cidr[]> {
	if (!signal) {
		let timer: ReturnType<typeof setTimeout> | undefined
		return Promise.race([
			inflightPromise,
			new Promise<readonly Cidr[]>((resolve) => {
				timer = setTimeout(() => resolve(cached?.ranges ?? snapshotRanges()), INFLIGHT_WAIT_MS)
				unrefTimer(timer)
			})
		]).finally(() => {
			if (timer) clearTimeout(timer)
		})
	}
	if (signal.aborted) return Promise.reject(signal.reason ?? new Error('aborted'))
	return new Promise<readonly Cidr[]>((resolve, reject) => {
		const timer = setTimeout(() => {
			signal.removeEventListener('abort', onAbort)
			resolve(cached?.ranges ?? snapshotRanges())
		}, INFLIGHT_WAIT_MS)
		unrefTimer(timer)
		const onAbort = () => {
			clearTimeout(timer)
			signal.removeEventListener('abort', onAbort)
			reject(signal.reason ?? new Error('aborted'))
		}
		signal.addEventListener('abort', onAbort, { once: true })
		inflightPromise.then(
			(value) => {
				clearTimeout(timer)
				signal.removeEventListener('abort', onAbort)
				resolve(value)
			},
			(err) => {
				clearTimeout(timer)
				signal.removeEventListener('abort', onAbort)
				reject(err)
			}
		)
	})
}

/**
 * The Cloudflare ranges to test an address against. Cached for `ttlMs`; falls back to the bundled
 * snapshot on any failure, so the returned list is always usable. A failed refresh is cached
 * briefly to avoid hammering the endpoints.
 */
async function getCfRanges(options: CfRangesOptions = {}): Promise<readonly Cidr[]> {
	const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS
	const now = Date.now()
	if (!options.force && cached && now < cached.expiresAt) return cached.ranges
	if (inflight) return waitForInflight(inflight, options.signal)

	const fetchImpl = options.fetchImpl ?? fetch
	const gen = generation
	const ref: { current?: Promise<readonly Cidr[]> } = {}
	ref.current = (async () => {
		try {
			const ranges = await loadRanges(fetchImpl)
			if (generation === gen) cached = { ranges, expiresAt: Date.now() + ttlMs }
			return ranges
		} catch {
			// A stale cache beats the snapshot; the snapshot beats nothing. Cache the fallback
			// briefly so a broken endpoint does not trigger two fetches per caller.
			const ranges = cached?.ranges ?? snapshotRanges()
			if (generation === gen) cached = { ranges, expiresAt: Date.now() + Math.min(ttlMs, FAILURE_TTL_MS) }
			return ranges
		} finally {
			if (inflight === ref.current) inflight = null
		}
	})()
	const current = ref.current
	inflight = current

	return waitForInflight(current, options.signal)
}

/** Synchronous snapshot access for callers that cannot await — no network, no cache. */
function getCfRangesSnapshot(): readonly Cidr[] {
	return snapshotRanges()
}

/** Test hook: forget the live cache and any in-flight fetch. */
function resetCfRanges(): void {
	generation++
	cached = null
	inflight = null
}

export { parseCfRanges, getCfRanges, getCfRangesSnapshot, resetCfRanges }
export type { CfRangesOptions }
