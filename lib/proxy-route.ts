// Automatic proxy routing for hosts the runtime cannot dial directly.
//
// A Worker refuses outbound TCP to Cloudflare's own ranges. Any host behind Cloudflare therefore
// has to leave through the pool, and which hosts those are is knowable before a socket is opened:
// resolve the name, test the addresses against the published ranges. That turns a runtime failure
// into a routing decision — no doomed connection, no race between a direct and a proxied attempt.
//
// Two escape hatches keep the policy honest:
//   - no resolver, or no records → stay direct and let the dial report the real error;
//   - an empty pool → stay direct, because there is nothing to route to and the extra lookup
//     would only add latency to the common case. The dial's own refusal is then reported as
//     ENOPROXY rather than as a raw platform error.

import { getCfRanges } from './cf-ranges.ts'
import { resolveHost } from './dns-cache.ts'
import { HellojsError } from './errors.ts'
import { hasProxies, selectProxy } from './proxy-store.ts'
import { planRoute } from './route.ts'

import type { SelectedProxy } from './proxy-store.ts'

/** workerd's wording when a socket target is disallowed (Cloudflare ranges, loopback, private). */
const DISALLOWED_TARGET = /cannot connect to the specified address/i

function isDisallowedTarget(err: unknown): boolean {
	if (!(err instanceof Error)) return false
	const cause = (err as { cause?: unknown }).cause
	const text = cause instanceof Error ? `${err.message} ${cause.message}` : err.message
	return DISALLOWED_TARGET.test(text)
}

function throwIfAborted(signal?: AbortSignal | null): void {
	if (!signal?.aborted) return
	throw signal.reason ?? new Error('aborted')
}

async function waitForDns(host: string, signal?: AbortSignal | null): Promise<readonly { address: string }[] | null> {
	const lookup = resolveHost(host)
	// Keep the shared lookup alive for other callers; only observe this caller's wait.
	void lookup.catch(() => {})
	try {
		if (!signal) return await lookup
		throwIfAborted(signal)
		return await new Promise<readonly { address: string }[]>((resolve, reject) => {
			const onAbort = () => {
				signal.removeEventListener('abort', onAbort)
				reject(signal.reason ?? new Error('aborted'))
			}
			signal.addEventListener('abort', onAbort, { once: true })
			lookup.then(
				(value) => {
					signal.removeEventListener('abort', onAbort)
					resolve(value)
				},
				(err) => {
					signal.removeEventListener('abort', onAbort)
					reject(err)
				}
			)
		})
	} catch (err) {
		if (signal?.aborted) throw signal.reason ?? err
		// Unknown host or no resolver in this runtime: keep the direct path.
		return null
	}
}

/**
 * The proxy to use for a request that did not specify one, or `null` to go direct.
 * Throws ENOPROXY when the host is Cloudflare-owned and the pool cannot serve it.
 */
async function resolveAutoProxy(
	host: string,
	options: { signal?: AbortSignal | null } = {}
): Promise<SelectedProxy | null> {
	if (!hasProxies()) return null

	const addresses = await waitForDns(host, options.signal)
	if (!addresses) return null

	const ranges = await getCfRanges({ signal: options.signal })
	if (planRoute(addresses, ranges) === 'direct') return null

	const entry = selectProxy(host)
	if (!entry) {
		throw new HellojsError(
			`${host} resolves only to Cloudflare-owned addresses and no pooled proxy can serve it`,
			'ENOPROXY'
		)
	}
	return entry
}

/** Another proxy for the same host, skipping the URLs already tried. */
function rerouteProxy(host: string, tried: ReadonlySet<string>): SelectedProxy | null {
	return selectProxy(host, tried)
}

/** The error to surface when a Cloudflare-owned target cannot be reached through any route. */
function blockedTargetError(host: string, cause: unknown): HellojsError {
	if (!hasProxies()) {
		return new HellojsError(
			`${host} resolves only to Cloudflare-owned addresses and the proxy pool is empty`,
			'ENOPROXY',
			cause
		)
	}
	return new HellojsError(
		`the runtime cannot dial ${host} directly (Cloudflare-owned address)`,
		'ECFIPBLOCKED',
		cause
	)
}

export { resolveAutoProxy, rerouteProxy, isDisallowedTarget, blockedTargetError }
