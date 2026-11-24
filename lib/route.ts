// Route policy: can this host be reached directly from the runtime, or only through a proxy?
//
// The runtime refuses outbound TCP to Cloudflare's own ranges, so the answer depends only on the
// resolved addresses. Keeping the decision here — a pure function over addresses and ranges —
// makes it testable without DNS, sockets or a Worker, and leaves `client.ts` responsible for
// acting on it rather than for knowing the rule.

import { ipInAny } from './cidr.ts'

import type { Cidr } from './cidr.ts'

export type Route = 'direct' | 'proxy'

/** Structural shape of a resolved address, so this module need not import a DNS implementation. */
interface RouteAddress {
	address: string
}

/**
 * `direct` when at least one resolved address escapes Cloudflare's ranges — the runtime will
 * pick a usable family on its own. `proxy` only when every address is Cloudflare-owned, which is
 * the one case where a direct socket is guaranteed to fail.
 *
 * An unknown host (no addresses) stays `direct`: routing to a proxy on no evidence would turn a
 * transient DNS failure into a proxy bill.
 */
function planRoute(addresses: readonly RouteAddress[], ranges: readonly Cidr[]): Route {
	if (addresses.length === 0) return 'direct'
	for (const { address } of addresses) {
		if (!ipInAny(address, ranges)) return 'direct'
	}
	return 'proxy'
}

export { planRoute }
export type { RouteAddress }
