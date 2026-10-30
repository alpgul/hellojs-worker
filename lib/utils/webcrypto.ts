// Web Crypto resolution for both runtimes the library runs on.
//
// Worker/edge runtimes expose SubtleCrypto as `globalThis.crypto`. Node exposes it there too
// from v19, but a standard Node project can run with that global absent (older Node, a bundler
// that strips it, an app that deleted it). `node:crypto.webcrypto` carries the same interface
// either way, so fall back to it instead of making the host install a global — the library
// never writes to `globalThis`.
//
// No caching: the lookup runs a handful of times per handshake, and staying stateless keeps
// tests from needing a reset seam.
//
// The type is read off the global `crypto` VALUE so it is the host runtime's own: the tsconfig
// loads @cloudflare/workers-types/experimental, so this is workerd's ML-KEM-capable SubtleCrypto.

// The slice of node:crypto the fallback needs, typed structurally so this module does not
// depend on @types/node's module declaration.
type NodeCryptoModule = { webcrypto?: { subtle?: unknown } }
type Subtle = typeof crypto.subtle

function isSubtle(value: unknown): value is Subtle {
	return !!value && typeof (value as Subtle).importKey === 'function'
}

function getSubtle(): Subtle {
	const globalCrypto = (globalThis as { crypto?: { subtle?: unknown } }).crypto
	if (isSubtle(globalCrypto?.subtle)) return globalCrypto.subtle

	if (typeof process !== 'undefined' && typeof process.getBuiltinModule === 'function') {
		const nodeCrypto = process.getBuiltinModule('node:crypto') as NodeCryptoModule | undefined
		const s = nodeCrypto?.webcrypto?.subtle
		if (isSubtle(s)) return s
	}

	throw new Error('Web Crypto unavailable: neither globalThis.crypto.subtle nor node:crypto.webcrypto is reachable')
}

export { getSubtle, type Subtle }
