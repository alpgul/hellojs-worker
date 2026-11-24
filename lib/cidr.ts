// CIDR parsing and membership for IPv4 and IPv6.
//
// A Worker cannot open an outbound TCP socket to Cloudflare's own IP ranges, so a host behind
// Cloudflare is reachable only through a proxy. That decision has to be made from an address
// before any socket exists, and it has to be exact: a false negative costs a doomed connection,
// a false positive sends traffic through a proxy for nothing.
//
// BigInt keeps both families in one shape — parse, mask, compare — instead of duplicating the
// arithmetic per bit width. `::ffff:a.b.c.d` is normalised to IPv4 because it dials the same
// host, so it must match the same ranges.

export interface Cidr {
	family: 4 | 6
	base: bigint
	bits: number
}

const V4_BITS = 32n
const V6_BITS = 128n
/** `::ffff:0:0/96` — an IPv4 address wearing an IPv6 spelling. */
const V4_MAPPED_PREFIX = 0xffffn

function parseIPv4(ip: string): bigint | null {
	const parts = ip.split('.')
	if (parts.length !== 4) return null
	let value = 0n
	for (const part of parts) {
		if (!/^\d{1,3}$/.test(part)) return null
		const octet = Number(part)
		if (octet > 255) return null
		value = (value << 8n) | BigInt(octet)
	}
	return value
}

function parseIPv6(ip: string): bigint | null {
	if (!ip.includes(':')) return null

	let text = ip
	// An embedded IPv4 tail (`::ffff:1.2.3.4`, `64:ff9b::1.2.3.4`) becomes two hex groups.
	const lastColon = text.lastIndexOf(':')
	if (text.includes('.')) {
		const v4 = parseIPv4(text.slice(lastColon + 1))
		if (v4 === null) return null
		const hi = ((v4 >> 16n) & 0xffffn).toString(16)
		const lo = (v4 & 0xffffn).toString(16)
		text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`
	}

	const halves = text.split('::')
	if (halves.length > 2) return null
	const head = halves[0] ? halves[0].split(':') : []
	const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
	// `::` must stand for at least one group; a full eight-group address needs no compression.
	const missing = 8 - head.length - tail.length
	if (halves.length === 1 ? missing !== 0 : missing < 1) return null

	const groups = halves.length === 1 ? head : [...head, ...new Array<string>(missing).fill('0'), ...tail]
	if (groups.length !== 8) return null

	let value = 0n
	for (const group of groups) {
		if (!/^[0-9a-f]{1,4}$/i.test(group)) return null
		value = (value << 16n) | BigInt(Number.parseInt(group, 16))
	}
	return value
}

/**
 * Parse an address literal into a family and a numeric value. Returns null for anything that is
 * not a bare IPv4/IPv6 literal — hostnames, zone indices and malformed text all fall through.
 */
function ipToBigInt(ip: string): { family: 4 | 6; value: bigint } | null {
	const text = ip.trim()
	if (!text || text.includes('%')) return null

	const v4 = parseIPv4(text)
	if (v4 !== null) return { family: 4, value: v4 }

	const v6 = parseIPv6(text)
	if (v6 === null) return null
	if (v6 >> V4_BITS === V4_MAPPED_PREFIX) return { family: 4, value: v6 & 0xffff_ffffn }
	return { family: 6, value: v6 }
}

/**
 * Parse one CIDR (`10.0.0.0/8`, `2606:4700::/32`) or a bare address, which is treated as a
 * single-host prefix. Returns null for malformed input so list parsing can skip a bad line
 * instead of throwing on a whole feed.
 */
function parseCidr(text: string): Cidr | null {
	const trimmed = text.trim()
	if (!trimmed) return null

	const slash = trimmed.lastIndexOf('/')
	const address = slash === -1 ? trimmed : trimmed.slice(0, slash)
	const bitsText = slash === -1 ? null : trimmed.slice(slash + 1)
	if (bitsText !== null && !/^\d{1,3}$/.test(bitsText)) return null

	const parsed = ipToBigInt(address)
	if (!parsed) return null

	const width = parsed.family === 4 ? 32 : 128
	const bits = bitsText === null ? width : Number(bitsText)
	if (bits > width) return null

	// Store the network address, not the caller's host bits, so comparisons stay a plain shift.
	const hostBits = BigInt(width - bits)
	const base = (parsed.value >> hostBits) << hostBits
	return { family: parsed.family, base, bits }
}

/** Parse a newline-, comma- or whitespace-separated feed. Unparseable entries are dropped. */
function parseCidrList(text: string): Cidr[] {
	const out: Cidr[] = []
	for (const token of text.split(/[\s,]+/)) {
		if (!token) continue
		const cidr = parseCidr(token)
		if (cidr) out.push(cidr)
	}
	return out
}

function ipInCidr(ip: string, cidr: Cidr): boolean {
	const parsed = ipToBigInt(ip)
	if (!parsed || parsed.family !== cidr.family) return false
	const shift = (cidr.family === 4 ? V4_BITS : V6_BITS) - BigInt(cidr.bits)
	return parsed.value >> shift === cidr.base >> shift
}

function ipInAny(ip: string, cidrs: readonly Cidr[]): boolean {
	const parsed = ipToBigInt(ip)
	if (!parsed) return false
	const width = parsed.family === 4 ? V4_BITS : V6_BITS
	for (const cidr of cidrs) {
		if (cidr.family !== parsed.family) continue
		const shift = width - BigInt(cidr.bits)
		if (parsed.value >> shift === cidr.base >> shift) return true
	}
	return false
}

export { ipToBigInt, parseCidr, parseCidrList, ipInCidr, ipInAny }
