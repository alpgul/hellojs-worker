// Allowlist for the Worker's /proxy route. Kept as a pure function so the policy can be
// unit-tested without booting a Worker or importing the TLS/root-certificate bundle.
//
// Without this, a public Worker with `?url=` would be an open relay: anyone could point it at
// an internal service or use it to hide the origin of their traffic.

export type ProxyTargetResult = { ok: true; url: URL } | { ok: false; status: number; message: string }

const PRIVATE_V4 = /^(?:0|10|127|169\.254|172\.(?:1[6-9]|2\d|3[01])|192\.168)\./
const PRIVATE_V6 = /^(?:::1|fc[0-9a-f]*:|fd[0-9a-f]*:|fe80:)/i

function isPrivateHost(hostname: string): boolean {
	const host = hostname.replaceAll(/^\[|\]$/g, '').toLowerCase()
	if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true
	if (PRIVATE_V4.test(host)) return true
	if (PRIVATE_V6.test(host)) return true
	return false
}

/**
 * Resolve a `?url=` parameter into a target hellojs may dial. `allowedHosts` comes from the
 * ALLOWED_HOSTS Worker variable (comma-separated); an empty list denies everything.
 */
export function resolveProxyTarget(raw: string | null, allowedHosts: string | undefined): ProxyTargetResult {
	if (!raw) return { ok: false, status: 400, message: 'missing url parameter' }

	let url: URL
	try {
		url = new URL(raw)
	} catch {
		return { ok: false, status: 400, message: 'invalid url parameter' }
	}
	if (url.protocol !== 'http:' && url.protocol !== 'https:') {
		return { ok: false, status: 403, message: 'only http and https targets are allowed' }
	}
	if (url.username || url.password) {
		return { ok: false, status: 403, message: 'credentials in the target URL are not allowed' }
	}
	if (isPrivateHost(url.hostname)) {
		return { ok: false, status: 403, message: 'private or loopback targets are not allowed' }
	}

	const allowed = new Set(
		(allowedHosts ?? '')
			.split(',')
			.map((host) => host.trim().toLowerCase())
			.filter(Boolean)
	)
	if (!allowed.has(url.hostname.toLowerCase())) {
		return { ok: false, status: 403, message: 'target host is not in ALLOWED_HOSTS' }
	}

	return { ok: true, url }
}
