// Alt-Svc cache: host → { port, expiry }. Populated when an h2 response advertises
// `alt-svc: h3=":443"; ma=N`, consulted by the next request so it can upgrade to QUIC.

const altSvcCache = new Map()

function recordAltSvc(host, value) {
	if (!value || value === 'clear') { altSvcCache.delete(host); return }
	const m = value.match(/h3="?:?(\d+)"?(?:[^,]*?ma=(\d+))?/i)
	if (m) {
		const port = parseInt(m[1], 10)
		const maxAge = m[2] ? parseInt(m[2], 10) : 86400
		altSvcCache.set(host, { port, expiry: Date.now() + maxAge * 1000 })
	}
}

function lookupAltSvc(host) {
	const e = altSvcCache.get(host)
	if (!e) return null
	if (e.expiry < Date.now()) { altSvcCache.delete(host); return null }
	return e
}

function clearAltSvc() { altSvcCache.clear() }

module.exports = { recordAltSvc, lookupAltSvc, clearAltSvc }
