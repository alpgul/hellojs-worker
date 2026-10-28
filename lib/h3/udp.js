// UDP seam for the QUIC client: a drop-in stand-in for `node:dgram`, so connection.js
// keeps calling `dgram.createSocket(type)` and the transport can be swapped or taken out
// of reach without touching the QUIC code.
//
// Runtimes without a UDP API (worker/edge sandboxes) passiveize HTTP/3 with
//   setUdpProvider(null)
// openSocket then throws EUDPUNAVAILABLE, connect() reports the h3 failure and client.js
// retries the request over TCP + TLS. A runtime that does expose datagram sockets installs
// its own transport instead:
//   setUdpProvider((type) => myRuntimeUdpSocket(type))
// The socket only has to provide the subset connection.js uses —
//   on('message', (buf, rinfo))  on('error', (err))
//   bind(port, cb)               send(buf, port, host[, cb])
//   close()                      destroyed
// which node:dgram.Socket already satisfies. With no provider configured the seam resolves
// to dgram, so Node needs no setup.

let provider = null
let resolved = false

function dgramProvider() {
	let dgram
	try { dgram = require('dgram') } catch (_) { return null }
	if (!dgram || typeof dgram.createSocket !== 'function') return null
	return (type) => dgram.createSocket(type)
}

function currentProvider() {
	if (!resolved) { resolved = true; provider = dgramProvider() }
	return provider
}

function setUdpProvider(fn) {
	provider = fn || null
	resolved = true
}

function udpAvailable() { return !!currentProvider() }

function createSocket(type = 'udp4') {
	const open = currentProvider()
	if (!open) {
		const err = new Error('no UDP transport available — HTTP/3 needs a datagram socket')
		err.code = 'EUDPUNAVAILABLE'
		throw err
	}
	return open(type)
}

module.exports = { createSocket, setUdpProvider, udpAvailable }
