// UDP seam for the QUIC client: a drop-in stand-in for `node:dgram`, so connection.ts
// keeps calling `createSocket(type)` and the transport can be swapped or taken out
// of reach without touching the QUIC code.
//
// Runtimes without a UDP API (worker/edge sandboxes) passiveize HTTP/3 with
//   setUdpProvider(null)
// openSocket then throws EUDPUNAVAILABLE, connect() reports the h3 failure and client.ts
// retries the request over TCP + TLS. A runtime that does expose datagram sockets installs
// its own transport instead:
//   setUdpProvider((type) => myRuntimeUdpSocket(type))
// The socket only has to provide the subset connection.ts uses —
//   on('message', (buf, rinfo))  on('error', (err))
//   bind(port, cb)               send(buf, port, host[, cb])
//   close()                      destroyed
// which node:dgram.Socket already satisfies. With no provider configured the seam resolves
// to dgram, so Node needs no setup.

export interface UdpRinfo {
	address: string
	family: string
	port: number
}

export interface UdpSocket {
	on(event: 'message', listener: (buf: Buffer, rinfo: UdpRinfo) => void): unknown
	on(event: 'error', listener: (err: Error) => void): unknown
	bind(port: number, callback: () => void): unknown
	send(buf: Buffer, port: number, host: string, callback?: () => void): unknown
	close(): unknown
	readonly destroyed: boolean
}

export type UdpFamily = 'udp4' | 'udp6'
export type UdpProvider = (type: UdpFamily) => UdpSocket

let provider: UdpProvider | null = null
let resolved = false

function dgramProvider(): UdpProvider | null {
	let dgram
	try {
		if (typeof process === 'undefined' || typeof process.getBuiltinModule !== 'function') return null
		dgram = process.getBuiltinModule('node:dgram')
	} catch { return null }
	if (!dgram || typeof dgram.createSocket !== 'function') return null
	// dgram.Socket's overloaded bind()/send() are wider than the subset the seam promises,
	// and it leaves `destroyed` undeclared.
	return (type: UdpFamily) => dgram.createSocket(type) as unknown as UdpSocket
}

function currentProvider(): UdpProvider | null {
	if (!resolved) { resolved = true; provider = dgramProvider() }
	return provider
}

function setUdpProvider(fn: UdpProvider | null): void {
	provider = fn || null
	resolved = true
}

function udpAvailable(): boolean { return !!currentProvider() }

function createSocket(type: UdpFamily = 'udp4'): UdpSocket {
	const open = currentProvider()
	if (!open) {
		const err = new Error('no UDP transport available — HTTP/3 needs a datagram socket') as NodeJS.ErrnoException
		err.code = 'EUDPUNAVAILABLE'
		throw err
	}
	return open(type)
}

export { createSocket, setUdpProvider, udpAvailable }
