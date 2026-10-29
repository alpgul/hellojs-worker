// Bind a server to an ephemeral loopback port and give back the port it chose.

import type net from 'node:net'

async function listenOnLoopback(server: net.Server): Promise<number> {
	await new Promise<void>((resolve) => server.listen({ port: 0, host: '127.0.0.1' }, () => resolve()))
	const addr = server.address()
	if (!addr || typeof addr === 'string') throw new Error('expected a bound TCP port')
	return addr.port
}

export { listenOnLoopback }
