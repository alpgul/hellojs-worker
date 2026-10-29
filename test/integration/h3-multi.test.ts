// Smoke test h3 handshake against several public h3 endpoints.
//
// Serial — concurrent UDP handshakes tickle a packet-reordering bug in our naive UDP recv
// loop (out-of-order Initial/Handshake packets across many sockets). Serial works reliably,
// so Vitest's default sequential-within-file execution is exactly what this wants.
// Live network: `network` project only.

import { expect, it } from 'vitest'

import { QuicConnection } from '../../lib/h3/connection.ts'
import { H3Client } from '../../lib/h3/h3.ts'

const TARGETS = [
	{ host: 'cloudflare-quic.com', path: '/' },
	{ host: 'www.cloudflare.com', path: '/cdn-cgi/trace' },
	{ host: 'www.google.com', path: '/' },
	{ host: 'cloud.google.com', path: '/' },
	{ host: 'quic.aiortc.org', path: '/' },
]

async function tryOne({ host, path }: { host: string; path: string }): Promise<string> {
	const conn = new QuicConnection(host, 443)
	try {
		const ready = new Promise<void>((resolve, reject) => {
			const t = setTimeout(() => reject(new Error('handshake timeout')), 8000)
			conn.once('ready', () => { clearTimeout(t); resolve() })
			conn.once('error', (e: Error) => { clearTimeout(t); reject(e) })
		})
		await conn.connect()
		await ready
		const h3 = new H3Client(conn)
		const res = await Promise.race([
			h3.request({ method: 'GET', path, host }),
			new Promise<never>((_, rej) => setTimeout(() => rej(new Error('req timeout')), 6000)),
		])
		return `${res.status} ${res.headers.server ?? ''}`.trim()
	} finally {
		conn.close()
	}
}

it.each(TARGETS)('$host', async (target) => {
	const summary = await tryOne(target)
	expect(summary).toMatch(/^2\d\d/)
})
