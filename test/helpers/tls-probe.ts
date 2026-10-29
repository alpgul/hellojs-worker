// Drive a real TLS handshake against a live host with the library's own TLS class and report
// what was negotiated. Shared by the network suites that probe fleets of servers.
//
// Never throws: a failed, rejected or timed-out handshake comes back as { ok: false, err },
// so a suite decides what to assert instead of dying on the first unreachable host.

import { TLS } from '../../lib/tls/tls.ts'

import type { TLSOptions } from '../../lib/tls/tls.ts'

interface TlsProbe {
	host: string
	ok: boolean
	alpn?: string
	version?: string
	cipher?: string
	group?: string
	err?: string
}

function probeTls(host: string, opts: { port?: number; timeoutMs?: number; tlsOpts?: TLSOptions } = {}): Promise<TlsProbe> {
	const { port = 443, timeoutMs = 15_000, tlsOpts = {} } = opts
	return new Promise((resolve) => {
		const tls = new TLS(host, port, null, tlsOpts)
		const finish = (alpn: string) => {
			clearTimeout(timer)
			const isTls12 = !!tls.tls12
			const group = isTls12 ? 'n/a(1.2)' : tls.server.serverKShare
				? `0x${tls.server.serverKShare.group.toString(16)}`
				: 'n/a'
			tls.h2Session?.close()
			tls.socket?.destroy()
			resolve({
				host,
				ok: true,
				alpn,
				group,
				cipher: `0x${tls.server.cipherSuite.toString(16)}`,
				version: isTls12 ? '1.2' : '1.3',
			})
		}
		const fail = (err: string) => {
			clearTimeout(timer)
			tls.socket?.destroy()
			resolve({ host, ok: false, err })
		}
		const timer = setTimeout(() => fail('timeout'), timeoutMs)
		tls.on('ready', () => finish('h2'))
		tls.on('ready-http1', () => finish('http/1.1'))
		tls.on('error', (e: Error) => fail(e.message))
		void tls.connect().catch((e: Error) => fail(e.message))
	})
}

export { probeTls }
export type { TlsProbe }
