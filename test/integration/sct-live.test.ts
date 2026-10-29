// The live half of the SCT tests: a real CT-enforced certificate, fetched over the network.
// Runs in the `network` project only (npm run test:network), never under `npm test`.

import * as tls from 'node:tls'

import { expect, it } from 'vitest'

import { findSctExtension, parseSctList } from '../../lib/tls/sct.ts'
import { TLS13_HOST } from '../helpers/hosts.ts'

import type * as crypto from 'node:crypto'

it('findSctExtension on a real-world cert returns the extension bytes', async () => {
	// Fetch the cert from a real CT-enforced site by opening a TLS socket.
	// rejectUnauthorized only because the assertion is about the SCT extension inside the
	// cert, not about the chain; the socket is destroyed as soon as the cert is read.
	const peer = await new Promise<crypto.X509Certificate>((resolve, reject) => {
		const sock = tls.connect({ host: TLS13_HOST, port: 443, servername: TLS13_HOST, rejectUnauthorized: false }, () => {
			const cert = sock.getPeerX509Certificate()
			sock.destroy()
			if (!cert) reject(new Error(`no peer certificate from ${TLS13_HOST}`))
			else resolve(cert)
		})
		sock.on('error', reject)
	})

	const ext = findSctExtension(Buffer.from(peer.raw))
	expect(ext, 'cloudflare.com cert should have an SCT extension').not.toBeNull()
	const scts = parseSctList(ext!)
	expect(scts.length, `expected >=1 SCT, got ${scts.length}`).toBeGreaterThanOrEqual(1)
	for (const s of scts) {
		expect(s.logId.length).toBe(32)
		expect(s.timestamp).toBeGreaterThan(0)
	}
})
