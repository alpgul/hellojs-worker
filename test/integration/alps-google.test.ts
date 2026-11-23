// Live regression for the Chrome 147 ALPS handshake. Google's frontends negotiate
// application_settings (0x44cd) in EncryptedExtensions; without the matching client
// EncryptedExtensions they abort with fatal alert 10 (unexpected_message) after our Finished.

import * as dgram from 'node:dgram'

import { afterAll, beforeAll, expect, it } from 'vitest'

import request from '../../index.ts'
import { ALPS_HOST, ALPS_HOST_ALT } from '../helpers/hosts.ts'

import type { UdpSocket } from '../../lib/h3/udp.ts'

// This test is about the TLS path. With UDP available the transport race can pick h3 and pass
// without ever running the ALPS CEE code, so pin this file to TCP.
beforeAll(() => request.udp.setUdpProvider(null))
afterAll(() => request.udp.setUdpProvider((type) => dgram.createSocket(type) as unknown as UdpSocket))

for (const host of [ALPS_HOST, ALPS_HOST_ALT]) {
	it(`completes an ALPS h2 GET over TCP against ${host}`, async () => {
		expect(request.udp.udpAvailable()).toBe(false)
		const res = await request(`https://${host}/`, {
			signal: AbortSignal.timeout(15_000),
			keepalive: false
		})
		expect(res.status).toBe(200)
		expect(res.headers.get('content-type')).toBeTruthy()
		// Consume the stream so the test does not leave an open response behind.
		expect((await res.text()).length).toBeGreaterThan(0)
	}, 30_000)
}
