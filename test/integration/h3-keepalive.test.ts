// HTTP/3 keep-alive: two sequential requests to the same origin must reuse one QUIC session.
// Live network + node:dgram, so this runs in the network project alongside h3.test.ts.

import * as dgram from 'node:dgram'

import { expect, it } from 'vitest'

import request from '../../index.ts'
import { clearPool } from '../../lib/pool.ts'
import { QUIC_HOST } from '../helpers/hosts.ts'

import type { UdpSocket } from '../../lib/h3/udp.ts'

it('reuses one QUIC session for sequential h3 requests', async () => {
	let opened = 0
	const alpns: (string | null)[] = []
	const onEnd = (payload: unknown) => {
		const tls = (payload as { tls?: { alpn?: string | null } } | undefined)?.tls
		alpns.push(tls?.alpn ?? null)
	}
	request.udp.setUdpProvider((type) => {
		opened += 1
		return dgram.createSocket(type) as unknown as UdpSocket
	})
	request.observability.on('request:end', onEnd)
	try {
		for (let i = 0; i < 2; i++) {
			const res = await request(`https://${QUIC_HOST}/`, { signal: AbortSignal.timeout(30_000) })
			expect(res.status).toBeLessThan(400)
			await res.arrayBuffer()
		}
		expect(alpns).toEqual(['h3', 'h3'])
		expect(opened).toBe(1)
	} finally {
		request.observability.off('request:end', onEnd)
		clearPool('test-teardown')
		request.udp.setUdpProvider((type) => dgram.createSocket(type) as unknown as UdpSocket)
	}
}, 90_000)
