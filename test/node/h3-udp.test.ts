// The UDP seam that gates QUIC socket creation: default provider, explicit disable,
// custom provider injection.

import { expect, it } from 'vitest'

import type * as UdpSeam from '../../lib/h3/udp.ts'

// Each case wants its own view of the seam's module-level state. ESM caches modules
// permanently, so a unique query string gives each case a fresh evaluation. The import is
// vite-ignored: the specifier is built at runtime, so Vite must not try to glob-analyse it.
let seamGeneration = 0
async function freshSeam(): Promise<typeof UdpSeam> {
	seamGeneration++
	return (await import(/* @vite-ignore */ `../../lib/h3/udp.ts?fresh=${seamGeneration}`)) as typeof UdpSeam
}

it('dgram is the default provider and opens a usable socket', async () => {
	const udp = await freshSeam()
	expect(udp.udpAvailable()).toBe(true)
	const sock = udp.createSocket()
	try {
		expect(typeof sock.bind).toBe('function')
		expect(typeof sock.send).toBe('function')
		expect(typeof sock.close).toBe('function')
		expect(typeof sock.on).toBe('function')
	} finally {
		sock.close()
	}
})

it('setUdpProvider(null) passiveizes the transport', async () => {
	const udp = await freshSeam()
	udp.setUdpProvider(null)
	expect(udp.udpAvailable()).toBe(false)
	expect(() => udp.createSocket()).toThrow(expect.objectContaining({ code: 'EUDPUNAVAILABLE' }))
})

it('a custom provider replaces dgram without touching connection.ts', async () => {
	const udp = await freshSeam()
	const stub = { on() {}, bind() {}, send() {}, close() {}, destroyed: false, type: '' }
	udp.setUdpProvider((type) => { stub.type = type; return stub })
	expect(udp.udpAvailable()).toBe(true)
	expect(udp.createSocket()).toBe(stub)
	expect(stub.type).toBe('udp4')
})
