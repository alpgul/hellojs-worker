// The UDP seam that gates QUIC socket creation: default provider, explicit disable,
// custom provider injection.

import assert from 'node:assert'
import test from 'node:test'

// Each case wants its own view of the seam's module-level state. ESM caches modules
// permanently, so a unique query string gives each case a fresh evaluation.
let seamGeneration = 0
function freshSeam() {
	seamGeneration++
	return import(`../../lib/h3/udp.js?fresh=${seamGeneration}`)
}

test('dgram is the default provider and opens a usable socket', async () => {
	const udp = await freshSeam()
	assert.equal(udp.udpAvailable(), true)
	const sock = udp.createSocket()
	try {
		assert.equal(typeof sock.bind, 'function')
		assert.equal(typeof sock.send, 'function')
		assert.equal(typeof sock.close, 'function')
		assert.equal(typeof sock.on, 'function')
	} finally {
		sock.close()
	}
})

test('setUdpProvider(null) passiveizes the transport', async () => {
	const udp = await freshSeam()
	udp.setUdpProvider(null)
	assert.equal(udp.udpAvailable(), false)
	assert.throws(() => udp.createSocket(), (e) => e.code === 'EUDPUNAVAILABLE')
})

test('a custom provider replaces dgram without touching connection.js', async () => {
	const udp = await freshSeam()
	const stub = { on() {}, bind() {}, send() {}, close() {}, destroyed: false }
	udp.setUdpProvider((type) => { stub.type = type; return stub })
	assert.equal(udp.udpAvailable(), true)
	assert.equal(udp.createSocket(), stub)
	assert.equal(stub.type, 'udp4')
})
