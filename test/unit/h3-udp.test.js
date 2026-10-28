// The UDP seam that gates QUIC socket creation: default provider, explicit disable,
// custom provider injection.

const test = require('node:test')
const assert = require('node:assert')

// Each case wants its own view of the seam's module-level state.
function freshSeam() {
	const path = require.resolve('../../lib/h3/udp')
	delete require.cache[path]
	return require(path)
}

test('dgram is the default provider and opens a usable socket', () => {
	const udp = freshSeam()
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

test('setUdpProvider(null) passiveizes the transport', () => {
	const udp = freshSeam()
	udp.setUdpProvider(null)
	assert.equal(udp.udpAvailable(), false)
	assert.throws(() => udp.createSocket(), (e) => e.code === 'EUDPUNAVAILABLE')
})

test('a custom provider replaces dgram without touching connection.js', () => {
	const udp = freshSeam()
	const stub = { on() {}, bind() {}, send() {}, close() {}, destroyed: false }
	udp.setUdpProvider((type) => { stub.type = type; return stub })
	assert.equal(udp.udpAvailable(), true)
	assert.equal(udp.createSocket(), stub)
	assert.equal(stub.type, 'udp4')
})
