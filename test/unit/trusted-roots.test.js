// setTrustedRoots() replaces the bundled store — workerd's node:tls has none.

import assert from 'node:assert'
import test from 'node:test'
import * as tls from 'node:tls'

import { setTrustedRoots, trustedRoots } from '../../lib/tls/cert-validate.js'

test('setTrustedRoots replaces the store and can restore the Node bundle', () => {
	setTrustedRoots([])
	assert.strictEqual(trustedRoots().length, 0)

	setTrustedRoots(tls.rootCertificates)
	assert.strictEqual(trustedRoots().length, tls.rootCertificates.length)
	assert.ok(trustedRoots()[0].subject)
})

test('setTrustedRoots skips unparseable entries', () => {
	setTrustedRoots(['not a certificate', tls.rootCertificates[0]])
	assert.strictEqual(trustedRoots().length, 1)

	setTrustedRoots(tls.rootCertificates)
})
