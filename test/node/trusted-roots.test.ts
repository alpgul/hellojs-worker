// setTrustedRoots() replaces the bundled store — workerd's node:tls has none.

import * as tls from 'node:tls'

import { expect, it } from 'vitest'

import { setTrustedRoots, trustedRoots } from '../../lib/tls/cert-validate.ts'

it('setTrustedRoots replaces the store and can restore the Node bundle', () => {
	setTrustedRoots([])
	expect(trustedRoots().length).toBe(0)

	setTrustedRoots([...tls.rootCertificates])
	expect(trustedRoots().length).toBe(tls.rootCertificates.length)
	expect(trustedRoots()[0].subject).toBeTruthy()
})

it('setTrustedRoots skips unparseable entries', () => {
	setTrustedRoots(['not a certificate', tls.rootCertificates[0]])
	expect(trustedRoots().length).toBe(1)

	setTrustedRoots([...tls.rootCertificates])
})
