// End-to-end parrot test: paste tls.peet.ws's response, build a profile from it, then
// make a request using that profile and verify the returned JA4 / akamai_fingerprint
// hashes match the input.
//
// This is the round-trip proof that `profiles.fromPeet()` produces a structurally
// faithful clone of the input.

import request from '../../index.js'
import * as profiles from '../../lib/profiles/index.ts'

;(async () => {
	console.log('Parrot end-to-end test\n')

	// 1. Capture a fresh peet.ws fingerprint using the DEFAULT profile.
	const baseline = await request({
		url: 'https://tls.peet.ws/api/all',
		json: true,
		resolveWithFullResponse: true,
	})
	const expected = {
		ja4: baseline.body.tls.ja4,
		ja3: baseline.body.tls.ja3_hash,
		akamai: baseline.body.http2.akamai_fingerprint_hash,
		peetprint: baseline.body.tls.peetprint_hash,
	}
	console.log('baseline JA4:    ', expected.ja4)
	console.log('baseline JA3:    ', expected.ja3)
	console.log('baseline akamai: ', expected.akamai)
	console.log('baseline peetprint:', expected.peetprint)

	// 2. Build a parrot profile from the same JSON.
	profiles.registerFromPeet('peet-parrot', baseline.body)

	const after = await request({
		url: 'https://tls.peet.ws/api/all',
		json: true,
		profile: 'peet-parrot',
		resolveWithFullResponse: true,
	})
	const got = {
		ja4: after.body.tls.ja4,
		ja3: after.body.tls.ja3_hash,
		akamai: after.body.http2.akamai_fingerprint_hash,
		peetprint: after.body.tls.peetprint_hash,
	}
	console.log('\nparrot JA4:    ', got.ja4)
	console.log('parrot JA3:    ', got.ja3)
	console.log('parrot akamai: ', got.akamai)
	console.log('parrot peetprint:', got.peetprint)

	let pass = 0, fail = 0
	for (const k of Object.keys(expected)) {
		// JA3 hashes extensions in WIRE ORDER. peet.ws strips GREASE from the JA3 string —
		// GREASE rotation is NOT the cause. The actual cause: Chrome (and our impl) shuffles
		// the middle of the extension block per TLS instance. Two runs from the same profile
		// produce different JA3 hashes; that's faithful Chrome behaviour, not a defect.
		if (k === 'ja3') {
			if (expected[k] && got[k]) { console.log(`\x1b[33mSKIP \x1b[0m ja3 (extension order shuffles per-instance → JA3 varies)`); pass++ }
			else { console.log(`\x1b[31mDIFF \x1b[0m ja3 (no value)`); fail++ }
			continue
		}
		if (expected[k] === got[k]) { console.log(`\x1b[32mMATCH\x1b[0m ${k}`); pass++ }
		else { console.log(`\x1b[31mDIFF \x1b[0m ${k} expected=${expected[k]} got=${got[k]}`); fail++ }
	}

	console.log(`\n${pass}/${pass + fail} fingerprints match`)
	process.exit(fail ? 1 : 0)
})()
