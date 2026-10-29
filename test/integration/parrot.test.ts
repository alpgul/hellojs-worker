// End-to-end parrot test: paste tls.peet.ws's response, build a profile from it, then
// make a request using that profile and verify the returned JA4 / peetprint /
// akamai_fingerprint hashes match the input.
//
// This is the round-trip proof that `profiles.fromPeet()` produces a structurally
// faithful clone of the input. Live network: `network` project only.

import { beforeAll, describe, expect, it } from 'vitest'

import request from '../../index.ts'
import * as profiles from '../../lib/profiles/index.ts'
import { PEET_HOST } from '../helpers/hosts.ts'

import type { PeetJson } from '../../lib/profiles/from-peet.ts'

// The four hashes peet.ws reports for whatever it saw on the wire.
function hashes(body: PeetJson): Record<string, string | undefined> {
	return {
		ja4: body.tls?.ja4,
		ja3: body.tls?.ja3_hash,
		akamai: body.http2?.akamai_fingerprint_hash,
		peetprint: body.tls?.peetprint_hash,
	}
}

let expected: Record<string, string | undefined> = {}
let got: Record<string, string | undefined> = {}

beforeAll(async () => {
	// This file is the only one that needs peet.ws (peetprint exists only there), and the host
	// blackholes bursts of fresh connections. Two attempts of backoff keep a throttle from
	// reading as a fingerprint regression; a real one fails every attempt.
	const retry = { limit: 2, baseDelayMs: 5_000 }

	// 1. Capture a fresh peet.ws fingerprint using the DEFAULT profile.
	const baseline = await request<PeetJson>({
		url: `https://${PEET_HOST}/api/all`,
		json: true,
		resolveWithFullResponse: true,
		retry,
	})
	expected = hashes(baseline.body)

	// 2. Build a parrot profile from the same JSON, and re-request with it.
	profiles.registerFromPeet('peet-parrot', baseline.body)
	const after = await request<PeetJson>({
		url: `https://${PEET_HOST}/api/all`,
		json: true,
		profile: 'peet-parrot',
		resolveWithFullResponse: true,
		retry,
	})
	got = hashes(after.body)
})

describe('parrot round-trip', () => {
	// JA3 hashes extensions in WIRE ORDER. peet.ws strips GREASE from the JA3 string —
	// GREASE rotation is NOT the cause. The actual cause: Chrome (and our impl) shuffles
	// the middle of the extension block per TLS instance. Two runs from the same profile
	// produce different JA3 hashes; that's faithful Chrome behaviour, not a defect. So JA3
	// is only checked to be present, never to be equal.
	it('ja3 is produced by both runs (extension order shuffles per instance)', () => {
		expect(expected.ja3).toBeTruthy()
		expect(got.ja3).toBeTruthy()
	})

	it('ja4 matches', () => {
		expect(got.ja4).toBe(expected.ja4)
	})

	it('akamai_fingerprint matches', () => {
		expect(got.akamai).toBe(expected.akamai)
	})

	it('peetprint matches', () => {
		expect(got.peetprint).toBe(expected.peetprint)
	})
})
