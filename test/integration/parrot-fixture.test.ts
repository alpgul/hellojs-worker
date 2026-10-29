// Verify a captured parrot.json still round-trips against tls.peet.ws.
//
// Unlike parrot.test.ts, which captures a FRESH baseline each run, this reads a pre-captured
// fixture — the JSON you originally used to build the profile — and checks that a live request
// through hellojs still produces the same JA4 / peetprint / akamai_fingerprint. This is the
// regression test for "it matched before, does it still".
//
// Usage:
//   PARROT_FIXTURE=/path/to/parrot.json npx vitest run --project network test/integration/parrot-fixture
//
// Without the env var there is no fixture to check, so the whole file skips.
//
// Why not JA3: Chrome (and our impl mirroring it) shuffles the middle of the extension
// block per TLS instance, so JA3 hash — computed over extensions in wire order — varies
// run to run. JA4, peetprint, and akamai_fingerprint are all extension-order-invariant.

import * as fs from 'node:fs'

import { beforeAll, describe, expect, it } from 'vitest'

import request from '../../index.ts'
import * as profiles from '../../lib/profiles/index.ts'

import type { PeetJson } from '../../lib/profiles/from-peet.ts'

const FIXTURE_PATH = process.env.PARROT_FIXTURE

// peet.ws lists an extension it has never heard of as "Unknown extension 0x44cd"; once it
// learns the name the id appears in parentheses at the end of the label instead.
const UNKNOWN = /^Unknown extension\s+(?:0x([0-9a-fA-F]+)|(\d+))$/
const TRAILING_ID = /\((?:0x([0-9a-fA-F]+)|(\d+))\)\s*$/

function idFrom(m: RegExpExecArray | null): number | null {
	return m ? (m[1] ? Number.parseInt(m[1], 16) : Number.parseInt(m[2], 10)) : null
}

const unknownIds = (body: PeetJson): number[] =>
	(body.tls?.extensions ?? []).map((e) => idFrom(UNKNOWN.exec(String(e.name)))).filter((id): id is number => id !== null)

// Every id peet.ws named on the wire, known or not — the superset the unknown ones must appear in.
const sentIds = (body: PeetJson): Set<number> =>
	new Set((body.tls?.extensions ?? [])
		.map((e) => idFrom(TRAILING_ID.exec(String(e.name))) ?? idFrom(UNKNOWN.exec(String(e.name))))
		.filter((id): id is number => id !== null))

const known = {
	ja4: undefined as string | undefined,
	peetprint: undefined as string | undefined,
	akamai: undefined as string | undefined,
}
let live: PeetJson = {}
let fixture: PeetJson = {}

beforeAll(async () => {
	if (!FIXTURE_PATH) return
	fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8')) as PeetJson
	known.ja4 = fixture.tls?.ja4
	known.peetprint = fixture.tls?.peetprint_hash
	known.akamai = fixture.http2?.akamai_fingerprint_hash
	if (!known.ja4 || !known.peetprint || !known.akamai) {
		throw new Error('Fixture is missing tls.ja4 / tls.peetprint_hash / http2.akamai_fingerprint_hash')
	}

	// Register the profile from the captured JSON. The profile is TLS-fingerprint-only
	// (extensionOrder, ciphers, GREASE positions, H/2 settings, etc.) — it does NOT inject
	// HTTP request headers automatically. Callers pull the captured header order off the
	// profile object and pass it as opts.headers so their HTTP layer matches Chrome too.
	const profile = profiles.registerFromPeet('parrot-fixture', fixture)

	live = await request<PeetJson>({
		url: 'https://tls.peet.ws/api/all',
		json: true,
		profile: 'parrot-fixture',
		headers: profile.headers ? { ...profile.headers } : undefined,
		resolveWithFullResponse: false,
		timeouts: { tlsHandshake: 15_000, response: 15_000 },
	})
})

describe.skipIf(!FIXTURE_PATH)('parrot fixture round-trip', () => {
	it('ja4 still matches the fixture', () => {
		expect(live.tls?.ja4).toBe(known.ja4)
	})

	it('peetprint still matches the fixture', () => {
		expect(live.tls?.peetprint_hash).toBe(known.peetprint)
	})

	it('akamai_fingerprint still matches the fixture', () => {
		expect(live.http2?.akamai_fingerprint_hash).toBe(known.akamai)
	})

	// Also verify the unknown-extension IDs the fixture asked for actually round-tripped.
	// tls.peet.ws lists them in tls.extensions with the same "Unknown extension N" labels
	// (or their proper names if peet learned about them since capture).
	it('every unknown extension id the fixture advertised is still on the wire', () => {
		const wanted = unknownIds(fixture)
		if (!wanted.length) return
		const onTheWire = sentIds(live)
		expect(wanted.filter((id) => !onTheWire.has(id)).map((id) => `0x${id.toString(16)}`)).toStrictEqual([])
	})
})
