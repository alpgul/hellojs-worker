// Unit test for TLS._profileNeedsMlkem — the gate that decides whether MLKEM keygen and
// key_share construction run during connect(). TLS-1.2-only / non-key_share profiles must
// not pay the MLKEM cost.

import { expect, it } from 'vitest'

import { TLS } from '../../lib/tls/tls.ts'

import type { TlsProfile } from '../../lib/profiles/types.ts'

// Synthesize a TLS instance with just enough state to invoke _profileNeedsMlkem(). Constructing
// with a host opens no socket; we then replace the profile with the branch under test, keeping
// every other tls field absent so the legacy fall-through is actually exercised.
function withProfile(tls: Partial<TlsProfile>): boolean {
	const t = new TLS('example.com', 443, null)
	t.profile = { name: 'synthetic', tls: tls as TlsProfile, http2: {} }
	return t._profileNeedsMlkem()
}

it('_profileNeedsMlkem: chrome147-default (no supportedVersions, no extensionOrder) → true', () => {
	expect(withProfile({})).toBe(true)
})

it('_profileNeedsMlkem: explicit supportedVersions incl. TLS 1.3 → true', () => {
	expect(withProfile({ supportedVersions: [0x0304, 0x0303] })).toBe(true)
})

it('_profileNeedsMlkem: TLS-1.2-only supportedVersions → false', () => {
	expect(withProfile({ supportedVersions: [0x0303] })).toBe(false)
})

it('_profileNeedsMlkem: extensionOrder without id 51 → false', () => {
	expect(withProfile({
		extensionOrder: [{ id: 0 }, { id: 10 }, { id: 43 }],
	})).toBe(false)
})

it('_profileNeedsMlkem: extensionOrder with id 51 → true', () => {
	expect(withProfile({
		extensionOrder: [{ id: 0 }, { id: 51 }, { id: 43 }],
	})).toBe(true)
})

it('_profileNeedsMlkem: GREASE markers in extensionOrder are skipped', () => {
	expect(withProfile({
		extensionOrder: [{ grease: true }, { id: 0 }, { id: 10 }],
	})).toBe(false)
})
