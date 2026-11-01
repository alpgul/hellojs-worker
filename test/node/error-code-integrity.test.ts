// Error-code integrity.
//
// Subsystems tag errors deliberately (`err.code = 'ETLS_ALERT'`, `_certFail('ECERTPARSE', …)`),
// and `wrap()` keeps a tagged code only when it exists in the CODES taxonomy — otherwise the code
// silently degrades to `EPROTO` and the caller loses the diagnosis. These tests pin that contract
// from three directions so the three lists (emitters, taxonomy, published types) cannot drift.

import * as fs from 'node:fs'
import * as path from 'node:path'

import { expect, it } from 'vitest'

import { TLS } from '../../lib/tls/tls.ts'
import { CODES, CATEGORY, wrap } from '../../lib/errors.ts'

const ROOT = path.resolve(__dirname, '..', '..')

function walk(dir: string, out: string[] = []): string[] {
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		const p = path.join(dir, entry.name)
		if (entry.isDirectory()) walk(p, out)
		else if (entry.name.endsWith('.ts')) out.push(p)
	}
	return out
}

// Codes the source deliberately attaches to errors at their point of origin.
function taggedCodes(): string[] {
	const found = new Set<string>()
	const patterns = [
		/\.code\s*=\s*'(E[A-Z0-9_]+)'/g, //   err.code = 'ETLS_ALERT'
		/_certFail\(\s*'(E[A-Z0-9_]+)'/g, //  this._certFail('ECERTPARSE', …)
	]
	for (const file of walk(path.join(ROOT, 'lib'))) {
		const text = fs.readFileSync(file, 'utf8')
		for (const re of patterns) {
			for (const m of text.matchAll(re)) found.add(m[1])
		}
	}
	return [...found].sort()
}

it('every code tagged by a subsystem exists in the CODES taxonomy', () => {
	const missing = taggedCodes().filter((code) => !(code in CODES))
	expect(missing, `wrap() would collapse these to EPROTO: ${missing.join(', ')}`).toEqual([])
})

it('the taxonomy assigns every tagged code a real category', () => {
	for (const code of taggedCodes()) {
		expect(CODES[code as keyof typeof CODES]?.category, `${code} category`).toBeTruthy()
	}
})

it('index.d.ts declares every taxonomy code', () => {
	const dts = fs.readFileSync(path.join(ROOT, 'index.d.ts'), 'utf8')
	const union = /export type HellojsErrorCode =([\s\S]*?)\n\n/.exec(dts)
	expect(union, 'HellojsErrorCode union not found in index.d.ts').not.toBeNull()
	const declared = new Set([...union![1].matchAll(/'([A-Z0-9_]+)'/g)].map((m) => m[1]))
	const absent = Object.keys(CODES).filter((code) => !declared.has(code))
	expect(absent, `index.d.ts is missing ${absent.join(', ')}`).toEqual([])
})

it('a fatal TLS alert surfaces as ETLS_ALERT with the tls category', () => {
	// The code emitted on the wire path and the code in the taxonomy must be the SAME spelling,
	// otherwise wrap() below cannot find it and the caller sees EPROTO instead.
	const t = new TLS('127.0.0.1', 1, null)
	let raw!: Error & { code?: string }
	t.on('error', (e) => { raw = e as Error & { code?: string } })
	;(t as unknown as { _handleAlert(level: number, desc: number, where: string): void })
		._handleAlert(2, 40, 'unit-test')

	expect(raw.code, 'emitted code').toBe('ETLS_ALERT')
	const e = wrap(raw)
	expect(e.code).toBe('ETLS_ALERT')
	expect(e.category).toBe(CATEGORY.TLS)
	expect(e.cause).toBe(raw)
})
