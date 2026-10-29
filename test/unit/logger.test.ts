// Logger: levels + JSON mode.

import { afterEach, expect, it } from 'vitest'

import logger from '../../lib/models/log.ts'

interface JsonRecord {
	level: string
	mod: string
	msg: string
	ts: string
}

function captureLogs(fn: () => void): string[] {
	const orig = console.log
	const out: string[] = []
	console.log = (...args: unknown[]) => { out.push(String(args[0])) }
	try { fn() } finally { console.log = orig }
	return out
}

afterEach(() => {
	logger.setJsonMode(false)
	logger.setLevel('off')
})

it('default level is off (silent)', () => {
	logger.setLevel('off')
	const log = logger('[t]')
	const out = captureLogs(() => { log.error('err'); log.warn('warn'); log.notify('info') })
	expect(out).toStrictEqual([])
})

it('level=info shows info/warn/error but not debug/trace', () => {
	logger.setLevel('info')
	const log = logger('[t]')
	const out = captureLogs(() => { log.error('err'); log.warn('warn'); log.notify('info'); log.debug('debug'); log.trace('trace') })
	expect(out.length).toBe(3)
})

it('JSON mode emits JSON-line records', () => {
	logger.setLevel('info')
	logger.setJsonMode(true)
	const log = logger('[tls]')
	const out = captureLogs(() => log.notify('handshake complete', { ms: 42 }))
	expect(out.length).toBe(1)
	const rec = JSON.parse(out[0]) as JsonRecord
	expect(rec.level).toBe('info')
	expect(rec.mod).toBe('[tls]')
	expect(rec.msg).toMatch(/handshake complete/)
	expect(rec.msg).toMatch(/"ms":42/)
	expect(new Date(rec.ts).toString()).not.toBe('Invalid Date')
	expect(rec.ts).toBeTruthy()
})

it('JSON mode survives non-serializable args (no crash)', () => {
	logger.setLevel('error')
	logger.setJsonMode(true)
	const log = logger('[t]')
	const circular: Record<string, unknown> = {}
	circular.self = circular
	const out = captureLogs(() => log.error('oops', circular))
	expect(out.length).toBe(1)
	// Just verify it didn't throw and produced a record.
	const rec = JSON.parse(out[0]) as JsonRecord
	expect(rec.level).toBe('error')
})
