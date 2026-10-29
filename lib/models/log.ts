// Internal logger.
//
// Silent by default — a published library shouldn't write to stdout/stderr in normal
// operation; errors flow through `emit('error', ...)` per Node convention.
//
// Configuration:
//   HELLOJS_LOG=error|warn|info|debug|trace    — choose the level (default: silent/off)
//   HELLOJS_LOG_JSON=1                         — emit JSON-line records (one per line) for
//                                                ingestion into structured-log pipelines
//   HELLOJS_DEBUG=1                            — legacy alias for `trace`
//   -d on argv                                 — legacy alias for `trace`
//   ENV=development                            — legacy alias for `trace`
//
// In-process:
//   import log from './log.ts'
//   log.setLevel('info')
//   log.setJsonMode(true)
//
// Level ordering (each level shows itself + everything more severe):
//   off (0) < error (1) < warn (2) < info (3) < debug (4) < trace (5)

const LEVELS = { off: 0, error: 1, warn: 2, info: 3, debug: 4, trace: 5 } as const

type LevelName = keyof typeof LEVELS

export interface Logger {
	error: (...m: unknown[]) => false
	warn: (...m: unknown[]) => void
	success: (...m: unknown[]) => true
	notify: (...m: unknown[]) => void
	pretty: (...m: unknown[]) => void
	debug: (...m: unknown[]) => void
	trace: (...m: unknown[]) => void
}

interface LoggerFactory {
	(prefix?: string): Logger
	setLevel(level: number | string): void
	getLevel(): number
	setJsonMode(enabled: unknown): void
	getJsonMode(): boolean
	LEVELS: typeof LEVELS
}

function resolveInitialLevel(): number {
	const v = process.env.HELLOJS_LOG
	if (v && Object.prototype.hasOwnProperty.call(LEVELS, v.toLowerCase())) {
		return LEVELS[v.toLowerCase() as LevelName]
	}
	const argv = Array.isArray(process.argv) ? process.argv : []
	if (process.env.HELLOJS_DEBUG === '1' || argv.includes('-d') || process.env.ENV === 'development') {
		return LEVELS.trace
	}
	return LEVELS.off
}

let currentLevel = resolveInitialLevel()
let jsonMode = process.env.HELLOJS_LOG_JSON === '1'

function setLevel(level: number | string): void {
	if (typeof level === 'number') { currentLevel = level; return }
	const n = LEVELS[String(level).toLowerCase() as LevelName]
	if (n != null) currentLevel = n
}

function getLevel(): number { return currentLevel }

function setJsonMode(enabled: unknown): void { jsonMode = !!enabled }
function getJsonMode(): boolean { return jsonMode }

const ts = (): string => {
	const d = new Date()
	const pad = (n: number, w = 2): string => String(n).padStart(w, '0')
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
		`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}:${pad(d.getMilliseconds(), 3)}`
}

const colored = (color: string, prefix: string, msg: unknown[]): string => `\x1B[${color}m[${ts()}] ${prefix}${msg.join(' ')}\x1B[0m`

function jsonLine(level: string, prefix: string, args: unknown[]): string {
	const rec = {
		ts: new Date().toISOString(),
		level,
		mod: prefix.trim() || null,
		msg: args.map((x) => typeof x === 'string' ? x : (() => { try { return JSON.stringify(x) } catch { return String(x) } })()).join(' '),
	}
	return JSON.stringify(rec)
}

const logger = ((prefix = '') => {
	if (prefix !== '') prefix = `${prefix} `

	const emit = (level: LevelName, color: string, label: string) => (...m: unknown[]): void => {
		if (currentLevel < LEVELS[level]) return
		if (jsonMode) console.log(jsonLine(level, prefix, m))
		else console.log(colored(color, label + prefix, m))
	}

	const log: Logger = {
		error: (...m) => { emit('error', '31', '')(...m); return false },
		warn: emit('warn', '33', ''),
		success: (...m) => { emit('info', '32', '')(...m); return true },
		notify: emit('info', '36', ''),
		pretty: emit('debug', '35', ''),
		debug: emit('debug', '1;37;40', '[DEBUG] '),
		trace: emit('trace', '90', '[TRACE] '),
	}
	return log
}) as LoggerFactory

logger.setLevel = setLevel
logger.getLevel = getLevel
logger.setJsonMode = setJsonMode
logger.getJsonMode = getJsonMode
logger.LEVELS = LEVELS

export default logger
