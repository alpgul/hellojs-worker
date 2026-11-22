// Turn a V8 .cpuprofile into file/function-level self and total time tables.
//
//   npm run bench:analyze -- test/bench/.out/Isolate-xxx.cpuprofile
//   TOP=40 npm run bench:analyze -- <profile>
//
// No external dependency: the profile is plain JSON and timeDeltas are in microseconds.

import * as fs from 'node:fs'
import * as path from 'node:path'

interface CallFrame {
	functionName: string
	url: string
	lineNumber: number
	columnNumber: number
}

interface ProfileNode {
	id: number
	callFrame: CallFrame
	children?: number[]
	hitCount?: number
}

interface CpuProfile {
	nodes: ProfileNode[]
	samples: number[]
	timeDeltas: number[]
}

interface TimeRow {
	key: string
	selfUs: number
	totalUs: number
}

const arg = process.argv.find((a) => a.endsWith('.cpuprofile'))
if (!arg) {
	console.error('usage: node test/bench/analyze.ts <file.cpuprofile>  (TOP=40 to widen the tables)')
	process.exit(1)
}

const TOP = Number(process.env.TOP ?? 25)
const profile = JSON.parse(fs.readFileSync(arg, 'utf8')) as CpuProfile
const byId = new Map<number, ProfileNode>()
const parent = new Map<number, number>()

for (const node of profile.nodes) {
	byId.set(node.id, node)
	for (const child of node.children ?? []) parent.set(child, node.id)
}

const selfUs = new Map<number, number>()
let sampledUs = 0
for (let i = 0; i < profile.samples.length; i++) {
	const us = profile.timeDeltas[i] ?? 0
	const id = profile.samples[i]!
	selfUs.set(id, (selfUs.get(id) ?? 0) + us)
	sampledUs += us
}

// Push each sample's self time up the stack so a caller's "total" includes its callees.
const totalUs = new Map(selfUs)
for (const [id, us] of selfUs) {
	let current = parent.get(id)
	while (current != null) {
		totalUs.set(current, (totalUs.get(current) ?? 0) + us)
		current = parent.get(current)
	}
}

function label(node: ProfileNode): string {
	const frame = node.callFrame
	const fn = frame.functionName || '(anonymous)'
	if (!frame.url) return fn
	const file = frame.url.startsWith(process.cwd() + '/')
		? frame.url.slice(process.cwd().length + 1)
		: path.basename(frame.url)
	return `${fn} @ ${file}:${frame.lineNumber + 1}`
}

function fileLabel(node: ProfileNode): string {
	const url = node.callFrame.url
	if (!url) return '(native / internal)'
	return url.startsWith(process.cwd() + '/') ? url.slice(process.cwd().length + 1) : path.basename(url)
}

function table(title: string, rows: TimeRow[], limit: number): void {
	console.log(`\n--- ${title} ---`)
	console.log(`function / file`.padEnd(78) + 'self(ms)  total(ms)  self%')
	console.log('-'.repeat(104))
	for (const row of rows.slice(0, limit)) {
		console.log(
			row.key.padEnd(78).slice(0, 78) +
				(row.selfUs / 1000).toFixed(1).padStart(9) +
				(row.totalUs / 1000).toFixed(1).padStart(11) +
				(sampledUs ? ((row.selfUs / sampledUs) * 100).toFixed(1) : '0.0').padStart(7)
		)
	}
}

const functions = new Map<string, TimeRow>()
const files = new Map<string, TimeRow>()
for (const [id, us] of selfUs) {
	const node = byId.get(id)
	if (!node) continue
	const fnKey = label(node)
	const fileKey = fileLabel(node)
	const fnRow = functions.get(fnKey) ?? { key: fnKey, selfUs: 0, totalUs: 0 }
	const fileRow = files.get(fileKey) ?? { key: fileKey, selfUs: 0, totalUs: 0 }
	fnRow.selfUs += us
	fnRow.totalUs += totalUs.get(id) ?? 0
	fileRow.selfUs += us
	fileRow.totalUs += totalUs.get(id) ?? 0
	functions.set(fnKey, fnRow)
	files.set(fileKey, fileRow)
}

const bySelf = (a: TimeRow, b: TimeRow) => b.selfUs - a.selfUs
const byTotal = (a: TimeRow, b: TimeRow) => b.totalUs - a.totalUs

console.log(`profile: ${arg}`)
console.log(`samples: ${profile.samples.length}  sampled time: ${(sampledUs / 1000).toFixed(1)} ms`)
table(`Top functions by self time (TOP=${TOP})`, [...functions.values()].sort(bySelf), TOP)
table(`Top functions by total time (TOP=${TOP})`, [...functions.values()].sort(byTotal), TOP)
table(`Top files by self time (TOP=${TOP})`, [...files.values()].sort(bySelf), TOP)
