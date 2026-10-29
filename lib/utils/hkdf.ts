// HKDF Helper functions
import * as crypto from 'node:crypto'

type Bytes = Buffer | Uint8Array

function Extract(hash: string, salt: Bytes, ikm: Bytes): Buffer {
	return crypto.createHmac(hash, salt).update(ikm).digest()
}

// HKDF-Expand with arbitrary info
function Expand(hash: string, prk: Bytes, info: Bytes, L: number, hashlen: number): Buffer {
	const n = Math.ceil(L / hashlen)
	const T: Buffer[] = []
	let prev = Buffer.alloc(0)
	for (let i = 1; i <= n; i++) {
		const h = crypto.createHmac(hash, prk)
		h.update(prev)
		h.update(info)
		h.update(Buffer.from([i])) // counter
		prev = h.digest()
		T.push(prev)
	}
	return Buffer.concat(T).subarray(0, L)
}

// RFC 8446: HKDF-Expand-Label(secret, label, context, L)
function ExpandLabel(secret: Bytes, label: string, context: Bytes | null, L: number, hash: string, hashlen: number): Buffer {
	const fullLabel = Buffer.from('tls13 ' + label, 'ascii')
	const ctx = Buffer.from(context || [])
	const info = Buffer.concat([
		// uint16 length
		Buffer.from([(L >> 8) & 0xff, L & 0xff]),
		// opaque label<7..255>
		Buffer.from([fullLabel.length]),
		fullLabel,
		// opaque context<0..255>
		Buffer.from([ctx.length]),
		ctx
	])

	return Expand(hash, secret, info, L, hashlen)
}

function sha256(...bufs: Bytes[]): Buffer {
	const h = crypto.createHash('sha256')
	bufs.forEach(b => h.update(b))
	return h.digest()
}

function sha384(...bufs: Bytes[]): Buffer {
	const h = crypto.createHash('sha384')
	bufs.forEach(b => h.update(b))
	return h.digest()
}

export {
	Extract,
	Expand,
	ExpandLabel,
	sha256,
	sha384
}
