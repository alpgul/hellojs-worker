// Byte comparison for tests.
//
// `expect(a).toStrictEqual(b)` also checks constructors, so a Buffer and a Uint8Array holding the
// same bytes are not equal — every protocol test here compares bytes that arrive as one or the
// other across two runtimes. Comparing hex keeps the assertion byte-exact and identical in workerd
// and in Node.

function hex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('hex')
}

export { hex }
