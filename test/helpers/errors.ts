// The rejection reason of a promise, as the library's own error type.
//
// Tests that care about `code` need this rather than `rejects.toThrow(/message/)`: the code is a
// property, not part of the message, and asserting only the message lets a different failure with a
// similar message pass.

import { expect } from 'vitest'

import type { HellojsError } from '../../lib/errors.ts'

async function rejection(promise: Promise<unknown>): Promise<HellojsError> {
	return promise.then(() => expect.unreachable('expected the promise to reject'), (error) => error as HellojsError)
}

export { rejection }
