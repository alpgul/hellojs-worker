import request from './lib/client.ts'
import * as udp from './lib/h3/udp.ts'
import { observability } from './lib/observability.ts'
import * as profiles from './lib/profiles/index.ts'
import { setTrustedRoots } from './lib/tls/cert-validate.ts'
import { clearSessionTickets } from './lib/tls/session-tickets.ts'
import { TLS } from './lib/tls/tls.ts'

// Preserve the historic property access (`request.TLS`) alongside named exports.
// Object.assign mutates and returns the same function object, so both spellings work.
const api = Object.assign(request, { TLS, observability, profiles, udp, setTrustedRoots, clearSessionTickets })

export default api
export { HellojsError } from './lib/errors.ts'
export { TLS, observability, profiles, setTrustedRoots, clearSessionTickets, udp }
export type { PerPhaseTimeouts } from './lib/connect.ts'
export type { Callback, DefaultsFn, Invokable, RequestFn, RequestOptions, Response, RetryPolicy } from './lib/client.ts'
export type { ErrorCode as HellojsErrorCode, ErrorCategory as HellojsErrorCategory } from './lib/errors.ts'
