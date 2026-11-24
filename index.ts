import request from './lib/client.ts'
import * as udp from './lib/h3/udp.ts'
import { observability } from './lib/observability.ts'
import { clearPool, setPoolConfig } from './lib/pool.ts'
import * as profiles from './lib/profiles/index.ts'
import { addProxy, getProxyList, removeProxy, setProxyPool } from './lib/proxy-store.ts'
import { setTrustedRoots } from './lib/tls/cert-validate.ts'
import { clearSessionTickets } from './lib/tls/session-tickets.ts'
import { TLS } from './lib/tls/tls.ts'

// Preserve the historic property access (`request.TLS`) alongside named exports.
// Object.assign mutates and returns the same function object, so both spellings work.
const api = Object.assign(request, {
	TLS,
	observability,
	profiles,
	udp,
	setTrustedRoots,
	clearSessionTickets,
	setPoolConfig,
	clearPool,
	setProxyPool,
	addProxy,
	removeProxy,
	getProxyList
})

export default api
export { HellojsError } from './lib/errors.ts'
export { TLS, observability, profiles, setPoolConfig, clearPool, setTrustedRoots, clearSessionTickets, udp }
export { setProxyPool, addProxy, removeProxy, getProxyList }
export type { ProxyPoolEntry } from './lib/proxy-store.ts'
export type {
	DefaultsFn,
	FetchInit,
	HttpMethod,
	Invokable,
	ProxyOptions,
	RedirectMode,
	RegisteredHttpMethod,
	RequestBodyValue,
	RequestFn,
	RequestOptions,
	Response,
	RetryPolicy
} from './lib/client.ts'
export type { ErrorCode as HellojsErrorCode, ErrorCategory as HellojsErrorCategory } from './lib/errors.ts'
