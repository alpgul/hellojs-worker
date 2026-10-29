import request from './lib/client.js'
import * as udp from './lib/h3/udp.js'
import { observability } from './lib/observability.ts'
import * as profiles from './lib/profiles/index.ts'
import { setTrustedRoots } from './lib/tls/cert-validate.js'
import { TLS } from './lib/tls/tls.js'

// Preserve the historic property access (`request.TLS`) alongside named exports.
request.TLS = TLS
request.observability = observability
request.profiles = profiles
request.udp = udp
request.setTrustedRoots = setTrustedRoots

export default request
export { TLS, observability, profiles, setTrustedRoots, udp }
