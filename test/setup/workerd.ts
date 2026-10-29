// Runs inside workerd before every file of the "workers" project.
//
// These are the same two module-scope fixes examples/worker.ts makes: workerd's node:tls ships an
// empty trust store, and the sandbox has no node:dgram. The pool reuses a Worker's module cache
// between test files, so this setup file — not `isolate` — is what resets the library's globals.

import roots from '../../examples/root-certificates.ts'
import * as udp from '../../lib/h3/udp.ts'
import { setTrustedRoots } from '../../lib/tls/cert-validate.ts'

udp.setUdpProvider(null)
setTrustedRoots(roots)
