# @unreleased/hellojs

[![Quality gate status](https://sonarcloud.io/api/project_badges/measure?project=alpgul_hellojs-worker&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=alpgul_hellojs-worker)
[![codecov](https://codecov.io/github/alpgul/hellojs-worker/graph/badge.svg?token=J5HFV1NLHF)](https://codecov.io/github/alpgul/hellojs-worker)

A Node.js HTTP client whose on-the-wire TLS handshake, HTTP/2 setup, and
HTTP/3 (QUIC) flight produces **the same JA4 / Akamai / peetprint
fingerprint as Chrome 147 on macOS**. Fetch-shaped API — always a real
`Response`, with `request(input, init)` and method shortcuts — plus a browser-like
transport that picks h3/h2 automatically.

```bash
npm install @unreleased/hellojs
```

## Install from GitHub (pinned to a tag)

You can install straight from the GitHub repository instead of npm. Pin the
install to a release tag so every checkout gets the same code:

```bash
npm install github:alpgul/hellojs-worker#v0.7.2
```

```json
{
	"dependencies": {
		"@unreleased/hellojs": "github:alpgul/hellojs-worker#v0.7.2"
	}
}
```

The package name is unchanged, so every example below uses the same
`import request from '@unreleased/hellojs'` as the npm install.

Leave off the tag to track the repository's default branch (the latest commit):

```bash
npm install github:alpgul/hellojs-worker
```

List the available tags before pinning a different release:

```bash
git ls-remote --tags https://github.com/alpgul/hellojs-worker.git
```

yarn/pnpm equivalents:

```bash
yarn add github:alpgul/hellojs-worker#v0.7.2
pnpm add github:alpgul/hellojs-worker#v0.7.2
```

```js
import request from '@unreleased/hellojs'

// Fetch-style: resolves a real Response.
const res = await request('https://www.cloudflare.com/')
console.log(res.status, res.ok, await res.text())

// Same shape as fetch: the URL is the input, everything else is init.
// Bodies are serialized by the caller — there is no `json` / `form` option.
const post = await request('https://api.example.com/v1/things', {
	method: 'POST',
	body: JSON.stringify({ name: 'foo' }),
	headers: {
		'content-type': 'application/json',
		authorization: 'Bearer …'
	}
})
const data = await post.json()
```

---

## Table of contents

- [Install from GitHub (pinned to a tag)](#install-from-github-pinned-to-a-tag)
- [Why](#why)
- [Quick start](#quick-start)
- [Request options](#request-options)
- [Method shortcuts and defaults](#method-shortcuts-and-defaults)
- [Cookie jar](#cookie-jar)
- [Timeouts and redirects](#timeouts-and-redirects)
- [Connection pool](#connection-pool)
- [Proxies](#proxies)
- [Observability hooks](#observability-hooks)
- [Parrot: clone any fingerprint](#parrot-clone-any-fingerprint-from-a-tlspeetws-response)
- [Fingerprint](#fingerprint)
- [HTTP/3 and automatic transport](#http3-and-automatic-transport)
- [Certificate validation](#certificate-validation)
- [TLS 1.3 session resumption](#tls-13-session-resumption)
- [TypeScript](#typescript)
- [Performance](#performance)
- [Testing](#testing)
- [Errors](#errors)
- [Debugging](#debugging)
- [API surface](#api-surface)
- [Architecture](#architecture)
- [Known limitations](#known-limitations)
- [License](#license)

---

## Why

`undici`, `axios`, `got`, `node-fetch`, etc. all emit a TLS / H2 / H3
fingerprint that is unmistakably Node.js:

- Cipher list ordered for OpenSSL defaults, not the BoringSSL shape Chrome ships
- No GREASE values
- No ALPS (application_settings) extension
- No `X25519MLKEM768` hybrid key share
- HTTP/2 SETTINGS in the wrong order, no `WINDOW_UPDATE +15663105`
- Different HEADERS frame flags
- Different `:method` / `:authority` / `:scheme` / `:path` pseudo-header order

Any bot-detection service (Cloudflare Bot Management, PerimeterX, DataDome,
Akamai Bot Manager, …) can identify Node-based traffic from the JA4
fingerprint alone, regardless of what `User-Agent` header you set.

hellojs produces:

```
JA4               = t13d1516h2_8daaf6152771_d8a2da3f94cd
HTTP/2 Akamai     = 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
ALPS              = h2 (v1, type 0x44CD)
key_share         = X25519MLKEM768 + X25519 + GREASE (1216-byte hybrid share)
extension order   = GREASE-first, per-instance shuffled middle, GREASE-last
```

…all matching a real Chrome 147 capture on every structural fingerprint hash
(JA4, Akamai, peetprint). Per-connection randomized fields (GREASE values,
`client_random`, key_share bytes, extension shuffle order) rotate every
handshake — same as a real Chrome browser.

---

## Quick start

```js
// Like fetch: 4xx/5xx resolve as a Response, so inspect res.ok/res.status.
const r = await request('https://httpbingo.org/status/418')
console.log(r.status, r.ok) // 418 false
await r.text() // drain the stream

// Read the response body the fetch way.
const body = await (await request('https://httpbingo.org/get')).json()
console.log(body.url)

// POST JSON — serialize it yourself and label the body.
await request('https://httpbingo.org/post', {
	method: 'POST',
	body: JSON.stringify({ hello: 'world' }),
	headers: { 'content-type': 'application/json' }
})

// POST form — URLSearchParams supplies the content-type automatically.
await request('https://httpbingo.org/post', {
	method: 'POST',
	body: new URLSearchParams({ user: 'alice', role: 'admin' })
})

// Query string — part of the input URL.
const url = new URL('https://httpbingo.org/get')
url.search = new URLSearchParams({ hello: 'world', n: String(42) }).toString()
await request(url)
```

---

## Request options

The URL is the **first argument** (`string`, `URL` or `Request`); there is no `url`/`uri` field
in `init`. Everything else is fetch-shaped:

| Option      | Type                              | Default           | Notes                                                                                                                                                                                                                                                                                                                                                                                                   |
| ----------- | --------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `method`    | `HttpMethod`                      | `'GET'`           | Registered HTTP methods in either case (`GET`/`get`, `PATCH`/`patch`, …). The runtime still accepts any HTTP token; the type is deliberately closed.                                                                                                                                                                                                                                                    |
| `headers`   | `HeadersInit`                     | `{}`              | `Headers`, tuple lists or plain records; merged into the profile's header set. Non-identity keys override in place, new keys append. Identity headers (`user-agent`, `sec-ch-ua*`) are fixed by the profile — a different value throws `EHEADERFIXED`.                                                                                                                                                  |
| `body`      | `BodyInit`                        | `null`            | `string`, `Buffer`/`Uint8Array`, `ArrayBuffer`, `Blob`, `FormData`, `URLSearchParams`, web `ReadableStream`. No plain objects and no Node `Readable`; serialize JSON with `JSON.stringify`. Only body types with their own media type (`FormData`, `URLSearchParams`, typed `Blob`) set `content-type` automatically.                                                                                   |
| `jar`       | `request.jar()`                   | —                 | cookie persistence across requests                                                                                                                                                                                                                                                                                                                                                                      |
| `redirect`  | `'follow' \| 'manual' \| 'error'` | `'follow'`        | fetch-style redirect handling; `follow` stops after **20 hops** (the Fetch standard limit) with `ETOOMANYREDIRECTS`.                                                                                                                                                                                                                                                                                    |
| `signal`    | `AbortSignal`                     | —                 | The only user-controlled deadline: abort before headers rejects the promise; after headers `res.body` errors. `AbortSignal.timeout(ms)` is the recommended way to cap a request.                                                                                                                                                                                                                        |
| `proxy`     | object                            | —                 | `{ url, authorization?, headers?, keepAlive? }` — all proxy settings live here; see [Proxies](#proxies). `proxy: null` clears a default.                                                                                                                                                                                                                                                                |
| `retry`     | object                            | none              | `{ limit, methods, statusCodes, baseDelayMs }`; status-based retries inspect `res.status` directly                                                                                                                                                                                                                                                                                                      |
| `profile`   | string                            | `'chrome147-mac'` | which fingerprint profile to emit                                                                                                                                                                                                                                                                                                                                                                       |
| `keepalive` | bool                              | `true`            | Reuse live h2/h3/h1 connections across requests (h2 multiplexes streams onto one socket per origin, h3 reuses the QUIC session, h1 parks an exclusive socket between requests). Pass `false` for one-shot connections. When the pool has no capacity the request opens a connection and closes it after the response, so this can never hold more sockets than the [pool caps](#connection-pool) allow. |
| `verifyTLS` | bool                              | `true`            | Validate the server certificate chain (RFC 5280) + hostname (RFC 6125 SubjectAltName) on the TCP h2/h1 path. The pure-JS QUIC/h3 path does not currently validate chains; see [Certificate validation](#certificate-validation).                                                                                                                                                                        |

Removed options (`url`, `uri`, `json`, `form`, `qs`, `gzip`, `resume`, `h3`,
`maxRedirects`, `timeout`, `timeouts`), the object call form, and callbacks all
reject with `EBADOPTS` at runtime and are rejected by `index.d.ts` in TypeScript.
Compression is always automatic; transport, TLS resumption and redirect limits
are internal state — see [Timeouts and redirects](#timeouts-and-redirects) and
[HTTP/3 and automatic transport](#http3-and-automatic-transport).

> Responses always stream, like `fetch()`: `request()` resolves once the headers arrive and
> `Response.body` delivers the rest progressively. Redirects are the exception — their
> (small) bodies are buffered first so the redirect policy can run. Read a body with
> `res.text()`, `res.json()`, `res.arrayBuffer()`, or `res.body`.

### Headers and profiles

Every request carries the resolved profile's header set automatically, in the profile's
order (`sec-ch-ua*`, `user-agent`, `accept`, `sec-fetch-*`, …). Your `headers` entries
override non-identity values without moving them; new names append after the profile
block. Identity headers are fixed by the profile — `user-agent` and the `sec-ch-ua*`
client hints for Chrome profiles, `user-agent` alone for `firefox147` — and a
conflicting value is rejected with `EHEADERFIXED`. Custom profiles can extend the fixed
set with a `fixedHeaders` array of lowercase names. Cookie-jar `Cookie` is inserted just
before `priority`, matching the browser header order.

---

## Method shortcuts and defaults

```js
await request.get('https://httpbingo.org/get')
await request.post('https://httpbingo.org/post', { body: '...' })
await request.put('https://...', { body: JSON.stringify({ … }) })
await request.del('https://...')
await request.patch('https://...', { body: new URLSearchParams({ … }) })
await request.head('https://...')
await request.options('https://...')

const api = request.defaults({
  headers: { 'x-api-key': '…' },
})

const r = await api('https://api.example.com/users') // Response
const data = await r.json()
const r2 = await api.get('https://api.example.com/things/42')
```

---

## Cookie jar

RFC 6265-compliant. Domain matching, path matching, `Secure`/`HttpOnly`/`SameSite`,
`Expires`/`Max-Age`, host-only vs domain cookies, longest-path-first ordering, public
suffix list defense.

```js
const jar = request.jar()

await request('https://example.com/login', {
	jar,
	method: 'POST',
	body: new URLSearchParams({ user: '…', pass: '…' })
})

// Subsequent requests sharing the same jar send saved cookies automatically.
// Domain matching, path matching, Secure on https-only, all honored.
const me = await request('https://example.com/account', { jar })
```

To defend against supercookies (`Domain=co.uk`), plug in a public suffix list:

```js
const jar = request.jar()
// A Set or a function(host) -> boolean
jar.setPublicSuffixList(new Set(['co.uk', 'github.io' /* ... */]))
```

The jar drops expired cookies automatically on read; call `jar.gc()` to bound memory
under high churn.

---

## Timeouts and redirects

There are no `timeout`, `timeouts` or `maxRedirects` options. Like a browser, hellojs
owns the transport deadlines and keeps its own redirect state:

| Phase                     | Fixed budget | Behavior on expiry                                          |
| ------------------------- | ------------ | ----------------------------------------------------------- |
| TCP connect (per attempt) | 30 s         | `ETIMEDOUT`, then the transport race can try the other path |
| Overall connect job       | 30 s         | `ETIMEDOUT`; cancels every in-flight dial                   |
| TLS 1.2/1.3 handshake     | 30 s         | `ETIMEDOUT`                                                 |
| Proxy CONNECT / hop       | 30 s         | `ETIMEDOUT`                                                 |
| QUIC handshake (h3)       | 2 s          | falls back to TCP                                           |
| Redirect chain            | 20 hops      | `ETOOMANYREDIRECTS` (Fetch Standard limit)                  |

These are the Chromium-shaped connect budgets, not a public knob. **There is no
response-header deadline and no body-idle watchdog**: once headers arrive, `request()`
has resolved and a streamed body can stay open as long as the server keeps sending —
the same as `fetch()`. An unconsumed body keeps the socket or stream open until it is
read, cancelled, or the signal aborts.

`signal` is the only user-controlled deadline. Use `AbortSignal.timeout()` for a
whole-request cap, or an `AbortController` for cancellation:

```js
await request('https://api.example.com/v1/things', {
	signal: AbortSignal.timeout(10_000)
})
```

### Streaming response bodies

`request()` always resolves a real fetch `Response`, so `res.body` is a web
`ReadableStream<Uint8Array>` for H1, H2, and H3. **Streaming is the default and the only
mode**, matching `fetch()`: the promise resolves as soon as headers arrive and bytes flow
progressively. `res.text()`, `res.json()` and `res.arrayBuffer()` consume the stream for
you when you do want the whole body.

```js
const res = await request('https://example.com/big.iso')
console.log(res.status, res.headers.get('content-length'))
for await (const chunk of res.body) {
	/* Uint8Array */
}

// Node stream interop:
import { Readable } from 'node:stream'
Readable.fromWeb(res.body).pipe(createWriteStream('./big.iso'))

// Buffer explicitly when you do need the whole body:
const bytes = new Uint8Array(await res.arrayBuffer())
```

Fetch parity details:

- Redirects are followed after their (small) bodies are buffered, so the redirect
  target is complete. 4xx/5xx responses resolve like `fetch()`; inspect `res.ok`.
- Redirects are counted internally and capped at 20 hops — there is no `maxRedirects`
  option. `redirect: 'error'` rejects on the first redirect.
- Errors before headers reject the `request()` promise. Errors after headers reject
  `res.body` and emit `request:error`; they are not retried because the request already
  resolved.
- An unconsumed body keeps the H1 socket / H2 stream alive until it is read, cancelled
  (`res.body.cancel()`) or the signal aborts. There is no body-idle watchdog; use
  `AbortSignal.timeout()` if you need a deadline.
- `simple`, `bodyOnly`, and the request.js callback form were removed. Passing
  `simple: true` or `bodyOnly: true`, or a callback function, rejects with `EBADOPTS`.
- All three transports pause when the consumer falls behind: H2 defers the per-stream
  `WINDOW_UPDATE`, H1 pauses the socket, and H3 withholds QUIC `MAX_DATA` /
  `MAX_STREAM_DATA` grants and pauses the stream. There is no fixed in-process body
  buffer cap and no `EBODYBACKPRESSURE` failure on the h3 path.

The body is auto-decompressed (gzip / brotli / deflate / zstd — through `node:zlib`) before
it reaches `res.body`/`res.text()`/`res.json()`.

### Streaming request bodies

For large uploads, pass a web `ReadableStream` (or any other `BodyInit`). Node streams
are not request bodies anymore; wrap them with `Readable.toWeb()` if needed. On H2/H3
the stream goes out as DATA frames; on H1 it uses `Transfer-Encoding: chunked`.

```js
import { createReadStream } from 'node:fs'
import { Readable } from 'node:stream'

await request('https://upload.example.com/blob', {
	method: 'POST',
	body: Readable.toWeb(createReadStream('./big-file.bin')),
	headers: { 'content-type': 'application/octet-stream' }
})
```

---

## Connection pool

The keep-alive pool owns sockets process-wide, so its caps are configured once with a static
call — they are not a request option. `keepalive` stays per request (default `true`): pass
`false` to opt that request out of the pooled h2/h3/h1 socket. Bundles are keyed by origin,
actual dial target (Alt-Svc can move it) and negotiated protocol, so a stale or different
transport never inherits another endpoint's socket.

```js
import request from '@unreleased/hellojs'

request.setPoolConfig({ maxSockets: 8, maxPerOrigin: 2, idleMs: 30_000 })
await request('https://example.com') // pooled
await request('https://example.com', { keepalive: false }) // one-shot
request.clearPool() // close and forget every pooled socket (test/shutdown helper)
```

Defaults are `{ maxSockets: 16, maxPerOrigin: 1, idleMs: 15_000 }`. `setPoolConfig()` takes a
partial object but **starts from the defaults on every call**: `setPoolConfig({ idleMs: 5_000 })`
resets the other two caps; `setPoolConfig()` restores all defaults. Invalid caps throw
`EBADOPTS`.

The same caps bound the proxy-hop pool ([`proxy.keepAlive`](#reusing-the-proxy-connection),
counted separately). A change applies to sockets released after the call — an already-idle
socket keeps its existing idle timer.

### Keepalive in a Worker (Durable Object)

A Worker isolate is short-lived, and a TCP socket belongs to the isolate that created it —
it cannot be serialized into a Durable Object call or moved to another isolate. A module-scope
pool in a Worker therefore only helps two requests that happen to land on the **same** isolate.
To make reuse deterministic, keep the Worker stateless and let one named Durable Object own
the client and the pool:

```
Worker (stateless) ──stub.fetch()──▶ Durable Object (hellojs + pool) ──▶ origin
```

`examples/connection-do.ts` is that DO. `examples/worker.ts` forwards `/run` to its tour path
and `/proxy?url=...` to its proxy path; the DO calls `request()` with `keepalive: true` (the
default), so later calls reuse the live h2 session for the same origin+profile. Only requests and
responses cross the boundary, never sockets. `wrangler.jsonc` supplies the binding, the
`new_classes` migration and the `ALLOWED_HOSTS` variable used by the Worker's proxy guard.

```jsonc
"durable_objects": { "bindings": [{ "name": "HELLO_POOL", "class_name": "HelloConnectionDO" }] },
"migrations": [{ "tag": "v1", "new_classes": ["HelloConnectionDO"] }],
"vars": { "ALLOWED_HOSTS": "httpbingo.org,tls.peet.ws" }
```

The `/proxy` route is allowlisted on purpose: an unrestricted `?url=` endpoint is an open
relay. Only `http:`/`https:`, no URL credentials, no loopback/private targets, and the hostname
must appear in `ALLOWED_HOSTS`. The same guard is a pure function in
`examples/proxy-policy.ts`, covered by `test/unit/proxy-policy.test.ts`.

**What this does and does not promise:**

- The pool is **in-memory**, not durable. Eviction, a crash, or an idle DO drops it; the next
  request handshakes again. An open socket keeps the DO resident for up to 15 minutes, then
  normal eviction rules resume. `evictDurableObject()` in `test/unit/durable-object.test.ts`
  demonstrates the reset.
- The example calls `setPoolConfig({ idleMs: 60_000 })` inside the DO to widen the reuse window
  from the library's 15s default. A longer idle window costs DO duration time while the socket
  sits open.
- A Durable Object is single-threaded, and hellojs does pure-JS TLS plus h2 framing on that
  thread. CPU work blocks the object's other requests; a single global DO maximizes reuse but
  is also a single point of contention. Shard by `getByName()` if CPU becomes the bottleneck —
  each shard then has its own pool.
- Every request pays for a DO fetch and, while sockets stay open, DO duration. Compare that
  against the handshake latency the pool saves before adopting this in production.

`GET /run` reports `pooledSockets` (one per origin+profile; one-shot requests never
join the pool) so the reuse is observable from the test page. The four slowest scenarios
(external fingerprint host, redirect chain, cookie redirect, h3 fallback) spend most of their
time on network round trips; `GET /run?fast=1` runs four representative scenarios instead
(GET, POST json, custom headers, status), which is the useful mode for a local smoke test.
Every scenario is a live request, so even a plain GET can take 20 s when the upstream is slow.
The test page exposes the same choice as a checkbox.

For an apples-to-apples latency check, `GET /bench?url=https%3A%2F%2Fhttpbingo.org%2Fget&n=5`
runs the same URL five times sequentially in three modes: the Worker's native `fetch()`, hellojs
through the DO with `keepalive: false`, and hellojs with `keepalive: true`. Each hellojs run
starts from an empty pool and the response reports per-request times, totals and medians plus
the final pool size. `&mode=native|false|true` isolates one mode.

**Keep-alive probes.** `GET /keepalive?url=...&mode=paired` sends two sequential origin requests
inside **one** DO fetch; `mode=single` sends one. Two separate `mode=single` Worker requests to
the same DO (the first with `reset=1`) show whether the pool survives between calls; a `slot`
parameter separates concurrent probes into their own named DOs. The JSON report carries the
cumulative counters from `poolStats()` — `created` counts new connections, `hits` counts pooled
hand-outs. `created: 1, hits: 1` in `paired` proves the second request reused the first one's
socket; `created: 0, hits: 1` on the second `single` call proves the DO kept that socket across
Worker requests. The test page exposes both scenarios as buttons.

The automated version needs `npm run example` running first:

```sh
WORKER_URL=http://127.0.0.1:8787 npm run test:network -- test/integration/worker-do-keepalive.test.ts
```

`httpbingo.org` is deliberately the default target even though it is the jitteriest one — the
assertions read counters, not latency. Set `KEEPALIVE_TARGET` to retarget.

`httpbingo.org` is far too jittery to benchmark against (a direct `curl` ranged from 1 s to
30 s between consecutive calls), and it made hellojs look slower than native fetch. Against a
stable target (`GET /bench?url=https%3A%2F%2Fapi.github.com%2F&n=5`), two consecutive runs
gave medians of **~70–85 ms** for hellojs with keepalive, **~420–440 ms** with keepalive off,
and **~290–550 ms** for native fetch — keepalive reuses one h2 socket (`pooledSockets: 1`) and
is 4–5× faster than either one-shot path. Compare medians across repeated runs, not totals.

---

## Proxies

### HTTP CONNECT

```js
await request('https://example.com', { proxy: { url: 'http://user:pass@proxy:8080' } })
```

`url` is required: `proxy: {}` (or a missing/blank URL) rejects with `EBADOPTS` before
any socket is opened. Basic auth credentials in the URL are auto-encoded into
`Proxy-Authorization`. For proxies that require a different scheme (e.g. Guardian/Masque
`Bearer`), pass the full header value as `proxy.authorization` — it overrides URL-derived
Basic auth:

```js
await request('https://example.com', {
	proxy: {
		url: 'https://proxy.example:8443',
		authorization: 'Bearer <jwt>',
		headers: { 'x-tenant': 'acme' },
		keepAlive: true
	}
})
```

`authorization` is the whole answer: a blank value (`''`) sends no `Proxy-Authorization`
even when the proxy URL carries credentials. Extra CONNECT headers go in `proxy.headers`,
where a `proxy-authorization` entry fills the same slot when `authorization` is unset —
ahead of URL Basic, which is the last resort. Both are validated before the proxy is
dialled: CR, LF, control or non-ASCII characters and CONNECT-owned names (`host`,
`connection`, `keep-alive`, …) reject with `EBADOPTS` instead of being written into the
CONNECT request. Neither option applies to `socks5://`, which authenticates from the URL's
username/password and rejects supplied `authorization`/`headers` with `EBADOPTS`.

### Reusing the proxy connection

`proxy.keepAlive` (default `true`) keeps the connection to an `http://`/`ws://`/`https://`/`wss://`
proxy open after the destination session closes, so the next request can issue a fresh
CONNECT over the same socket; pass `false` for one-shot hops. Separate from the request's
`keepalive` (which pools the h2/h3/h1 session to the origin), this pool is bounded by the same
[process-wide caps](#connection-pool)
and counts its sockets separately. One proxy hop is never shared by two live requests; if a
reused hop is dead, it is discarded and the CONNECT retried once on a fresh socket. `socks5://`
and h3 never use the proxy-hop pool.

### HTTPS proxy (CONNECT over TLS)

```js
await request('https://example.com', { proxy: { url: 'https://user:pass@proxy:443' } })
```

`https://` (alias `wss://`) dials the proxy with our own TLS stack first, then sends
the CONNECT request line and `Proxy-Authorization` inside that encrypted session. The
tunnel that follows carries the normal profile-faked handshake to the destination, so
**the fingerprint the destination sees is unchanged** — the extra hop is only ever
visible to the proxy, and it is the proxy's own certificate that gets validated under
`verifyTLS` and the process-wide trusted roots.

| scheme                            | default port | transport to the proxy              |
| --------------------------------- | ------------ | ----------------------------------- |
| `http://`, `ws://` (or no scheme) | 80           | plaintext TCP + CONNECT             |
| `https://`, `wss://`              | 443          | TLS session, then CONNECT inside it |
| `socks5://`, `socks5h://`         | 1080         | SOCKS5 handshake                    |

Known limits: HTTP/3 is not used through a proxy (the automatic transport selects
TCP+CONNECT rather than silently bypassing the proxy), a `407` answer is an `EPROXY`
error instead of a challenge/response round, and a tunneled session pays for two TLS
keypairs — one per hop.

### SOCKS5 (RFC 1928 + RFC 1929)

```js
await request('https://example.com', { proxy: { url: 'socks5://user:pass@proxy:1080' } })
await request('https://example.com', { proxy: { url: 'socks5://proxy:1080' } }) // no-auth
```

`socks5h://` is accepted as an alias. We always do remote DNS resolution (the proxy
resolves the hostname), not client-side, regardless of the scheme.

### Automatic routing for Cloudflare-owned hosts

A Worker cannot open an outbound TCP socket to Cloudflare's own IP ranges. A host whose
A/AAAA records all fall inside those ranges is therefore unreachable on the direct path,
no matter how many times the request is retried — the platform refuses the connection.

hellojs resolves the name, tests the addresses against the published ranges, and — when
`proxy` is omitted — sends the request through a proxy pool instead. The decision is made
before any socket is opened, so a hopeless direct dial is never attempted and nothing is
raced:

```js
import request from 'hellojs'

request.setProxyPool([
	{ url: 'http://203.0.113.10:8080' },
	{ url: 'http://203.0.113.11:8080', authorization: 'Basic dXNlcjpwYXNz' }
])

await request('https://cf-fronted.example') // every address is Cloudflare-owned → pool
await request('https://example.com') // outside the ranges → direct, as before
```

`proxy` decides who is in charge:

| `proxy`   | Behaviour                                                                          |
| --------- | ---------------------------------------------------------------------------------- |
| `{ url }` | Used exactly as given. The pool is never consulted, and the choice is not changed. |
| `null`    | Direct, even when the host is Cloudflare-owned.                                    |
| omitted   | Direct, unless every resolved address is Cloudflare-owned — then the pool.         |

One automatic reroute is allowed on the route above: a Cloudflare-blocked direct dial
picks a proxy, and a failed proxy picks a different one. The CONNECT tunnel is
transparent, so the TLS fingerprint is the profile's own, end to end.

```js
request.addProxy({ url: 'http://203.0.113.12:8080' })
request.getProxyList() // [{ url, success, fail, score, lastOutcome, live }]
request.removeProxy('http://203.0.113.12:8080')
```

Selection is weighted by the Wilson lower bound of each proxy's success ratio, so a proxy
with more evidence is picked more often without ever absorbing the whole pool's traffic —
and a proxy that loses its first requests is still reachable through the weight floor. A
`403` from an origin counts against that host only, not against the proxy everywhere.
`live` is derived, never probed: a slot stays live until its most recent request failed.

The pool is in memory and process-wide. On Node that means the whole process; on Workers
the module scope is per-isolate, so `setProxyPool()` at module scope is the portable way to
populate it (every isolate rebuilds the same list), while a runtime `addProxy()` reaches
only the isolate that served the call. Applications that need one shared, mutable pool keep
it in a Durable Object and call `setProxyPool()` there.

With an empty pool the direct path is untouched and the runtime's own refusal surfaces as
`ENOPROXY`. When the pool is tried and cannot deliver, the request rejects with
`EPROXYFAILED`; a Cloudflare-owned target that no route can reach rejects with
`ECFIPBLOCKED`.

---

## Observability hooks

Subscribe to request lifecycle events for metrics, tracing, or SLO tracking. Hook
exceptions are swallowed — they never break the request.

```js
const request = require('@unreleased/hellojs')

request.observability.on('request:end', (ev) => {
	console.log(`req ${ev.id} ${ev.status} in ${ev.durationMs}ms; ${ev.totalBytes}B`)
})

request.observability.on('request:firstByte', (ev) => {
	histogram.observe('ttfb_ms', ev.durationMs)
})
```

Available events: `request:start`, `request:headersSent`, `request:firstByte`,
`request:end`, `request:error`. Each carries a numeric `id` so a hook can correlate
events for the same request. Because responses stream, `request:firstByte`,
`request:end` and body-level `request:error` can arrive **after** the `request()`
promise has resolved — use them to observe body completion and post-header failures. The
same events fire for H1, H2 and H3.

---

## Parrot: clone any fingerprint from a tls.peet.ws response

Paste a [tls.peet.ws/api/all](https://tls.peet.ws/api/all) JSON response into
`profiles.registerFromPeet()` and hellojs will mimic that fingerprint:

```js
const fs = require('node:fs')
const request = require('@unreleased/hellojs')

const peetJson = JSON.parse(fs.readFileSync('./captured.json', 'utf8'))
request.profiles.registerFromPeet('chrome148-mac', peetJson)

const r = await request('https://tls.peet.ws/api/all', { profile: 'chrome148-mac' })
const captured = await r.json()
// captured.tls.ja4 will equal peetJson.tls.ja4
// captured.http2.akamai_fingerprint_hash will equal peetJson.http2.akamai_fingerprint_hash
```

What gets cloned (the structural fingerprint — JA4, akamai_fingerprint, peetprint):
cipher list, extension presence, supported_groups, supported_versions, signature_algorithms,
key_share group selection, ALPN order, ALPS extension type + protocols, cert compression,
HTTP/2 SETTINGS, WINDOW_UPDATE increment, HEADERS priority flag, pseudo-header order, and
the default request header set.

What is **not** cloned (these rotate per-handshake on purpose):

- Specific GREASE codepoints (Chrome picks fresh ones each handshake)
- `client_random`, `session_id`, `key_share` bytes
- ECH config bytes (per-handshake; we send a GREASE ECH instead)
- Extension order **within** the middle block — Chrome shuffles this per TLS instance, so
  JA3 (which hashes extensions in wire order) legitimately varies connection-to-connection
  from the **same** profile. JA4 sorts before hashing, so JA4 is stable.

This is the same behaviour as a real Chrome browser: open Wireshark and capture two
back-to-back handshakes from the same Chrome instance — the JA4 will match, the JA3 won't.

---

## Fingerprint

The default profile, `chrome147-mac`, was captured from a real Chrome 147 install
on macOS and lives at [`lib/profiles/chrome147-mac.js`](lib/profiles/chrome147-mac.js).
A `firefox147` profile (macOS) ships alongside it in
[`lib/profiles/firefox147.js`](lib/profiles/firefox147.js): fixed 17-cipher /
17-extension order, X25519MLKEM768 + X25519 key shares, no GREASE, HTTP/2
`1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`, and the Firefox navigation
header set.
To clone any other fingerprint, see [Parrot](#parrot-clone-any-fingerprint-from-a-tlspeetws-response).
The profile defines:

- Cipher list (16 entries, including TLS 1.2 padding suites)
- Per-instance extension permutation (GREASE-pinned at boundaries, middle shuffled deterministically from `client_random`)
- Signature algorithms (8 entries, exact order)
- Supported groups: GREASE, X25519MLKEM768, X25519, P-256, P-384
- Key share: hybrid X25519MLKEM768 (1216 B) + X25519 (32 B) + GREASE
- ALPS extension type 0x44CD (v1) advertising h2; when a server negotiates it in EncryptedExtensions, hellojs sends the matching client EncryptedExtensions (CEE, draft-vvv-tls-alps-01) before Finished
- compress_certificate: brotli only
- HTTP/2 SETTINGS values + insertion order
- HTTP/2 WINDOW_UPDATE +15663105 on stream 0
- Default header set + ordering matching Chrome 147's `accept` / `sec-fetch-*` / `priority` etc.

### Verifying

```bash
npm run test:fingerprint
```

Asserts JA4, cipher list, signature_algorithms, supported_groups,
supported_versions and the extension set against
`test/fixtures/chrome147-peet.json` (a real Chrome 147 capture on macOS via
[tls.peet.ws](https://tls.peet.ws)), using the one live reporter that parses our
ClientHello. The Akamai HTTP/2 fingerprint, HEADERS flags and header order are
asserted offline against the same fixture by
`test/unit/h2-chrome-headers.test.ts`.

Expected output: `8 passed (8)`. The suite reaches the reporter live, so it can
go red when that host is unreachable or rate-limiting — re-run before treating a
failure as a fingerprint regression.

---

## HTTP/3 and automatic transport

Pure-JS QUIC + HTTP/3 client at `lib/h3/`, integrated into `request()`. There is no
`h3` option — transport is picked from internal state, like a browser:

1. A live pooled session for the origin/dial target wins immediately: h3, then h2, then an
   idle h1 socket (if there is one).
2. Otherwise QUIC and TCP+TLS start **in the same tick** (Happy Eyeballs) and the first
   handshake to finish wins; the loser is closed at once. Chromium's 300 ms
   `quic_delay_tcp_race` is deliberately not reproduced — it taxes every origin whose QUIC
   path is unreachable with a fixed 300 ms. A QUIC handshake still has a 2 s budget.
3. No UDP provider, a configured proxy, or an Alt-Svc hint of h2/h1 skips QUIC
   entirely and goes straight to TCP/CONNECT.

```js
await request('https://www.cloudflare.com/') // h3 or h2, chosen automatically
await request('https://www.cloudflare.com/', { keepalive: false }) // fresh race, no pool
```

### Capability matrix

Everything below is internal state — none of these rows is a request option. "Supported"
means the library does it automatically when the peer and the environment allow it.

| Capability                             | HTTP/3 (QUIC)                                             | HTTP/2 (TCP + TLS)                                   | HTTP/1.1 (TCP + TLS)                                 |
| -------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| Keep-alive / connection reuse          | Yes — QUIC session reused across requests                 | Yes — bounded process-wide pool, multiplexed streams | Yes — exclusive socket parked between requests       |
| TLS 1.3 session resumption (1-RTT PSK) | Yes — internal ticket store, keyed by host/port/ALPN      | Yes — internal ticket store, keyed by host/port/ALPN | Yes — internal ticket store, keyed by host/port/ALPN |
| 0-RTT / early data                     | No                                                        | No — replays requests                                | No — replays requests                                |
| Learns `Alt-Svc` response header       | Yes                                                       | Yes                                                  | Yes                                                  |
| Learns h2 `ALTSVC` frame (`0xa`)       | No                                                        | Yes                                                  | N/A — h1 has no frames                               |
| Uses a cached Alt-Svc hint             | `h3` → QUIC directly, TCP fallback on failure             | `h2`/`h1` → TCP path, QUIC skipped                   | `h2`/`h1` → TCP path, QUIC skipped                   |
| `Alt-Used` on alternative requests     | Yes                                                       | Yes                                                  | Yes                                                  |
| Automatic selection                    | pooled h3 first, otherwise QUIC then TCP 300 ms later     | pooled session first, otherwise the race or TCP      | pooled h1 first, otherwise TCP (no UDP/proxy/hint)   |
| Streamed response body                 | Yes — QUIC `MAX_DATA`/`MAX_STREAM_DATA` backpressure      | Yes — HTTP/2 WINDOW_UPDATE                           | Yes — TCP receive window                             |
| Flow control / backpressure            | Receive windows granted as the app reads; no fixed cap    | Stream and connection windows                        | Socket pause/resume on consumer drain                |
| Through an HTTP/SOCKS proxy            | No — QUIC cannot be tunneled; TCP/CONNECT is used instead | Yes                                                  | Yes                                                  |

Resumption applies to TLS 1.3 on every transport: h3 caches QUIC `NewSessionTicket` PSKs
and offers them in the QUIC ClientHello, while h2/h1 use the TCP TLS ticket store. The
store is shared and ALPN-scoped, so h3 and h2 tickets for the same origin coexist and
`clearSessionTickets()` empties all of them. A resumed ClientHello carries `pre_shared_key`,
so fingerprint comparisons must use the same resumption state on both sides. Alt-Svc
header parsing and `421` invalidation are protocol-independent; only the `ALTSVC` frame
is h2-specific. See [TLS 1.3 session resumption](#tls-13-session-resumption) and
[Alt-Svc](#alt-svc-rfc-7838) for details.

### Chrome reference (Chromium defaults)

Same rows, as Chrome behaves with stock Chromium defaults. These are browser defaults,
not knobs hellojs exposes; flags, field trials and enterprise policy can change them.

| Capability                             | HTTP/3 (QUIC)                                                                                               | HTTP/2 (TCP + TLS)                                       | HTTP/1.1 (TCP + TLS)                        |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------- |
| Keep-alive / connection reuse          | Yes — `QuicSessionPool` reuses sessions (30 s idle default)                                                 | Yes — `SpdySessionPool` multiplexes onto one connection  | Yes — bounded TCP socket pool               |
| TLS 1.3 session resumption (1-RTT PSK) | Yes — QUIC crypto config caches resumption state                                                            | Yes — `SSLClientSessionCache`                            | Yes — `SSLClientSessionCache`               |
| 0-RTT / early data                     | Yes — QUIC 0-RTT when the server allows it and the request is replay-safe                                   | No — `kEnableTLS13EarlyData` is off by default           | No — same feature flag is off by default    |
| Learns `Alt-Svc` response header       | Yes — primary h3 discovery                                                                                  | Yes — h3 entries; h2 entries off by default              | Yes — h3 entries; h2 entries off by default |
| Learns h2 `ALTSVC` frame (`0xa`)       | N/A — Chromium uses h3's own discovery path                                                                 | Yes — parsed in `SpdySession`; h2 alternatives still off | N/A — h1 has no frames                      |
| Uses a cached Alt-Svc hint             | h3 entry → QUIC alternative job, with TCP fallback                                                          | h3 entry → QUIC; h2 hint ignored by default              | h3 entry → QUIC; h2 hint ignored by default |
| `Alt-Used` on alternative requests     | No — Chromium does not send the header (RFC 7838 only says SHOULD)                                          | No                                                       | No                                          |
| Automatic selection                    | QUIC attempted by default (Alt-Svc or DNS HTTPS ALPN), TCP runs in parallel or after a short platform delay | TCP main job, h2 via ALPN                                | TCP main job, HTTP/1.1 via ALPN             |
| Streamed response body                 | Yes — `Response.body` is a `ReadableStream`                                                                 | Yes                                                      | Yes                                         |
| Flow control / backpressure            | QUIC stream + connection receive windows                                                                    | HTTP/2 WINDOW_UPDATE                                     | TCP receive window                          |
| Through an HTTP/SOCKS proxy            | No for HTTP/SOCKS — TCP/CONNECT; a separate QUIC proxy scheme exists                                        | Yes                                                      | Yes                                         |

Key differences from hellojs: both pool h2/h3/h1 connections and do 1-RTT PSK resumption,
but Chrome supports QUIC 0-RTT, ignores h2 Alt-Svc hints by default, and does not send
`Alt-Used`. hellojs deliberately skips 0-RTT, accepts h2/h1 Alt-Svc hints, and sends
`Alt-Used` on every request that actually uses an alternative. Sources:
[features.cc](https://chromium.googlesource.com/chromium/src/+/main/net/base/features.cc),
[http_network_session.h](https://chromium.googlesource.com/chromium/src/+/HEAD/net/http/http_network_session.h),
[quic_context.h](https://chromium.googlesource.com/chromium/src/+/HEAD/net/quic/quic_context.h),
[http_stream_factory_job_controller.cc](https://chromium.googlesource.com/chromium/src/+/main/net/http/http_stream_factory_job_controller.cc).

### Alt-Svc (RFC 7838)

Servers can advertise an alternative via the `Alt-Svc` response header or an HTTP/2
`ALTSVC` frame (type `0xa`). The cache is internal and keyed by origin:

- `ma` sets freshness (default 24 h); `clear` invalidates the origin; a `421` drops
  the cached entry. The cache lives in process memory (no on-disk persistence).
- A cached `h3` hint skips the race and dials QUIC first; a failed handshake marks
  that entry broken and the current request falls back to TCP at the **origin**
  (not the alternative), without sending `Alt-Used`.
- Requests actually sent to an alternative carry `Alt-Used`. SNI and `Host` stay on
  the **origin** authority — only the dial target moves. TCP h2/h1 also validate
  the certificate against the origin; the current QUIC path does not validate a
  certificate chain (see [Certificate validation](#certificate-validation)).
- Proxy requests neither learn nor use Alt-Svc.
- Fingerprint verification is transport-specific: a QUIC ClientHello is not a TCP
  ClientHello. When comparing against a TCP capture, disable QUIC for that process
  with `request.udp.setUdpProvider(null)` so both observations use the same transport.

Or use the lower-level QUIC + H3 layer directly:

```js
const { QuicConnection } = require('@unreleased/hellojs/lib/h3/connection')
const { H3Client } = require('@unreleased/hellojs/lib/h3/h3')

const conn = new QuicConnection('cloudflare-quic.com', 443)
conn.on('ready', async () => {
	const res = await new H3Client(conn).request({
		method: 'GET',
		path: '/',
		host: 'cloudflare-quic.com'
	})
	console.log(res.status, res.headers, res.body.length)
	conn.close()
})
await conn.connect()
```

### UDP transport

QUIC is the only part of hellojs that needs a datagram socket, and `node:dgram` is
reached exclusively through the seam at `lib/h3/udp.ts` (`request.udp`). It exports the
same `createSocket(type)` surface as `node:dgram`, so the QUIC code never notices the
swap. Runtimes without a UDP API — worker/edge sandboxes — can take HTTP/3 out of reach
without deleting the QUIC code:

```js
import request from '@unreleased/hellojs'

request.udp.setUdpProvider(null) // QUIC skipped; transport selection uses TCP
await request('https://…') // still 200
```

`setUdpProvider(null)` makes `createSocket()` throw `EUDPUNAVAILABLE`, which the
transport selector treats as "go straight to TCP". A runtime that _does_ expose
datagram sockets installs its own provider instead — any object with
`on('message'|'error')`, `bind(port, cb)`, `send(buf, port, host[, cb])`, `close()` and
a `destroyed` flag (the subset of `dgram.Socket` we use):

```js
request.udp.setUdpProvider((type) => myRuntimeUdpSocket(type))
```

With no provider configured the seam resolves to `dgram`, so Node needs no setup.

`examples/worker.ts` plus `examples/connection-do.ts` are the worked version of this. The
Worker is stateless and imports no TLS code; the Durable Object it forwards to has no outbound
UDP, so it takes HTTP/3 off the table at module scope, installs the generated Mozilla root
bundle from `examples/root-certificates.ts` (workerd ships no roots), and still serves
every request over TCP + TLS. Open the URL wrangler prints and the Worker serves its
run-test page (`/run-test.html`): one button runs all fourteen scenarios from
`examples/scenarios.ts` concurrently inside the DO and colors each result; `GET /run` answers
the same report as JSON, plus a `pooledSockets` count. See
[Keepalive in a Worker](#keepalive-in-a-worker-durable-object).

`examples/node.ts` is the same tour on Node: `npm run example:node` runs all fourteen
scenarios concurrently and prints the report. Node needs no module-scope setup — it has a
real `node:dgram` transport (so the QUIC/TCP race actually attempts h3), a built-in trust
store, and Node 24.21+ supplies ML-KEM through `node:crypto.webcrypto`.

`wrangler.jsonc` is the single source of truth for the runtime config:
`compatibility_date` plus `nodejs_compat` (for the `node:` modules hellojs uses) and
`webcrypto_modern_algorithms` (for the ML-KEM-768 share in the Chrome 147 key exchange —
that flag has no default enable date, so it has to be named). `npm run example` is plain
`wrangler dev`, and the Vitest `workers` project reads the same file, so the runtime that
executes the library tests is the runtime the library is written for.

### What's implemented

- **QUIC v1 packet protection** (Initial / Handshake / 1-RTT) — AEAD payload + header protection. RFC 9001 Appendix A test vectors pass byte-perfect.
- **AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305** AEAD + matching header protection (AES-ECB / ChaCha20 stream).
- **Retry packet handling** (RFC 9000 §17.2.5).
- **Loss recovery**: per-epoch sent-packet log, ACK frame parsing with multi-range support, PTO timer with exponential backoff.
- **NewReno congestion control** (RFC 9002) on the 1-RTT epoch — slow start, congestion avoidance, recovery on PTO.
- **TLS 1.3 key updates** (RFC 9001 §6) — server-initiated phase rotation, pre-derived next keys, commit-on-decrypt-success.
- **DATAGRAM extension** (RFC 9221) — both 0x30 + 0x31 forms, peer transport-parameter parsing, `conn.sendDatagram(buf)`.
- **NEW_CONNECTION_ID rotation** (RFC 9000 §5.1) — parse + stash + retire_prior_to semantics, `conn.rotateConnectionId()`.
- **Path validation** (RFC 9000 §8.2) — auto-respond to PATH_CHALLENGE, `conn.validatePath()` round-trips.
- **QPACK static table + dynamic-table decode** — server's encoder stream is consumed into a local replica; HEADERS decode against both.
- **Graceful CONNECTION_CLOSE** on close.

### What's not implemented

- **Client-initiated key updates** — we follow the peer's rotation; we don't trigger our own based on a packets-per-key threshold.
- **CUBIC / BBR congestion control** — NewReno only.
- **QPACK encoder-side dynamic table** — our outbound encoder is static-only (slightly larger request headers).
- **Full connection migration** — path validation works, but we don't rebind the UDP socket to a new local 4-tuple.
- **0-RTT over QUIC** — QUIC 0-RTT-Protected packets aren't implemented.

### Server compatibility

| Server                | Result        |
| --------------------- | ------------- |
| `cloudflare-quic.com` | ✅            |
| `www.cloudflare.com`  | ✅            |
| `quic.aiortc.org`     | ✅            |
| `www.google.com`      | ✅ (ALPS CEE) |
| `cloud.google.com`    | ✅ (ALPS CEE) |

---

## Certificate validation

By default (`verifyTLS: true`), hellojs validates the server's certificate chain
on the **TCP** path (h2/h1), for both TLS 1.3 and TLS 1.2. A request whose cert
doesn't chain to a trusted root, doesn't match the hostname, or is outside its
validity window is rejected with `ETLS_CERT_VERIFY` _before any application data
is sent_.

The pure-JS **QUIC/h3** path currently does **not** validate the certificate
chain; it completes the TLS 1.3 handshake messages without running the RFC 5280
checks. Its session tickets are therefore marked unverified and ALPN-scoped to
`h3`, so they can never seed a verifying TCP handshake. See
[TLS 1.3 session resumption](#tls-13-session-resumption) for the store rules.

```js
// Default — chain is validated, hostname must match, must terminate in
// Node's bundled root CAs (tls.rootCertificates). MITM proxies are rejected.
await request('https://api.example.com/')

// Opt out — handshake completes regardless of cert validity. Useful for
// self-signed dev servers or when you've wired your own validation elsewhere.
// Treat this as analogous to curl -k / NODE_TLS_REJECT_UNAUTHORIZED=0.
await request('https://localhost:8443/', { verifyTLS: false })
```

### What's checked

For each cert in the chain (leaf → intermediates → trusted root):

- Validity window — `Date.now()` is within `notBefore` / `notAfter`
- `cert[i].issuer === cert[i+1].subject` — chain doesn't break
- `cert[i].verify(cert[i+1].publicKey)` — signature against the next cert's pubkey

On the leaf specifically:

- Hostname match against `SubjectAltName` per RFC 6125, including wildcard
  support (`*.example.com` matches `foo.example.com`, not `example.com` or
  `foo.bar.example.com`). **CN-only matching is rejected** (deprecated by
  Chrome since v58, 2017).

Chain must terminate either in a self-signed root present in Node's bundled
`tls.rootCertificates`, or in a cert whose issuer matches one of the bundled
roots' subjects and whose signature verifies against that root's pubkey.

`request.setTrustedRoots(pems)` replaces that store — required on runtimes that ship
none (workerd's `node:tls` reports an empty `rootCertificates`), and useful for a private
CA. `examples/root-certificates.ts` is the generated Mozilla bundle the Worker example
installs at module scope.

On TLS 1.2, the server's `ServerKeyExchange` signature is _additionally_ verified
against the leaf cert's public key — this authenticates the ECDHE parameters
themselves, not just the cert chain. (TLS 1.3 has equivalent built-in via
`CertificateVerify`.)

### OCSP stapling

When a server staples its OCSP response (RFC 6066 §8 `CertificateStatus`), hellojs
parses the response, verifies the responder's signature against the issuer cert (or
an embedded delegated responder), and:

- Hard-fails the handshake if any cert in the response is `revoked`
- Soft-fails (logs + continues, matching Chrome's policy) if the signature can't
  be verified — callers wanting hard-fail can inspect `tls.ocsp.signatureVerified`

### Certificate Transparency

We extract Signed Certificate Timestamps (SCTs) from the leaf cert's
`1.3.6.1.4.1.11129.2.4.2` extension and expose them as `result.scts` from
`validateChain()`. Full SCT signature verification requires a CT log key list (not
bundled — distribute via your own update mechanism, then call
`require('@unreleased/hellojs/lib/tls/sct').verifySct(sct, leafDer, logKeys)`).

### Errors

When validation fails, the rejection carries `code: 'ETLS_CERT_VERIFY'` (or
`ETLS_HANDSHAKE` for 1.2 SKE-sig mismatches) with a `message` describing exactly
what went wrong:

```
certificate validation failed: leaf cert does not match hostname "evil.com" (subjectAltName=DNS:legit.com)
certificate validation failed: cert[0] expired (notAfter=Mar 15 10:00:00 2025 GMT)
certificate validation failed: chain does not terminate in a trusted root (top issuer="CN=my-corp-ca")
certificate validation failed: OCSP responder reported the leaf as revoked
```

---

## TLS 1.3 session resumption

TLS 1.3 PSK resumption (RFC 8446 §4.6.1) is internal state, not a request option. The
handshake stores each `NewSessionTicket` the server sends; later handshakes to the
same `host:port` offer the most recent ticket in `pre_shared_key` as the last
ClientHello extension and reuse it when `ServerHello` selects it. The resumption
master secret and per-ticket PSK are derived per RFC 8446 §7.1, and the ClientHello
binder (§4.2.11.2) is verified byte-for-byte against the RFC 8448 §4 vector in the
test suite. QUIC carries the same handshake messages on its 1-RTT CRYPTO stream, so
h3 uses the same schedule and the same ticket store; Retry simply replays the already
built ClientHello.

- Only tickets from handshakes whose chain was verified are offered to requests that
  require verification (`verifyTLS: true`), so a `verifyTLS: false` session cannot
  seed a trusted connection. QUIC does not validate certificate chains, so its tickets
  are marked unverified and stays h3-only (ALPN scoping) instead of seeding a TCP
  handshake.
- The store is keyed by host, port and ALPN, capped at 64 entries (LRU) with a 7-day
  ceiling. h3 (`h3`) and TCP (`h2` / `http/1.1`) tickets for one origin coexist;
  `clearSessionTickets()` empties all of them.
- `connect()` always enables resumption internally. There is no escape hatch: a
  resumed ClientHello carries `pre_shared_key` (0x0029), so resumed and fresh
  connections can have different JA3/JA4.
- Only plain 1-RTT resumption is implemented on both TCP and QUIC. 0-RTT (`early_data`)
  would save a round trip but replays requests, so it is deliberately not offered.

```js
await request(url) // offers a cached ticket, if one exists
clearSessionTickets() // forget every stored ticket
```

---

## Migration from request.js-shaped calls

`request()` now has exactly fetch's call shape and always returns a real WHATWG
`Response`, with full streaming on H1/H2/H3 in Node and Cloudflare Workers.

| Old                                            | New                                                                                                    |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `request({ url, ...init })`                    | `request(url, init)`                                                                                   |
| `request.get({ url, ...init })`                | `request.get(url, init)`                                                                               |
| `json: { ... }`                                | `body: JSON.stringify({ ... })` + `headers: { 'content-type': 'application/json' }`                    |
| `form: { ... }`                                | `body: new URLSearchParams({ ... })` (content-type is automatic)                                       |
| `qs: { ... }`                                  | build the query into the input `URL`                                                                   |
| `gzip: true`                                   | nothing — decompression is automatic                                                                   |
| `h3: true`                                     | nothing — QUIC/TCP are selected automatically                                                          |
| `resume: false`                                | nothing — resumption is internal state                                                                 |
| `maxRedirects: n`                              | nothing — the Fetch standard 20-hop limit is fixed                                                     |
| `timeout` / `timeouts`                         | `signal: AbortSignal.timeout(ms)`; connect budgets are browser-shaped and fixed                        |
| `res.statusCode`                               | `res.status`                                                                                           |
| `res.headers['x']` (plain object)              | `res.headers.get('x')` (`Headers`)                                                                     |
| parsed `res.body` / returned body              | `await res.text()` / `await res.json()` / `res.body` (`ReadableStream`)                                |
| buffered response before resolving             | resolves at headers and streams `res.body`; `await res.arrayBuffer()` if you need the whole body       |
| `simple: true` (4xx/5xx throw)                 | removed: 4xx/5xx always resolve; inspect `res.ok` and `res.status`                                     |
| `bodyOnly: true` / callback `(err, res, body)` | removed: every call resolves a `Response`; use `await res.text()` / `res.json()` / `res.arrayBuffer()` |
| Node `Readable` request body                   | `Readable.toWeb(stream)` or any fetch `BodyInit`                                                       |
| `request<T>({ ... })` typed body               | `const data = await res.json() as T`                                                                   |

Any removed key still present in `init` rejects with `EBADOPTS` at runtime — this is a
deliberate breaking change, not a silent no-op.

---

## TypeScript

Type declarations ship with the package (`index.d.ts`) and are validated under
`tsc --strict` in CI. `RequestOptions` lists only the fields the client actually
consumes; other `RequestInit` fields such as `cache` or `integrity` are intentionally
not accepted. `body` is exactly fetch's `BodyInit`, and `method` is the closed
registered-method union (either case).

```ts
import request, { HellojsError, type Response } from '@unreleased/hellojs'

try {
	const res: Response = await request('https://api.example.com', {
		method: 'POST',
		body: JSON.stringify({ name: 'x' }),
		headers: { 'content-type': 'application/json' },
		signal: AbortSignal.timeout(5_000)
	})
	if (!res.ok) throw new Error(`HTTP ${res.status}`)
	const data = (await res.json()) as { name: string }
	console.log(res.headers.get('content-type'), data.name)
} catch (e) {
	if (e instanceof HellojsError && e.category === 'transport') {
		/* retry */
	}
}

// Read the body explicitly — there is no parsed-body escape hatch:
const body = await (await request('https://api.example.com')).json()
```

The test suite is TypeScript too: `test/**/*.ts` and `vitest.config.ts` are inside the
root `tsconfig.json` include, so `npm run typecheck` covers them. Tests that run in the
workerd pool get `cloudflare:test` typings from the triple-slash reference in
`test/env.d.ts`, and the program deliberately types `crypto.subtle` against
`@cloudflare/workers-types/experimental` rather than generated `wrangler types` output —
that entry is the one that declares ML-KEM.

---

## Performance

Measured on Linux / Node 24.21.0 against a local HTTP/2 server (127.0.0.1, 1 KB
fixed-size response). Each client runs as a fresh subprocess: 1 cold request
(includes TLS handshake), then 100 warm-serial requests on a reused connection,
then 50 parallel requests. Numbers are the median of 3 runs (`WARM_REPS=100 npm run bench`).
The keep-alive pool is on by default (`keepalive: false` opts out — see
[Request options](#request-options)). Reproduce with `npm run bench`; the same harness runs
in CI (`bench` job) to prove every client still completes. The profiling harness, bottleneck
analysis and before/after numbers live in [`test/bench/RESULTS.md`](test/bench/RESULTS.md).

| Client          |        Cold |   Warm p50 | Warm p99 | 50 parallel |      RSS Δ |
| --------------- | ----------: | ---------: | -------: | ----------: | ---------: |
| node-http2      | **14.9 ms** | **0.7 ms** |   1.7 ms | **12.6 ms** | **4.8 MB** |
| node-https (h1) |     18.3 ms |     0.6 ms |   1.4 ms |     84.0 ms |     8.8 MB |
| undici (h1)     |     22.2 ms |     0.9 ms |   2.3 ms |     14.8 ms |     6.6 MB |
| axios (h1)      |     21.0 ms |     1.0 ms |   2.9 ms |    108.9 ms |    14.1 MB |
| node-fetch (h1) |     20.4 ms |     1.1 ms |   2.6 ms |    100.6 ms |    20.3 MB |
| got (h2)        |     27.4 ms |     1.4 ms |   3.4 ms |     27.5 ms |    11.9 MB |
| fetch-native    |     39.2 ms |     1.0 ms |   4.7 ms |    125.2 ms |    31.5 MB |
| **hellojs**     |     63.3 ms |     1.3 ms |   3.0 ms |     22.7 ms |    10.5 MB |

**Where hellojs sits:**

- **Cold connect: 63.3 ms**, down from ~356 ms before the Happy Eyeballs change (the old
  300 ms QUIC head-start tax is gone; see [`test/bench/RESULTS.md`](test/bench/RESULTS.md)).
  The remaining ~48 ms gap to node-http2 is the cost of building a Chrome-shape ClientHello
  (~1500 B incl. the X25519MLKEM768 hybrid key share) and running a pure-JS TLS state machine
  instead of Node's native C++ TLS.
- **Warm p50: 1.3 ms** — close to the other h2 clients; the Huffman/HPACK rewrite and the
  cached TLS traffic keys removed ~0.3 ms of per-request work.
- **50 parallel: 22.7 ms** — 4-5× faster than the h1 clients, ahead of got (27.5 ms), behind
  node-http2 (12.6 ms) and undici (14.8 ms). h2 multiplexing still wins decisively over h1.
- **Memory: 10.5 MB RSS Δ** — leaner than every client here except node-http2, undici and
  node-https.

None of the alternatives can produce
`JA4 = t13d1516h2_8daaf6152771_d8a2da3f94cd` — that's the trade-off.

### Real-internet (`www.cloudflare.com/cdn-cgi/trace`)

> Historical numbers from an earlier build — the profiling environment had no network access,
> and the transport race / header encoder have changed since. Treat these as context only.

Same harness, different target — measures the cost over a real network path with
genuine TLS handshake RTT. 10 warm + 10 parallel (smaller load to be polite to a
shared endpoint).

| Client          |     Cold | Warm p50 | Warm p99 | 10 parallel |   RSS Δ |
| --------------- | -------: | -------: | -------: | ----------: | ------: |
| axios (h1)      |  82.5 ms |  23.9 ms |  28.4 ms |     85.6 ms |  9.1 MB |
| node-https (h1) |  85.4 ms |  20.8 ms |  22.9 ms |     74.3 ms |  9.9 MB |
| undici (h1)     |  86.9 ms |  22.0 ms |  23.7 ms |     90.0 ms |  9.4 MB |
| fetch-native    |  93.5 ms |  21.4 ms |  28.8 ms |     92.6 ms | 29.1 MB |
| node-fetch (h1) |  95.9 ms |  24.9 ms |  27.7 ms |     88.0 ms | 10.2 MB |
| node-http2      | 111.0 ms |  22.7 ms |  25.2 ms | **31.4 ms** |  9.4 MB |
| **hellojs**     | 157.1 ms |  25.3 ms |  49.5 ms | **41.9 ms** | 10.8 MB |
| got             | 199.0 ms |  54.1 ms |  62.4 ms |     39.5 ms |  7.9 MB |

**What this shows:**

- **Warm requests are network-bound.** Everyone clusters at 21–25 ms p50 because
  that's the RTT to Cloudflare's edge.
- **Concurrent 10-parallel: hellojs is 2nd-fastest** (41.9 ms), only beaten by
  raw node-http2 (31.4 ms). The h1 clients all pay 74–92 ms because they
  serialize over their pool.
- **Cold connect: hellojs is ~50 ms slower than node-http2** on a real network.
  This is the genuine, irreducible cost of the fingerprint: the larger
  ClientHello (~1500 B vs ~500 B for vanilla Node) takes longer to traverse the
  network, and the pure-JS TLS state machine processes the server's response
  more slowly than Node's native C++ TLS. The fixed 300 ms QUIC head start has since
  been removed (Happy Eyeballs race), but these live-internet numbers were never
  re-measured after that change.

Reproduce: `npm run bench:remote` (default target `www.cloudflare.com/cdn-cgi/trace`,
override with `REMOTE_TARGET=host/path`).

### Fresh connections vs curl

These numbers predate the keep-alive pool; the per-request comparison that matches
this fresh-connection design is against `curl` invoked once per sample. `npm run bench:curl` interleaves hellojs and curl, flips the order every round,
verifies the negotiated protocol from the Cloudflare trace body (`http=...`) and curl's
`http_version`, and reports end-to-end latency (curl's own `-w '%{json}'` timers, so
process spawn is excluded). The local curl 8.5.0 has no HTTP/3, so its h3 row is N/A.

Target `https://www.cloudflare.com/cdn-cgi/trace`, one fresh connection per request:

| Build                                 |        hellojs h2 p50 / mean |           curl h2 p50 / mean |    Δ p50 / Δ mean |
| ------------------------------------- | ---------------------------: | ---------------------------: | ----------------: |
| After Nagle fix                       |               212–215 ms / — |               145–152 ms / — |       +39–48% / — |
| After `setNoDelay`                    |             153.0 / 158.8 ms |             144.1 / 145.8 ms |     +6.2% / +8.9% |
| After certificate cache (25 samples)  |             151.8 / 154.4 ms |             150.7 / 152.1 ms | **+0.7% / +1.5%** |
| After DNS cache (25 samples × 2 runs) | 117.6–121.8 / 121.4–127.2 ms | 144.9–148.7 / 146.0–152.3 ms |   **−18% / −17%** |

hellojs h3 in the same runs: p50 118.6–119.6 ms; a curl h3 column requires an
HTTP/3-capable curl via `CURL_BIN`.

**Fix 1 — Nagle.** The TLS Finished record and the first HTTP/2 frames leave as
separate small writes. With Nagle enabled, the second write waits for the peer's
delayed ACK (~40 ms on Linux) before the request is even on the wire.
`setNoDelay(true)` is now applied in `_wireSocketListeners` (`lib/tls/tls.ts`), which
covers the TCP, CONNECT and SOCKS5 paths. This was the dominant fix: +39–48% → +6.2%.

**Fix 2 — certificate validation cache.** The remaining gap was the certificate
verification path, not Node: with `verifyTLS: false`, hellojs matched curl
(p50 146.0 vs 149.6 ms in an interleaved 20-round probe). Now:

- Successful chain validations are cached under `host + SHA-256(leaf..top DER)`
  (64-entry LRU, 10 min TTL). Every hit re-checks the validity windows against
  `now` and the terminating root's presence in the trust store; failures are never
  cached, `setTrustedRoots()` clears the cache, and an explicit `now` bypasses it.
- SPKI public keys are memoised by certificate DER (256-entry LRU) and by
  `X509Certificate` instance. `validateChain` warms the leaf entry, so the TLS 1.3
  CertificateVerify does not parse the leaf a second time.
- RFC 8879 compressed Certificate bodies are decompressed once per distinct body
  (32 entries / 1 MiB).

Measured: a cache hit costs 0.015 ms instead of a ~1.2 ms warm validation, and
resolving the leaf key costs 0.003 ms instead of 0.408 ms. The one-time cost is the
lazy parse of the bundled root store (~22 ms) on the first validated chain of a
process, not per request.

**Fix 3 — DNS cache + address pinning.** Node does not cache `getaddrinfo`: every
fresh connection paid the full lookup (33–38 ms on this host; curl's own timer shows
36–41 ms `time_namelookup` per process), and the QUIC path re-resolved on every
`dgram.send`. `lib/dns-cache.ts` adds a TTL-bounded cache (30 s, 256 entries,
successes only, in-flight dedupe, IP literals bypass) injected through the
`net.createConnection({ lookup })` seam for direct TCP, proxy CONNECT and SOCKS5.
QUIC resolves once through the same cache and pins the peer address for all datagrams
(SNI keeps the hostname). On workerd `node:dns` is absent, so `dnsCacheAvailable()` is
false and every path keeps connecting by hostname exactly as before.

Measured: one resolver call across 3 sequential requests, both h2 and h3; with curl
unchanged at 145–149 ms, hellojs h2 went 151.8 → 117.6–121.8 ms p50 and now leads
curl by ~18%.

**Fix 4 — TLS 1.3 PSK resumption (internal, on by default).** The client stores the
server's `NewSessionTicket` and offers it as `pre_shared_key` on the next connection to
the same host, so the server can skip the certificate flight and CertificateVerify.
Measured with
an interleaved connect-only A/B (30 rounds each, ticket seeded, 30/30 PSK accepted):
full handshake p50 82.2–82.6 ms vs resumed 80.0–83.4 ms, mean −1.9% / −2.5%. A 60-sample
end-to-end A/B left the median flat (120.2 vs 120.7 ms) and moved the mean by −7.5% to
−11.5% depending on how much tail noise the run collected. The reason the gain is small
here is structural: full and resumed TLS 1.3 handshakes are both 1-RTT, so resumption
removes only the ~4–6 KB certificate flight and its signature check — a few ms on this
path, and less than DNS caching saved. It scales with chain size and path loss, and 0-RTT
would remove a real round trip but replays requests, so it is not offered. The resumed
ClientHello differs from a fresh one, so a resumed connection's JA3/JA4 changes —
resumption is internal state and cannot be disabled per request.

**What remains.** TCP connect + one TLS round trip. CertificateVerify is still checked on
every full handshake (~1–2 ms), and run-to-run network drift moves both columns by
several ms. PSK resumption is internal and on for repeated connections to the same host;
0-RTT is the only remaining handshake shortcut, and it trades replay safety for the round trip.

**Pooling, now on by default.** Pooling removes DNS + TCP + TLS altogether, and the
fresh-connection-per-request prediction (~120 ms → ~35–40 ms) held once the bounded
keep-alive pool shipped (see [Request options](#request-options)).
Measured results, including through a proxy tunnel, are in the next section.

Reproduce: `npm run bench:curl`. Knobs: `BENCH_URL`, `SAMPLES`, `CURL_BIN`,
`BENCH_RESUME=1` (turns the hellojs h2 row into the resuming row).
Caveats: these are connect/handshake-heavy fresh-connection numbers, not steady-state
throughput; CDN anycast and PoP changes move both clients by several ms.

### Keep-alive vs curl through a CONNECT-over-TLS proxy

Measured with the sibling project's harness (`veepnApi/bench/veepn-vs-curl.ts`, run as
`npm run bench` there) on Linux / Node 26: a live VeePN datacenter proxy pool, requested
as `https://user:pass@addr:port` so the client takes a TLS hop to the proxy and runs
CONNECT inside it, then a second TLS handshake to the target through the tunnel — the
same dialect curl speaks with `--proxytunnel -x https://…`. Rounds are interleaved with
the order flipped every round. The pool ran bounded, as configured by the caller:
`maxPerOrigin: 1`, `idleMs: 15_000`.

Target `https://example.com/` (fast CDN edge), 15 samples, one proxy:

| Row                              |   min |   p50 |    p95 |
| -------------------------------- | ----: | ----: | -----: |
| curl (fresh process per request) | 571.7 | 721.5 | 7526.3 |
| hellojs, fresh connection        |  74.1 |  94.7 |  123.1 |
| hellojs, `keepalive: true`       |  26.7 |  33.7 |   99.1 |

hellojs beats curl by **−86.9% p50** even cold — per-sample curl carries process spawn,
proxy-side TLS and CONNECT setup, and the proxy's own handshake variance (its p95 tail
reached 7.5 s). Reusing the tunnel drops the client-side connection cost to near zero:
**−64.4% p50** versus a fresh hellojs connection.

The residual is not client work. Against `https://api.ipify.org/` (8 samples, same
suite) the same three rows measured p50 1230.3 / 229.4 / 173.8 ms — the keep-alive
saving shrinks to −24% because ~140 ms of that is the proxy's own path to the target
(server TTFB), which no client option can remove. Realistic budget for a proxied
request: **~30–40 ms floor + target TTFB** with a reused tunnel, plus ~60–100 ms for a
fresh hellojs handshake or ~500–700 ms for a fresh curl process.

Correctness was verified alongside the timings: through the same proxy, curl and hellojs
both returned the identical proxy exit IP (`51.158.254.152`) from api.ipify.org while a
direct request returned the local egress IP, and curl reported `http_version=2` inside
the tunnel — so the two rows really are dialing the same endpoint over the same dialect,
with no silent bypass on either side.

### Soak

The soak is a `node`-project test (`test/soak/soak.test.ts`), so it runs on every
`npm test` and in CI: a local h2 server under sustained load, with heap growth
(after an explicit GC) and active handles compared against the idle baseline.
The default run is a 300-request smoke; `npm run test:soak` runs just that file.
Baseline on this machine:

```
soak: 300 requests in 1.98s (152 rps), heap 1.54 MB, handles 5 -> 5
```

Knobs: `SOAK_REQUESTS=1000000 SOAK_CONCURRENCY=200 SOAK_HEAP_BUDGET_MB=128 npm run test:soak`
(raise `SOAK_TIMEOUT_MS` to match, default 120000).

---

## Testing

Vitest, in three projects. `lib/` is written for the workerd runtime, so the tests that
exercise it run there — via the official
[Workers Vitest integration](https://developers.cloudflare.com/workers/testing/vitest-integration/),
which boots a worker from `wrangler.jsonc` and gives each test file the real
`crypto.subtle`.

| Project   | Location                                           | Runs in                     | Covers                                                                                                                                                                    |
| --------- | -------------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `workers` | `test/unit/**/*.test.ts`                           | workerd (`cloudflare-pool`) | the library itself: handshake crypto, HKDF, HPACK/Huffman, frame codecs, parsers, profiles, fingerprint shaping                                                           |
| `node`    | `test/node/**/*.test.ts`, `test/soak/**/*.test.ts` | Node                        | the same lib, plus what workerd cannot host: `node:fs` fixtures, `openssl` subprocesses, loopback servers, `node:dgram`, a real trust store — and the sustained-load soak |
| `network` | `test/integration/**`, `test/fingerprint/**`       | Node, live internet         | round-trips against public servers and the Chrome 147 fingerprint regression, over a minimal host set (`test/helpers/hosts.ts`)                                           |

```bash
npm test                    # workers + node (incl. the soak) — offline, the default gate
npm run test:watch
npm run test:workers        # workerd pool only
npm run test:node           # node pool only
npm run test:soak           # soak file only; SOAK_* knobs raise the load
npm run test:network        # live internet; NOT part of npm test
npm run test:integration
npm run test:fingerprint
npm run test:all            # everything, network included

npm run bench               # benchmark vs. 7 other clients, local h2 server
npm run bench:remote        # same harness against a real host
npm run bench:h3            # h3 vs h2
npm run bench:vs-got
npm run bench:vs-axios
```

Why workerd: `lib/tls/x25519.ts` derives its shared secret through `crypto.subtle.deriveBits`
because workerd's `node:crypto diffieHellman()` rejects an imported peer key, and
`lib/tls/mlkem.ts` needs `ML-KEM-768` generate/encapsulate/decapsulate — native in workerd
only with the `webcrypto_modern_algorithms` flag, and in Node from 24.21 through
`node:crypto.webcrypto`. `lib/utils/webcrypto.ts` resolves SubtleCrypto per call:
`globalThis.crypto.subtle` when the host provides it, otherwise `node:crypto.webcrypto.subtle` —
a standard Node project never has to install a global. To prove the workerd coupling is real,
delete `webcrypto_modern_algorithms` from `wrangler.jsonc` and `npm run test:workers` fails with
`ML-KEM-768 unavailable: Web Crypto has no ML-KEM support; requires Node >= 24.21 or Cloudflare Workers with the webcrypto_modern_algorithms flag`.

Where a new test goes: `workers` by default. A test moves to `node` only because of a workerd
runtime limit — a missing or broken builtin, the empty trust store, the CPU budget — and never
to hide a library bug; a `lib/` bug is fixed in `lib/`. In practice that means anything using
`node:fs`, `node:child_process`, `node:dgram`, a `node:net`/`node:tls` server, or
`tls.rootCertificates` starts in `test/node/`. Anything that reaches a public host starts in
`test/integration/`, which is excluded from `npm test` so the default gate stays offline and
deterministic; those suites can legitimately go red when a host rate-limits us, retires TLS
1.2, or blocks UDP — re-run before treating a failure as a regression.

Byte comparisons use one helper, `hex()` from `test/helpers/bytes.ts`, rather than a deep-equal
on `Buffer` vs `Uint8Array` — the two are not interchangeable under `toStrictEqual`, and the
comparison must behave identically in both runtimes. `test/setup/workerd.ts` runs before every
`workers` test file and applies the same two module-scope fixes as the Worker example: no UDP
provider, and the generated Mozilla roots.

The soak is a real test — it asserts a request count, post-GC heap growth and handle growth —
so it lives in the `node` project and runs on every `npm test`. The `node` project sets
`execArgv: ['--expose-gc']` so the heap check can force a collection rather than measure
floating garbage; without it the heap assertion is skipped and only the handle check runs.

The benchmark is the exception: it shells out to each client in a fresh subprocess and its
output is numbers, not pass/fail, so Vitest would add nothing. It stays a plain script
(`test/bench/clients.ts`, run directly — Node 24+ strips the types), and CI runs it once as
a smoke test that every client still completes.

---

## Errors

Every operational failure surfaces as a `HellojsError` with a stable
`.code` and `.category`. Use the category for coarse-grained handling
and the code for precise behavior.

```js
const request = require('@unreleased/hellojs')

try {
	await request('https://example.com/foo')
} catch (e) {
	if (e instanceof request.HellojsError) {
		console.error(e.code, e.category, e.message)
		if (e.category === 'timeout') {
			/* retry */
		}
		if (e.code === 'ETLS_CERT_VERIFY') {
			/* refuse to trust */
		}
	}
}
```

| Category    | Codes                                                                                                                                           | Meaning                                                                                                                              |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `usage`     | `EBADOPTS`, `EBADARG`, `EHEADERFIXED`                                                                                                           | Caller passed bad options (programmer error)                                                                                         |
| `transport` | `ECONNREFUSED`, `ECONNRESET`, `ENOTFOUND`, `EPROXY`, `ENOPROXY`, `EPROXYFAILED`, `ECFIPBLOCKED`, `EUDPUNAVAILABLE`, `ETOOMANYREDIRECTS`         | TCP / DNS / proxy issues, no route to a Cloudflare-owned host, no UDP provider, or a redirect chain exceeding the 20-hop Fetch limit |
| `tls`       | `ETLS_ALERT`, `ETLS_HANDSHAKE`, `ETLS_CERT_VERIFY`, `ETLS_VERSION`, `ECERTPARSE`, `ECERTVALIDATION`, `ECERTVERIFY`, `ETLSPSK`, `ETLS12`, `EHRR` | Handshake, record-layer or certificate problem                                                                                       |
| `protocol`  | `EH2STREAM`, `EH2GOAWAY`, `EH2COMPRESS`, `EH2KEEPALIVE`, `EH3STREAM`, `EH3CONN`, `EH3PARSE`, `EPROTO`                                           | h2 / h3 / QUIC protocol-level failure                                                                                                |
| `http`      | `EHTTP`, `EBADRESP`, `EDECOMPRESS`                                                                                                              | HTTP policy error (e.g. `redirect: 'error'`), parser failure, or content-encoding error                                              |
| `body`      | `EBODYSTREAM`                                                                                                                                   | Request body stream errored mid-upload                                                                                               |
| `timeout`   | `ETIMEDOUT`                                                                                                                                     | A fixed connect / handshake phase budget was exceeded (`signal` aborts are reported through the signal's reason)                     |

Retries (when `opts.retry.limit > 0` is set and the method is in
`opts.retry.methods`) automatically retry these codes:
`ETIMEDOUT`, `ECONNRESET`, `EH2STREAM`, `EH3STREAM`. A response whose status is
in `opts.retry.statusCodes` is also retried: the client cancels the unread body
at the header stage and re-issues the request, so no throw-on-status option is
needed.

---

## Debugging

By default the library is silent. Choose a log level via `HELLOJS_LOG`:

```bash
HELLOJS_LOG=error  node my-script.js   # only errors
HELLOJS_LOG=warn   node my-script.js   # + warnings
HELLOJS_LOG=info   node my-script.js   # + notices (handshake summary, etc.)
HELLOJS_LOG=debug  node my-script.js   # + protocol-level detail
HELLOJS_LOG=trace  node my-script.js   # everything (very loud)
```

`HELLOJS_DEBUG=1`, `-d` on argv, and `ENV=development` are all accepted as legacy
aliases for `trace`. You can also set the level from JS:

```js
const log = require('@unreleased/hellojs/lib/models/log')
log.setLevel('info')
log.setJsonMode(true) // emit JSON-line records instead of colored text
```

`HELLOJS_LOG_JSON=1` is the env-var equivalent for JSON-line output (useful for
ingesting into structured-log pipelines).

Sample lines:

```
[h3] [cc] recovery cwnd=10000 ssthresh=10000 ev=1
[h3] [cid] +seq=2 (pool size=3)
```

### Wireshark decryption

Set `HELLOJS_KEYLOG` to a file path and hellojs will write
SSLKEYLOGFILE-format entries you can load into Wireshark to decrypt
captured TLS sessions:

```bash
HELLOJS_KEYLOG=/tmp/hellojs.keys node my-script.js
```

---

## API surface

```js
const request = require('@unreleased/hellojs')

// Main API — fetch's (input, init) shape
request(input, init?)            // Promise<Response>
request.get(input, init?)
request.post(input, init?)
request.put(input, init?)
request.del(input, init?)
request.patch(input, init?)
request.head(input, init?)
request.options(input, init?)
request.defaults(defaultInit)    // bound instance
request.jar()                    // new RFC 6265 cookie jar
request.setPoolConfig(opts?)     // set process-wide keep-alive pool caps
request.clearSessionTickets()    // forget cached TLS 1.3 session tickets
request.HellojsError             // error class
request.observability            // EventEmitter — see Observability hooks

// Profile registry — clone fingerprints from peet.ws JSON
request.profiles.registerFromPeet(name, peetJson)
request.profiles.register(name, profileObject)
request.profiles.get(name)
request.profiles.list()

// Low-level for advanced use
request.TLS                      // class TLS(host, port, proxy?, opts?)

// HTTP/3 stand-alone
const { QuicConnection } = require('@unreleased/hellojs/lib/h3/connection')
const { H3Client }       = require('@unreleased/hellojs/lib/h3/h3')
```

Errors are `HellojsError` instances. See [Errors](#errors) for the full taxonomy.

---

## Architecture

```
lib/
├── client.ts                  request()-shape API (URL parsing, redirects,
│                              cookie jar integration, body codec, retry policy,
│                              streaming response, observability hooks)
├── transport-race.ts          automatic QUIC/TCP race (300ms TCP delay), UDP/proxy fallback
├── alt-svc.ts                 RFC 7838 origin-keyed cache (header + h2 ALTSVC frame,
│                              ma/clear/persist, 421 invalidation, Alt-Used)
├── connect.ts                 per-request TLS/QUIC connection factory (h2/h1/h3),
│                              fixed Chromium-shaped connect budgets
├── socks5.ts                  SOCKS5 client (RFC 1928 + RFC 1929 user/pass)
├── dns-cache.ts               TTL-bounded getaddrinfo cache + net lookup seam (Node only)
├── tls-summary.ts             best-effort TLS state summary for observability hooks
├── cookies.ts                 RFC 6265 cookie jar (Domain/Path/Secure/SameSite/Expires)
├── headers.ts                 Chrome 147 default header set + ordering
├── errors.ts                  HellojsError + closed-set codes + wrap() promotion
├── observability.ts           EventEmitter for request lifecycle
├── tls/
│   ├── tls.ts                 TLS 1.3 state machine + AEAD + HKDF key schedule
│   ├── tls12.ts               TLS 1.2 handshake + 12-suite cipher catalog + EMS
│   ├── tls12_records.ts       TLS 1.2 record codec (AEAD GCM/ChaCha20 + CBC)
│   ├── tls12_prf.ts           TLS 1.2 PRF (P_SHA256/SHA384) + key schedule
│   ├── cert-validate.ts       Chain validation (path + SAN + dates + intermediate trust)
│   ├── session-tickets.ts     TLS 1.3 NewSessionTicket store + PSK binder (RFC 8446)
│   ├── fingerprint.ts         JA3 + JA4 + PeetPrint derivation from a ClientHello
│   ├── sig-verify.ts          streaming signature verifier (workerd crypto gaps)
│   ├── ocsp.ts                OCSP response parser + signature verifier (RFC 6960)
│   ├── sct.ts                 Signed Certificate Timestamp parser (RFC 6962)
│   ├── mlkem.ts               X25519MLKEM768 hybrid key exchange (Web Crypto ML-KEM-768)
│   └── x25519.ts              X25519 shared secret via Web Crypto (workerd-safe)
├── h2/
│   ├── frame.ts               9-byte frame header codec + type/flag constants
│   ├── hpack.ts               full HPACK (static + dynamic tables, Huffman)
│   └── session.ts             H2Session + H2Stream (replaces Node's http2,
│                              with CONTINUATION + per-stream flow control)
├── h3/
│   ├── connection.ts          QUIC v1 connection + NewReno + key updates + NCID
│   ├── udp.ts                 UDP transport seam (dgram by default, swappable/off)
│   ├── h3.ts                  HTTP/3 layer (control + encoder + decoder streams)
│   ├── packet.ts              QUIC packet build/parse + frame codec
│   ├── keys.ts                Initial + traffic key derivation + AEAD helpers
│   ├── qpack.ts               QPACK static + dynamic-table decode
│   ├── huffman.ts             RFC 7541 Huffman encoder + decoder
│   ├── transport-params.ts    QUIC transport-parameters TLS extension codec
│   └── varint.ts              QUIC variable-length integer codec
├── extensions/
│   └── index.ts               every TLS extension builder (profile-driven)
├── profiles/
│   ├── index.ts               registry (get/register/registerFromPeet)
│   ├── types.ts               Profile / TlsProfile / Http2Profile shapes
│   ├── chrome147-mac.ts       canonical Chrome 147 profile
│   ├── firefox147.ts          Firefox 147 (macOS) profile
│   └── from-peet.ts           paste a tls.peet.ws response → profile object
├── utils/
│   ├── config.ts              MESSAGE_TYPES, CIPHERS, HASHES tables
│   └── hkdf.ts                HKDF-Extract / Expand / Expand-Label / hashes
└── models/
    └── log.ts                 leveled logger (HELLOJS_LOG=info/debug/trace;
                               JSON-line output via HELLOJS_LOG_JSON=1)
```

```
test/
├── unit/                  Vitest `workers` project — runs inside workerd
│   ├── smoke.test.ts      the whole module graph boots in workerd
│   ├── mlkem.test.ts      ML-KEM-768 via the Worker's Web Crypto
│   ├── x25519.test.ts     the WebCrypto X25519 bridge
│   └── …                  crypto, h2/h3 codecs, HPACK/Huffman, parsers, profiles
├── node/                  Vitest `node` project — same lib, workerd-hostile needs
├── integration/           Vitest `network` project — live public servers
├── fingerprint/           Vitest `network` project — Chrome 147 vs the fixture
├── setup/workerd.ts       per-file workers setup (no UDP, Mozilla roots)
├── helpers/               hex(), rejection(), listenOnLoopback(), probeTls()
├── fixtures/              captured peet.json / peet samples
├── types/                 strict-tsc consumer check for index.d.ts
├── bench/                 cross-client benchmarks (plain script, run via npm run bench)
└── soak/                  sustained-load soak (Vitest node project, runs in npm test)
```

The custom h2 client (`lib/h2/session.ts`) replaces Node's built-in
`http2.connect()` on the hot path. It handles the SETTINGS exchange, HPACK
encode/decode, per-stream and connection flow control, CONTINUATION frame
assembly/emission, frame dispatch, and PING auto-response — vs. the thousands of
lines of internal http2 machinery it bypasses. This is where ~22% of the
cold-connect gains and ~45% of the concurrent-throughput gains came from.

---

## Known limitations

- **ECH:** GREASE-shape only. Real Encrypted Client Hello against published ECHConfigs
  (read from DNS HTTPS records) is not implemented.
- **Certificate Transparency:** SCTs are parsed and exposed; signature verification
  requires a caller-supplied CT log key map. We don't ship the log list.
- **OCSP:** stapled responses are parsed + verified. We don't fetch OCSP responses
  out-of-band when the server doesn't staple.
- **HTTP/2:** Server push not supported (we set `ENABLE_PUSH=0`).
- **Cloudflare-owned targets:** a Worker refuses outbound TCP to Cloudflare's IP ranges, so a
  host behind Cloudflare is reachable only through a proxy. The pool routes those requests, but
  it ships empty — supplying proxies is the caller's job.
- **HTTP/3:** see [HTTP/3 → What's not implemented](#whats-not-implemented).
  Missing: client-initiated key updates, CUBIC/BBR, QPACK encoder dynamic table, full
  connection migration (socket rebind), 0-RTT-Protected packets.
- **Common HTTP features not yet implemented:** WebSocket (`Upgrade: ws`),
  multipart/form-data builder, `Expect: 100-continue`, response Cache-Control/ETag
  semantics, `Retry-After` honoring on 429/503, `Content-Range` resumable
  uploads. These don't affect the fingerprint or TLS layer — they're caller
  conveniences that can sit on top.

---

## License

MIT © Conor Reid
