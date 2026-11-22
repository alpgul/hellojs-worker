# Performance profiling — Phase 1 / 2 / 3 report

> All numbers were collected **locally**: Node v24.21.0, Linux, network disabled. The server is
> the self-signed HTTP/2 server started with `helpers.ts` in this folder (loopback, 1 KB body;
> `/large` is 1 MB). Every measurement is the **median** of 3 runs. Raw outputs live under
> `test/bench/.out/` (gitignored).

## Gate status

| Check                  | Result                                                                       |
| ---------------------- | ---------------------------------------------------------------------------- |
| `npm test`             | 69 files / 477 tests passed                                                  |
| `npm run typecheck`    | passed                                                                       |
| `npm run lint`         | passed (0 errors, 54 pre-existing warnings)                                  |
| `npm run format:check` | already failing on **47 pre-existing files**; unrelated files were untouched |

## Added tools

| File / command                                           | Purpose                                                                                     |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `helpers.ts`                                             | Cert + local h2 server + statistics (the existing `clients.ts` now uses this too)           |
| `profile.ts` / `npm run bench:profile`                   | 4 scenarios: cold / warm / concurrent / large-body; wall clock, RSS, `observability` events |
| `profile.ts` / `bench:profile:cpu`, `bench:profile:heap` | V8 CPU / sampling heap profiles (`.out/`)                                                   |
| `profile.ts` / `PROFILE_NO_UDP=1`                        | Disable the UDP seam for a TCP-only control run                                             |
| `micro.ts` / `npm run bench:micro`                       | ns/op for pure functions (median of 3 passes)                                               |
| `analyze.ts` / `npm run bench:analyze -- <profile>`      | `.cpuprofile` → self/total time tables                                                      |

---

## Phase 1 — Profiling results

### A. Client comparison (`npm run bench`, WARM_REPS=100, median)

| Client       | Cold (ms) | Warm p50 | Warm p99 | 50 parallel |      RSS Δ |
| ------------ | --------: | -------: | -------: | ----------: | ---------: |
| **hellojs**  | **356.2** |      1.6 |      3.3 |        36.1 |    11.4 MB |
| node-https   |      23.4 |      0.6 |      1.6 |        76.4 |     8.7 MB |
| node-http2   |      14.8 |      0.6 |      1.5 |    **13.5** | **4.8 MB** |
| undici       |      22.3 |      0.9 |      2.7 |        14.6 |     7.0 MB |
| got          |      28.0 |      1.4 |      3.2 |        28.1 |    11.9 MB |
| axios        |      22.7 |      1.0 |      3.0 |       101.3 |    13.9 MB |
| node-fetch   |      22.0 |      1.1 |      2.8 |        95.1 |    20.6 MB |
| fetch-native |      39.0 |      1.0 |      3.5 |       131.4 |    31.0 MB |

### B. Scenario profile (UDP on vs off, median)

| Scenario                   | UDP on (current) | UDP off (control) |                 Diff |
| -------------------------- | ---------------: | ----------------: | -------------------: |
| cold p50 (30 req)          |        313.38 ms |           7.50 ms | **+305.9 ms (~42x)** |
| warm p50 (200 req)         |          1.64 ms |           1.59 ms |             +0.05 ms |
| concurrent p50 (50 req)    |         32.12 ms |          31.98 ms |             +0.14 ms |
| large-body p50 (10 × 1 MB) |         18.55 ms |          17.24 ms |             +1.31 ms |

CPU profile (10.7 s sampling): **87.5% `(idle)`** — i.e. the cold cost is **waiting**, not CPU.
Warm-focused profile (3000 requests): idle 13.1%, `huffman.encode` self **315 ms (~105 µs/request,
7.5%)**, `hpack.findInTables` 25 ms, `buildH2Headers` 36 ms self. In the cold (UDP off) profile
`spawnSync` (certificate generation) at 322 ms and `deriveBits`/WASM (X25519 + ML-KEM) lead;
these are one-time startup costs, not per-request.

Heap profile is sparse (9 samples / 512 KB interval): X25519 `deriveBitsImpl` ~512 KB, ML-KEM WASM
~512 KB, `h2/session.ts:_dispatch` ~512 KB, module compilation ~1.5 MB. Not conclusive on its own;
the 1 MB body scenario shows RSS Δ of 26–52 MB (10 requests), which needs separate memory analysis.

### C. Micro-benchmarks (median ns/op)

| Bench                        |       ns/op |
| ---------------------------- | ----------: |
| huffman-encode-600B          | **100,923** |
| hpack-encode-17headers       |      88,413 |
| huffman-decode-600B          |      30,574 |
| hpack-decode-17headers       |      28,909 |
| qpack-encodeHeaders-17       |      16,965 |
| qpack-decodeHeaders-17       |       4,655 |
| headers-buildH2-with-profile |       7,627 |
| headers-buildH1-with-profile |       6,166 |
| headers-mergeProfile         |       3,111 |
| cookies-parseSetCookie       |       1,051 |
| qpack-findStatic-hit / miss  |   300 / 266 |
| varint-encode / decode       |   97 / 14.5 |

Note: `hpack.encodeString` tries to Huffman-encode every string (`lib/h2/hpack.ts:157`), so
`huffman.encode` is on the header path of **every h2 request**.

---

## Phase 2 — Bottleneck analysis

| #      | Bottleneck                                                                                              | Measured cost                          | Evidence                                                      | Class            | Risk                                     |
| ------ | ------------------------------------------------------------------------------------------------------- | -------------------------------------- | ------------------------------------------------------------- | ---------------- | ---------------------------------------- |
| **B1** | QUIC→TCP race: when UDP is present TCP starts 300 ms late; paid in full on a non-responsive QUIC origin | **+306 ms to cold** (97% of cold)      | 313.38 vs 7.50 ms; CPU 87.5% idle; `transport-race.ts:17,137` | latency / design | **High** (changes Chrome race semantics) |
| **B2** | `huffman.encode` BigInt accumulator with byte-by-byte shifting                                          | **100.9 µs/request**, 7.5% of warm CPU | micro + warm cpuprofile; `h3/huffman.ts:103`                  | CPU              | Low (output can stay identical)          |
| **B3** | QPACK/HPACK static table lookups are linear                                                             | ~300 ns/lookup, 17 headers ≈ 5 µs      | micro; `qpack.ts:126`, `hpack.ts:172`                         | algorithmic      | Low                                      |
| **B4** | 50 parallel requests 32 ms; node-http2 13.5 ms. Does not improve with UDP off → not B1                  | ~18.6 ms gap                           | bench + scenario profile                                      | CPU / h2 flow    | Medium (profiling needed)                |
| **B5** | RSS Δ 26–52 MB per 10 requests for 1 MB bodies                                                          | memory pressure                        | scenario profile + sparse heap profile                        | memory / GC      | Medium (weak evidence)                   |
| **B6** | `observability.ts` documents dns/connect/handshake events but never emits them                          | no phase-level timing possible         | `grep safeEmit`: only `client.ts` request events              | observability    | Low (an audit finding, not a feature)    |

**Do not touch:** ClientHello parabola/header order (JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`),
profile fixed headers (`EHEADERFIXED`), h2 header order, and the 300 ms race itself (without a
product decision). The B1 "fix" is a behavior change as much as a performance win; Phase 4 will
ask for **user approval first**.

---

## Phase 3 — Performance audit

**Methodology:** 3 runs + median, loopback server, warm-up (2 requests), `hrtime.bigint()`, same
Node version. Weak spots: (a) no network, so RTT/real QUIC cannot be measured; (b) RSS Δ is
sensitive to GC timing; (c) the CPU profile includes certificate generation (`spawnSync` ~322 ms),
so the cold profile must not be read in isolation; (d) 47 files are already broken in the
`format:check` baseline.

**Regression guards (to run after every change in Phase 4):**
`npm test` (including fingerprint + JA4), `npm run typecheck`, `npm run lint`, `prettier --check`
for new files, `npm run bench:profile` (same scenarios), `npm run bench:micro`, `npm test --
--project=node test/soak` (heap/handle return).

**Cross-runtime:** workerd has no `node:dgram`; the UDP seam already handles this via
`setUdpProvider(null)`. Optimizations must not add Node-only APIs; the existing `Buffer` usage in
`huffman.ts`/`hpack.ts` is also supported on workers.

**Recommended order (Phase 4):**

1. **B2** — `huffman.encode`: BigInt → 53-bit safe number accumulator; byte-for-byte verification
   against existing output (fuzz + unit test). Expected: 5–10x encode speed, ~0.05–0.1 ms off
   warm p50.
2. **B3** — name/value → index Maps for static table lookups; expected ~5 µs/request.
3. **B4/B5** — targeted profiling + separate steps; do not touch without measurement.
4. **B1** — product decision: keep the race delay, or fall back to TCP quickly when QUIC is absent?
   This step will not be implemented without approval.

---

## Phase 4 — Applied optimizations (measure → change → measure → keep)

### B2 — `huffman.encode`: BigInt → 53-bit safe number accumulator

- `lib/h3/huffman.ts`: per-byte BigInt shifting/conversion replaced with a `number` accumulator
  (after each flush ≤7 bits remain plus at most a 30-bit code = 2^37 < 2^53).
- `test/unit/huffman.test.ts`: the old BigInt algorithm is **kept as an oracle**; output is
  compared byte-for-byte for the full 256-byte set plus 50 random buffers.
- Micro: **100,923 → 31,630 ns/op** (3.2x). `hpack.encode` benefited too:
  **88,413 → 42,101 ns/op** (2.1x).

### B3 — Static table lookups with Maps

- `lib/h2/hpack.ts` and `lib/h3/qpack.ts`: immutable static tables are loaded at module init into
  `exact (name\0value)` and `name → index` Maps; dynamic-table lookup and the
  "exact first, then name-only, static first" order are preserved.
- `test/unit/qpack.test.ts`: added exact/name-only/miss and encode→decode round-trip tests for all
  static entries.
- Micro: `findStatic` hit **300 → 34 ns**, miss **266 → 19 ns**; `qpack.encodeHeaders`
  16,965 → 15,692 ns.

### End-to-end verification (median of 3 runs)

| Scenario               |    Before |     After |                 Change |
| ---------------------- | --------: | --------: | ---------------------: |
| bench warm p50         |    1.6 ms |    1.5 ms |                    -6% |
| bench 50 parallel      |   36.1 ms |   28.4 ms |               **-21%** |
| profile warm p50       |   1.64 ms |   1.50 ms |                  -8.5% |
| profile concurrent p50 |  32.12 ms |  27.39 ms |               **-15%** |
| cold p50               | 313.38 ms | 312.63 ms | ~0 (B1 still dominant) |
| large-body p50         |  18.55 ms |  17.93 ms |  within the noise band |

**Decision:** B2 and B3 kept (≥5% and above noise; 50-parallel and warm improved clearly).
No meaningful change in cold and large-body scenarios — the expected result.

**Checks:** `npm test` 70 files / 480 tests passed (including 3 new tests), `typecheck` passed,
`lint` 0 errors, new/changed files passed `prettier --check`, soak: 300 requests / 4.21 s,
heap 2.30 MB, handles 5 → 5 (no leak).

### B1 — Happy Eyeballs: 300 ms head start removed (speed-first decision)

User decision: **speed first**; Chrome's 300 ms priority for QUIC is unacceptable.
`lib/transport-race.ts` now starts QUIC and TCP+TLS **in the same tick**; the first connection to
finish wins and the other is aborted/closed immediately. The fixed delay and its timer were
removed. `test/node/transport-race.test.ts` requires the connection to complete in under 250 ms
in a local scenario where QUIC never responds (the old code took ≥300 ms).

| Scenario (median of 3 runs) | Before all optimizations |       Final |           Change |
| --------------------------- | -----------------------: | ----------: | ---------------: |
| bench cold                  |                 356.2 ms | **62.0 ms** |         **-83%** |
| bench warm p50              |                   1.6 ms |      1.6 ms |               ~0 |
| bench 50 parallel           |                  36.1 ms |     28.2 ms |         **-22%** |
| profile cold p50            |                313.38 ms | **8.52 ms** | **-97% / 36.8x** |
| profile warm p50            |                  1.64 ms |     1.43 ms |             -13% |
| profile concurrent p50      |                 32.12 ms |    27.08 ms |             -16% |
| profile large-body p50      |                 18.55 ms |    17.27 ms |              -7% |

Note: bench cold (62 ms) is higher than profile cold (8.5 ms) because each client starts in a
separate subprocess and the measurement includes the first byte of the first request; the two do
not measure the same thing.

**Final checks:** `npm test` 71 files / 481 tests passed, `typecheck` passed, `lint` 0 errors,
changed files passed `prettier --check`. The README Performance section and transport-selection
docs were updated with current numbers.

## Phase 5 — Targeted B4/B5 profiling

Tool extension: `profile.ts` now produces `PROFILE_ROUNDS`, `PROFILE_BODY_REPS`, `PROFILE_BODY_GZIP`,
`PROFILE_BODY_IDENTITY`, `PROFILE_GC`, a memory dump (rss / heapUsed / arrayBuffers / external),
`poolStats()`, event-loop lag and a per-request `headersSent → firstByte → end` timeline.
`helpers.ts` gained a gzip'd `/large.gz` endpoint and `package.json` gained the
`bench:profile:heap:fine` script with a 64 KB interval. Raw outputs are in `test/bench/.out/b4-*`
and `b5-*`.

### B4 — Parallel throughput: root cause is per-TLS-record cipher creation

Scaling curve (each row 3 rounds, same server):

| Parallelism |  req p50 |  req p95 | queue p50 (hSent→FB) | body p50 (FB→end) | event-loop lag | pool (created) |
| ----------: | -------: | -------: | -------------------: | ----------------: | -------------: | -------------: |
|           5 |  9.12 ms |  9.83 ms |              3.97 ms |           1.83 ms |   2.5 / 4.1 ms |              1 |
|          10 | 11.89 ms | 16.62 ms |              6.58 ms |           2.07 ms |   3.9 / 7.3 ms |              1 |
|          25 | 22.66 ms | 30.85 ms |             10.78 ms |           2.38 ms |  5.4 / 11.8 ms |              1 |
|          50 | 36.76 ms | 50.26 ms |             19.95 ms |           5.81 ms | 11.6 / 20.9 ms |              1 |
|         100 | 63.88 ms | 80.65 ms |             34.10 ms |           7.64 ms | 18.5 / 41.8 ms |              1 |

**Ruled out:**

- **Not connection setup:** all 5000 requests ran over **one** h2 connection (`created=1`,
  `hits` 1 → 5001); no extra TLS handshakes.
- **Not flow control:** body time stays between 1.8 → 7.6 ms while queue time grows linearly
  4 → 34 ms. The bottleneck is CPU/stream processing serializing requests.
- **CPU profile (5000 requests, isolated concurrent):** the `createCipheriv`/`createDecipheriv`
  chain under `encrypt`/`decrypt` totals **~331 ms / 2861 ms (11.6%)**:
  `getKeyObjectSlots < isKeyObject < prepareSecretKey < createCipheriv` 119.5 ms,
  `getSlots < isCryptoKey < prepareSecretKey < createCipheriv` 85.2 ms,
  `createCipherBase` 44 + 11.8 ms, `update` 32 + 2.6 ms, decrypt side 36.4 ms.
  Source: `lib/tls/tls.ts:1358 / 1396` — a new Cipher/Decipher object is created for **every TLS
  record**. `huffman.encode` 145 ms (5.1%), `hpack.findInTables` 28 ms (1.0%).
- **Queue delay = event-loop lag:** average lag 11.6 ms (50 parallel), queue p50 19.95 ms;
  together they confirm serialization.

**B4 diagnosis:** most of the ~28 ms at 50 parallel is key preparation + object setup from calling
`crypto.createCipheriv` for each of 100+ TLS records on a single h2 connection. node-http2
(12.6 ms) avoids this cost with C++ TLS and cipher reuse.

### B5 — 1 MB body memory: retention is fine, native Buffer high-water mark

| Scenario (100 × 1 MB)      |    wall |  req p50 |       RSS Δ | arrayBuffers (before→after→GC) | external (before→after→GC) |
| -------------------------- | ------: | -------: | ----------: | ------------------------------ | -------------------------- |
| `/large` (uncompressed)    | 1448 ms | 13.14 ms |     91.7 MB | 0.33 → 24.91 → **0.39 MB**     | 11.56 → 36.12 → 36.12 MB   |
| `/large.gz` (auto-deflate) | 1036 ms | 10.34 ms | **20.8 MB** | 0.33 → 4.45 → **0.45 MB**      | 11.56 → 15.67 → 15.67 MB   |
| `/large` + `identity`      | 1449 ms | 13.23 ms |    100.8 MB | 0.33 → 34.08 → **0.39 MB**     | 11.56 → 45.29 → 13.67 MB   |
| `/large` 200 reps          | 2729 ms | 12.41 ms |    101.7 MB | 0.33 → 81.06 → **0.39 MB**     | 11.56 → 92.27 → 21.60 MB   |

**Ruled out:**

- **No JS leak:** after forced GC `arrayBuffers` drops from 24–81 MB to 0.39 MB. Even if RSS
  stays high (glibc arena high-water mark), the memory is reclaimable; RSS Δ is the same at 100
  and 200 reps (~92–102 MB) — no linear growth.
- **zlib is not to blame:** the gzip'd body gives RSS Δ 20.8 MB (vs 91.7 MB uncompressed). The
  same 1 MB output is produced, but only ~1 KB is sent on the wire → the difference comes from
  Buffer churn in the 100 MB **uncompressed TLS record** stream. This points to the same root
  cause as B4.
- **Heap profiler limitation:** even at a 64 KB interval only ~100 samples / ~6 MB were collected;
  V8's sampling heap profiler does not cover native `Buffer`/`external` allocations. The decisive
  evidence came from `process.memoryUsage()` dumps.

**Common root cause:** B4 and B5 both point to the same place — the per-record
`createCipheriv`/`createDecipheriv` + `Buffer.concat` chain in `lib/tls/tls.ts`. The earlier
"insufficient evidence" note is no longer valid.

## Phase 6 — B4/B5 optimization

### 6.1 — Caching traffic keys as `KeyObject` (kept)

`reinit` does not exist in Node 24; the measured alternative was a `CryptoKey` cache:
`WeakMap<Buffer, crypto.KeyObject>` + `createSecretKey`. Micro measurement (16 KB, 20k iterations):
encrypt 38.1 → 17.3 µs (2.2x), decrypt 34.9 → 12.6 µs (2.8x). `createSecretKey` working under
workerd's `nodejs_compat` was verified with a real workers test. Thanks to the WeakMap, a key
update makes the old entry collectible automatically — no explicit invalidation.

`test/node/tls-record-keyobject.test.ts`: the old Buffer-key implementation is **kept as an
oracle**; byte-for-byte comparison including header/nonce/AAD/tag over 3 rounds, decrypt
round-trip and rejection of a different key's AEAD tag are tested.

| Scenario (median of 3 runs) |   Before |        After |                  Change |
| --------------------------- | -------: | -----------: | ----------------------: |
| bench 50 parallel           |  28.2 ms |      22.7 ms |              **-19.5%** |
| bench warm p50              |   1.6 ms |       1.3 ms |                **-19%** |
| bench cold                  |  62.0 ms |      63.3 ms | noise (60.3–64.9 range) |
| profile concurrent p50      | 26.37 ms | **21.86 ms** |                **-17%** |
| profile warm p50            |  1.42 ms |  **1.24 ms** |                **-13%** |
| profile large-body p50      | 17.27 ms | **12.07 ms** |                **-30%** |
| profile cold p50            |  8.52 ms |      8.36 ms |                   noise |

Isolated CPU profile (5000 requests): cipher stack share **11.6% → 4.5%** (116.3 ms / 2559.2 ms).
Mechanism verified; gain ≥5% and above the noise band → **kept**.

Gates: 484 tests passed, `typecheck`, `lint` (0 errors), Prettier clean; soak 300 requests /
2.02 s (was 2.13 s), heap 2.33 MB, handles 5 → 5.

### 6.2 — Single-buffer record assembly (rejected / reverted)

Replacing the `Buffer.concat` chain with `Buffer.allocUnsafe(5 + payloadLength)` + `copy()` was
tried. The byte-for-byte oracle test and all 484 tests passed, but measurement showed no gain:

| Scenario (median of 3 runs) | 6.1 (KeyObject) | 6.2 (single buffer) |                               Change |
| --------------------------- | --------------: | ------------------: | -----------------------------------: |
| bench 50 parallel           |         22.7 ms |             22.9 ms |                                   ~0 |
| bench warm p50              |          1.3 ms |              1.3 ms |                                   ~0 |
| profile concurrent p50      |        21.86 ms |            21.74 ms |                        -0.5% (noise) |
| profile warm p50            |         1.24 ms |             1.21 ms |                        -2.4% (noise) |
| profile large-body p50      |        12.07 ms |            11.42 ms | -5.4% but 9.5–12.5 ms spread → noise |

The assembly change looked promising in the micro-benchmark (29%) but did not show up end to end;
`Buffer.concat` cost is small next to cipher setup. The acceptance criterion (≥5% **and** above
noise) was not met, so the code was **reverted**; only change 6.1 remains in the tree.

## Phase 7 — Keepalive / TLS resume fingerprint verification

After the optimizations, whether the fingerprint degraded was verified using browserleaks' two
endpoints (`/tls`, `/http2`) and a second observer that issues tickets (`tools.scrapfly.io`).

### 7.1 — Cold ClientHello: no degradation

`https://tls.browserleaks.com/tls` was called with a fresh connection using the `chrome147-mac`
profile:

| Field         | Observed                               | Expected (fixture) |
| ------------- | -------------------------------------- | ------------------ |
| JA4           | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | same               |
| cipher_suites | 16                                     | 16                 |
| extensions    | 18 (2 GREASE + 16)                     | same               |

Changes B1/B2/B3/6.1 did not affect the cold CH bytes — JA4 was preserved byte-for-byte. The
offline guard in `test/node/fingerprint.test.ts` pins the same value in `npm test`.

### 7.2 — TLS resume: changes as expected, not a regression

Browsers add the `pre_shared_key` (0x0029) extension on resumption, so JA4 goes from 16 → 17
extensions. The same holds for us and is correct behavior:

| Scenario (observer)              | JA4                                    | Note                           |
| -------------------------------- | -------------------------------------- | ------------------------------ |
| Cold (browserleaks)              | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | reference                      |
| Resume (scrapfly)                | `t13d1517h2_8daaf6152771_b6f405a00624` | 17 ext, `0029` in `ja4_r`      |
| Real Chrome 158 (headless, cold) | `t13d1517h2_8daaf6152771_cb7bf5808d99` | same JA4_a class, same `ja4_b` |

Key points: `ja4_b` (sorted cipher hash) **does not change** (`8daaf6152771`), cipher/group/sigalg
lists stay the same, only `ja4_c` differs because of the new extension. In the live scrapfly
report the `pre_shared_key (41)` extension appears last. The offline test
(`test/node/fingerprint.test.ts`) verifies that PSK is the last extension and JA4 is
`t13d1517h2_...`; the live test (`test/fingerprint/browserleaks.test.ts`) verifies that `0029` is
visible to the observer.

Note: browserleaks does not issue `NewSessionTicket`, so live resumption was measured via
scrapfly. Both observers use the same JA4 syntax (FoxIO spec), so the values are comparable.

### 7.3 — Keepalive: no new fingerprint produced

When a connection is taken from the pool, no new ClientHello or SETTINGS is sent; from the
observer's point of view there is no byte that could change the fingerprint. The risk was on the
h2 HEADERS side; `test/unit/h2-keepalive-headers.test.ts` issues two requests on the same
`H2Session` and verifies:

- HEADERS payload (5 B priority + full HPACK block) is **byte-for-byte identical**,
- `END_STREAM | END_HEADERS | PRIORITY` flags are preserved,
- no extra SETTINGS / WINDOW_UPDATE frames on the second request.

The live `/http2` check also confirmed the Akamai fingerprint from that session:
`akamai_text = 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
(offline reference: `test/unit/h2-chrome-headers.test.ts`).

### 7.4 — Conclusion and gates

**No degradation.** Cold JA4 preserved; the resume difference is in the same direction as Chrome
and expected; keepalive produces no new fingerprint bytes. Added tests: `test/node/fingerprint.test.ts`
(offline resume guard), `test/unit/h2-keepalive-headers.test.ts` (byte-for-byte keepalive) and
`test/fingerprint/browserleaks.test.ts` (live, `network` project — not part of `npm test`).

Gates: 490 tests / 73 files passed, `typecheck`, `lint` (0 warnings), Prettier clean.
The live fingerprint test also passed 4/4 with `npm run test:fingerprint`.

### Remaining

- Most of the B4/B5 common root cause was resolved by 6.1; the remaining TLS record Buffer churn
  needs a broader write-path redesign, and the current measurements do not justify it.
- Real network / live QUIC measurement was not possible in this environment; the remote tables
  remain historical.
