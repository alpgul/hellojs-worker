# Performance profiling — Faz 1 / 2 / 3 raporu

> Tüm sayılar **yerel** ortamda alındı: Node v24.21.0, Linux, ağ kapalı. Sunucu, bu klasördeki
> `helpers.ts` ile ayağa kaldırılan self-signed HTTP/2 sunucusu (loopback, 1 KB gövde; `/large`
> 1 MB). Her ölçüm 3 tekrarın **medyanı**. Ham çıktılar `test/bench/.out/` (gitignore) altında.

## Gate durumu

| Kontrol                | Sonuç                                                                 |
| ---------------------- | --------------------------------------------------------------------- |
| `npm test`             | 69 dosya / 477 test geçti                                             |
| `npm run typecheck`    | geçti                                                                 |
| `npm run lint`         | geçti (0 hata, 54 mevcut uyarı)                                       |
| `npm run format:check` | **47 mevcut dosyada** zaten başarısız; ilgisiz dosyalar formatlanmadı |

## Eklenen araçlar

| Dosya / komut                                            | Amaç                                                                                         |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `helpers.ts`                                             | Cert + yerel h2 sunucusu + istatistik (mevcut `clients.ts` de artık bunu kullanıyor)         |
| `profile.ts` / `npm run bench:profile`                   | 4 senaryo: cold / warm / concurrent / large-body; duvar saati, RSS, `observability` olayları |
| `profile.ts` / `bench:profile:cpu`, `bench:profile:heap` | V8 CPU / sampling heap profili (`.out/`)                                                     |
| `profile.ts` / `PROFILE_NO_UDP=1`                        | UDP seam'ini kapatıp TCP-only kontrol koşusu                                                 |
| `micro.ts` / `npm run bench:micro`                       | Saf fonksiyonlar için ns/op (3 geçişin medyanı)                                              |
| `analyze.ts` / `npm run bench:analyze -- <profile>`      | `.cpuprofile` → self/total time tabloları                                                    |

---

## Faz 1 — Profiling sonuçları

### A. İstemci karşılaştırması (`npm run bench`, WARM_REPS=100, medyan)

| Client       | Cold (ms) | Warm p50 | Warm p99 | 50 paralel |      RSS Δ |
| ------------ | --------: | -------: | -------: | ---------: | ---------: |
| **hellojs**  | **356.2** |      1.6 |      3.3 |       36.1 |    11.4 MB |
| node-https   |      23.4 |      0.6 |      1.6 |       76.4 |     8.7 MB |
| node-http2   |      14.8 |      0.6 |      1.5 |   **13.5** | **4.8 MB** |
| undici       |      22.3 |      0.9 |      2.7 |       14.6 |     7.0 MB |
| got          |      28.0 |      1.4 |      3.2 |       28.1 |    11.9 MB |
| axios        |      22.7 |      1.0 |      3.0 |      101.3 |    13.9 MB |
| node-fetch   |      22.0 |      1.1 |      2.8 |       95.1 |    20.6 MB |
| fetch-native |      39.0 |      1.0 |      3.5 |      131.4 |    31.0 MB |

### B. Senaryo profili (UDP açık vs kapalı, medyan)

| Senaryo                    | UDP açık (mevcut) | UDP kapalı (kontrol) |                 Fark |
| -------------------------- | ----------------: | -------------------: | -------------------: |
| cold p50 (30 req)          |         313.38 ms |              7.50 ms | **+305.9 ms (~42x)** |
| warm p50 (200 req)         |           1.64 ms |              1.59 ms |             +0.05 ms |
| concurrent p50 (50 req)    |          32.12 ms |             31.98 ms |             +0.14 ms |
| large-body p50 (10 × 1 MB) |          18.55 ms |             17.24 ms |             +1.31 ms |

CPU profili (10.7 s örnekleme): **%87.5 `(idle)`** — yani cold maliyeti CPU değil **bekleyiş**.
Warm odaklı profil (3000 istek): idle %13.1, `huffman.encode` self **315 ms (~105 µs/istek,
%7.5)**, `hpack.findInTables` 25 ms, `buildH2Headers` 36 ms Self. Cold (UDP kapalı) profilinde
`spawnSync` (sertifika üretimi) 322 ms ve `deriveBits`/WASM (X25519 + ML-KEM) ilk sıralarda;
bunlar tek seferlik başlangıç maliyeti, istek başına değil.

Heap profili seyrek (9 örnek / 512 KB aralık): X25519 `deriveBitsImpl` ~512 KB, ML-KEM WASM
~512 KB, `h2/session.ts:_dispatch` ~512 KB, modül derlemesi ~1.5 MB. Kesin sonuç için yeterli
değil; 1 MB gövde senaryosunda RSS Δ 26–52 MB (10 istek) bellek tarafında ayrıca incelenmeli.

### C. Mikro-bench (medyan ns/op)

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

Not: `hpack.encodeString` her string'i Huffman ile kodlamaya çalışır (`lib/h2/hpack.ts:157`),
dolayısıyla `huffman.encode` **her h2 isteğinin** header yolundadır.

---

## Faz 2 — Bottleneck analysis

| #      | Darboğaz                                                                                                | Ölçülmüş maliyet                        | Kanıt                                                         | Sınıf              | Risk                                       |
| ------ | ------------------------------------------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------- | ------------------ | ------------------------------------------ |
| **B1** | QUIC→TCP race: UDP varsa TCP 300 ms gecikmeli başlıyor; QUIC yanıt vermeyen origin'de bu bedel ödeniyor | cold'a **+306 ms** (cold'un %97'si)     | 313.38 vs 7.50 ms; CPU %87.5 idle; `transport-race.ts:17,137` | latency / tasarım  | **Yüksek** (Chrome race semantiği değişir) |
| **B2** | `huffman.encode` BigInt birikteç ile bayt bayt kaydırma                                                 | **100.9 µs/istek**, warm CPU'nun %7.5'i | micro + warm cpuprofile; `h3/huffman.ts:103`                  | CPU                | Düşük (çıktı aynı kalabilir)               |
| **B3** | QPACK/HPACK statik tablo aramaları lineer                                                               | ~300 ns/arama, 17 header ≈ 5 µs         | micro; `qpack.ts:126`, `hpack.ts:172`                         | algoritmik         | Düşük                                      |
| **B4** | 50 paralel istek 32 ms; node-http2 13.5 ms. UDP kapalı olunca düzelmiyor → B1 değil                     | ~18.6 ms fark                           | bench + senaryo profili                                       | CPU / h2 akışı     | Orta (profil gerek)                        |
| **B5** | 1 MB gövdeler için RSS Δ 26–52 MB/10 istek                                                              | bellek baskısı                          | senaryo profili + seyrek heap profili                         | bellek / GC        | Orta (kanıt zayıf)                         |
| **B6** | `observability.ts` dns/connect/handshake olaylarını dokümante ediyor ama hiç emit edilmiyor             | faz bazlı ölçüm yapılamadı              | `grep safeEmit`: sadece `client.ts` request olayları          | gözlemlenebilirlik | Düşük (özellik değil, audit bulgusu)       |

**Dokunulmaması gerekenler:** ClientHello parabola/header sırası (JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`),
profil sabit header'ları (`EHEADERFIXED`), h2 header sırası, 300 ms race'in kendisi (ürün kararı
olmadan). B1'in "düzeltmesi" performans kazanımı kadar davranış değişikliğidir; Faz 4'te **önce
kullanıcı onayı** istenecek.

---

## Faz 3 — Performance audit

**Metodoloji:** 3 tekrar + medyan, loopback sunucu, warm-up (2 istek), `hrtime.bigint()`, aynı
Node sürümü. Zayıf noktalar: (a) ağ olmadığı için RTT/gerçek QUIC ölçülemiyor; (b) RSS Δ GC
zamanına duyarlı; (c) CPU profiline sertifika üretimi (`spawnSync` ~322 ms) giriyor, bu yüzden
cold profili tek başına yorumlanmamalı; (d) `format:check` tabanında 47 dosya zaten bozuk.

**Regresyon korumaları (Faz 4'te her değişiklikten sonra çalıştırılacak):**
`npm test` (fingerprint + JA4 dahil), `npm run typecheck`, `npm run lint`, yeni dosyalar için
`prettier --check`, `npm run bench:profile` (aynı senaryolar), `npm run bench:micro`, `npm test --
 --project=node test/soak` (heap/handle geri dönüşü).

**Cross-runtime:** workerd'da `node:dgram` yok; UDP seam zaten bunu `setUdpProvider(null)` ile
ele alıyor. Optimizasyonlar Node-only API eklememeli; `huffman.ts`/`hpack.ts` mevcut `Buffer`
kullanımı workers tarafında da destekleniyor.

**Önerilen sıra (Faz 4):**

1. **B2** — `huffman.encode`: BigInt → 53-bit güvenli sayı birikteç; mevcut çıktıyla birebir
   doğrulama (fuzz + unit test). Beklenen: 5–10x encode hızı, warm p50'de ~0.05–0.1 ms.
2. **B3** — statik tablo aramaları için name/value → index Map; beklenen ~5 µs/istek.
3. **B4/B5** — hedefli profil + ayrı adımlar; ölçüm yoksa dokunulmaz.
4. **B1** — ürün kararı: race gecikmesini korumak mı, yoksa QUIC yoksa hızlı TCP fallback mi?
   Bu adım onaysız uygulanmayacak.

---

## Faz 4 — Uygulanan optimizasyonlar (ölç → değiştir → ölç → sakla)

### B2 — `huffman.encode`: BigInt → 53-bit güvenli sayı birikteç

- `lib/h3/huffman.ts`: bayt başına BigInt kaydırma/ dönüşüm yerine `number` birikteç
  (her flush sonrası ≤7 bit + en fazla 30 bitlik kod = 2^37 < 2^53).
- `test/unit/huffman.test.ts`: eski BigInt algoritması **oracle olarak korundu**; 256 baytlık
  tam set + 50 rastgele buffer için çıktı birebir karşılaştırılıyor.
- Mikro: **100,923 → 31,630 ns/op** (3.2x). `hpack.encode` de bundan faydalandı:
  **88,413 → 42,101 ns/op** (2.1x).

### B3 — statik tablo aramaları Map ile

- `lib/h2/hpack.ts` ve `lib/h3/qpack.ts`: değişmeyen statik tablolar modül yüklenirken
  `exact (name\0value)` ve `name → index` Map'lerine alındı; dinamik tablo araması ve
  "önce exact, sonra name-only, önce statik" sırası korundu.
- `test/unit/qpack.test.ts`: tüm statik girdiler için exact/name-only/miss ve encode→decode
  round-trip testi eklendi.
- Mikro: `findStatic` hit **300 → 34 ns**, miss **266 → 19 ns**; `qpack.encodeHeaders`
  16,965 → 15,692 ns.

### Uçtan uca doğrulama (3 tekrarın medyanı)

| Senaryo                |    Öncesi |   Sonrası |              Değişim |
| ---------------------- | --------: | --------: | -------------------: |
| bench warm p50         |    1.6 ms |    1.5 ms |                  -6% |
| bench 50 paralel       |   36.1 ms |   28.4 ms |             **-21%** |
| profile warm p50       |   1.64 ms |   1.50 ms |                -8.5% |
| profile concurrent p50 |  32.12 ms |  27.39 ms |             **-15%** |
| cold p50               | 313.38 ms | 312.63 ms |  ~0 (B1 hâlâ baskın) |
| large-body p50         |  18.55 ms |  17.93 ms | gürültü bandı içinde |

**Karar:** B2 ve B3 saklandı (≥%5 ve gürültü üstü; 50 paralel ve warm belirgin iyileşti).
Cold ve büyük gövde senaryolarında anlamlı değişim yok — beklenen sonuç.

**Kontroller:** `npm test` 70 dosya / 480 test geçti (yeni 3 test dahil), `typecheck` geçti,
`lint` 0 hata, yeni/değişen dosyalar `prettier --check` geçti, soak: 300 istek / 4.21 s,
heap 2.30 MB, handle 5 → 5 (sızıntı yok).

### B1 — Happy Eyeballs: 300 ms head start kaldırıldı (hız öncelikli karar)

Kullanıcı kararı: **hız öncelikli**; Chrome'un QUIC'e 300 ms öncelik vermesi kabul edilemez.
`lib/transport-race.ts` artık QUIC ve TCP+TLS'i **aynı tick'te** başlatıyor, ilk biten bağlantı
kazanıyor ve diğeri hemen abort/close ediliyor. Sabit gecikme ve ilgili timer kaldırıldı.
`test/node/transport-race.test.ts`: QUIC'in yanıt vermediği yerel seneryoda bağlantının
250 ms altında tamamlanmasını zorunlu kılıyor (eski kod ≥300 ms alırdı).

| Senaryo (3 tekrar medyanı) | Tüm optimizasyon öncesi |   Son final |          Değişim |
| -------------------------- | ----------------------: | ----------: | ---------------: |
| bench cold                 |                356.2 ms | **62.0 ms** |         **-83%** |
| bench warm p50             |                  1.6 ms |      1.6 ms |               ~0 |
| bench 50 paralel           |                 36.1 ms |     28.2 ms |         **-22%** |
| profile cold p50           |               313.38 ms | **8.52 ms** | **-97% / 36.8x** |
| profile warm p50           |                 1.64 ms |     1.43 ms |             -13% |
| profile concurrent p50     |                32.12 ms |    27.08 ms |             -16% |
| profile large-body p50     |                18.55 ms |    17.27 ms |              -7% |

Not: bench cold (62 ms), profil cold'undan (8.5 ms) yüksektir çünkü her istemci ayrı
subprocess'te başlar ve ölçüm ilk isteğin ilk baytını içerir; ikisi aynı şeyi ölçmez.

**Son kontroller:** `npm test` 71 dosya / 481 test geçti, `typecheck` geçti, `lint` 0 hata,
değişen dosyalar `prettier --check` geçti. README Performance bölümü ve transport seçimi
dokümantasyonu güncel sayılarla güncellendi.

## Faz 5 — B4/B5 hedefli profil

Araç genişletmesi: `profile.ts` artık `PROFILE_ROUNDS`, `PROFILE_BODY_REPS`, `PROFILE_BODY_GZIP`,
`PROFILE_BODY_IDENTITY`, `PROFILE_GC`, bellek dökümü (rss / heapUsed / arrayBuffers / external),
`poolStats()`, event-loop lag ve istek bazlı `headersSent → firstByte → end` zaman çizelgesi
üretiyor. `helpers.ts` gzip'lı `/large.gz` endpoint'i, `package.json` ise 64 KB aralıklı
`bench:profile:heap:fine` scripti aldı. Ham çıktılar `test/bench/.out/b4-*`, `b5-*`.

### B4 — Paralel throughput: kök neden TLS kayıt başına cipher oluşturma

Ölçekleme eğrisi (her satır 3 tur, aynı sunucu):

| Paralellik |  req p50 |  req p95 | kuyruk p50 (hSent→FB) | gövde p50 (FB→end) | event-loop lag | havuz (created) |
| ---------: | -------: | -------: | --------------------: | -----------------: | -------------: | --------------: |
|          5 |  9.12 ms |  9.83 ms |               3.97 ms |            1.83 ms |   2.5 / 4.1 ms |               1 |
|         10 | 11.89 ms | 16.62 ms |               6.58 ms |            2.07 ms |   3.9 / 7.3 ms |               1 |
|         25 | 22.66 ms | 30.85 ms |              10.78 ms |            2.38 ms |  5.4 / 11.8 ms |               1 |
|         50 | 36.76 ms | 50.26 ms |              19.95 ms |            5.81 ms | 11.6 / 20.9 ms |               1 |
|        100 | 63.88 ms | 80.65 ms |              34.10 ms |            7.64 ms | 18.5 / 41.8 ms |               1 |

**Ayırt edilen nedenler:**

- **Bağlantı kurulumu değil:** 5000 isteğin tamamı **tek** h2 bağlantısında (`created=1`,
  `hits` 1 → 5001); ek TLS handshake yok.
- **Flow-control değil:** gövde süresi 1.8 → 7.6 ms arasında kalırken kuyruk süresi 4 → 34 ms
  doğrusal artıyor. Darboğaz istekleri sıraya sokan CPU/stream işleme.
- **CPU profili (5000 istek, izole concurrent):** `encrypt`/`decrypt` altındaki
  `createCipheriv`/`createDecipheriv` zinciri toplam **~331 ms / 2861 ms (%11.6)**:
  `getKeyObjectSlots < isKeyObject < prepareSecretKey < createCipheriv` 119.5 ms,
  `getSlots < isCryptoKey < prepareSecretKey < createCipheriv` 85.2 ms,
  `createCipherBase` 44 + 11.8 ms, `update` 32 + 2.6 ms, decrypt tarafı 36.4 ms.
  Kaynak: `lib/tls/tls.ts:1358 / 1396` — **her TLS kaydı** için yeni Cipher/Decipher nesnesi
  oluşturuluyor. `huffman.encode` 145 ms (%5.1), `hpack.findInTables` 28 ms (%1.0).
- **Kuyruk gecikmesi = event-loop lag:** lag ort. 11.6 ms (50 paralel), kuyruk p50 19.95 ms;
  ikisi birlikte serileşmeyi doğruluyor.

**B4 tanısı:** 50 paraleldeki ~28 ms'in ana bölümü, tek h2 bağlantısında 100+ TLS kaydının
her biri için `crypto.createCipheriv` çağrısının getirdiği anahtar hazırlama + nesne kurulumu.
node-http2 (12.6 ms) C++ TLS ve cipher Reuse kullandığı için bu bedeli ödemiyor.

### B5 — 1 MB gövde belleği: tutma değil, native Buffer tepe değeri

| Senaryo (100 × 1 MB)       |    wall |  req p50 |       RSS Δ | arrayBuffers (önce→sonra→GC) | external (önce→sonra→GC) |
| -------------------------- | ------: | -------: | ----------: | ---------------------------- | ------------------------ |
| `/large` (sıkışmamış)      | 1448 ms | 13.14 ms |     91.7 MB | 0.33 → 24.91 → **0.39 MB**   | 11.56 → 36.12 → 36.12 MB |
| `/large.gz` (auto-deflate) | 1036 ms | 10.34 ms | **20.8 MB** | 0.33 → 4.45 → **0.45 MB**    | 11.56 → 15.67 → 15.67 MB |
| `/large` + `identity`      | 1449 ms | 13.23 ms |    100.8 MB | 0.33 → 34.08 → **0.39 MB**   | 11.56 → 45.29 → 13.67 MB |
| `/large` 200 tekrar        | 2729 ms | 12.41 ms |    101.7 MB | 0.33 → 81.06 → **0.39 MB**   | 11.56 → 92.27 → 21.60 MB |

**Ayırt edilen nedenler:**

- **JS sızıntısı yok:** zorunlu GC sonrası `arrayBuffers` 24–81 MB → 0.39 MB'a düşüyor.
  RSS yüksek kalsa da (glibc arena high-water mark) bellek geri alınabilir durumda; 100 ve
  200 tekrarda RSS Δ aynı (~92–102 MB) — doğrusal büyüme yok.
- **zlib suçlu değil:** gzip'lı gövde RSS Δ 20.8 MB (sıkışmamış 91.7 MB). Aynı 1 MB çıktı
  üretilmesine rağmen telde ~1 KB gönderiliyor → fark, 100 MB'lık **sıkışmamış TLS kayıt**
  akışının Buffer churn'ünden geliyor. Bu da B4 ile aynı kök nedeni gösteriyor.
- **Heap profiler sınırı:** 64 KB aralığa rağmen sadece ~100 örnek / ~6 MB toplandı; V8
  sampling heap profiler native `Buffer`/`external` ayırmalarını kapsamıyor. Karar verici
  kanıt `process.memoryUsage()` dökümü oldu.

**Ortak kök neden:** B4 ve B5 aynı yere işaret ediyor — `lib/tls/tls.ts` içindeki kayıt başına
`createCipheriv`/`createDecipheriv` + `Buffer.concat` zinciri. Önceki "kanıt yetersiz" notu
artık geçerli değil.

## Faz 6 — B4/B5 optimizasyonu

### 6.1 — Traffic key'leri `KeyObject` olarak önbelleğe alma (saklandı)

`reinit` Node 24'te yok; ölçülen alternatif `CryptoKey` önbelleğiydi:
`WeakMap<Buffer, crypto.KeyObject>` + `createSecretKey`. Mikro ölçüm (16 KB, 20k iter):
encrypt 38.1 → 17.3 µs (2.2x), decrypt 34.9 → 12.6 µs (2.8x). `createSecretKey`'in workerd
`nodejs_compat`'ında çalıştığı gerçek workers testiyle doğrulandı. WeakMap sayesinde key update
olduğunda eski girdi kendiliğinden collectible — elle invalidation yok.

`test/node/tls-record-keyobject.test.ts`: eski Buffer-key implementasyonu oracle olarak
korundu; 3 tur boyunca header/nonce/AAD/tag dahil **byte-for-byte** karşılaştırma, decrypt
round-trip ve farklı key'in AEAD tag'ini reddetmesi test ediliyor.

| Senaryo (3 tekrar medyanı) |   Öncesi |      Sonrası |                     Değişim |
| -------------------------- | -------: | -----------: | --------------------------: |
| bench 50 paralel           |  28.2 ms |      22.7 ms |                  **-19.5%** |
| bench warm p50             |   1.6 ms |       1.3 ms |                    **-19%** |
| bench cold                 |  62.0 ms |      63.3 ms | gürültü (60.3–64.9 aralığı) |
| profile concurrent p50     | 26.37 ms | **21.86 ms** |                    **-17%** |
| profile warm p50           |  1.42 ms |  **1.24 ms** |                    **-13%** |
| profile large-body p50     | 17.27 ms | **12.07 ms** |                    **-30%** |
| profile cold p50           |  8.52 ms |      8.36 ms |                     gürültü |

İzole CPU profili (5000 istek): cipher stack payı **%11.6 → %4.5** (116.3 ms / 2559.2 ms).
Mekanizma doğrulandı; kazanım ≥%5 ve gürültü bandının üstünde → **saklandı**.

Gate'ler: 484 test geçti, `typecheck`, `lint` (0 hata), Prettier temiz; soak 300 istek /
2.02 s (önce 2.13 s), heap 2.33 MB, handle 5 → 5.

### 6.2 — Tek Buffer ile kayıt montajı (reddedildi / revert edildi)

`Buffer.concat` zinciri yerine `Buffer.allocUnsafe(5 + payloadLength)` + `copy()` denendi.
Byte-for-byte oracle testi ve 484 test geçti, ama ölçüm kazanım göstermedi:

| Senaryo (3 tekrar medyanı) | 6.1 (KeyObject) | 6.2 (tek buffer) |                                 Değişim |
| -------------------------- | --------------: | ---------------: | --------------------------------------: |
| bench 50 paralel           |         22.7 ms |          22.9 ms |                                      ~0 |
| bench warm p50             |          1.3 ms |           1.3 ms |                                      ~0 |
| profile concurrent p50     |        21.86 ms |         21.74 ms |                         -0.5% (gürültü) |
| profile warm p50           |         1.24 ms |          1.21 ms |                         -2.4% (gürültü) |
| profile large-body p50     |        12.07 ms |         11.42 ms | -5.4% ama 9.5–12.5 ms dağılım → gürültü |

Mikro-bench'te umut verici görünen (%29) montaj değişikliği uçtan uca ölçümde görünmedi;
`Buffer.concat` maliyeti cipher kurulumunun yanında küçük kaldı. Kabul kriteri (≥%5 **ve** gürültü
üstü) sağlanmadığı için kod **geri alındı**; ağaçta yalnızca 6.1 değişikliği kaldı.

### Kalanlar

- B4/B5 ortak kök nedeninin büyük kısmı 6.1 ile çözüldü; kalan TLS kaydı Buffer churn'ü için
  daha kapsamlı bir yazma yolu redesign'ı gerekir ve mevcut ölçümler bunu haklı çıkarmıyor.
- Gerçek ağ / canlı QUIC ölçümü bu ortamda yapılamadı; remote tabloları historical olarak kaldı.
