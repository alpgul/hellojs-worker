// Live hosts for the `network` project — one per capability, not one per test.
//
// Tests import these constants instead of hard-coding a host so the whole suite is retargeted
// in one place. Each host answers a question the others cannot (HTTP echo, ClientHello parsing,
// TLS 1.2-only, QUIC); repeating the same assertion against several servers reports on those
// servers, not on this library.

// HTTP semantics: echo endpoints, redirects, compression, cookies.
export const HTTP_HOST = 'httpbingo.org'
// Fingerprint reporting: parses the ClientHello it just received.
export const FINGERPRINT_HOST = 'tools.scrapfly.io'
// TLS 1.3 + h2 baseline; also the HRR and SCT subject.
export const TLS13_HOST = 'www.cloudflare.com'
// QUIC / HTTP/3 endpoint.
export const QUIC_HOST = 'cloudflare-quic.com'
// TLS 1.2-only server for the fallback path.
export const TLS12_HOST = 'httpbin.org'
// Parrot captures: peetprint exists only in this API's response.
export const PEET_HOST = 'tls.peet.ws'
