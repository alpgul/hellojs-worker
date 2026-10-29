// Chrome 147 on macOS profile — pinned values that produce a fingerprint identical to
// the real browser captured in test/fixtures/chrome147-peet.json.

import { CIPHERS, GROUPS, SIGNATURE_ALGORITHMS, EXTENSIONS, CERT_COMPRESSION } from '../utils/config.js'

const CHROME_147_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36'

// Insertion order is the wire order for HTTP/2 request headers.
const CHROME_147_HEADERS = Object.freeze({
	'sec-ch-ua': '"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"',
	'sec-ch-ua-mobile': '?0',
	'sec-ch-ua-platform': '"macOS"',
	'upgrade-insecure-requests': '1',
	'user-agent': CHROME_147_UA,
	'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	'sec-fetch-site': 'none',
	'sec-fetch-mode': 'navigate',
	'sec-fetch-user': '?1',
	'sec-fetch-dest': 'document',
	'accept-encoding': 'gzip, deflate, br, zstd',
	'accept-language': 'en-US,en;q=0.9,es;q=0.8',
	'priority': 'u=0, i',
})

export default {
	name: 'chrome147-mac',

	tls: {
		// Cipher list (exclusive of GREASE which is added at runtime per connection)
		ciphers: [
			CIPHERS.TLS_AES_128_GCM_SHA256,
			CIPHERS.TLS_AES_256_GCM_SHA384,
			CIPHERS.TLS_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			CIPHERS.TLS_RSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_RSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_RSA_WITH_AES_128_CBC_SHA,
			CIPHERS.TLS_RSA_WITH_AES_256_CBC_SHA,
		],

		// Per-instance extension permutation. true = pinned at start/end (GREASE).
		// All other extensions are shuffled per-instance.
		extensionPermutation: 'shuffle-middle',

		// ALPN order (Chrome prefers h2)
		alpn: ['h2', 'http/1.1'],

		// signature_algorithms (RFC 8446 §4.2.3) — exact Chrome 147 list, in order
		signatureAlgorithms: [
			SIGNATURE_ALGORITHMS.ECDSA_SECP256R1_SHA256,
			SIGNATURE_ALGORITHMS.RSA_PSS_RSAE_SHA256,
			SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA256,
			SIGNATURE_ALGORITHMS.ECDSA_SECP384R1_SHA384,
			SIGNATURE_ALGORITHMS.RSA_PSS_RSAE_SHA384,
			SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA384,
			SIGNATURE_ALGORITHMS.RSA_PSS_RSAE_SHA512,
			SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA512,
		],

		// supported_groups (excl. GREASE)
		supportedGroups: [GROUPS.X25519MLKEM768, GROUPS.X25519, GROUPS.P256, GROUPS.P384],

		// Which groups to send a key_share for (key_share entries are MLKEM hybrid + X25519)
		keyShareGroups: [GROUPS.X25519MLKEM768, GROUPS.X25519],

		// ALPS extension type (v1 vs v2). Chrome 147 still uses v1.
		alpsExtensionType: EXTENSIONS.APPLICATION_SETTINGS,
		alpsProtocols: ['h2'],

		// compress_certificate algorithms — brotli only
		certCompressionAlgorithms: [CERT_COMPRESSION.BROTLI],
	},

	http2: {
		// SETTINGS values + insertion order (matters for fingerprint)
		settings: {
			headerTableSize: 65536,
			enablePush: false,
			initialWindowSize: 6291456,
			maxHeaderListSize: 262144,
		},

		// Connection-level WINDOW_UPDATE increment
		windowUpdateIncrement: 15663105,

		// Whether to send a PRIORITY frame on stream 1 (Chrome 147: yes)
		sendPriorityFrame: true,
		priority: { weight: 256, exclusive: true, parent: 0 },

		// Pseudo-header order
		pseudoHeaderOrder: [':method', ':authority', ':scheme', ':path'],
	},

	headers: CHROME_147_HEADERS,
	// Identity headers: callers may not replace these, mirroring a browser.
	fixedHeaders: ['user-agent', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'],
	userAgent: CHROME_147_UA,
}
