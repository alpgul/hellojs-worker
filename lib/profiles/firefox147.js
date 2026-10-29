// Firefox 147 on macOS profile — TLS ClientHello + HTTP/2 fingerprint pinned to the
// Firefox 147 impersonation values (cipher/groups/sigalg lists, extension order,
// settings, pseudo-header order) with the macOS navigation header set.

import { CIPHERS, TLS_VERSIONS, GROUPS, SIGNATURE_ALGORITHMS, EXTENSIONS, CERTIFICATE_STATUS_TYPE, CERT_COMPRESSION } from '../utils/config.js'

// Wire encodings for captured raw extension bodies.
function u16Vector(values) {
	const buf = Buffer.alloc(2 + values.length * 2)
	buf.writeUInt16BE(values.length * 2, 0)
	values.forEach((v, i) => buf.writeUInt16BE(v, 2 + i * 2))
	return buf
}
function u16(value) {
	const buf = Buffer.alloc(2)
	buf.writeUInt16BE(value, 0)
	return buf
}

const FIREFOX_147_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0'

// Insertion order is the wire order for HTTP/2 request headers.
const FIREFOX_147_HEADERS = Object.freeze({
	'user-agent': FIREFOX_147_UA,
	'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'accept-language': 'en-US,en;q=0.9',
	'accept-encoding': 'gzip, deflate, br, zstd',
	'upgrade-insecure-requests': '1',
	'sec-fetch-dest': 'document',
	'sec-fetch-mode': 'navigate',
	'sec-fetch-site': 'none',
	'sec-fetch-user': '?1',
	'priority': 'u=0, i',
	'te': 'trailers',
})

export default {
	name: 'firefox147',

	tls: {
		// Cipher list (Firefox emits no GREASE, so this is the whole wire list)
		ciphers: [
			CIPHERS.TLS_AES_128_GCM_SHA256,
			CIPHERS.TLS_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_AES_256_GCM_SHA384,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			CIPHERS.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			CIPHERS.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			CIPHERS.TLS_RSA_WITH_AES_128_GCM_SHA256,
			CIPHERS.TLS_RSA_WITH_AES_256_GCM_SHA384,
			CIPHERS.TLS_RSA_WITH_AES_128_CBC_SHA,
			CIPHERS.TLS_RSA_WITH_AES_256_CBC_SHA,
		],

		// Firefox uses a fixed wire order rather than per-instance shuffling.
		extensionPermutation: 'preserve',
		extensionOrder: [
			{ id: EXTENSIONS.SERVER_NAME },
			{ id: EXTENSIONS.EXTENDED_MASTER_SECRET },
			{ id: EXTENSIONS.RENEGOTIATION_INFO },
			{ id: EXTENSIONS.SUPPORTED_GROUPS },
			{ id: EXTENSIONS.EC_POINT_FORMATS },
			{ id: EXTENSIONS.SESSION_TICKET },
			{ id: EXTENSIONS.ALPN },
			{ id: EXTENSIONS.STATUS_REQUEST },
			{ id: EXTENSIONS.DELEGATED_CREDENTIALS },
			{ id: EXTENSIONS.SIGNED_CERTIFICATE_TIMESTAMP },
			{ id: EXTENSIONS.KEY_SHARE },
			{ id: EXTENSIONS.SUPPORTED_VERSIONS },
			{ id: EXTENSIONS.SIGNATURE_ALGORITHMS },
			{ id: EXTENSIONS.PSK_KEY_EXCHANGE_MODES },
			{ id: EXTENSIONS.RECORD_SIZE_LIMIT },
			{ id: EXTENSIONS.COMPRESS_CERTIFICATE },
			{ id: EXTENSIONS.ENCRYPTED_CLIENT_HELLO },
		],
		// delegated_credentials and record_size_limit have no semantic builder;
		// emit their captured bodies verbatim.
		rawExtensionBodies: {
			// delegated_credentials: ECDSA P-256/P-384/P-521 + SHA-1
			[EXTENSIONS.DELEGATED_CREDENTIALS]: u16Vector([
				SIGNATURE_ALGORITHMS.ECDSA_SECP256R1_SHA256,
				SIGNATURE_ALGORITHMS.ECDSA_SECP384R1_SHA384,
				SIGNATURE_ALGORITHMS.ECDSA_SECP521R1_SHA512,
				SIGNATURE_ALGORITHMS.ECDSA_SHA1,
			]),
			// record_size_limit: 16385
			[EXTENSIONS.RECORD_SIZE_LIMIT]: u16(16385),
		},

		alpn: ['h2', 'http/1.1'],

		signatureAlgorithms: [
			SIGNATURE_ALGORITHMS.ECDSA_SECP256R1_SHA256,
			SIGNATURE_ALGORITHMS.ECDSA_SECP384R1_SHA384,
			SIGNATURE_ALGORITHMS.ECDSA_SECP521R1_SHA512,
			SIGNATURE_ALGORITHMS.RSA_PSS_RSAE_SHA256,
			SIGNATURE_ALGORITHMS.RSA_PSS_RSAE_SHA384,
			SIGNATURE_ALGORITHMS.RSA_PSS_RSAE_SHA512,
			SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA256,
			SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA384,
			SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA512,
			SIGNATURE_ALGORITHMS.ECDSA_SHA1,
			SIGNATURE_ALGORITHMS.RSA_PKCS1_SHA1,
		],

		supportedVersions: [TLS_VERSIONS.TLS1_3, TLS_VERSIONS.TLS1_2],

		supportedGroups: [
			GROUPS.X25519MLKEM768,
			GROUPS.X25519,
			GROUPS.P256,
			GROUPS.P384,
			GROUPS.P521,
			GROUPS.FFDHE2048,
			GROUPS.FFDHE3072,
		],

		// key_share carries the MLKEM hybrid plus X25519 (no GREASE entry)
		keyShareGroups: [GROUPS.X25519MLKEM768, GROUPS.X25519],

		// compress_certificate: zlib, brotli, zstd
		certCompressionAlgorithms: [
			CERT_COMPRESSION.ZLIB,
			CERT_COMPRESSION.BROTLI,
			CERT_COMPRESSION.ZSTD,
		],

		statusRequest: {
			certificateStatusType: CERTIFICATE_STATUS_TYPE.OCSP,
			responderIdListLength: 0,
			requestExtensionsLength: 0,
		},

		// Firefox sends no GREASE codepoints anywhere in the ClientHello.
		useGrease: false,
	},

	http2: {
		// SETTINGS values + insertion order (matters for fingerprint)
		settings: {
			headerTableSize: 65536,
			enablePush: false,
			initialWindowSize: 131072,
			maxFrameSize: 16384,
		},

		windowUpdateIncrement: 12517377,

		// PRIORITY payload on the request HEADERS frame (weight 42, non-exclusive)
		sendPriorityFrame: true,
		priority: { weight: 42, exclusive: false, parent: 0 },

		// m,p,a,s
		pseudoHeaderOrder: [':method', ':path', ':authority', ':scheme'],
	},

	headers: FIREFOX_147_HEADERS,
	// Identity header: callers may not replace the UA, mirroring a browser.
	fixedHeaders: ['user-agent'],
	userAgent: FIREFOX_147_UA,
}
