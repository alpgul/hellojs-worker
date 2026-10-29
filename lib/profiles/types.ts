// Structural shape of a fingerprint profile. `lib/headers.ts`, `lib/tls/tls.ts` and
// `lib/h3/transport-params.js` consume these fields; anything extra is profile-specific
// and simply carried along.

export interface PrioritySettings {
	weight: number
	exclusive: boolean
	parent: number
}

export interface Http2Settings {
	headerTableSize?: number
	enablePush?: boolean
	initialWindowSize?: number
	maxHeaderListSize?: number
	maxConcurrentStreams?: number
	maxFrameSize?: number
	noRfc7540Priorities?: number
}

export interface Http2Profile {
	settings?: Http2Settings
	windowUpdateIncrement?: number
	sendPriorityFrame?: boolean
	priority?: PrioritySettings
	pseudoHeaderOrder?: string[]
}

// An entry in the captured/advertised extension order: either a real extension, or a GREASE
// marker standing where the client puts one. The two shapes are exclusive so reading `id`
// after skipping `grease` is type-safe.
export type ExtensionRef = { id: number; grease?: false } | { grease: true; id?: number }

export interface CertificateStatusRequest {
	certificateStatusType: number
	responderIdListLength: number
	requestExtensionsLength: number
}

export interface TlsProfile {
	// Required: the ClientHello cipher list is written straight from this field.
	ciphers: number[]
	extensionPermutation?: 'shuffle-middle' | 'preserve'
	extensionOrder?: ExtensionRef[]
	// Turn the "extension lists an id with no builder" warning into a throw.
	strictExtensions?: boolean
	rawExtensionBodies?: Record<number, Buffer>
	alpn?: string[]
	signatureAlgorithms?: number[]
	signatureAlgorithmsCert?: number[] | null
	signatureAlgorithmsCertRaw?: Buffer | null
	supportedGroups?: number[]
	supportedVersions?: number[]
	pskKemModes?: number[]
	keyShareGroups?: number[]
	alpsExtensionType?: number | null
	alpsProtocols?: string[] | null
	certCompressionAlgorithms?: number[]
	paddingLength?: number | null
	statusRequest?: CertificateStatusRequest | null
	statusRequestV2?: CertificateStatusRequest | null
	useGrease?: boolean
}

export interface ExpectedFingerprint {
	ja3?: string
	ja4?: string
	akamai_fingerprint?: string
	peetprint?: string
}

export interface Profile {
	name: string
	source?: string
	expected?: ExpectedFingerprint
	tls: TlsProfile
	http2: Http2Profile
	headers?: Record<string, string>
	fixedHeaders?: string[]
	userAgent?: string
}
