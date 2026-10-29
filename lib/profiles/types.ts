// Structural shape of a fingerprint profile. `lib/headers.ts`, `lib/tls/tls.js` and
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

export interface ExtensionRef {
	id?: number
	grease?: boolean
}

export interface CertificateStatusRequest {
	certificateStatusType: number
	responderIdListLength: number
	requestExtensionsLength: number
}

export interface TlsProfile {
	ciphers?: number[]
	extensionPermutation?: 'shuffle-middle' | 'preserve'
	extensionOrder?: ExtensionRef[]
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
