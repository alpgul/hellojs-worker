// Pure-JS QUIC v1 client connection. Pairs with our existing TLS 1.3 extension
// builders + key schedule from lib/tls/. Goal: handshake to a real QUIC server,
// derive 1-RTT keys, expose stream send/recv for HTTP/3.
//
// What's implemented:
//   - UDP socket I/O (through the ./udp.ts seam)
//   - Initial / Handshake / 1-RTT epochs with full packet protection
//   - ACK generation (single-range, no fancy stuff)
//   - CRYPTO frame buffering across packets
//   - Retry (RFC 9000 §17.2.5) with Initial-key re-derivation
//   - Key updates (RFC 9001 §6) driven by the peer's K bit
//   - NEW_CONNECTION_ID pool + retirement, path validation, RFC 9221 datagrams
//   - NewReno congestion control for 1-RTT stream data (RFC 9002)
//   - Reuses TLS ClientHello builder, signing-secret derivation, finished verification
//   - X25519 (group 0x001d) — MLKEM-hybrid omitted from h3 path for now (most h3 servers accept X25519-only)
//
// What's NOT implemented (MVP scope):
//   - Loss detection / retransmission. A PTO probe re-sends handshake CRYPTO or elicits an
//     ACK, but lost stream data is never retransmitted.
//   - Connection migration and 0-RTT. 1-RTT TLS PSK resumption is supported (NewSessionTicket +
//     pre_shared_key); early data is deliberately not offered.
//   - Stateless reset.

import * as crypto from 'node:crypto'
import { EventEmitter } from 'node:events'

import { resolveHost, type ResolvedAddress } from '../dns-cache.ts'
import {
	CreateALPNExtension,
	CreatePSKExchangeModesExtension,
	CreateSignatureAlgorithmsExtension,
	CreateSNIExtension
} from '../extensions/index.ts'
import logFactory from '../models/log.ts'
import { getSessionTicket, pskBinder, storeSessionTicket } from '../tls/session-tickets.ts'
import { CIPHERS, HASHES, MESSAGE_TYPES } from '../utils/config.ts'
import * as HKDF from '../utils/hkdf.ts'

import * as keys from './keys.ts'
import * as pkt from './packet.ts'
import * as tp from './transport-params.ts'
import * as dgram from './udp.ts' // seam over node:dgram — same createSocket surface
import * as varint from './varint.ts'

import type { SessionTicket } from '../tls/session-tickets.ts'
import type { HashInfo } from '../utils/config.ts'

const log = logFactory('[h3]')

// Receive windows are granted in half-window steps: small enough to keep the peer fed, large
// enough to avoid a MAX_* frame per packet. The same windows are advertised in our transport
// parameters (tp.FLOW_CONTROL), so the peer can never outrun the memory we budget.
const WINDOW_UPDATE_FRACTION = 2
// Servers that omit the flow-control TPs still get a usable request-body limit.
// -------- types -------------------------------------------------------------

type Epoch = 'initial' | 'handshake' | 'oneRtt'

const EPOCHS: Epoch[] = ['initial', 'handshake', 'oneRtt']

interface EpochMap<T> {
	initial: T
	handshake: T
	oneRtt: T
}

type RetryPacket = Extract<pkt.ParsedPacket, { kind: 'retry' }>
type NcidFrame = Extract<pkt.QuicFrame, { type: 'new_connection_id' }>

// A packet we put on the wire and keep until it is acked. `payload` is what a handshake
// retransmission needs; `size` is what congestion control accounts for on 1-RTT.
interface SentPacket {
	time: number
	payload?: Buffer
	size?: number
	includesCrypto: boolean
	flowControlKeys?: string[]
}

interface DstCidEntry {
	seq: number
	cid: Buffer
	statelessResetToken: Buffer
	retired: boolean
}

interface QueuedPacket {
	packet: Buffer
	size: number
	pn: number
}

interface PendingPathChallenge {
	data: Buffer
	resolve: (ok: boolean) => void
}

interface TrafficSecrets {
	client: Buffer
	server: Buffer
}

// NewReno state (RFC 9002 §7.3 + Appendix B). The k-prefixed fields are the spec's constants.
interface CongestionState {
	kInitialWindow: number
	kMinimumWindow: number
	kMaxDatagramSize: number
	kLossReductionFactor: number
	cwnd: number
	ssthresh: number
	bytesInFlight: number
	recoveryStart: number
	congestionEvents: number
}

// Transcript-hash helper named by the negotiated suite — HASHES stores the name as a string,
// so the two HKDF functions are looked up through this table instead of the module namespace.
const HASH_FNS: Record<string, (...bufs: Buffer[]) => Buffer> = {
	sha256: HKDF.sha256,
	sha384: HKDF.sha384
}

// -------- helpers ---------------------------------------------------------

// Transport parameters decode to number | bigint | Buffer depending on their length; the
// ones we act on are small counters, so anything else means "peer sent nothing usable".
function asParamNumber(value: number | bigint | Buffer | undefined, fallback = 0): number {
	if (typeof value === 'number') return value
	if (typeof value === 'bigint') return Number(value)
	return fallback
}

function rawX25519ToSpkiDer(raw32: Buffer): Buffer {
	const hdr = Buffer.from('302a300506032b656e032100', 'hex')
	return Buffer.concat([hdr, raw32])
}

// -------- QuicConnection --------------------------------------------------

class QuicConnection extends EventEmitter {
	declare host: string
	declare port: number
	/** SNI/certificate identity; differs from `host` only for Alt-Svc alternative authorities. */
	declare sniHost: string

	declare socket: dgram.UdpSocket | null
	declare serverAddr: { host: string; port: number } | null

	// Connection IDs
	declare dstCid: Buffer // we initially pick the server's dst CID; server may issue a new one
	declare srcCid: Buffer
	declare serverChosenSrcCid: Buffer | null // server's chosen CID (becomes our dstCid for non-Initial packets)

	// Key schedule
	declare initialKeys: keys.EpochKeys | null
	declare handshakeKeys: keys.EpochKeys | null
	declare appKeys: keys.EpochKeys | null
	declare cipher: HashInfo // QUIC TLS handshake: assume AES-128-GCM (Chrome's preferred for h3 Initial). Updated when we see ServerHello cipher.

	// Packet number per epoch
	declare pn: EpochMap<number>
	declare recv: EpochMap<Set<number>>
	declare largestRecv: EpochMap<number>
	declare needAck: EpochMap<boolean>

	// CRYPTO stream offsets
	declare cryptoOffsetOut: EpochMap<number>
	declare cryptoOffsetIn: EpochMap<number>
	declare cryptoBufIn: EpochMap<Buffer>

	// Retry handling state
	declare retryToken: Buffer
	declare originalDstCid: Buffer | null

	// Sent-packet tracking for loss recovery (per epoch)
	declare sentPackets: EpochMap<Map<number, SentPacket>>
	declare ptoTimer: ReturnType<typeof setTimeout> | null
	declare retryCount: number

	// NewReno congestion control (RFC 9002 §7.3 + Appendix B). Initial/Handshake epochs
	// are exempt; CC applies only to 1-RTT stream data. Standalone ACKs and PTO probes
	// bypass CC so we can always ack and probe even when cwnd is exhausted.
	declare cc: CongestionState
	declare appSendQueue: QueuedPacket[] // 1-RTT stream packets blocked on cwnd

	// Key update state (RFC 9001 §6). currentPhase is what *we* send under. peerPhase
	// is what we last saw inbound; when the two disagree on a successfully-decrypted
	// inbound packet, we advance and rotate keys.
	declare currentPhase: number
	declare appKeysPrev: keys.EpochKeys | null
	declare appKeysNext: keys.EpochKeys | null
	declare appSecretsCurrent: TrafficSecrets | null // {client, server}
	declare keyUpdatesSeen: number

	// DATAGRAM (RFC 9221). 0 = peer didn't advertise support.
	declare peerMaxDatagramFrameSize: number

	// Receive-side flow control (RFC 9000 §19). `recvLimit` is the absolute stream/connection
	// offset we have granted; `recvConsumed` is how much the application has actually read.
	// Withholding the next grant is the backpressure signal to the peer.
	declare recvLimit: number
	declare recvConsumed: number
	/** Cumulative bytes accepted from the peer across all streams (for the connection window). */
	declare recvReceived: number
	/** Latest MAX_* frame per bucket, replayed on PTO because MAX frames are idempotent. */
	declare flowControlFrames: Map<string, Buffer>

	// Send-side flow control: the peer's advertised limits plus what we have sent so far.
	declare peerMaxData: number
	declare peerMaxDataSent: number
	declare peerMaxStreamDataBidiLocal: number
	declare peerMaxStreamDataBidiRemote: number
	declare peerMaxStreamDataUni: number

	// Connection ID pool (RFC 9000 §5.1). Server issues additional dst CIDs via
	// NEW_CONNECTION_ID frames; we use them when rotating or migrating.
	declare availableDstCids: DstCidEntry[] // [{ seq, cid: Buffer, statelessResetToken: Buffer, retired: false }]
	declare activeDstCidSeq: number // seq of the dstCid we're currently sending under
	declare lowestNotRetired: number // matches retire_prior_to semantics
	declare peerActiveConnectionIdLimit: number // default per RFC 9000 §18.2

	// TLS state
	declare clientRandom: Buffer | null
	declare clientPrivateKey: crypto.KeyObject | null
	declare peerAddr: { address: string; port: number } | null
	declare clientPubRaw32: Buffer | null
	declare transcript: Buffer[]
	declare cipherSuite: number
	declare handshakeSecret: Buffer | null
	declare cHsTraffic: Buffer | null
	declare sHsTraffic: Buffer | null
	declare masterSecret: Buffer | null
	declare resumptionMasterSecret: Buffer | null
	declare pskTicket: SessionTicket | null
	declare pskAccepted: boolean
	declare alpn: string | null
	declare handshakeComplete: boolean

	// Streams (h3 layer attaches here)
	declare streams: Map<number, QuicStream>
	declare nextClientBidiStreamId: number // client-initiated bidirectional: 0,4,8,...
	declare nextClientUniStreamId: number // client-initiated unidirectional: 2,6,10,...

	// Populated by the HTTP/3 layer to claim server-initiated unidirectional streams.
	declare onServerStream: ((stream: QuicStream) => void) | undefined

	// Handshake secrets are null until ServerHello is processed, and every later step needs
	// them; the handshake order is the invariant, so those uses assert instead of re-checking.
	declare _clientFinishedVerifyData: Buffer | null
	declare _pendingPathChallenge: PendingPathChallenge | null
	declare _closed: boolean

	constructor(host: string, port = 443, sniHost?: string) {
		super()
		this.host = host
		this.port = port
		// Alt-Svc can move the dial target while SNI/certificate identity stays on the origin.
		this.sniHost = sniHost || host

		this.socket = null
		this.serverAddr = null

		// Connection IDs
		this.dstCid = crypto.randomBytes(8)
		this.srcCid = crypto.randomBytes(8)
		this.serverChosenSrcCid = null

		// Key schedule
		this.initialKeys = null
		this.handshakeKeys = null
		this.appKeys = null
		this.cipher = HASHES['1301']

		this.pn = { initial: 0, handshake: 0, oneRtt: 0 }
		this.recv = { initial: new Set(), handshake: new Set(), oneRtt: new Set() }
		this.largestRecv = { initial: -1, handshake: -1, oneRtt: -1 }
		this.needAck = { initial: false, handshake: false, oneRtt: false }

		this.cryptoOffsetOut = { initial: 0, handshake: 0, oneRtt: 0 }
		this.cryptoOffsetIn = { initial: 0, handshake: 0, oneRtt: 0 }
		this.cryptoBufIn = { initial: Buffer.alloc(0), handshake: Buffer.alloc(0), oneRtt: Buffer.alloc(0) }

		this.retryToken = Buffer.alloc(0)
		this.originalDstCid = null

		this.sentPackets = { initial: new Map(), handshake: new Map(), oneRtt: new Map() }
		this.ptoTimer = null
		this.retryCount = 0

		const kMaxDatagramSize = 1200
		this.cc = {
			kInitialWindow: 10 * kMaxDatagramSize,
			kMinimumWindow: 2 * kMaxDatagramSize,
			kMaxDatagramSize,
			kLossReductionFactor: 0.5,
			cwnd: 10 * kMaxDatagramSize,
			ssthresh: Number.MAX_SAFE_INTEGER,
			bytesInFlight: 0,
			recoveryStart: 0,
			congestionEvents: 0
		}
		this.appSendQueue = []

		this.currentPhase = 0
		this.appKeysPrev = null
		this.appKeysNext = null
		this.appSecretsCurrent = null
		this.keyUpdatesSeen = 0

		this.peerMaxDatagramFrameSize = 0

		this.recvLimit = tp.FLOW_CONTROL.maxData
		this.recvConsumed = 0
		this.recvReceived = 0
		this.flowControlFrames = new Map()

		// Send-side limits are what the PEER grants us. Until its transport parameters (or a
		// MAX_* frame) arrive, the RFC default is zero — our own receive-window constants must
		// never be used here or we would send bytes the peer has not granted.
		this.peerMaxData = 0
		this.peerMaxDataSent = 0
		this.peerMaxStreamDataBidiLocal = 0
		this.peerMaxStreamDataBidiRemote = 0
		this.peerMaxStreamDataUni = 0

		this.availableDstCids = []
		this.activeDstCidSeq = 0
		this.lowestNotRetired = 0
		this.peerActiveConnectionIdLimit = 2 // default per RFC 9000 §18.2

		this.clientRandom = null
		this.clientPrivateKey = null
		this.peerAddr = null
		this.clientPubRaw32 = null
		this.transcript = []
		this.cipherSuite = CIPHERS.TLS_AES_128_GCM_SHA256
		this.handshakeSecret = null
		this.cHsTraffic = null
		this.sHsTraffic = null
		this.masterSecret = null
		this.resumptionMasterSecret = null
		this.pskTicket = null
		this.pskAccepted = false
		this.alpn = null
		this.handshakeComplete = false

		this.streams = new Map()
		this.nextClientBidiStreamId = 0
		this.nextClientUniStreamId = 2

		this._clientFinishedVerifyData = null
		this._pendingPathChallenge = null
		this._closed = false
	}

	async connect(): Promise<void> {
		// Resolve once through the TTL cache and pin every send to the chosen address: dgram.send()
		// with a hostname re-resolves per call, so a multi-A-record host can answer from one
		// address and receive our replies on another, and each send pays DNS again.
		let addresses: ResolvedAddress[] | null = null
		try {
			addresses = await resolveHost(this.host)
		} catch {
			// No resolver (workerd) or a failed lookup: keep the hostname and the old behaviour.
		}
		const chosen = addresses?.find((a) => a.family === 4) ?? addresses?.[0]
		const socket = dgram.createSocket(chosen?.family === 6 ? 'udp6' : 'udp4')
		this.socket = socket
		socket.on('message', (msg: Buffer, rinfo: { address: string; port: number }) => {
			// Pin the peer to the address that answered: send() on a hostname re-resolves per call,
			// so a multi-A-record host can answer from one address and receive our replies on another,
			// which stalls the handshake once the server retransmits.
			if (!this.peerAddr) this.peerAddr = { address: rinfo.address, port: rinfo.port }
			this._onDatagram(msg)
		})
		socket.on('error', (e: Error) => this.emit('error', e))

		await new Promise<void>((res) => socket.bind(0, () => res()))

		this.serverAddr = { host: chosen?.address ?? this.host, port: this.port }

		this.initialKeys = keys.deriveInitialKeys(this.dstCid)
		this._sendClientHello()
	}

	_sendClientHello(): void {
		this.clientRandom = crypto.randomBytes(32)
		// TLS 1.3 over QUIC: session_id MUST be empty (no compatibility mode — RFC 9001).
		const sessionId = Buffer.alloc(0)

		// Cipher list — TLS 1.3 ciphers only (no GREASE, no legacy TLS 1.2 ciphers).
		const cipherList = [
			CIPHERS.TLS_AES_128_GCM_SHA256,
			CIPHERS.TLS_AES_256_GCM_SHA384,
			CIPHERS.TLS_CHACHA20_POLY1305_SHA256
		]
		const cipherSuites = Buffer.alloc(cipherList.length * 2)
		cipherList.forEach((id, i) => cipherSuites.writeUInt16BE(id, i * 2))

		const compression = Buffer.from([0x01, 0x00])

		// X25519-only key share for h3 (no MLKEM, no GREASE).
		const { publicKey: x25519Pub, privateKey: x25519Priv } = crypto.generateKeyPairSync('x25519')
		const x25519Raw = x25519Pub.export({ type: 'spki', format: 'der' }).slice(-32)
		this.clientPrivateKey = x25519Priv
		this.clientPubRaw32 = x25519Raw
		const keyShare = (() => {
			const entry = Buffer.concat([Buffer.from([0x00, 0x1d, 0x00, 0x20]), x25519Raw]) // group=x25519, len=32, key
			const sharesLen = Buffer.alloc(2)
			sharesLen.writeUInt16BE(entry.length, 0)
			const extBody = Buffer.concat([sharesLen, entry])
			const extLen = Buffer.alloc(2)
			extLen.writeUInt16BE(extBody.length, 0)
			return { extension: Buffer.concat([Buffer.from([0x00, 0x33]), extLen, extBody]) }
		})()

		// QUIC transport parameters extension (id 0x0039 in TLS).
		const tpBlock = tp.buildChrome147({ initialSourceConnectionId: this.srcCid })
		const tpExt = tp.asTlsExtension(tpBlock)

		// h3 ALPN
		const alpn = CreateALPNExtension(['h3'])

		// QUIC-only supported_versions: only TLS 1.3 (no GREASE, no TLS 1.2).
		const supportedVersionsQuic = (() => {
			const body = Buffer.from([0x03, 0x04]) // just TLS 1.3
			const lenByte = Buffer.from([body.length])
			return Buffer.concat([Buffer.from([0x00, 0x2b]), Buffer.from([0x00, body.length + 1]), lenByte, body])
		})()

		// X25519-only supported_groups (no MLKEM, no GREASE).
		const supportedGroupsX25519 = (() => {
			const groups = Buffer.from([0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]) // X25519, P-256, P-384
			const ll = Buffer.alloc(2)
			ll.writeUInt16BE(groups.length, 0)
			const data = Buffer.concat([ll, groups])
			const el = Buffer.alloc(2)
			el.writeUInt16BE(data.length, 0)
			return Buffer.concat([Buffer.from([0x00, 0x0a]), el, data])
		})()

		// Minimal h3 extension set — only what's strictly required, to isolate the rejection.
		const namedExts: Record<string, Buffer> = {
			signature_algorithms: CreateSignatureAlgorithmsExtension(),
			supported_versions: supportedVersionsQuic,
			key_share: keyShare.extension,
			supported_groups: supportedGroupsX25519,
			alpn,
			sni: CreateSNIExtension(this.sniHost),
			psk_key_exchange_modes: CreatePSKExchangeModesExtension(),
			quic_transport_parameters: tpExt
		}

		// --- TLS 1.3 PSK resumption (RFC 8446 §4.2.11) ---
		// Offer an h3-scoped ticket from a previous QUIC handshake. pre_shared_key must be the
		// last ClientHello extension. needVerified=false: QUIC does not validate certificate
		// chains, so its tickets never carry a verified lineage; the ALPN-scoped store keeps
		// them out of TCP h2/h1 handshakes that do verify.
		this.pskTicket = getSessionTicket(this.host, this.port, ['h3'], false)
		let pskPrefix: Buffer | null = null
		let pskBindersLen = 0
		if (this.pskTicket) {
			const age = Buffer.alloc(4)
			const ageMs = Date.now() - this.pskTicket.receivedAt
			age.writeUInt32BE(((ageMs + this.pskTicket.ageAdd) % 0x100000000) >>> 0, 0)
			const identity = Buffer.concat([
				Buffer.from([this.pskTicket.ticket.length >> 8, this.pskTicket.ticket.length & 0xff]),
				this.pskTicket.ticket,
				age
			])
			const identities = Buffer.concat([Buffer.from([identity.length >> 8, identity.length & 0xff]), identity])
			pskBindersLen = 2 + 1 + this.pskTicket.hashLen
			const extBodyLen = identities.length + pskBindersLen
			// The binder is omitted from the transcript, so pskPrefix stops after the identities.
			pskPrefix = Buffer.concat([Buffer.from([0x00, 0x29, extBodyLen >> 8, extBodyLen & 0xff]), identities])
		}

		const extensionsList = Buffer.concat([
			...Object.keys(namedExts).map((n) => namedExts[n]),
			...(pskPrefix ? [pskPrefix] : [])
		])
		const extensionsLen = Buffer.alloc(2)
		extensionsLen.writeUInt16BE(extensionsList.length, 0)

		const sessionIdLen = Buffer.from([sessionId.length])
		const cipherSuitesLen = Buffer.alloc(2)
		cipherSuitesLen.writeUInt16BE(cipherSuites.length, 0)

		const clientHelloBody = Buffer.concat([
			Buffer.from([0x03, 0x03]), // legacy_version
			this.clientRandom,
			sessionIdLen,
			sessionId,
			cipherSuitesLen,
			cipherSuites,
			compression,
			extensionsLen,
			extensionsList
		])
		const hsLen = Buffer.alloc(3)
		hsLen.writeUIntBE(clientHelloBody.length + pskBindersLen, 0, 3)

		let handshakeMsg: Buffer
		if (this.pskTicket && pskPrefix) {
			const truncated = Buffer.concat([Buffer.from([MESSAGE_TYPES.CLIENT_HELLO]), hsLen, clientHelloBody])
			const transcriptHash = HASH_FNS[this.pskTicket.hash](...this.transcript, truncated)
			const binder = pskBinder(this.pskTicket, transcriptHash)
			handshakeMsg = Buffer.concat([
				truncated,
				Buffer.from([(pskBindersLen - 2) >> 8, (pskBindersLen - 2) & 0xff, this.pskTicket.hashLen]),
				binder
			])
		} else {
			handshakeMsg = Buffer.concat([Buffer.from([MESSAGE_TYPES.CLIENT_HELLO]), hsLen, clientHelloBody])
		}
		this.transcript.push(handshakeMsg)

		// Build CRYPTO frame containing the ClientHello.
		const cryptoFrame = pkt.encodeCryptoFrame(this.cryptoOffsetOut.initial, handshakeMsg)
		this.cryptoOffsetOut.initial += handshakeMsg.length

		this._sendInitial(cryptoFrame)
	}

	_padInitialPayload(payload: Buffer): Buffer {
		// Pad the UDP datagram to ≥1200 bytes (RFC 9000 §14.1).
		const TARGET = 1200
		const tokenLen = this.retryToken.length
		const headerOverheadGuess =
			1 + 4 + 1 + this.dstCid.length + 1 + this.srcCid.length + (tokenLen > 0 ? 2 : 1) + tokenLen + 2 + 4
		const padTarget = TARGET - headerOverheadGuess - 16
		if (payload.length < padTarget) {
			return Buffer.concat([payload, Buffer.alloc(padTarget - payload.length, 0x00)])
		}
		return payload
	}

	_sendInitial(cryptoFrame: Buffer): void {
		const payload = this._padInitialPayload(cryptoFrame)
		const packet = pkt.buildInitial({
			dstCid: this.dstCid,
			srcCid: this.srcCid,
			token: this.retryToken,
			payloadFrames: payload,
			pn: this.pn.initial,
			pnLen: 4,
			clientKeys: this.initialKeys!.client
		})
		// Record for loss recovery
		this.sentPackets.initial.set(this.pn.initial, { time: Date.now(), payload, includesCrypto: true })
		this.pn.initial++
		this._sendDatagram(packet)
		this._armPto()
	}

	_sendDatagram(buf: Buffer): void {
		if (this._closed) return
		try {
			if (this.peerAddr) this.socket?.send(buf, this.peerAddr.port, this.peerAddr.address)
			else this.socket?.send(buf, this.port, this.serverAddr?.host ?? this.host)
		} catch {}
	}

	_onDatagram(msg: Buffer): void {
		// A datagram may contain multiple coalesced QUIC packets. A malformed/hostile datagram must
		// never crash the process — parser exceptions drop the rest of the datagram (RFC 9000 permits
		// silently discarding packets that cannot be processed).
		try {
			let off = 0
			while (off < msg.length) {
				const result = pkt.parsePacket(
					msg,
					off,
					{
						initial: { server: this.initialKeys?.server, aead: 'aes-128-gcm' },
						handshake: { server: this.handshakeKeys?.server, aead: this.cipher.aead },
						oneRtt: {
							server: this.appKeys?.server,
							serverNext: this.appKeysNext?.server,
							currentPhase: this.currentPhase,
							aead: this.cipher.aead
						}
					},
					this.srcCid.length
				)
				if (!result || result.consumed === 0) break
				off += result.consumed
				if (result.kind === '1rtt' && result.usedNextKeys) this._commitKeyUpdate()
				this._handlePacket(result)
			}
		} catch (e) {
			log.error(`[h3] dropped malformed datagram: ${(e as Error).message}`)
		}
	}

	_handlePacket(p: pkt.ParsedPacket): void {
		if (p.kind === 'initial' || p.kind === 'handshake' || p.kind === '1rtt') {
			const epoch: Epoch = p.kind === 'initial' ? 'initial' : p.kind === 'handshake' ? 'handshake' : 'oneRtt'
			if (p.pn > this.largestRecv[epoch]) this.largestRecv[epoch] = p.pn
			this.recv[epoch].add(p.pn)
			this.needAck[epoch] = true

			if (p.kind === 'initial' && p.srcCid && !this.serverChosenSrcCid) {
				this.serverChosenSrcCid = p.srcCid
				this.dstCid = p.srcCid
			}

			const frames = pkt.decodeFrames(p.payload)
			for (const f of frames) this._handleFrame(epoch, f)

			// After processing a flight, if we owe acks send them along with any outgoing CRYPTO.
			this._maybeSendAcks(epoch)
		} else if (p.kind === 'retry') {
			this._handleRetry(p)
		} else if (p.kind === 'decrypt-failed') {
			log.error(`[h3] decrypt failed (${p.epoch}): ${p.error}`)
		}
	}

	_handleRetry(p: RetryPacket): void {
		// Per RFC 9000 §17.2.5: client must reset the connection state, use the server's
		// new src CID as the new dst CID, attach the retry token to the next Initial,
		// and re-derive initial keys against the new dst CID.
		if (this.retryCount > 0) {
			this.emit('error', new Error('multiple Retry packets received'))
			return
		}
		this.retryCount = 1
		this.originalDstCid = this.dstCid
		this.dstCid = p.srcCid
		this.retryToken = p.retryToken
		this.initialKeys = keys.deriveInitialKeys(this.dstCid)
		// Reset Initial epoch state
		this.pn.initial = 0
		this.recv.initial = new Set()
		this.largestRecv.initial = -1
		this.needAck.initial = false
		this.cryptoOffsetOut.initial = 0
		this.cryptoOffsetIn.initial = 0
		this.cryptoBufIn.initial = Buffer.alloc(0)
		this.sentPackets.initial = new Map()
		// Re-emit ClientHello (already in transcript[0])
		const ch = this.transcript[0]
		const cryptoFrame = pkt.encodeCryptoFrame(0, ch)
		this.cryptoOffsetOut.initial = ch.length
		this._sendInitial(cryptoFrame)
	}

	_handleFrame(epoch: Epoch, f: pkt.QuicFrame): void {
		if (f.type === 'ack') {
			// Remove acked packets from the sent log + drive congestion control on the 1-RTT epoch.
			const sent = this.sentPackets[epoch]
			if (sent) {
				const ackOne = (pn: number): void => {
					const info = sent.get(pn)
					if (!info) return
					sent.delete(pn)
					this._onPacketAcked(epoch, pn, info)
				}
				// Build the acked intervals, then ack only packets we actually have outstanding.
				// Iterating the sent log (not the ranges) keeps work at O(sent × ranges): the range
				// widths are attacker-controlled varints that could otherwise span up to 2^62 and
				// freeze the event loop.
				const intervals: [lower: number, upper: number][] = [[f.largestAcked - f.firstAckRange, f.largestAcked]]
				let cursor = f.largestAcked - f.firstAckRange - 1
				for (const r of f.ranges) {
					cursor -= r.gap + 1
					const top = cursor
					const bot = top - r.length
					intervals.push([bot, top])
					cursor = bot - 1
				}
				// Snapshot: acking a 1-RTT packet can drain the send queue and add new entries
				// to the same log while we are still walking it.
				const outstanding = [...sent.keys()]
				for (const pn of outstanding) {
					for (const [bot, top] of intervals) {
						if (pn >= bot && pn <= top) {
							ackOne(pn)
							break
						}
					}
				}
			}
			// If we made progress, reset retry count and re-arm PTO if anything outstanding.
			this.retryCount = 0
			this._rearmPto()
			return
		}
		if (f.type === 'crypto') {
			// CRYPTO frames carry a stream offset but can arrive retransmitted, duplicated, or with a
			// gap. The buffer holds the unparsed tail, so the contiguous point is its end; keep only
			// the new suffix and drop anything that would start past a gap (the peer retransmits it).
			const expected = this.cryptoOffsetIn[epoch] + this.cryptoBufIn[epoch].length
			const end = f.offset + f.data.length
			if (f.offset > expected || end <= expected) return
			this.cryptoBufIn[epoch] = Buffer.concat([
				this.cryptoBufIn[epoch],
				f.data.subarray(Math.max(0, expected - f.offset))
			])
			this._processCryptoBuffer(epoch)
			return
		}
		if (f.type === 'stream') {
			let s = this.streams.get(f.streamId)
			if (!s) {
				// Server-initiated stream: ID's bit 0x01 is set (server), bit 0x02 set = uni.
				// Auto-create a QuicStream and let the H3 layer's onServerStream hook claim it.
				const isServerInit = (f.streamId & 0x01) !== 0
				const isUni = (f.streamId & 0x02) !== 0
				if (isServerInit && isUni && this.onServerStream) {
					s = new QuicStream(this, f.streamId, 'uni')
					this.streams.set(f.streamId, s)
					this.onServerStream(s)
				}
			}
			if (s) s._onData(f.offset, f.data, f.fin)
			return
		}
		if (f.type === 'reset_stream' || f.type === 'stop_sending') {
			// Only the peer's own direction may be reset. Echoing RESET_STREAM on a send-only
			// uni stream (or STOP_SENDING on a receive-only one) is a STREAM_STATE_ERROR.
			const s = this.streams.get(f.streamId)
			if (!s) return
			const serverInitiated = (f.streamId & 0x01) !== 0
			const uni = (f.streamId & 0x02) !== 0
			if (f.type === 'reset_stream') {
				if (uni && !serverInitiated) return // peer is only the receiver here
				const alreadyStopped = s.cancelled
				if (uni) s._stopReceiving()
				else s.cancel() // our own H3_REQUEST_CANCELLED, never the peer's code
				if (!alreadyStopped && s.listenerCount('error') > 0) {
					s.emit('error', new Error(`QUIC RESET_STREAM on stream ${s.id}: ${f.errorCode}`))
				}
			} else {
				if (uni && serverInitiated) return // peer is only the sender here
				// STOP_SENDING ends our send direction only; a response may still be in flight.
				s._resetSend(0x0c, false)
			}
			return
		}
		if (f.type === 'connection_close') {
			log.error(`[h3] connection_close error=${f.errorCode} reason="${f.reason}"`)
			this.emit('error', new Error(`QUIC connection_close: ${f.errorCode} ${f.reason}`))
			return
		}
		if (f.type === 'handshake_done') {
			this.handshakeComplete = true
			this.emit('ready')
			return
		}
		if (f.type === 'path_challenge') {
			// Per RFC 9000 §8.2.2: respond immediately with PATH_RESPONSE echoing the data.
			// MUST be sent on the same path that received the challenge (we only have one path).
			this._sendPathResponse(f.data)
			return
		}
		if (f.type === 'path_response') {
			// Outstanding challenge being acked. Match against pending and resolve.
			if (this._pendingPathChallenge && this._pendingPathChallenge.data.equals(f.data)) {
				const { resolve } = this._pendingPathChallenge
				this._pendingPathChallenge = null
				resolve(true)
			}
			return
		}
		if (f.type === 'new_connection_id') {
			this._onNewConnectionId(f)
			return
		}
		if (f.type === 'retire_connection_id') {
			// Server is telling us to retire one of our srcCids. We only use one srcCid, so
			// for now we just acknowledge by ignoring — full migration support would mint a
			// fresh srcCid and issue NEW_CONNECTION_ID back.
			log.notify(`[cid] server requested retirement of our srcCid seq=${f.seq}`)
			return
		}
		if (f.type === 'datagram') {
			this.emit('datagram', f.data)
			return
		}
		if (f.type === 'flow_control') {
			if (f.subtype === pkt.FRAME_TYPE.MAX_DATA) this._onPeerMaxData(f.value)
			return
		}
		if (f.type === 'max_stream_data') {
			this._onPeerMaxStreamData(f.streamId, f.value)
			return
		}
		if (
			f.type === 'data_blocked' ||
			f.type === 'stream_data_blocked' ||
			f.type === 'new_token' ||
			f.type === 'ping'
		)
			return
		// ignore unknown
	}

	_armPto(): void {
		this._rearmPto()
	}
	_rearmPto(): void {
		if (this.ptoTimer) clearTimeout(this.ptoTimer)
		const totalOutstanding =
			(this.sentPackets.initial?.size || 0) +
			(this.sentPackets.handshake?.size || 0) +
			(this.sentPackets.oneRtt?.size || 0)
		if (totalOutstanding === 0) return
		// PTO: 1.5s base * 2^retryCount, capped at 16s. Conservative — we'd rather be slow than spam retries.
		const timeout = Math.min(1500 * Math.pow(2, this.retryCount), 16000)
		this.ptoTimer = setTimeout(() => this._onPtoFire(), timeout)
		this.ptoTimer.unref?.()
	}
	_onPtoFire(): void {
		if (this._closed) return
		this.retryCount++
		if (this.retryCount > 5) {
			this.emit('error', new Error('QUIC PTO retry limit exceeded'))
			this.close()
			return
		}
		// Resend the oldest outstanding Initial / Handshake CRYPTO frame.
		// Strategy: if any Initial unacked, resend the first one; else if Handshake unacked, resend; else 1-RTT.
		for (const epoch of EPOCHS) {
			const sent = this.sentPackets[epoch]
			if (!sent || sent.size === 0) continue
			const [oldestPn, info] = [...sent.entries()].sort((a, b) => a[1].time - b[1].time)[0]
			sent.delete(oldestPn)
			if (epoch === 'initial' && info.includesCrypto) {
				// Re-send the ClientHello as a fresh Initial.
				const cryptoFrame = pkt.encodeCryptoFrame(0, this.transcript[0])
				this._sendInitial(cryptoFrame)
				return
			}
			if (epoch === 'handshake' && info.includesCrypto) {
				// Re-send Client Finished
				this._sendClientFinishedRaw()
				return
			}
			if (epoch === 'oneRtt') {
				// Declare the unacked 1-RTT packet lost, react to congestion event,
				// and emit a PING to elicit an ACK. PING itself bypasses CC.
				if (info.size) this.cc.bytesInFlight = Math.max(0, this.cc.bytesInFlight - info.size)
				this._onCongestionEvent(info.time)
				if (!this.appKeys) return
				// MAX frames are idempotent, so replaying the latest grants with the PING is safe
				// and prevents a lost grant from wedging a paused-then-resumed response.
				const keys = [...this.flowControlFrames.keys()]
				const frame = Buffer.concat([...this.flowControlFrames.values(), Buffer.from([0x01])])
				const pn = this.pn.oneRtt
				const packet = pkt.buildOneRtt({
					dstCid: this.dstCid,
					payloadFrames: frame,
					pn,
					pnLen: 2,
					clientKeys: this.appKeys.client,
					aead: this.cipher.aead,
					keyPhase: this.currentPhase
				})
				this.pn.oneRtt++
				this.cc.bytesInFlight += packet.length
				this.sentPackets.oneRtt.set(pn, {
					time: Date.now(),
					size: packet.length,
					includesCrypto: false,
					flowControlKeys: keys
				})
				this._sendDatagram(packet)
				this._rearmPto()
				return
			}
		}
	}

	_processCryptoBuffer(epoch: Epoch): void {
		// TLS handshake messages: 4-byte header (type + 3-byte length) + body.
		const buf = this.cryptoBufIn[epoch]
		let off = 0
		while (off + 4 <= buf.length) {
			const type = buf[off]
			const len = (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]
			if (off + 4 + len > buf.length) break
			const full = buf.subarray(off, off + 4 + len)
			const body = buf.subarray(off + 4, off + 4 + len)
			off += 4 + len
			this._onTlsHandshakeMessage(epoch, type, body, full)
		}
		this.cryptoOffsetIn[epoch] += off
		this.cryptoBufIn[epoch] = buf.subarray(off)
	}

	_onTlsHandshakeMessage(epoch: Epoch, type: number, body: Buffer, full: Buffer): void {
		if (type === MESSAGE_TYPES.SERVER_HELLO) {
			this.transcript.push(full)
			this._processServerHello(body)
			return
		}
		if (type === MESSAGE_TYPES.ENCRYPTED_EXTENSIONS) {
			this.transcript.push(full)
			this._processEncryptedExtensions(body)
			return
		}
		if (
			type === MESSAGE_TYPES.SERVER_CERTIFICATE ||
			type === 0x19 /*CompressedCertificate*/ ||
			type === MESSAGE_TYPES.SERVER_CERTIFICATE_VERIFY
		) {
			this.transcript.push(full)
			return
		}
		if (type === MESSAGE_TYPES.FINISHED) {
			this._validateServerFinished(body)
			this.transcript.push(full)
			this._deriveApplicationKeys()
			this._sendClientFinished()
			// Resumption master secret covers the transcript through our Finished; later
			// NewSessionTicket messages derive their PSK from it (RFC 8446 §7.1).
			this._deriveResumptionMasterSecret()
			return
		}
		if (type === 0x04 /*NewSessionTicket*/) {
			this._handleNewSessionTicket(body)
			return
		}
	}

	// NewSessionTicket (RFC 8446 §4.6.1) arrives on the 1-RTT CRYPTO stream. Derive the PSK
	// from the nonce and our resumption master secret, then cache it for the next h3 handshake.
	// Malformed tickets are ignored — they only cost a future full handshake.
	_handleNewSessionTicket(body: Buffer): void {
		if (!this.resumptionMasterSecret || !this.cipher) return
		try {
			let p = 0
			const lifetime = body.readUInt32BE(p)
			p += 4
			const ageAdd = body.readUInt32BE(p)
			p += 4
			const nonceLen = body[p++]
			if (body.length < p + nonceLen + 2) return
			const nonce = body.subarray(p, p + nonceLen)
			p += nonceLen
			const ticketLen = body.readUInt16BE(p)
			p += 2
			if (ticketLen === 0 || body.length < p + ticketLen) return
			if (lifetime === 0) return // RFC 8446 §4.6.1: discard immediately
			const ticket = Buffer.from(body.subarray(p, p + ticketLen))
			const { hash, hashLen } = this.cipher
			const psk = HKDF.ExpandLabel(this.resumptionMasterSecret, 'resumption', nonce, hashLen, hash, hashLen)
			storeSessionTicket(this.host, this.port, {
				ticket,
				psk,
				cipherSuite: this.cipherSuite,
				hash,
				hashLen,
				lifetime,
				ageAdd,
				receivedAt: Date.now(),
				alpn: this.alpn || 'h3',
				// QUIC never validates a certificate chain, so this ticket cannot seed a
				// later handshake that requires verification. ALPN scoping keeps it h3-only.
				verified: false
			})
			log.debug(`[resume] QUIC stored session ticket for ${this.host}:${this.port} (${ticketLen}B, ${lifetime}s)`)
		} catch (e) {
			log.notify(`[resume] ignoring malformed QUIC NewSessionTicket: ${(e as Error).message}`)
		}
	}

	_processServerHello(body: Buffer): void {
		// legacy_version (2) + random (32) carry nothing the QUIC layer needs; the transcript
		// keeps the full message for key derivation.
		let o = 2 + 32
		const sidLen = body[o++]
		o += sidLen
		const cipherSuite = body.readUInt16BE(o)
		o += 2
		this.cipher = HASHES[cipherSuite.toString(16)]
		this.cipherSuite = cipherSuite
		o += 1 // legacy compression method — always null in TLS 1.3
		const extLen = body.readUInt16BE(o)
		o += 2
		const end = o + extLen
		let serverKShare: { group: number; key: Buffer } | null = null
		let pskSelected = false
		while (o + 4 <= end) {
			const et = body.readUInt16BE(o)
			o += 2
			const el = body.readUInt16BE(o)
			o += 2
			const ed = body.subarray(o, o + el)
			o += el
			if (et === 0x0033) {
				const group = ed.readUInt16BE(0)
				const klen = ed.readUInt16BE(2)
				const key = ed.subarray(4, 4 + klen)
				serverKShare = { group, key }
			} else if (et === 0x0029) {
				// pre_shared_key: the server accepted our offered ticket (selected_identity = 0).
				pskSelected = true
			}
		}
		if (pskSelected) {
			const err: Error | null = !this.pskTicket
				? new Error('QUIC: ServerHello selected a PSK that was never offered')
				: this.cipher.hash !== this.pskTicket.hash
					? new Error(
							`QUIC: ServerHello selected a PSK whose hash (${this.pskTicket.hash}) does not match the negotiated suite (${this.cipher.hash})`
						)
					: null
			if (err) {
				this.emit('error', err)
				return
			}
		}
		this.pskAccepted = pskSelected
		if (pskSelected) log.notify('[resume] QUIC server accepted the offered PSK')
		else if (this.pskTicket) log.debug('[resume] QUIC server rejected the PSK; full handshake')
		if (!serverKShare || serverKShare.group !== 0x001d) {
			this.emit('error', new Error(`unsupported group in ServerHello: 0x${serverKShare?.group?.toString(16)}`))
			return
		}
		// X25519 ECDH
		const serverPub = crypto.createPublicKey({
			type: 'spki',
			format: 'der',
			key: rawX25519ToSpkiDer(serverKShare.key)
		})
		const shared = crypto.diffieHellman({ publicKey: serverPub, privateKey: this.clientPrivateKey! })

		// Derive handshake-traffic secrets
		const hashFn = HASH_FNS[this.cipher.hash]
		const thSH = hashFn(this.transcript[0], this.transcript[1])
		const zeros = Buffer.alloc(this.cipher.hashLen, 0x00)
		// With an accepted PSK the Early Secret is extracted from the ticket's PSK instead of
		// zeros (RFC 8446 §7.1); the rest of the schedule is unchanged.
		const earlySecret =
			this.pskAccepted && this.pskTicket
				? HKDF.Extract(this.cipher.hash, zeros, this.pskTicket.psk)
				: HKDF.Extract(this.cipher.hash, zeros, zeros)
		const emptyHash = crypto.createHash(this.cipher.hash).update(Buffer.alloc(0)).digest()
		const derived0 = HKDF.ExpandLabel(
			earlySecret,
			'derived',
			emptyHash,
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)
		this.handshakeSecret = HKDF.Extract(this.cipher.hash, derived0, shared)
		this.cHsTraffic = HKDF.ExpandLabel(
			this.handshakeSecret,
			'c hs traffic',
			thSH,
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)
		this.sHsTraffic = HKDF.ExpandLabel(
			this.handshakeSecret,
			's hs traffic',
			thSH,
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)

		// QUIC handshake-epoch keys: same labels but length and AEAD chosen by negotiated cipher
		this.handshakeKeys = {
			client: keys.deriveKeysFromSecret(this.cHsTraffic, this.cipher.hash, this.cipher.keyLen, 12),
			server: keys.deriveKeysFromSecret(this.sHsTraffic, this.cipher.hash, this.cipher.keyLen, 12)
		}
	}

	_processEncryptedExtensions(body: Buffer): void {
		// Find ALPN to confirm h3 was picked, plus parse peer transport_parameters (id 0x39).
		let p = 0
		const total = body.readUInt16BE(p)
		p += 2
		const end = p + total
		while (p + 4 <= end) {
			const t = body.readUInt16BE(p)
			p += 2
			const l = body.readUInt16BE(p)
			p += 2
			const data = body.subarray(p, p + l)
			p += l
			if (t === 0x0010) {
				const listLen = data.readUInt16BE(0)
				if (listLen > 0) {
					const protoLen = data[2]
					this.alpn = data.subarray(3, 3 + protoLen).toString('ascii')
				}
			} else if (t === 0x0039) {
				const peerTp = tp.decode(data)
				this.peerMaxDatagramFrameSize = asParamNumber(peerTp[tp.TP.max_datagram_frame_size])
				if (this.peerMaxDatagramFrameSize > 0) {
					log.notify(`[datagram] peer supports DATAGRAM up to ${this.peerMaxDatagramFrameSize}B`)
				}
				this.peerActiveConnectionIdLimit = asParamNumber(peerTp[tp.TP.active_connection_id_limit], 2)
				this.peerMaxData = asParamNumber(peerTp[tp.TP.initial_max_data], this.peerMaxData)
				this.peerMaxStreamDataBidiLocal = asParamNumber(
					peerTp[tp.TP.initial_max_stream_data_bidi_local],
					this.peerMaxStreamDataBidiLocal
				)
				this.peerMaxStreamDataBidiRemote = asParamNumber(
					peerTp[tp.TP.initial_max_stream_data_bidi_remote],
					this.peerMaxStreamDataBidiRemote
				)
				this.peerMaxStreamDataUni = asParamNumber(
					peerTp[tp.TP.initial_max_stream_data_uni],
					this.peerMaxStreamDataUni
				)
			}
		}
	}

	_validateServerFinished(body: Buffer): void {
		const transcriptHash = HASH_FNS[this.cipher.hash](...this.transcript)
		const finishedKey = HKDF.ExpandLabel(
			this.sHsTraffic!,
			'finished',
			Buffer.alloc(0),
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)
		const expected = crypto.createHmac(this.cipher.hash, finishedKey).update(transcriptHash).digest()
		if (!crypto.timingSafeEqual(body, expected)) throw new Error('QUIC: Server Finished verification failed')
	}

	_sendClientFinished(): void {
		const transcriptHash = HASH_FNS[this.cipher.hash](...this.transcript)
		const finishedKey = HKDF.ExpandLabel(
			this.cHsTraffic!,
			'finished',
			Buffer.alloc(0),
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)
		this._clientFinishedVerifyData = crypto
			.createHmac(this.cipher.hash, finishedKey)
			.update(transcriptHash)
			.digest()
		this._sendClientFinishedRaw()
		const finishedMsg = Buffer.concat([
			Buffer.from([MESSAGE_TYPES.FINISHED]),
			Buffer.from([0x00, 0x00, this.cipher.hashLen]),
			this._clientFinishedVerifyData
		])
		this.transcript.push(finishedMsg)
	}

	_sendClientFinishedRaw(): void {
		const finishedMsg = Buffer.concat([
			Buffer.from([MESSAGE_TYPES.FINISHED]),
			Buffer.from([0x00, 0x00, this.cipher.hashLen]),
			this._clientFinishedVerifyData!
		])
		const cryptoFrame = pkt.encodeCryptoFrame(0, finishedMsg)
		const ackFrame =
			this.largestRecv.handshake >= 0 ? pkt.encodeAckFrame(this.largestRecv.handshake) : Buffer.alloc(0)
		if (ackFrame.length) this.needAck.handshake = false
		const payload = Buffer.concat([ackFrame, cryptoFrame])
		const packet = pkt.buildHandshake({
			dstCid: this.dstCid,
			srcCid: this.srcCid,
			payloadFrames: payload,
			pn: this.pn.handshake,
			pnLen: 4,
			clientKeys: this.handshakeKeys!.client,
			aead: this.cipher.aead
		})
		this.sentPackets.handshake.set(this.pn.handshake, { time: Date.now(), payload, includesCrypto: true })
		this.pn.handshake++
		this._sendDatagram(packet)
		this._rearmPto()
	}

	_deriveApplicationKeys(): void {
		const transcriptHash = HASH_FNS[this.cipher.hash](...this.transcript)
		const emptyHash = crypto.createHash(this.cipher.hash).update(Buffer.alloc(0)).digest()
		const derivedSecret = HKDF.ExpandLabel(
			this.handshakeSecret!,
			'derived',
			emptyHash,
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)
		const masterSecret = HKDF.Extract(this.cipher.hash, derivedSecret, Buffer.alloc(this.cipher.hashLen, 0x00))
		this.masterSecret = masterSecret
		const cAppTraffic = HKDF.ExpandLabel(
			masterSecret,
			'c ap traffic',
			transcriptHash,
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)
		const sAppTraffic = HKDF.ExpandLabel(
			masterSecret,
			's ap traffic',
			transcriptHash,
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)
		this.appKeys = {
			client: keys.deriveKeysFromSecret(cAppTraffic, this.cipher.hash, this.cipher.keyLen, 12),
			server: keys.deriveKeysFromSecret(sAppTraffic, this.cipher.hash, this.cipher.keyLen, 12)
		}
		this.appSecretsCurrent = { client: cAppTraffic, server: sAppTraffic }
		this._precomputeNextPhaseKeys()
	}

	_deriveResumptionMasterSecret(): void {
		if (!this.masterSecret) return
		const transcriptHash = HASH_FNS[this.cipher.hash](...this.transcript)
		this.resumptionMasterSecret = HKDF.ExpandLabel(
			this.masterSecret,
			'res master',
			transcriptHash,
			this.cipher.hashLen,
			this.cipher.hash,
			this.cipher.hashLen
		)
	}

	_precomputeNextPhaseKeys(): void {
		this.appKeysNext = {
			client: keys.deriveKeyUpdate(
				this.appSecretsCurrent!.client,
				this.cipher.hash,
				this.cipher.keyLen,
				12,
				this.appKeys!.client.hp
			),
			server: keys.deriveKeyUpdate(
				this.appSecretsCurrent!.server,
				this.cipher.hash,
				this.cipher.keyLen,
				12,
				this.appKeys!.server.hp
			)
		}
	}

	// Called when an inbound 1-RTT packet decrypted under the next phase's key set,
	// confirming the peer has initiated a key update. Commit the rotation.
	_commitKeyUpdate(): void {
		this.appKeysPrev = this.appKeys
		this.appKeys = this.appKeysNext
		this.appSecretsCurrent = {
			client: this.appKeysNext!.client.secret,
			server: this.appKeysNext!.server.secret
		}
		this.currentPhase ^= 1
		this.keyUpdatesSeen++
		this._precomputeNextPhaseKeys()
		log.notify(`[key-update] phase=${this.currentPhase} total=${this.keyUpdatesSeen}`)
	}

	_maybeSendAcks(epoch: Epoch): void {
		// Send an ACK on the epoch the packet arrived on. Initial and Handshake ACKs used to be
		// left to the next outgoing CRYPTO, but a server whose flight outgrows the 3x
		// anti-amplification budget (a large certificate chain) stops mid-flight and waits for an
		// ACK that never comes, so those epochs need standalone ACKs too.
		if (!this.needAck[epoch]) return
		this.needAck[epoch] = false
		if (epoch === 'initial' && this.initialKeys) {
			const packet = pkt.buildInitial({
				dstCid: this.dstCid,
				srcCid: this.srcCid,
				token: this.retryToken,
				payloadFrames: this._padInitialPayload(pkt.encodeAckFrame(this.largestRecv.initial)),
				pn: this.pn.initial,
				pnLen: 4,
				clientKeys: this.initialKeys.client
			})
			this.pn.initial++
			this._sendDatagram(packet)
		} else if (epoch === 'handshake' && this.handshakeKeys) {
			const packet = pkt.buildHandshake({
				dstCid: this.dstCid,
				srcCid: this.srcCid,
				payloadFrames: pkt.encodeAckFrame(this.largestRecv.handshake),
				pn: this.pn.handshake,
				pnLen: 4,
				clientKeys: this.handshakeKeys.client,
				aead: this.cipher.aead
			})
			this.pn.handshake++
			this._sendDatagram(packet)
		} else if (epoch === 'oneRtt' && this.appKeys) {
			const ack = pkt.encodeAckFrame(this.largestRecv.oneRtt)
			const packet = pkt.buildOneRtt({
				dstCid: this.dstCid,
				payloadFrames: ack,
				pn: this.pn.oneRtt,
				pnLen: 2,
				clientKeys: this.appKeys.client,
				aead: this.cipher.aead,
				keyPhase: this.currentPhase
			})
			this.pn.oneRtt++
			this._sendDatagram(packet)
		}
	}

	// Public API (used by HTTP/3 layer):
	openUniStream(): QuicStream {
		const id = this.nextClientUniStreamId
		this.nextClientUniStreamId += 4
		const stream = new QuicStream(this, id, 'uni')
		stream.sendLimit = this.peerMaxStreamDataUni
		this.streams.set(id, stream)
		return stream
	}
	openBidiStream(): QuicStream {
		const id = this.nextClientBidiStreamId
		this.nextClientBidiStreamId += 4
		const stream = new QuicStream(this, id, 'bidi')
		stream.sendLimit = this.peerMaxStreamDataBidiRemote
		this.streams.set(id, stream)
		return stream
	}

	_sendPathResponse(challengeData: Buffer): void {
		if (!this.appKeys) return
		const frame = pkt.encodePathResponseFrame(challengeData)
		const pn = this.pn.oneRtt++
		const packet = pkt.buildOneRtt({
			dstCid: this.dstCid,
			payloadFrames: frame,
			pn,
			pnLen: 2,
			clientKeys: this.appKeys.client,
			aead: this.cipher.aead,
			keyPhase: this.currentPhase
		})
		this._sendDatagram(packet)
	}

	// Public: send a PATH_CHALLENGE and wait for the matching PATH_RESPONSE. Useful for
	// confirming the current path is still alive (e.g., before migrating to a new srcCid).
	validatePath(timeoutMs = 3000): Promise<boolean> {
		if (!this.appKeys) return Promise.reject(new Error('1-RTT keys not ready'))
		const data = crypto.randomBytes(8)
		const frame = pkt.encodePathChallengeFrame(data)
		const pn = this.pn.oneRtt++
		const packet = pkt.buildOneRtt({
			dstCid: this.dstCid,
			payloadFrames: frame,
			pn,
			pnLen: 2,
			clientKeys: this.appKeys.client,
			aead: this.cipher.aead,
			keyPhase: this.currentPhase
		})
		this._sendDatagram(packet)
		return new Promise<boolean>((resolve, reject) => {
			const t = setTimeout(() => {
				if (this._pendingPathChallenge?.data.equals(data)) {
					this._pendingPathChallenge = null
					reject(new Error('PATH_CHALLENGE timeout'))
				}
			}, timeoutMs)
			t.unref?.()
			this._pendingPathChallenge = {
				data,
				resolve: (ok: boolean) => {
					clearTimeout(t)
					resolve(ok)
				}
			}
		})
	}

	// Stash a server-issued CID. Also honors retire_prior_to: any earlier-seq CIDs are queued
	// for retirement on the next outbound 1-RTT packet.
	_onNewConnectionId(f: NcidFrame): void {
		// Reject if we'd exceed our own active_connection_id_limit (we said 8).
		const live = this.availableDstCids.filter((e) => !e.retired).length
		if (live >= 8) {
			log.notify(`[cid] peer overflowing active_connection_id_limit; dropping seq=${f.seq}`)
			return
		}
		this.availableDstCids.push({
			seq: f.seq,
			cid: f.cid,
			statelessResetToken: f.statelessResetToken,
			retired: false
		})
		if (f.retirePriorTo > this.lowestNotRetired) {
			const toRetire = this.availableDstCids.filter((e) => e.seq < f.retirePriorTo && !e.retired)
			for (const e of toRetire) {
				e.retired = true
				this._sendRetireConnectionId(e.seq)
			}
			this.lowestNotRetired = f.retirePriorTo
		}
		log.notify(`[cid] +seq=${f.seq} (pool size=${this.availableDstCids.filter((e) => !e.retired).length})`)
	}

	_sendRetireConnectionId(seq: number): void {
		if (!this.appKeys) return
		const frame = pkt.encodeRetireConnectionIdFrame(seq)
		const pn = this.pn.oneRtt++
		const packet = pkt.buildOneRtt({
			dstCid: this.dstCid,
			payloadFrames: frame,
			pn,
			pnLen: 2,
			clientKeys: this.appKeys.client,
			aead: this.cipher.aead,
			keyPhase: this.currentPhase
		})
		this._sendDatagram(packet)
	}

	// Public API: rotate to a fresh server-issued dstCid. Returns the new seq or null if no
	// unretired CID is available. Migration support (path validation) is separate; this just
	// changes which CID we address packets to.
	rotateConnectionId(): number | null {
		const next = this.availableDstCids.find((e) => !e.retired && e.seq !== this.activeDstCidSeq)
		if (!next) return null
		const oldSeq = this.activeDstCidSeq
		this.dstCid = next.cid
		this.activeDstCidSeq = next.seq
		// Retire the one we were using
		const oldEntry = this.availableDstCids.find((e) => e.seq === oldSeq)
		if (oldEntry) {
			oldEntry.retired = true
			this._sendRetireConnectionId(oldSeq)
		}
		log.notify(`[cid] rotated active dstCid seq ${oldSeq}→${next.seq}`)
		return next.seq
	}

	// Public API for RFC 9221 unreliable datagrams. Sent best-effort on the 1-RTT epoch,
	// not retransmitted on loss, exempt from stream flow control. The peer must have
	// advertised max_datagram_frame_size > 0 or this throws.
	sendDatagram(data: Buffer): void {
		if (!this.appKeys) throw new Error('1-RTT keys not ready')
		if (this.peerMaxDatagramFrameSize === 0) throw new Error('peer did not advertise DATAGRAM support')
		const frame = pkt.encodeDatagramFrame(data)
		if (frame.length > this.peerMaxDatagramFrameSize) {
			throw new Error(`DATAGRAM frame ${frame.length}B exceeds peer max ${this.peerMaxDatagramFrameSize}B`)
		}
		const pn = this.pn.oneRtt
		const packet = pkt.buildOneRtt({
			dstCid: this.dstCid,
			payloadFrames: frame,
			pn,
			pnLen: 2,
			clientKeys: this.appKeys.client,
			aead: this.cipher.aead,
			keyPhase: this.currentPhase
		})
		this.pn.oneRtt++
		// Datagrams are unreliable — we don't track them for retransmission.
		this._sendDatagram(packet)
	}

	// --- Flow control (RFC 9000 §19) -----------------------------------------
	//
	// MAX_* frames are sent directly (not through NewReno): they are tiny, idempotent, and must
	// still get out when cwnd is full. The latest frame per bucket is remembered and replayed on
	// PTO so a lost grant cannot stall a response whose consumer has stopped reading.

	_sendFlowControlFrame(frame: Buffer, keys?: string[]): void {
		if (!this.appKeys || this._closed) return
		const pn = this.pn.oneRtt
		const packet = pkt.buildOneRtt({
			dstCid: this.dstCid,
			payloadFrames: frame,
			pn,
			pnLen: 2,
			clientKeys: this.appKeys.client,
			aead: this.cipher.aead,
			keyPhase: this.currentPhase
		})
		this.pn.oneRtt++
		this.cc.bytesInFlight += packet.length
		this.sentPackets.oneRtt.set(pn, {
			time: Date.now(),
			size: packet.length,
			includesCrypto: false,
			flowControlKeys: keys
		})
		this._sendDatagram(packet)
		this._rearmPto()
	}

	_grantFlowControl(key: string, frame: Buffer): void {
		this.flowControlFrames.set(key, frame)
		this._sendFlowControlFrame(frame, [key])
	}

	/** Called by QuicStream only when bytes actually reach the application. */
	_onBytesConsumed(stream: QuicStream, bytes: number): void {
		if (bytes <= 0) return
		stream.recvConsumed += bytes
		this.recvConsumed += bytes
		this._grantStreamCredit(stream)
		this._grantConnectionCredit()
	}

	/** Discarded bytes still free connection credit, otherwise sibling streams stall. */
	_onBytesDiscarded(bytes: number): void {
		if (bytes <= 0) return
		this.recvConsumed += bytes
		this._grantConnectionCredit()
	}

	_grantStreamCredit(stream: QuicStream): void {
		// A paused consumer must not grant more credit: that is the whole backpressure contract.
		if (stream.paused || this._closed) return
		const step = Math.max(1, Math.floor(stream.recvWindow / WINDOW_UPDATE_FRACTION))
		if (stream.recvConsumed + step < stream.recvLimit) return
		stream.recvLimit = stream.recvConsumed + stream.recvWindow
		this._grantFlowControl(`stream:${stream.id}`, pkt.encodeMaxStreamDataFrame(stream.id, stream.recvLimit))
	}

	_grantConnectionCredit(): void {
		if (this._closed) return
		const step = Math.max(1, Math.floor(tp.FLOW_CONTROL.maxData / WINDOW_UPDATE_FRACTION))
		if (this.recvConsumed + step < this.recvLimit) return
		this.recvLimit = this.recvConsumed + tp.FLOW_CONTROL.maxData
		this._grantFlowControl('connection', pkt.encodeMaxDataFrame(this.recvLimit))
	}

	_onPeerMaxData(value: number): void {
		if (value <= this.peerMaxData) return
		this.peerMaxData = value
		for (const stream of this.streams.values()) stream._flushSend()
	}

	_onPeerMaxStreamData(streamId: number, value: number): void {
		const stream = this.streams.get(streamId)
		stream?._applyPeerLimit(value)
	}

	_canSend(stream: QuicStream, bytes: number): boolean {
		return this.peerMaxDataSent + bytes <= this.peerMaxData && stream.sendOffset + bytes <= stream.sendLimit
	}

	_reserveSend(bytes: number): void {
		this.peerMaxDataSent += bytes
	}

	sendStreamData(streamId: number, offset: number, data: Buffer, fin: boolean): void {
		if (!this.appKeys) throw new Error('1-RTT keys not ready')
		const frame = pkt.encodeStreamFrame(streamId, offset, data, fin)
		const packet = pkt.buildOneRtt({
			dstCid: this.dstCid,
			payloadFrames: frame,
			pn: this.pn.oneRtt,
			pnLen: 2,
			clientKeys: this.appKeys.client,
			aead: this.cipher.aead,
			keyPhase: this.currentPhase
		})
		const pn = this.pn.oneRtt++
		this._send1Rtt(packet, pn)
	}

	// 1-RTT send wrapped by NewReno. Stream data only — standalone ACKs / PTO probes
	// bypass this and call _sendDatagram directly so they can flow when cwnd is exhausted.
	_send1Rtt(packet: Buffer, pn: number): void {
		const size = packet.length
		if (this.cc.bytesInFlight + size > this.cc.cwnd) {
			this.appSendQueue.push({ packet, size, pn })
			return
		}
		this.cc.bytesInFlight += size
		this.sentPackets.oneRtt.set(pn, { time: Date.now(), size, includesCrypto: false })
		this._sendDatagram(packet)
		this._rearmPto()
	}

	_onPacketAcked(epoch: Epoch, _pn: number, info: SentPacket): void {
		if (epoch !== 'oneRtt') return
		for (const key of info.flowControlKeys || []) {
			// A cancel is only replayed while unacked; keeping it forever bloats every PTO.
			if (key.startsWith('cancel:')) this.flowControlFrames.delete(key)
		}
		if (!info.size) return
		this.cc.bytesInFlight = Math.max(0, this.cc.bytesInFlight - info.size)
		// Only grow cwnd for packets sent after the last recovery start (RFC 9002 §7.3.1).
		if (info.time < this.cc.recoveryStart) return
		if (this.cc.cwnd < this.cc.ssthresh) {
			// Slow start
			this.cc.cwnd += info.size
		} else {
			// Congestion avoidance — additive increase, per RFC 9002 §7.3.2.
			this.cc.cwnd += Math.floor((this.cc.kMaxDatagramSize * info.size) / this.cc.cwnd)
		}
		this._drainSendQueue()
	}

	_onCongestionEvent(sentTime: number): void {
		// Only react once per RTT (a single recovery period covers all losses in it).
		if (sentTime < this.cc.recoveryStart) return
		this.cc.recoveryStart = Date.now()
		this.cc.ssthresh = Math.max(Math.floor(this.cc.cwnd * this.cc.kLossReductionFactor), this.cc.kMinimumWindow)
		this.cc.cwnd = this.cc.ssthresh
		this.cc.congestionEvents++
		log.notify(`[cc] recovery cwnd=${this.cc.cwnd} ssthresh=${this.cc.ssthresh} ev=${this.cc.congestionEvents}`)
	}

	_drainSendQueue(): void {
		while (this.appSendQueue.length > 0) {
			const next = this.appSendQueue[0]
			if (this.cc.bytesInFlight + next.size > this.cc.cwnd) return
			this.appSendQueue.shift()
			this.cc.bytesInFlight += next.size
			this.sentPackets.oneRtt.set(next.pn, { time: Date.now(), size: next.size, includesCrypto: false })
			this._sendDatagram(next.packet)
		}
		this._rearmPto()
	}

	close(code = 0, reason = ''): void {
		this._closed = true
		if (this.ptoTimer) clearTimeout(this.ptoTimer)
		this.ptoTimer = null
		// Best-effort CONNECTION_CLOSE on 1-RTT epoch
		try {
			// Use the public `socket.destroyed` — `_handle` is internal and triggers Node
			// DEP0112 deprecation warnings on modern versions.
			if (this.appKeys && this.socket && !this.socket.destroyed) {
				const socket = this.socket
				const reasonBuf = Buffer.from(reason, 'utf8')
				const frame = Buffer.concat([
					Buffer.from([0x1c]), // CONNECTION_CLOSE (transport)
					varint.encode(code), // error code
					varint.encode(0), // frame_type that caused (0 = generic)
					varint.encode(reasonBuf.length),
					reasonBuf
				])
				const packet = pkt.buildOneRtt({
					dstCid: this.dstCid,
					payloadFrames: frame,
					pn: this.pn.oneRtt,
					pnLen: 2,
					clientKeys: this.appKeys.client,
					aead: this.cipher.aead,
					keyPhase: this.currentPhase
				})
				this.pn.oneRtt++
				socket.send(packet, this.port, this.serverAddr?.host ?? this.host, () => {
					try {
						socket.close()
					} catch {}
				})
				return
			}
		} catch {}
		try {
			this.socket?.close()
		} catch {}
	}
}

class QuicStream extends EventEmitter {
	declare conn: QuicConnection
	declare id: number
	declare kind: 'uni' | 'bidi'
	declare recvOffset: number
	declare pending: { offset: number; data: Buffer; fin: boolean }[]
	declare fin: boolean
	declare sendOffset: number
	// Bytes held in `pending` that cannot be flushed in order yet. Absent until the first
	// chunk arrives; every read goes through `|| 0` so it behaves as zero.
	declare _pendingBytes: number | undefined

	// Receive flow control: `recvLimit` is granted by us, `recvConsumed` is read by the app.
	declare recvLimit: number
	declare recvWindow: number
	declare recvConsumed: number
	declare highestOffset: number
	declare paused: boolean
	/** Receive side stopped: inbound bytes are discarded and MAX_* credit is granted. */
	declare cancelled: boolean
	/** Send side stopped: DATA/STOP_SENDING no longer leave this stream. */
	declare sendCancelled: boolean
	declare stopSendingSent: boolean
	declare _flowControlErrored: boolean

	// Send flow control: peer grants are pushed in via MAX_*; blocked writes wait here.
	declare sendLimit: number
	declare blocked: boolean
	declare sendQueue: { data: Buffer; fin: boolean }[]

	constructor(conn: QuicConnection, id: number, kind: 'uni' | 'bidi') {
		super()
		this.conn = conn
		this.id = id
		this.kind = kind
		this.recvOffset = 0
		this.pending = [] // out-of-order chunks: [{offset, data, fin}]
		this.fin = false
		this.sendOffset = 0

		this.recvWindow = kind === 'uni' ? tp.FLOW_CONTROL.maxStreamDataUni : tp.FLOW_CONTROL.maxStreamDataBidiLocal
		this.recvLimit = this.recvWindow
		this.recvConsumed = 0
		this.highestOffset = 0
		this.paused = false
		this.cancelled = false
		this.sendCancelled = false
		this.stopSendingSent = false
		this._flowControlErrored = false

		// A new stream starts with whatever credit the peer's transport parameters grant us;
		// before those arrive this is zero, never our own receive-window constant.
		this.sendLimit = kind === 'uni' ? this.conn.peerMaxStreamDataUni : this.conn.peerMaxStreamDataBidiRemote
		this.blocked = false
		this.sendQueue = []
	}

	send(data: Buffer, fin = false): void {
		if (this.cancelled || this.sendCancelled) return
		if (!this.conn._canSend(this, data.length)) {
			this.sendQueue.push({ data, fin })
			if (!this.blocked) {
				this.blocked = true
				const frame =
					this.sendOffset + data.length > this.sendLimit
						? pkt.encodeStreamDataBlockedFrame(this.id, this.sendLimit)
						: pkt.encodeDataBlockedFrame(this.conn.peerMaxData)
				this.conn._sendFlowControlFrame(frame)
			}
			return
		}
		this._write(data, fin)
		// A MAX_* grant that arrived while this chunk was blocked may unblock the next one.
		this._flushSend()
	}

	_write(data: Buffer, fin: boolean): void {
		if (this.cancelled || this.sendCancelled) return
		if (data.length === 0 && !fin) return
		this.conn.sendStreamData(this.id, this.sendOffset, data, fin)
		this.conn._reserveSend(data.length)
		this.sendOffset += data.length
		if (fin) this.emit('fin-sent')
	}

	_flushSend(): void {
		if (this.cancelled || this.sendCancelled) return
		while (this.sendQueue.length && this.conn._canSend(this, this.sendQueue[0].data.length)) {
			const { data, fin } = this.sendQueue.shift()!
			this._write(data, fin)
		}
		if (this.sendQueue.length === 0) this.blocked = false
	}

	_applyPeerLimit(value: number): void {
		if (value <= this.sendLimit) return
		this.sendLimit = value
		this._flushSend()
	}

	/** Stop receiving on this stream while crediting discarded bytes to the connection window. */
	_stopReceiving(): void {
		if (this.cancelled) return
		this.cancelled = true
		// `pending` can hold overlapping frames; credit only the unique offset span that
		// connection flow control already charged as received.
		const farthest = this.pending.reduce((max, c) => Math.max(max, c.offset + c.data.length), this.recvOffset)
		this.conn._onBytesDiscarded(Math.max(0, farthest - this.recvOffset))
		this.pending = []
		this._pendingBytes = 0
		this.paused = false
	}

	/** Stop sending on this stream. Optionally also ask the peer to stop sending. */
	_resetSend(errorCode: number, includeStopSending: boolean): void {
		if (this.sendCancelled && (!includeStopSending || this.stopSendingSent)) return
		this.sendCancelled = true
		this.sendQueue = []
		this.blocked = false
		if (includeStopSending) this.stopSendingSent = true
		if (this.conn.appKeys && !this.conn._closed) {
			const frames = [pkt.encodeResetStreamFrame(this.id, errorCode, this.sendOffset)]
			if (includeStopSending) frames.push(pkt.encodeStopSendingFrame(this.id, errorCode))
			this.conn._grantFlowControl(`cancel:${this.id}`, Buffer.concat(frames))
		}
	}

	/**
	 * Cancel only this stream. RESET_STREAM / STOP_SENDING let the peer and the rest of the
	 * QUIC session continue, unlike closing the whole connection from a request's cancel path.
	 */
	cancel(errorCode = 0x0c): void {
		if (this.cancelled && this.sendCancelled) return
		this._stopReceiving()
		this._resetSend(errorCode, true)
	}

	/** Consumer is behind: stop emitting DATA and stop granting credit. */
	pause(): void {
		this.paused = true
	}

	resume(): void {
		if (!this.paused) return
		this.paused = false
		this._flushPending()
	}

	_onData(offset: number, data: Buffer, fin: boolean): void {
		if (this.cancelled) {
			// In-flight STREAM frames still count against connection credit even though the
			// application discarded them; without this, sibling streams stall at MAX_DATA.
			const end = offset + data.length
			if (end <= this.highestOffset) return
			const fresh = end - this.highestOffset
			const charged = Math.min(fresh, Math.max(0, this.conn.recvLimit - this.conn.recvReceived))
			this.conn.recvReceived += charged
			this.highestOffset = end
			this.conn._onBytesDiscarded(charged)
			return
		}
		const end = offset + data.length
		const flowControlError = (scope: string) => {
			if (!this._flowControlErrored) {
				this._flowControlErrored = true
				this.emit('error', new Error(`QUIC ${scope} flow control limit exceeded on stream ${this.id}`))
			}
		}
		if (end > this.recvLimit) {
			flowControlError('stream')
			return
		}
		// Count fresh offset coverage (not duplicates) against the connection window too. Gaps
		// are charged conservatively, which can only make us grant credit later, never earlier.
		if (end > this.highestOffset) {
			const fresh = end - this.highestOffset
			if (this.conn.recvReceived + fresh > this.conn.recvLimit) {
				flowControlError('connection')
				return
			}
			this.conn.recvReceived += fresh
			this.highestOffset = end
		}
		// Buffer out-of-order chunks; flush in-order ones. The receive window above bounds how
		// much can ever land here; the 8 MiB cap is defense in depth for hostile offsets.
		const MAX_PENDING = 8 * 1024 * 1024
		if ((this._pendingBytes || 0) + data.length > MAX_PENDING) {
			this.pending = []
			this._pendingBytes = 0
			this.emit('error', new Error('stream reassembly buffer exceeded'))
			return
		}
		this._pendingBytes = (this._pendingBytes || 0) + data.length
		this.pending.push({ offset, data, fin })
		this.pending.sort((a, b) => a.offset - b.offset)
		this._flushPending()
	}

	_flushPending(): void {
		while (!this.cancelled && !this.paused && this.pending.length && this.pending[0].offset <= this.recvOffset) {
			const chunk = this.pending.shift()!
			this._pendingBytes = (this._pendingBytes || 0) - chunk.data.length
			const skipBytes = this.recvOffset - chunk.offset
			if (skipBytes >= chunk.data.length) {
				if (chunk.fin) {
					this.fin = true
					this.emit('end')
				}
				continue
			}
			const slice = chunk.data.subarray(skipBytes)
			this.recvOffset += slice.length
			// Credit before the event: a consumer may cancel synchronously from this callback.
			this.conn._onBytesConsumed(this, slice.length)
			this.emit('data', slice)
			// A listener may cancel mid-emit; that ends the stream immediately, so no FIN/end
			// from this chunk may be delivered afterwards.
			if (this.cancelled) return
			// A listener may pause us mid-emit; the next loop iteration will stop, and the rest
			// of the already-received bytes stay buffered without granting more credit.
			if (chunk.fin) {
				this.fin = true
				this.emit('end')
			}
		}
	}
}

export { QuicConnection, QuicStream }
