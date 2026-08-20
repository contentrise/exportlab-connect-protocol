import Foundation

// MARK: - Shared vocabulary

/// Which side of a connection a peer is on.
///
/// The Mac advertises and listens; the phone browses and connects. That is not
/// arbitrary — iOS tears down listeners on backgrounding, so a phone-advertised
/// service would vanish every time the device went into a pocket and return on
/// a different port.
public enum ELCPRole: String, Codable, Sendable {
    case initiator  // the phone
    case responder  // the Mac
}

public enum DevicePlatform: String, Codable, Sendable {
    case macOS
    case iOS
    case iPadOS
}

/// Whether the receiving device can play a video as-is.
public enum Playability: String, Codable, Sendable {
    /// H.264/HEVC at a bitrate a Wi-Fi link can sustain — stream the original.
    case native
    /// ProRes, DNxHR, or an unsustainable bitrate — the Mac must make a proxy.
    case needsTranscode
    /// R3D, BRAW, CinemaDNG — AVFoundation cannot decode these at all. Show a
    /// poster frame and say so plainly rather than failing at playback.
    case unsupported
}

/// Capabilities a peer advertises. Unknown values are ignored, so an older peer
/// meeting a newer one degrades instead of failing.
public struct PeerCapabilities: OptionSet, Codable, Sendable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let livePreview   = PeerCapabilities(rawValue: 1 << 0)
    public static let watchFolder   = PeerCapabilities(rawValue: 1 << 1)
    public static let transcode     = PeerCapabilities(rawValue: 1 << 2)
    public static let resume        = PeerCapabilities(rawValue: 1 << 3)
    public static let cloudFallback = PeerCapabilities(rawValue: 1 << 4)
}

// MARK: - Handshake

public struct HelloMessage: Codable, Sendable {
    public var version: UInt8
    public var role: ELCPRole
    public var deviceID: String
    public var deviceName: String
    public var platform: DevicePlatform
    public var osVersion: String
    public var appVersion: String
    /// Base64url SHA-256 of the peer's SPKI. Must match the TLS certificate's
    /// public key — the binding that makes a relayed handshake useless.
    public var spkiSHA256: String
    public var capabilities: PeerCapabilities
    /// 32 random bytes contributed by the initiator.
    ///
    /// Carried in the hello rather than in a later frame so that both sides can
    /// build the identical transcript: the responder needs it before it can
    /// derive the pairing code, and a round trip to fetch it would let the two
    /// sides disagree about ordering.
    public var nonce: Data

    public init(
        version: UInt8 = ELCP.version,
        role: ELCPRole,
        deviceID: String,
        deviceName: String,
        platform: DevicePlatform,
        osVersion: String,
        appVersion: String,
        spkiSHA256: String,
        capabilities: PeerCapabilities,
        nonce: Data = Data()
    ) {
        self.version = version
        self.role = role
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.platform = platform
        self.osVersion = osVersion
        self.appVersion = appVersion
        self.spkiSHA256 = spkiSHA256
        self.capabilities = capabilities
        self.nonce = nonce
    }
}

public struct HelloAckMessage: Codable, Sendable {
    /// The version both sides will actually speak: `min(mine, theirs)`.
    public var negotiatedVersion: UInt8
    /// Capabilities present on both sides.
    public var sharedCapabilities: PeerCapabilities
    public var deviceID: String
    public var deviceName: String
    public var platform: DevicePlatform
    public var spkiSHA256: String
    /// True when this peer has no active pairing for the other and a short
    /// authentication string must be confirmed by a human before anything else.
    public var requiresPairing: Bool

    public init(
        negotiatedVersion: UInt8,
        sharedCapabilities: PeerCapabilities,
        deviceID: String,
        deviceName: String,
        platform: DevicePlatform,
        spkiSHA256: String,
        requiresPairing: Bool
    ) {
        self.negotiatedVersion = negotiatedVersion
        self.sharedCapabilities = sharedCapabilities
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.platform = platform
        self.spkiSHA256 = spkiSHA256
        self.requiresPairing = requiresPairing
    }
}

public struct AuthChallengeMessage: Codable, Sendable {
    /// 32 random bytes, base64. Freshness only — the replay defence is the
    /// transcript binding, not this value.
    public var nonce: Data
    public init(nonce: Data) { self.nonce = nonce }
}

public struct AuthResponseMessage: Codable, Sendable {
    /// Signature over the handshake transcript (see `HandshakeTranscript`),
    /// made with the private key whose SPKI the certificate presented.
    public var signature: Data
    public init(signature: Data) { self.signature = signature }
}

// MARK: - Transfer

public struct FileDescriptor: Codable, Sendable, Equatable {
    public var fileID: String
    /// Original filename. Treated as hostile input by the receiver: reduced to a
    /// basename and normalised before it ever reaches the filesystem.
    public var name: String
    public var byteCount: UInt64
    /// UTType identifier, e.g. "public.jpeg". Not a MIME type — AVFoundation
    /// silently produces no tracks when handed a MIME type.
    public var utType: String
    public var sha256: Data
    public var pixelWidth: Int?
    public var pixelHeight: Int?
    public var durationSeconds: Double?
    public var colorSpaceName: String?
    public var playability: Playability?
    /// Small JPEG shown immediately, before any of the original has arrived.
    public var thumbnailJPEG: Data?

    public init(
        fileID: String,
        name: String,
        byteCount: UInt64,
        utType: String,
        sha256: Data,
        pixelWidth: Int? = nil,
        pixelHeight: Int? = nil,
        durationSeconds: Double? = nil,
        colorSpaceName: String? = nil,
        playability: Playability? = nil,
        thumbnailJPEG: Data? = nil
    ) {
        self.fileID = fileID
        self.name = name
        self.byteCount = byteCount
        self.utType = utType
        self.sha256 = sha256
        self.pixelWidth = pixelWidth
        self.pixelHeight = pixelHeight
        self.durationSeconds = durationSeconds
        self.colorSpaceName = colorSpaceName
        self.playability = playability
        self.thumbnailJPEG = thumbnailJPEG
    }
}

public struct OfferMessage: Codable, Sendable {
    public var offerID: String
    public var files: [FileDescriptor]
    /// How the sender came by these files — drives the receiver's copy, e.g.
    /// "Watching Exports" rather than a bare filename.
    public var origin: String?

    public init(offerID: String, files: [FileDescriptor], origin: String? = nil) {
        self.offerID = offerID
        self.files = files
        self.origin = origin
    }
}

public struct AcceptMessage: Codable, Sendable {
    public var offerID: String
    /// Byte offset per file to start from, for resuming an interrupted
    /// transfer. Absent or zero means start at the beginning.
    public var resumeOffsets: [String: UInt64]

    public init(offerID: String, resumeOffsets: [String: UInt64] = [:]) {
        self.offerID = offerID
        self.resumeOffsets = resumeOffsets
    }
}

public struct RejectMessage: Codable, Sendable {
    public var offerID: String
    public var reason: String
    public init(offerID: String, reason: String) {
        self.offerID = offerID
        self.reason = reason
    }
}

/// Receiver-driven credit.
///
/// TCP backpressure reflects network congestion only. A phone writing to a
/// nearly-full disk will happily accept into the kernel buffer and then stall,
/// leaving the Mac's progress bar at 100% while the phone is still hundreds of
/// megabytes behind. That looks like a bug and gets reported as one.
public struct FlowMessage: Codable, Sendable {
    public var fileID: String
    public var consumedBytes: UInt64
    public init(fileID: String, consumedBytes: UInt64) {
        self.fileID = fileID
        self.consumedBytes = consumedBytes
    }
}

public struct CompleteMessage: Codable, Sendable {
    public var fileID: String
    public var byteCount: UInt64
    public var sha256: Data
    public init(fileID: String, byteCount: UInt64, sha256: Data) {
        self.fileID = fileID
        self.byteCount = byteCount
        self.sha256 = sha256
    }
}

// MARK: - Live preview

/// Pushed by the Mac to say "this is what is being reviewed now".
///
/// Changing the current file on the Mac changes what the phone shows, which is
/// what turns the phone into a second monitor rather than a file list.
public struct CurrentFileMessage: Codable, Sendable {
    public var sessionID: String
    public var file: FileDescriptor
    /// Real frame from the source, shown while a proxy is still encoding.
    public var posterJPEG: Data?
    /// Progress of proxy transcoding, 0...1. Nil when no proxy is needed.
    public var transcodeProgress: Double?

    public init(
        sessionID: String,
        file: FileDescriptor,
        posterJPEG: Data? = nil,
        transcodeProgress: Double? = nil
    ) {
        self.sessionID = sessionID
        self.file = file
        self.posterJPEG = posterJPEG
        self.transcodeProgress = transcodeProgress
    }
}

public struct RangeRequestMessage: Codable, Sendable {
    public var requestID: String
    public var fileID: String
    public var offset: UInt64
    public var length: Int

    public init(requestID: String, fileID: String, offset: UInt64, length: Int) {
        self.requestID = requestID
        self.fileID = fileID
        self.offset = offset
        self.length = length
    }
}

public struct RangeEndMessage: Codable, Sendable {
    public var requestID: String
    public var deliveredBytes: Int
    public var isEndOfFile: Bool

    public init(requestID: String, deliveredBytes: Int, isEndOfFile: Bool) {
        self.requestID = requestID
        self.deliveredBytes = deliveredBytes
        self.isEndOfFile = isEndOfFile
    }
}

public struct RangeCancelMessage: Codable, Sendable {
    public var requestID: String
    public init(requestID: String) { self.requestID = requestID }
}

// MARK: - Control

public struct ErrorMessage: Codable, Sendable {
    public var code: UInt16
    /// Human-readable, for logs. Deliberately vague about parser internals.
    public var message: String
    public var isFatal: Bool

    public init(code: UInt16, message: String, isFatal: Bool) {
        self.code = code
        self.message = message
        self.isFatal = isFatal
    }

    public init(_ error: ELCPError, message: String) {
        self.code = error.code
        self.message = message
        self.isFatal = error.isFatal
    }
}

public struct CancelMessage: Codable, Sendable {
    public var offerID: String?
    public var fileID: String?
    public init(offerID: String? = nil, fileID: String? = nil) {
        self.offerID = offerID
        self.fileID = fileID
    }
}

// MARK: - Coding

/// JSON coding for message payloads.
///
/// One shared configuration so both sides agree byte-for-byte: sorted keys make
/// frames reproducible, which matters because the handshake transcript is
/// hashed. `.base64` for Data is explicit rather than assumed.
public enum ELCPCoding {
    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dataEncodingStrategy = .base64
        return encoder
    }

    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        return decoder
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        do {
            return try encoder().encode(value)
        } catch {
            throw ELCPError.internalFailure("encode \(T.self): \(error)")
        }
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try decoder().decode(type, from: data)
        } catch {
            // The peer sees only "malformed payload" — never the decoder's
            // description of which key was missing.
            throw ELCPError.malformedPayload(String(describing: type))
        }
    }
}

extension ELCPFrame {
    /// Builds a frame whose payload is the JSON encoding of `message`.
    public static func json<T: Encodable>(
        _ kind: ELCPFrameKind,
        _ message: T,
        streamID: UInt64 = 0,
        flags: ELCPFrameFlags = []
    ) throws -> ELCPFrame {
        ELCPFrame(
            kind: kind,
            flags: flags,
            streamID: streamID,
            payload: try ELCPCoding.encode(message)
        )
    }

    /// Decodes this frame's payload, asserting the frame kind first so a
    /// mismatched pairing is a clear error rather than a decode failure.
    public func decode<T: Decodable>(_ type: T.Type, expecting kind: ELCPFrameKind) throws -> T {
        guard header.kind == kind else {
            throw ELCPError.malformedPayload("expected \(kind), got \(header.kind)")
        }
        return try ELCPCoding.decode(type, from: payload)
    }
}
