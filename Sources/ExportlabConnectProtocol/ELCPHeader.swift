import Foundation

/// Wire-level constants for ELCP/1.
public enum ELCP {
    /// Magic bytes prefixing every frame: "ELCP" in ASCII.
    public static let magic: UInt32 = 0x45_4C_43_50

    /// The protocol version this build speaks.
    public static let version: UInt8 = 1

    /// Fixed on-wire header size in bytes.
    ///
    /// magic(4) + version(1) + kind(1) + flags(2) + streamID(8) + payloadLength(4)
    public static let headerSize = 20

    /// Largest payload a single frame may carry.
    ///
    /// Frames are deliberately small: a cancel during scrubbing can only take
    /// effect between frames, so a large frame is a large cancel latency.
    /// 4 MiB is the adaptive chunk ceiling; the limit sits one bit above it so a
    /// legitimate maximum-size chunk is never rejected by its own framing.
    public static let maxPayloadLength: UInt32 = 8 << 20
}

/// The type of a frame. Raw values are wire format — never renumber an existing
/// case, only append. A peer that receives an unknown kind must respond with an
/// `error` frame rather than closing, so that a newer peer can degrade
/// gracefully against an older one.
public enum ELCPFrameKind: UInt8, Sendable, CaseIterable {
    // Session lifecycle
    case hello = 1
    case helloAck = 2
    case authChallenge = 3
    case authResponse = 4

    // Transfer
    case offer = 10
    case accept = 11
    case reject = 12
    case chunk = 13
    case flow = 14
    case complete = 15
    case resume = 16

    // Live preview
    case currentFile = 30
    case rangeRequest = 31
    case rangeData = 32
    case rangeEnd = 33
    case rangeCancel = 34
    case rangeError = 35

    // Control
    case ping = 60
    case pong = 61
    case cancel = 62
    case error = 63

    /// Frames whose payload is raw bytes rather than JSON.
    ///
    /// These carry media on the hot path and must not pay for JSON encoding or
    /// base64 inflation.
    public var hasBinaryPayload: Bool {
        switch self {
        case .chunk, .rangeData: true
        default: false
        }
    }
}

public struct ELCPFrameFlags: OptionSet, Sendable {
    public let rawValue: UInt16
    public init(rawValue: UInt16) { self.rawValue = rawValue }

    /// This frame completes the logical message on its stream.
    public static let endOfMessage = ELCPFrameFlags(rawValue: 1 << 0)
}

/// The fixed-size prefix on every ELCP frame.
///
/// Encoding is big-endian throughout. `streamID` multiplexes concurrent logical
/// operations over one connection — AVFoundation routinely asks for the moov
/// atom at the tail while streaming from the head, so several ranges are in
/// flight at once and each needs its own identity.
public struct ELCPHeader: Equatable, Sendable {
    public var kind: ELCPFrameKind
    public var flags: ELCPFrameFlags
    public var streamID: UInt64
    public var payloadLength: UInt32

    public init(
        kind: ELCPFrameKind,
        flags: ELCPFrameFlags = [],
        streamID: UInt64 = 0,
        payloadLength: UInt32
    ) {
        self.kind = kind
        self.flags = flags
        self.streamID = streamID
        self.payloadLength = payloadLength
    }

    public func encode() -> Data {
        var out = Data(capacity: ELCP.headerSize)
        out.appendBigEndian(ELCP.magic)
        out.append(ELCP.version)
        out.append(kind.rawValue)
        out.appendBigEndian(flags.rawValue)
        out.appendBigEndian(streamID)
        out.appendBigEndian(payloadLength)
        return out
    }

    /// Parses a header from exactly `ELCP.headerSize` bytes.
    ///
    /// Every failure mode here is reachable from the network, so each one is a
    /// named error rather than a `nil` — a peer that sends garbage gets told
    /// precisely what was wrong, and the fuzzer's output stays legible.
    public static func decode(_ bytes: Data) throws -> ELCPHeader {
        guard bytes.count >= ELCP.headerSize else {
            throw ELCPError.truncatedHeader(got: bytes.count)
        }
        // `bytes` may be a slice with a non-zero startIndex; index relative to it.
        let base = bytes.startIndex

        let magic = bytes.bigEndianUInt32(at: base)
        guard magic == ELCP.magic else { throw ELCPError.badMagic(magic) }

        let version = bytes[base + 4]
        guard version == ELCP.version else { throw ELCPError.unsupportedVersion(version) }

        let rawKind = bytes[base + 5]
        guard let kind = ELCPFrameKind(rawValue: rawKind) else {
            throw ELCPError.unknownFrameKind(rawKind)
        }

        let flags = ELCPFrameFlags(rawValue: bytes.bigEndianUInt16(at: base + 6))
        let streamID = bytes.bigEndianUInt64(at: base + 8)
        let payloadLength = bytes.bigEndianUInt32(at: base + 16)

        guard payloadLength <= ELCP.maxPayloadLength else {
            throw ELCPError.payloadTooLarge(payloadLength)
        }

        return ELCPHeader(
            kind: kind,
            flags: flags,
            streamID: streamID,
            payloadLength: payloadLength
        )
    }
}

/// A complete frame: header plus its payload bytes.
public struct ELCPFrame: Equatable, Sendable {
    public var header: ELCPHeader
    public var payload: Data

    public init(header: ELCPHeader, payload: Data) {
        self.header = header
        self.payload = payload
    }

    /// Builds a frame, deriving `payloadLength` from the payload so the two can
    /// never disagree.
    public init(
        kind: ELCPFrameKind,
        flags: ELCPFrameFlags = [],
        streamID: UInt64 = 0,
        payload: Data = Data()
    ) {
        self.header = ELCPHeader(
            kind: kind,
            flags: flags,
            streamID: streamID,
            payloadLength: UInt32(payload.count)
        )
        self.payload = payload
    }

    public func encode() -> Data {
        var out = header.encode()
        out.append(payload)
        return out
    }
}

// MARK: - Big-endian helpers

extension Data {
    mutating func appendBigEndian(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value >> 8))
        append(UInt8(truncatingIfNeeded: value))
    }

    mutating func appendBigEndian(_ value: UInt32) {
        for shift in stride(from: 24, through: 0, by: -8) {
            append(UInt8(truncatingIfNeeded: value >> UInt32(shift)))
        }
    }

    mutating func appendBigEndian(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }

    /// Reads a big-endian integer without assuming alignment.
    ///
    /// `load(as:)` traps on unaligned access; a frame boundary lands wherever
    /// the network puts it, so the bytes are assembled by hand.
    func bigEndianUInt16(at index: Index) -> UInt16 {
        UInt16(self[index]) << 8 | UInt16(self[index + 1])
    }

    func bigEndianUInt32(at index: Index) -> UInt32 {
        var value: UInt32 = 0
        for offset in 0..<4 { value = value << 8 | UInt32(self[index + offset]) }
        return value
    }

    func bigEndianUInt64(at index: Index) -> UInt64 {
        var value: UInt64 = 0
        for offset in 0..<8 { value = value << 8 | UInt64(self[index + offset]) }
        return value
    }
}
