import Foundation

/// Everything that can go wrong on the wire.
///
/// These values cross the network in `error` frames, so `code` is part of the
/// protocol contract: never renumber, only append. The associated values stay
/// local — they are for logs and tests, not for the peer, because echoing back
/// exactly which byte offended is a gift to anyone probing the parser.
public enum ELCPError: Error, Equatable, Sendable {
    // Framing
    case truncatedHeader(got: Int)
    case badMagic(UInt32)
    case unsupportedVersion(UInt8)
    case unknownFrameKind(UInt8)
    case payloadTooLarge(UInt32)

    // Session
    case handshakeTimeout
    case versionNegotiationFailed(peerVersion: UInt8)
    case authenticationFailed
    case notPaired
    case pairingRejected
    case pairingExpired

    // Transfer
    case unknownStream(UInt64)
    case integrityMismatch(itemID: String)
    case fileVanished
    case rejectedByPeer(reason: String)
    case cancelled
    case flowViolation

    // Preview
    case rangeOutOfBounds
    case previewUnavailable

    // Generic
    case peerClosed
    case malformedPayload(String)
    case internalFailure(String)

    /// The stable numeric code sent to the peer.
    public var code: UInt16 {
        switch self {
        case .truncatedHeader:          1000
        case .badMagic:                 1001
        case .unsupportedVersion:       1002
        case .unknownFrameKind:         1003
        case .payloadTooLarge:          1004
        case .handshakeTimeout:         1100
        case .versionNegotiationFailed: 1101
        case .authenticationFailed:     1102
        case .notPaired:                1103
        case .pairingRejected:          1104
        case .pairingExpired:           1105
        case .unknownStream:            1200
        case .integrityMismatch:        1201
        case .fileVanished:             1202
        case .rejectedByPeer:           1203
        case .cancelled:                1204
        case .flowViolation:            1205
        case .rangeOutOfBounds:         1300
        case .previewUnavailable:       1301
        case .peerClosed:               1400
        case .malformedPayload:         1401
        case .internalFailure:          1402
        }
    }

    /// Whether the connection should be torn down rather than kept alive.
    ///
    /// A framing fault means the byte stream is no longer trustworthy — there is
    /// no way to find the next header, so resynchronising is guesswork. A
    /// per-stream fault (a vanished file, a rejected offer) leaves the
    /// connection perfectly usable.
    public var isFatal: Bool {
        switch self {
        case .truncatedHeader, .badMagic, .unsupportedVersion, .payloadTooLarge,
             .handshakeTimeout, .versionNegotiationFailed, .authenticationFailed,
             .notPaired, .peerClosed, .flowViolation:
            true
        default:
            false
        }
    }
}
