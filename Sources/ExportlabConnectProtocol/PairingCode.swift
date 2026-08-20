import CryptoKit
import Foundation

/// The bytes both peers agree were exchanged during a handshake.
///
/// The authentication signature covers this, not just a nonce. Because the
/// transcript includes both certificate key hashes, a signature captured on one
/// connection is worthless on another: an attacker relaying the handshake would
/// have to present one of the two private keys, which live in the Secure
/// Enclave and cannot be extracted.
public struct HandshakeTranscript: Sendable, Equatable {
    public var initiatorSPKISHA256: String
    public var responderSPKISHA256: String
    public var initiatorNonce: Data
    public var responderNonce: Data
    public var negotiatedVersion: UInt8

    public init(
        initiatorSPKISHA256: String,
        responderSPKISHA256: String,
        initiatorNonce: Data,
        responderNonce: Data,
        negotiatedVersion: UInt8
    ) {
        self.initiatorSPKISHA256 = initiatorSPKISHA256
        self.responderSPKISHA256 = responderSPKISHA256
        self.initiatorNonce = initiatorNonce
        self.responderNonce = responderNonce
        self.negotiatedVersion = negotiatedVersion
    }

    /// Canonical bytes, built in a fixed order with length prefixes.
    ///
    /// Length prefixes rather than separators: with plain concatenation an
    /// attacker could shift a byte from the end of one field to the start of the
    /// next and produce an identical digest for a different handshake.
    public func canonicalBytes() -> Data {
        var out = Data()
        out.append(contentsOf: Array("ELCP/1 transcript\u{0}".utf8))
        out.append(ELCP.version)
        out.append(negotiatedVersion)
        appendLengthPrefixed(&out, Data(initiatorSPKISHA256.utf8))
        appendLengthPrefixed(&out, Data(responderSPKISHA256.utf8))
        appendLengthPrefixed(&out, initiatorNonce)
        appendLengthPrefixed(&out, responderNonce)
        return out
    }

    private func appendLengthPrefixed(_ out: inout Data, _ field: Data) {
        out.appendBigEndian(UInt32(field.count))
        out.append(field)
    }

    /// The digest that gets signed by each peer.
    public func digest() -> Data {
        Data(SHA256.hash(data: canonicalBytes()))
    }
}

/// Derivation of the six-digit short authentication string shown on both
/// screens during first-time pairing.
///
/// The user compares two numbers and taps confirm, exactly as with AirPlay. The
/// number is not a secret and is not transmitted — it is computed independently
/// on each side from the transcript. If a machine-in-the-middle sat between the
/// two devices, each side would have negotiated a different transcript and the
/// two numbers would differ, which is precisely what the human is checking.
public enum PairingCode {
    /// Number of digits displayed. Six gives a 1-in-a-million chance that a
    /// tampered handshake happens to show a matching code — and unlike a
    /// password this is a one-shot check an attacker cannot retry, because a
    /// mismatch tears the connection down.
    public static let digitCount = 6

    private static let modulus: UInt32 = 1_000_000

    /// Derives the code from a completed transcript.
    ///
    /// Domain-separated from the signature digest so that the displayed number
    /// can never be confused with, or substituted for, signed material.
    public static func code(for transcript: HandshakeTranscript) -> String {
        var input = Data("ELCP/1 pairing-sas\u{0}".utf8)
        input.append(transcript.digest())
        let digest = Data(SHA256.hash(data: input))

        // Take the leading 4 bytes big-endian, then reduce. The modulo bias
        // across 2^32 into 10^6 is under one part in four thousand — far below
        // anything an attacker can exploit in a single non-retryable attempt.
        let value = digest.bigEndianUInt32(at: digest.startIndex) % modulus
        return String(format: "%0\(digitCount)u", value)
    }

    /// Commitment a device publishes to the backend before the codes are
    /// compared, so neither side can adjust its transcript after seeing the
    /// other's value.
    public static func commitment(for transcript: HandshakeTranscript, deviceID: String) -> String {
        var input = Data("ELCP/1 pairing-commit\u{0}".utf8)
        input.append(transcript.digest())
        input.append(contentsOf: Array(deviceID.utf8))
        return Data(SHA256.hash(data: input)).base64URLEncodedString()
    }

    /// Constant-time comparison of two displayed codes.
    ///
    /// Timing analysis on a six-digit human-confirmed value is not a realistic
    /// attack, but a variable-time compare in security-adjacent code invites
    /// someone to copy the pattern somewhere it does matter.
    public static func matches(_ lhs: String, _ rhs: String) -> Bool {
        let a = Array(lhs.utf8), b = Array(rhs.utf8)
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices { difference |= a[index] ^ b[index] }
        return difference == 0
    }
}

// MARK: - Key fingerprints

public enum SPKIFingerprint {
    /// The pinning value: base64url SHA-256 of a DER SubjectPublicKeyInfo.
    ///
    /// 43 characters unpadded, which fits comfortably in a Bonjour TXT record
    /// where the whole record is limited to 255 bytes per key-value pair.
    public static func compute(spkiDER: Data) -> String {
        Data(SHA256.hash(data: spkiDER)).base64URLEncodedString()
    }
}

extension Data {
    /// base64url without padding, per RFC 4648 §5.
    ///
    /// Plain base64 is unusable here: `+` and `/` are not safe in a TXT record
    /// or a URL path, and `=` padding is pure noise at a fixed length.
    public func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public init?(base64URLEncoded string: String) {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if s.count % 4 != 0 { s += String(repeating: "=", count: 4 - s.count % 4) }
        guard let data = Data(base64Encoded: s) else { return nil }
        self = data
    }
}
