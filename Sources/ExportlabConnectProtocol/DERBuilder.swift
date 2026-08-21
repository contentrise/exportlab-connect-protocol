import Foundation

/// Minimal DER (ASN.1 Distinguished Encoding Rules) writer.
///
/// This exists because there is no Apple API that builds an X.509 certificate
/// around a Secure Enclave key. `SecKeyCreateRandomKey` gives a key whose
/// private half can never leave the enclave, and `SecIdentityCreate` is not
/// public — so the certificate has to be assembled byte by byte and the
/// signature produced by asking the enclave to sign the TBS bytes.
///
/// Only the subset X.509 needs is implemented. Every value is written in the
/// definite-length form DER requires; BER's indefinite lengths are not valid
/// here and are not produced.
public enum DER {

    /// ASN.1 tag numbers, with the constructed bit already applied where the
    /// type is always constructed.
    public enum Tag: UInt8 {
        case boolean = 0x01
        case integer = 0x02
        case bitString = 0x03
        case octetString = 0x04
        case null = 0x05
        case objectIdentifier = 0x06
        case utf8String = 0x0C
        case printableString = 0x13
        case utcTime = 0x17
        case generalizedTime = 0x18
        case sequence = 0x30
        case set = 0x31
    }

    /// Wraps `content` in a tag-length-value triple.
    public static func encode(_ tag: Tag, _ content: Data) -> Data {
        encode(tag.rawValue, content)
    }

    public static func encode(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        out.append(length(content.count))
        out.append(content)
        return out
    }

    /// A context-specific constructed tag, e.g. `[0]` for the X.509 version.
    public static func contextConstructed(_ number: UInt8, _ content: Data) -> Data {
        encode(0xA0 | number, content)
    }

    /// A context-specific primitive tag, used inside SubjectAltName.
    public static func contextPrimitive(_ number: UInt8, _ content: Data) -> Data {
        encode(0x80 | number, content)
    }

    /// DER length encoding: short form below 128, otherwise a byte count
    /// followed by big-endian length bytes with no leading zeros.
    public static func length(_ value: Int) -> Data {
        if value < 0x80 { return Data([UInt8(value)]) }

        var bytes: [UInt8] = []
        var remaining = value
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    public static func sequence(_ parts: [Data]) -> Data {
        encode(.sequence, parts.reduce(into: Data()) { $0.append($1) })
    }

    public static func set(_ parts: [Data]) -> Data {
        encode(.set, parts.reduce(into: Data()) { $0.append($1) })
    }

    /// An INTEGER. DER requires the minimum number of bytes, and a leading
    /// zero when the high bit is set — otherwise the value reads as negative.
    public static func integer(_ value: Data) -> Data {
        var bytes = Array(value)
        while bytes.count > 1, bytes[0] == 0x00, bytes[1] & 0x80 == 0 {
            bytes.removeFirst()
        }
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        }
        return encode(.integer, Data(bytes))
    }

    public static func integer(_ value: Int) -> Data {
        var bytes: [UInt8] = []
        var remaining = value
        repeat {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        } while remaining != 0
        return integer(Data(bytes))
    }

    /// A BIT STRING with no unused trailing bits, which is always the case for
    /// the byte-aligned values X.509 puts in one.
    public static func bitString(_ content: Data) -> Data {
        var body = Data([0x00])  // unused-bit count
        body.append(content)
        return encode(.bitString, body)
    }

    public static func octetString(_ content: Data) -> Data { encode(.octetString, content) }
    public static func utf8String(_ value: String) -> Data { encode(.utf8String, Data(value.utf8)) }
    public static func null() -> Data { Data([0x05, 0x00]) }
    public static func boolean(_ value: Bool) -> Data { encode(.boolean, Data([value ? 0xFF : 0x00])) }

    /// Encodes a dotted OID.
    ///
    /// The first two arcs share one byte as `40 * a + b`; the rest are base-128
    /// with the continuation bit set on every byte but the last.
    public static func objectIdentifier(_ dotted: String) -> Data {
        let arcs = dotted.split(separator: ".").compactMap { UInt64($0) }
        guard arcs.count >= 2 else { return Data() }

        var bytes: [UInt8] = [UInt8(arcs[0] * 40 + arcs[1])]
        for arc in arcs.dropFirst(2) {
            var chunks: [UInt8] = [UInt8(arc & 0x7F)]
            var remaining = arc >> 7
            while remaining > 0 {
                chunks.insert(UInt8(remaining & 0x7F) | 0x80, at: 0)
                remaining >>= 7
            }
            bytes.append(contentsOf: chunks)
        }
        return encode(.objectIdentifier, Data(bytes))
    }

    /// X.509 time. Dates before 2050 use UTCTime with a two-digit year, later
    /// ones GeneralizedTime — a rule from RFC 5280 that certificate parsers
    /// enforce strictly.
    public static func time(_ date: Date) -> Data {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let parts = calendar.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: date
        )
        let year = parts.year ?? 2000

        func pad(_ value: Int?, _ width: Int) -> String {
            String(format: "%0\(width)d", value ?? 0)
        }

        let tail = pad(parts.month, 2) + pad(parts.day, 2)
            + pad(parts.hour, 2) + pad(parts.minute, 2) + pad(parts.second, 2) + "Z"

        if year < 2050 {
            return encode(.utcTime, Data((pad(year % 100, 2) + tail).utf8))
        } else {
            return encode(.generalizedTime, Data((pad(year, 4) + tail).utf8))
        }
    }
}
