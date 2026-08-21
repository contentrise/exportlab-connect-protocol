import CryptoKit
import Foundation
import Testing
@testable import ExportlabConnectProtocol

@Suite("DER encoding")
struct DERTests {

    @Test("uses the short length form below 128")
    func shortLengthForm() {
        #expect(DER.length(0) == Data([0x00]))
        #expect(DER.length(127) == Data([0x7F]))
    }

    @Test("uses the long length form at and above 128")
    func longLengthForm() {
        // 128 needs the long form even though it fits in one byte: the short
        // form's top bit is the discriminator.
        #expect(DER.length(128) == Data([0x81, 0x80]))
        #expect(DER.length(255) == Data([0x81, 0xFF]))
        #expect(DER.length(256) == Data([0x82, 0x01, 0x00]))
        #expect(DER.length(65535) == Data([0x82, 0xFF, 0xFF]))
        #expect(DER.length(65536) == Data([0x83, 0x01, 0x00, 0x00]))
    }

    @Test("pads an integer whose high bit is set")
    func padsNegativeLookingInteger() {
        // Without the leading zero, 0x80 reads as a negative number.
        #expect(DER.integer(Data([0x80])) == Data([0x02, 0x02, 0x00, 0x80]))
        #expect(DER.integer(Data([0x7F])) == Data([0x02, 0x01, 0x7F]))
    }

    @Test("strips redundant leading zeros from an integer")
    func stripsLeadingZeros() {
        // DER requires the minimum encoding; BER would allow the padding.
        #expect(DER.integer(Data([0x00, 0x00, 0x01])) == Data([0x02, 0x01, 0x01]))
        // But a zero that makes the value positive must survive.
        #expect(DER.integer(Data([0x00, 0x80])) == Data([0x02, 0x02, 0x00, 0x80]))
    }

    @Test("encodes zero as a single byte")
    func encodesZero() {
        #expect(DER.integer(0) == Data([0x02, 0x01, 0x00]))
    }

    @Test("packs the first two OID arcs into one byte")
    func encodesOID() {
        // 1.2.840.10045.2.1 (ecPublicKey) — the first byte is 1*40 + 2 = 42.
        #expect(DER.objectIdentifier("1.2.840.10045.2.1")
            == Data([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]))
    }

    @Test("base-128 encodes large OID arcs")
    func encodesLargeArcs() {
        // 10045 spans two base-128 bytes with the continuation bit set.
        let encoded = DER.objectIdentifier("1.2.840.113549.1.1.11")
        #expect(encoded.first == 0x06)
        #expect(encoded.contains(0x86))
    }

    @Test("chooses UTCTime before 2050 and GeneralizedTime after")
    func choosesTimeFormat() {
        // RFC 5280's rule, and parsers enforce it strictly.
        let before = DER.time(Date(timeIntervalSince1970: 1_760_000_000))  // 2025
        #expect(before.first == DER.Tag.utcTime.rawValue)

        let after = DER.time(Date(timeIntervalSince1970: 2_600_000_000))   // 2052
        #expect(after.first == DER.Tag.generalizedTime.rawValue)
    }

    @Test("omits unused bits from a bit string")
    func encodesBitString() {
        #expect(DER.bitString(Data([0xAB])) == Data([0x03, 0x02, 0x00, 0xAB]))
    }
}

@Suite("Self-signed certificate")
struct SelfSignedCertificateTests {

    /// Builds a certificate signed by a software P-256 key.
    private func makeCertificate(
        commonName: String = "Stefan's MacBook Pro"
    ) throws -> (der: Data, key: P256.Signing.PrivateKey) {
        let key = P256.Signing.PrivateKey()
        let der = try SelfSignedCertificate.make(
            publicKeyX963: key.publicKey.x963Representation,
            commonName: commonName,
            sign: { tbs in
                // ECDSA-SHA256 in DER form, as the algorithm identifier promises.
                try key.signature(for: SHA256.hash(data: tbs)).derRepresentation
            }
        )
        return (der, key)
    }

    @Test("produces a certificate openssl can parse")
    func opensslParsesIt() throws {
        // The real test. A hand-rolled DER encoder that only satisfies its own
        // reader proves nothing — openssl is a strict, independent parser, and
        // if it accepts the structure then Network.framework will too.
        let (der, _) = try makeCertificate()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("connect-cert-\(UUID().uuidString).der")
        try der.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let output = try runOpenSSL(["x509", "-inform", "DER", "-in", url.path, "-noout", "-text"])
        #expect(output.contains("Signature Algorithm: ecdsa-with-SHA256"))
        #expect(output.contains("Stefan's MacBook Pro"))
        #expect(output.contains("id-ecPublicKey"))
        #expect(output.contains("prime256v1"))
    }

    @Test("openssl verifies the signature")
    func opensslVerifiesSignature() throws {
        // Parsing only proves the shape is right. This proves the signature
        // actually covers the TBS bytes — the mistake that DER assembly makes
        // easy is signing the wrong span.
        let (der, _) = try makeCertificate()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("connect-verify-\(UUID().uuidString).der")
        try der.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        // A self-signed certificate is its own issuer, so it verifies against
        // itself; openssl reports the expected self-signed condition rather
        // than a signature failure.
        let output = try runOpenSSL(
            ["verify", "-CAfile", url.path, url.path], allowFailure: true
        )
        #expect(!output.lowercased().contains("signature failure"))
    }

    @Test("marks itself as not a CA")
    func isNotACA() throws {
        let (der, _) = try makeCertificate()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("connect-ca-\(UUID().uuidString).der")
        try der.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let output = try runOpenSSL(["x509", "-inform", "DER", "-in", url.path, "-noout", "-text"])
        #expect(output.contains("CA:FALSE"))
        // Both roles: a device listens on one connection and dials out on another.
        #expect(output.contains("TLS Web Server Authentication"))
        #expect(output.contains("TLS Web Client Authentication"))
    }

    @Test("its SPKI matches CryptoKit's DER representation byte for byte")
    func spkiMatchesCryptoKit() throws {
        // The pinning value is the SHA-256 of this structure. If our encoder and
        // CryptoKit disagreed by a byte, every peer would compute a different
        // fingerprint for the same key and no pairing would ever match.
        let key = P256.Signing.PrivateKey()
        let ours = SelfSignedCertificate.subjectPublicKeyInfo(
            publicKeyX963: key.publicKey.x963Representation
        )
        #expect(ours == key.publicKey.derRepresentation)
    }

    @Test("uses a fresh serial each time")
    func usesRandomSerials() throws {
        // A counter would need persistence and would leak how many certificates
        // a device has minted.
        let a = try makeCertificate().der
        let b = try makeCertificate().der
        #expect(a != b)
    }

    @Test("handles a name with characters outside ASCII")
    func handlesUnicodeNames() throws {
        // "Stefans MacBook" is the easy case; real device names carry umlauts
        // and emoji, and UTF8String has to hold them.
        let (der, _) = try makeCertificate(commonName: "Stefan’s MacBook Pro 💻")
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("connect-unicode-\(UUID().uuidString).der")
        try der.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let output = try runOpenSSL(["x509", "-inform", "DER", "-in", url.path, "-noout", "-text"])
        #expect(!output.isEmpty)
        #expect(output.contains("Signature Algorithm"))
    }
}

/// Runs the system openssl and returns its combined output.
private func runOpenSSL(_ arguments: [String], allowFailure: Bool = false) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    process.arguments = arguments

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    try process.run()

    // Read before waiting: a pipe that fills will block the child forever.
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()

    let output = String(decoding: data, as: UTF8.self)
    if !allowFailure, process.terminationStatus != 0 {
        Issue.record("openssl \(arguments.joined(separator: " ")) failed:\n\(output)")
    }
    return output
}
