import CryptoKit
import Foundation
import Security

/// Builds the self-signed X.509 certificate that carries a device's identity
/// key into TLS.
///
/// The certificate is not a trust statement — nobody signs it and no CA is
/// involved. It is a container: TLS needs a certificate, and we need the
/// connection bound to a key we can pin. Verification is entirely our own
/// (`PeerPinning`), comparing the SPKI hash to a value the backend vouched for.
///
/// A Secure Enclave key cannot be exported, so the signature must be produced
/// by the enclave over the TBS bytes rather than by assembling it locally.
public enum SelfSignedCertificate {

    /// OIDs used below. Spelled out rather than inlined so a typo is visible.
    private enum OID {
        static let ecPublicKey = "1.2.840.10045.2.1"
        static let prime256v1 = "1.2.840.10045.3.1.7"
        static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
        static let commonName = "2.5.4.3"
        static let organization = "2.5.4.10"
        static let basicConstraints = "2.5.29.19"
        static let keyUsage = "2.5.29.15"
        static let extendedKeyUsage = "2.5.29.37"
        static let subjectAltName = "2.5.29.17"
        static let serverAuth = "1.3.6.1.5.5.7.3.1"
        static let clientAuth = "1.3.6.1.5.5.7.3.2"
    }

    /// Signs the certificate's to-be-signed bytes.
    ///
    /// Implemented by the enclave-backed identity in the app and by a software
    /// key in tests, so the DER assembly under test is the code that ships.
    public typealias Signer = @Sendable (Data) throws -> Data

    /// Assembles a self-signed certificate for `publicKeyX963`.
    ///
    /// - Parameters:
    ///   - publicKeyX963: the uncompressed P-256 point (65 bytes, 0x04-prefixed)
    ///   - commonName: shown in diagnostics only; identity comes from the key
    ///   - validity: kept long, because a device that stops being able to
    ///     connect because its certificate expired would look like a bug and be
    ///     impossible for a user to diagnose
    ///   - sign: produces an ECDSA-SHA256 signature in DER form
    public static func make(
        publicKeyX963: Data,
        commonName: String,
        organization: String = "Exportlab Connect",
        serialNumber: Data? = nil,
        notBefore: Date = Date().addingTimeInterval(-3600),
        validity: TimeInterval = 60 * 60 * 24 * 365 * 10,
        sign: Signer
    ) throws -> Data {
        let spki = subjectPublicKeyInfo(publicKeyX963: publicKeyX963)

        // A random serial, not a counter: a counter would need persistence and
        // would leak how many certificates a device has minted.
        let serial = serialNumber ?? randomSerial()

        let name = DER.sequence([
            DER.set([DER.sequence([
                DER.objectIdentifier(OID.organization),
                DER.utf8String(organization),
            ])]),
            DER.set([DER.sequence([
                DER.objectIdentifier(OID.commonName),
                DER.utf8String(commonName),
            ])]),
        ])

        let algorithm = DER.sequence([DER.objectIdentifier(OID.ecdsaWithSHA256)])

        let tbs = DER.sequence([
            // [0] EXPLICIT version, v3 (value 2). Required for extensions.
            DER.contextConstructed(0, DER.integer(2)),
            DER.integer(serial),
            algorithm,
            name,  // issuer == subject: this is what "self-signed" means
            DER.sequence([DER.time(notBefore), DER.time(notBefore.addingTimeInterval(validity))]),
            name,
            spki,
            DER.contextConstructed(3, extensions(commonName: commonName, spki: spki)),
        ])

        let signature = try sign(tbs)

        return DER.sequence([
            tbs,
            algorithm,
            DER.bitString(signature),
        ])
    }

    /// The DER SubjectPublicKeyInfo — the structure whose SHA-256 is the
    /// pinning value, so it must be byte-identical to what `SPKIFingerprint`
    /// hashes elsewhere.
    public static func subjectPublicKeyInfo(publicKeyX963: Data) -> Data {
        DER.sequence([
            DER.sequence([
                DER.objectIdentifier(OID.ecPublicKey),
                DER.objectIdentifier(OID.prime256v1),
            ]),
            DER.bitString(publicKeyX963),
        ])
    }

    private static func extensions(commonName: String, spki: Data) -> Data {
        func ext(_ oid: String, critical: Bool, _ value: Data) -> Data {
            var parts = [DER.objectIdentifier(oid)]
            // DEFAULT FALSE: DER forbids encoding a value equal to the default.
            if critical { parts.append(DER.boolean(true)) }
            parts.append(DER.octetString(value))
            return DER.sequence(parts)
        }

        return DER.sequence([
            // Not a CA. Marked critical so a parser cannot ignore it.
            ext(OID.basicConstraints, critical: true, DER.sequence([])),

            // digitalSignature | keyEncipherment. Three unused trailing bits.
            ext(OID.keyUsage, critical: true, DER.encode(.bitString, Data([0x05, 0xA0]))),

            // Both roles: a device listens on one connection and dials out on
            // another, so it is server and client depending on direction.
            ext(OID.extendedKeyUsage, critical: false, DER.sequence([
                DER.objectIdentifier(OID.serverAuth),
                DER.objectIdentifier(OID.clientAuth),
            ])),

            // dNSName. Present because some TLS stacks refuse a certificate
            // without a SAN outright, regardless of custom verification.
            ext(OID.subjectAltName, critical: false, DER.sequence([
                DER.contextPrimitive(2, Data(commonName.utf8)),
            ])),
        ])
    }

    private static func randomSerial() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        // Clear the high bit so the INTEGER is unambiguously positive.
        bytes[0] &= 0x7F
        return Data(bytes)
    }
}
