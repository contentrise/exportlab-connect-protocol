import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Builds a PKCS#12 blob so a `SecIdentity` can be created without touching
/// the keychain.
///
/// `SecIdentityCreate` is not public API, and the documented alternative —
/// adding a key and a certificate to the keychain and letting it pair them —
/// requires a keychain-access entitlement backed by a provisioning profile.
/// An unsigned binary gets `errSecMissingEntitlement` (-34018), which would
/// make the entire TLS path untestable outside a signed app bundle.
///
/// `SecPKCS12Import` has no such requirement: it takes bytes and returns an
/// identity. So the identity is assembled in memory and imported, which also
/// means throwaway identities leave nothing behind on the machine.
///
/// Only the subset needed for one key and one certificate is implemented, with
/// the encryption PKCS#12 mandates.
/// Builds a PKCS#12 blob so a `SecIdentity` can be created without the keychain.
///
/// Lives in the shared package rather than in each app: both sides derive their
/// TLS identity this way, and the SPKI these bytes describe is what the other
/// end pins on. Two copies would be two chances to diverge.
public enum PKCS12 {

    private enum OID {
        static let data = "1.2.840.113549.1.7.1"
        static let encryptedData = "1.2.840.113549.1.7.6"
        static let keyBag = "1.2.840.113549.1.12.10.1.1"
        static let pkcs8ShroudedKeyBag = "1.2.840.113549.1.12.10.1.2"
        static let certBag = "1.2.840.113549.1.12.10.1.3"
        static let x509Certificate = "1.2.840.113549.1.9.22.1"
        static let localKeyID = "1.2.840.113549.1.9.21"
        static let pbeWithSHA1And3KeyTripleDESCBC = "1.2.840.113549.1.12.1.3"
        static let pbeWithSHA1And40BitRC2CBC = "1.2.840.113549.1.12.1.6"
        static let ecPublicKey = "1.2.840.10045.2.1"
        static let prime256v1 = "1.2.840.10045.3.1.7"
        static let sha1 = "1.3.14.3.2.26"
    }

    /// Assembles a PKCS#12 blob containing one P-256 key and its certificate.
    public static func make(
        privateKeyX963: Data,
        certificateDER: Data,
        password: String
    ) throws -> Data {
        let salt = randomBytes(8)
        let macSalt = randomBytes(8)
        let iterations = 2048

        // The key is wrapped as PKCS#8 PrivateKeyInfo, then encrypted in place
        // as a *shrouded* key bag inside a plain data content-info.
        //
        // This asymmetry is the whole trick. Wrapping the key bag in
        // pkcs7-encryptedData instead — the obvious symmetry with the
        // certificates — parses correctly everywhere, and openssl will happily
        // list both halves, but SecPKCS12Import then returns only "chain" and
        // no identity. Security looks for the private key specifically in a
        // shrouded key bag, and finds nothing.
        let pkcs8 = pkcs8PrivateKey(x963: privateKeyX963)
        let shroudedKey = try encrypt(pkcs8, password: password, salt: salt, iterations: iterations)

        // Both bags carry the same localKeyID, which is how the import pairs
        // the key with its certificate.
        let localKeyID = randomBytes(20)
        let keyIDAttribute = DER.sequence([
            DER.objectIdentifier(OID.localKeyID),
            DER.set([DER.octetString(localKeyID)]),
        ])

        let keyBagContent = DER.sequence([
            DER.objectIdentifier(OID.pkcs8ShroudedKeyBag),
            DER.contextConstructed(0, DER.sequence([
                DER.sequence([
                    DER.objectIdentifier(OID.pbeWithSHA1And3KeyTripleDESCBC),
                    DER.sequence([DER.octetString(salt), DER.integer(iterations)]),
                ]),
                DER.octetString(shroudedKey),
            ])),
            DER.set([keyIDAttribute]),
        ])
        let keyBags = DER.sequence([keyBagContent])

        let certBagContent = DER.sequence([
            DER.objectIdentifier(OID.certBag),
            DER.contextConstructed(0, DER.sequence([
                DER.objectIdentifier(OID.x509Certificate),
                DER.contextConstructed(0, DER.octetString(certificateDER)),
            ])),
            DER.set([keyIDAttribute]),
        ])
        let certBags = DER.sequence([certBagContent])

        // Certificates go in an encrypted content-info; the key bag rides in a
        // plain one because it is already shrouded.
        let encryptedCerts = try encrypt(
            certBags, password: password, salt: macSalt, iterations: iterations
        )

        let authSafe = DER.sequence([
            // Plain data content-info holding the shrouded key bag.
            DER.sequence([
                DER.objectIdentifier(OID.data),
                DER.contextConstructed(0, DER.octetString(keyBags)),
            ]),
            contentInfo(encrypted: encryptedCerts, salt: macSalt, iterations: iterations),
        ])
        let authSafeData = DER.octetString(authSafe)

        let macKey = pkcs12KDF(password: password, salt: macSalt, iterations: iterations, id: 3, length: 20)
        let mac = hmacSHA1(key: macKey, message: authSafe)

        return DER.sequence([
            DER.integer(3),
            DER.sequence([
                DER.objectIdentifier(OID.data),
                DER.contextConstructed(0, authSafeData),
            ]),
            DER.sequence([
                DER.sequence([
                    DER.sequence([DER.objectIdentifier(OID.sha1), DER.null()]),
                    DER.octetString(mac),
                ]),
                DER.octetString(macSalt),
                DER.integer(iterations),
            ]),
        ])
    }

    /// Imports the blob and returns the identity it contains.
    public static func identity(from blob: Data, password: String) throws -> SecIdentity {
        var items: CFArray?
        // Memory only. Without this SecPKCS12Import writes the private key into
        // the login keychain, where it lands as another "Imported Private Key"
        // on every launch — 942 of them accumulated during development — and
        // macOS then raises an authorisation prompt every time one is used to
        // sign. The identity is needed for the length of a TLS session and has
        // no business outliving the process.
        let status = SecPKCS12Import(
            blob as CFData,
            [
                kSecImportExportPassphrase as String: password,
                kSecImportToMemoryOnly as String: true,
            ] as CFDictionary,
            &items
        )
        guard status == errSecSuccess,
              let array = items as? [[String: Any]],
              let identity = array.first?[kSecImportItemIdentity as String]
        else {
            throw NSError(
                domain: NSOSStatusErrorDomain, code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "SecPKCS12Import failed: \(status)"]
            )
        }
        return identity as! SecIdentity
    }

    // MARK: - Structure

    private static func contentInfo(encrypted: Data, salt: Data, iterations: Int) -> Data {
        DER.sequence([
            DER.objectIdentifier(OID.encryptedData),
            DER.contextConstructed(0, DER.sequence([
                DER.integer(0),
                DER.sequence([
                    DER.objectIdentifier(OID.data),
                    DER.sequence([
                        DER.objectIdentifier(OID.pbeWithSHA1And3KeyTripleDESCBC),
                        DER.sequence([DER.octetString(salt), DER.integer(iterations)]),
                    ]),
                    // [0] IMPLICIT: the encrypted bytes carry a context tag
                    // rather than an OCTET STRING tag.
                    DER.encode(0x80, encrypted),
                ]),
            ])),
        ])
    }

    /// Wraps a raw X9.63 key as PKCS#8 PrivateKeyInfo.
    private static func pkcs8PrivateKey(x963: Data) -> Data {
        // X9.63 for a private key is 0x04 || X || Y || D, so the scalar is the
        // final third.
        let fieldSize = 32
        let scalar = x963.suffix(fieldSize)
        let publicPoint = x963.prefix(1 + fieldSize * 2)

        let ecPrivateKey = DER.sequence([
            DER.integer(1),
            DER.octetString(Data(scalar)),
            DER.contextConstructed(1, DER.bitString(Data(publicPoint))),
        ])

        return DER.sequence([
            DER.integer(0),
            DER.sequence([
                DER.objectIdentifier(OID.ecPublicKey),
                DER.objectIdentifier(OID.prime256v1),
            ]),
            DER.octetString(ecPrivateKey),
        ])
    }

    // MARK: - PBES1 with 3DES

    private static func encrypt(
        _ plaintext: Data, password: String, salt: Data, iterations: Int
    ) throws -> Data {
        let key = pkcs12KDF(password: password, salt: salt, iterations: iterations, id: 1, length: 24)
        let iv = pkcs12KDF(password: password, salt: salt, iterations: iterations, id: 2, length: 8)
        return try tripleDESCBC(plaintext: pad(plaintext, blockSize: 8), key: key, iv: iv)
    }

    private static func pad(_ data: Data, blockSize: Int) -> Data {
        // PKCS#7: always pads, even when already aligned, so the last byte is
        // unambiguously a pad count.
        let padding = blockSize - (data.count % blockSize)
        return data + Data(repeating: UInt8(padding), count: padding)
    }

    private static func tripleDESCBC(plaintext: Data, key: Data, iv: Data) throws -> Data {
        // Capacity read before the buffer is borrowed: reading `out.count`
        // inside the closure overlaps with its own mutable access.
        let capacity = plaintext.count + 8
        var out = Data(count: capacity)
        var moved = 0

        let status = out.withUnsafeMutableBytes { outBuffer in
            plaintext.withUnsafeBytes { inBuffer in
                key.withUnsafeBytes { keyBuffer in
                    iv.withUnsafeBytes { ivBuffer in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithm3DES),
                            CCOptions(0),  // padding already applied above
                            keyBuffer.baseAddress, key.count,
                            ivBuffer.baseAddress,
                            inBuffer.baseAddress, plaintext.count,
                            outBuffer.baseAddress, capacity,
                            &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw NSError(domain: "PKCS12", code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "3DES failed: \(status)"])
        }
        out.removeSubrange(moved...)
        return out
    }

    /// The key derivation from PKCS#12 appendix B.
    ///
    /// Not PBKDF2 — PKCS#12 predates it and defines its own scheme, with the
    /// password as big-endian UTF-16 terminated by two zero bytes. Using PBKDF2
    /// here produces a blob that imports nowhere.
    private static func pkcs12KDF(
        password: String, salt: Data, iterations: Int, id: UInt8, length: Int
    ) -> Data {
        var passwordBytes = Data()
        for unit in password.utf16 {
            passwordBytes.append(UInt8(unit >> 8))
            passwordBytes.append(UInt8(unit & 0xFF))
        }
        passwordBytes.append(contentsOf: [0x00, 0x00])

        let blockSize = 64
        let diversifier = Data(repeating: id, count: blockSize)

        func fill(_ source: Data) -> Data {
            guard !source.isEmpty else { return Data() }
            var out = Data()
            while out.count < ((source.count + blockSize - 1) / blockSize) * blockSize {
                out.append(source)
            }
            return out.prefix(((source.count + blockSize - 1) / blockSize) * blockSize)
        }

        let saltBlock = fill(salt)
        let passwordBlock = fill(passwordBytes)
        var combined = saltBlock + passwordBlock

        var output = Data()
        while output.count < length {
            var digest = Data(Insecure.SHA1.hash(data: diversifier + combined))
            for _ in 1..<iterations {
                digest = Data(Insecure.SHA1.hash(data: digest))
            }
            output.append(digest)
            guard output.count < length else { break }

            // Adjust the combined block by adding B+1, per the specification.
            var b = Data()
            while b.count < blockSize { b.append(digest) }
            b = b.prefix(blockSize)

            var adjusted = Data()
            for chunkStart in stride(from: 0, to: combined.count, by: blockSize) {
                let chunk = Array(combined[chunkStart..<min(chunkStart + blockSize, combined.count)])
                var carry = 1
                var result = [UInt8](repeating: 0, count: chunk.count)
                for index in stride(from: chunk.count - 1, through: 0, by: -1) {
                    let sum = Int(chunk[index]) + Int(b[index]) + carry
                    result[index] = UInt8(sum & 0xFF)
                    carry = sum >> 8
                }
                adjusted.append(contentsOf: result)
            }
            combined = adjusted
        }
        return output.prefix(length)
    }

    private static func hmacSHA1(key: Data, message: Data) -> Data {
        let symmetric = SymmetricKey(data: key)
        return Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetric))
    }

    private static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
}
