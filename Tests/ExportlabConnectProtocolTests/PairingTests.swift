import Foundation
import Testing
@testable import ExportlabConnectProtocol

@Suite("Pairing code")
struct PairingCodeTests {

    private func transcript(
        initiator: String = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        responder: String = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        initiatorNonce: Data = Data(repeating: 0x01, count: 32),
        responderNonce: Data = Data(repeating: 0x02, count: 32)
    ) -> HandshakeTranscript {
        HandshakeTranscript(
            initiatorSPKISHA256: initiator,
            responderSPKISHA256: responder,
            initiatorNonce: initiatorNonce,
            responderNonce: responderNonce,
            negotiatedVersion: 1
        )
    }

    @Test("is deterministic for a given transcript")
    func isDeterministic() {
        // Both devices compute it independently and never transmit it; if the
        // derivation were not deterministic they could never agree.
        let t = transcript()
        #expect(PairingCode.code(for: t) == PairingCode.code(for: t))
    }

    @Test("always renders exactly six digits")
    func hasFixedWidth() {
        // Values below 100000 must stay zero-padded — a code that renders as
        // five digits looks broken and won't match the other screen.
        for byte in UInt8(0)...UInt8(60) {
            let t = transcript(initiatorNonce: Data(repeating: byte, count: 32))
            let code = PairingCode.code(for: t)
            #expect(code.count == PairingCode.digitCount)
            #expect(code.allSatisfy { $0.isNumber })
        }
    }

    @Test("differs when either side's key differs")
    func dependsOnBothKeys() {
        // This is the property the human check relies on: a machine-in-the-middle
        // negotiates a different transcript with each side, so the two numbers
        // diverge and the user sees the mismatch.
        let base = PairingCode.code(for: transcript())
        #expect(PairingCode.code(for: transcript(initiator: String(repeating: "c", count: 43))) != base)
        #expect(PairingCode.code(for: transcript(responder: String(repeating: "d", count: 43))) != base)
    }

    @Test("differs when either nonce differs")
    func dependsOnBothNonces() {
        let base = PairingCode.code(for: transcript())
        #expect(PairingCode.code(for: transcript(initiatorNonce: Data(repeating: 0x09, count: 32))) != base)
        #expect(PairingCode.code(for: transcript(responderNonce: Data(repeating: 0x09, count: 32))) != base)
    }

    @Test("is not symmetric between the roles")
    func isRoleOrdered() {
        // Swapping the two peers must change the code. If it did not, an
        // attacker could reflect one side's handshake back at it and have the
        // numbers agree.
        let forward = transcript()
        let swapped = HandshakeTranscript(
            initiatorSPKISHA256: forward.responderSPKISHA256,
            responderSPKISHA256: forward.initiatorSPKISHA256,
            initiatorNonce: forward.responderNonce,
            responderNonce: forward.initiatorNonce,
            negotiatedVersion: 1
        )
        #expect(PairingCode.code(for: forward) != PairingCode.code(for: swapped))
    }

    @Test("resists field-boundary shifting")
    func resistsFieldShifting() {
        // Length-prefixed fields, not concatenation. With plain concatenation
        // "ab"+"cd" and "a"+"bcd" hash identically, so an attacker could shift a
        // byte across a boundary and keep the same code.
        let a = transcript(initiator: "abc", responder: "def")
        let b = transcript(initiator: "ab", responder: "cdef")
        #expect(PairingCode.code(for: a) != PairingCode.code(for: b))
    }

    @Test("keeps the SAS domain-separated from the signing digest")
    func separatesDomains() {
        // The displayed number must never be substitutable for signed material.
        let t = transcript()
        let sasSource = PairingCode.code(for: t)
        let digestPrefix = String(t.digest().base64URLEncodedString().prefix(6))
        #expect(sasSource != digestPrefix)
    }

    @Test("binds a commitment to the device that made it")
    func commitmentBindsDevice() {
        let t = transcript()
        let mac = PairingCode.commitment(for: t, deviceID: "mac-1")
        let phone = PairingCode.commitment(for: t, deviceID: "phone-1")
        #expect(mac != phone)
        #expect(mac == PairingCode.commitment(for: t, deviceID: "mac-1"))
    }

    @Test("compares codes without a length shortcut")
    func comparesCodes() {
        #expect(PairingCode.matches("123456", "123456"))
        #expect(!PairingCode.matches("123456", "123457"))
        #expect(!PairingCode.matches("123456", "12345"))
        #expect(!PairingCode.matches("", "123456"))
    }
}

@Suite("base64url")
struct Base64URLTests {

    @Test("round-trips arbitrary bytes")
    func roundTrips() {
        for length in [0, 1, 2, 3, 31, 32, 33, 64] {
            let data = Data((0..<length).map { UInt8($0 % 251) })
            let encoded = data.base64URLEncodedString()
            #expect(Data(base64URLEncoded: encoded) == data)
        }
    }

    @Test("emits no character unsafe in a TXT record or URL")
    func usesURLSafeAlphabet() {
        // The fingerprint travels in a Bonjour TXT record and in URL paths;
        // '+', '/' and '=' are all wrong there.
        let data = Data((0...255).map { UInt8($0) })
        let encoded = data.base64URLEncodedString()
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains("/"))
        #expect(!encoded.contains("="))
    }

    @Test("produces a 43-character SHA-256 fingerprint")
    func fingerprintLength() {
        // 32 bytes unpadded base64 is 43 characters — it has to fit a TXT record.
        let fingerprint = SPKIFingerprint.compute(spkiDER: Data(repeating: 0xAB, count: 91))
        #expect(fingerprint.count == 43)
    }
}
