import Foundation
import Testing
@testable import ExportlabConnectProtocol

@Suite("Message coding")
struct MessageCodingTests {

    @Test("round-trips a hello through a frame")
    func roundTripsHello() throws {
        let hello = HelloMessage(
            role: .initiator,
            deviceID: "phone-1",
            deviceName: "Stefan's iPhone",
            platform: .iOS,
            osVersion: "26.3",
            appVersion: "1.0.0",
            spkiSHA256: String(repeating: "a", count: 43),
            capabilities: [.livePreview, .resume]
        )
        let frame = try ELCPFrame.json(.hello, hello)
        let decoded = try frame.decode(HelloMessage.self, expecting: .hello)

        #expect(decoded.deviceID == hello.deviceID)
        #expect(decoded.deviceName == hello.deviceName)
        #expect(decoded.capabilities == hello.capabilities)
        #expect(decoded.platform == .iOS)
    }

    @Test("round-trips a file descriptor including binary fields")
    func roundTripsFileDescriptor() throws {
        let file = FileDescriptor(
            fileID: "f1",
            name: "final_grade_v7.mov",
            byteCount: 12_884_901_888,  // 12 GiB — must not overflow
            utType: "com.apple.quicktime-movie",
            sha256: Data(repeating: 0xAB, count: 32),
            pixelWidth: 3840,
            pixelHeight: 2160,
            durationSeconds: 212.5,
            colorSpaceName: "Display P3",
            playability: .needsTranscode,
            thumbnailJPEG: Data(repeating: 0xFF, count: 128)
        )
        let frame = try ELCPFrame.json(.offer, OfferMessage(offerID: "o1", files: [file]))
        let decoded = try frame.decode(OfferMessage.self, expecting: .offer)

        #expect(decoded.files.first == file)
        #expect(decoded.files.first?.byteCount == 12_884_901_888)
        #expect(decoded.files.first?.playability == .needsTranscode)
    }

    @Test("carries the initiator nonce in the hello")
    func helloCarriesNonce() throws {
        // The responder needs the initiator's nonce before it can derive the
        // pairing code it has to display. Moving it to a later frame would let
        // the two sides build different transcripts and show different numbers.
        let nonce = Data(repeating: 0x5A, count: 32)
        let hello = HelloMessage(
            role: .initiator,
            deviceID: "phone-1",
            deviceName: "iPhone",
            platform: .iOS,
            osVersion: "26.3",
            appVersion: "1.0.0",
            spkiSHA256: String(repeating: "a", count: 43),
            capabilities: [],
            nonce: nonce
        )
        let frame = try ELCPFrame.json(.hello, hello)
        #expect(try frame.decode(HelloMessage.self, expecting: .hello).nonce == nonce)
    }

    @Test("rejects a payload decoded as the wrong kind")
    func rejectsKindMismatch() throws {
        let frame = try ELCPFrame.json(.ping, CancelMessage())
        #expect(throws: ELCPError.self) {
            try frame.decode(HelloMessage.self, expecting: .hello)
        }
    }

    @Test("reports malformed payloads without leaking parser detail")
    func rejectsMalformedPayload() {
        let frame = ELCPFrame(kind: .hello, payload: Data("{\"nope\":1}".utf8))
        #expect(throws: ELCPError.self) {
            try frame.decode(HelloMessage.self, expecting: .hello)
        }
        // A decoder's "keyNotFound(deviceID)" tells a prober exactly which field
        // to forge next, so only the type name is surfaced.
        do {
            _ = try frame.decode(HelloMessage.self, expecting: .hello)
        } catch let error as ELCPError {
            guard case .malformedPayload(let detail) = error else {
                Issue.record("expected malformedPayload, got \(error)")
                return
            }
            #expect(!detail.contains("deviceID"))
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    @Test("encodes deterministically")
    func encodesDeterministically() throws {
        // Sorted keys: the handshake transcript is hashed, so two encodings of
        // the same value must be byte-identical.
        let flow = FlowMessage(fileID: "f1", consumedBytes: 4_194_304)
        #expect(try ELCPCoding.encode(flow) == ELCPCoding.encode(flow))
    }

    @Test("derives payload length from the payload")
    func derivesPayloadLength() throws {
        let frame = try ELCPFrame.json(.offer, OfferMessage(offerID: "o1", files: []))
        #expect(frame.header.payloadLength == UInt32(frame.payload.count))
    }

    @Test("marks only media frames as binary")
    func classifiesBinaryFrames() {
        // Chunk and range data carry media on the hot path and must not pay for
        // JSON encoding or base64 inflation.
        #expect(ELCPFrameKind.chunk.hasBinaryPayload)
        #expect(ELCPFrameKind.rangeData.hasBinaryPayload)
        #expect(!ELCPFrameKind.hello.hasBinaryPayload)
        #expect(!ELCPFrameKind.offer.hasBinaryPayload)
    }

    @Test("survives a full frame round-trip through the framer")
    func survivesFramerRoundTrip() throws {
        let current = CurrentFileMessage(
            sessionID: "s1",
            file: FileDescriptor(
                fileID: "f1",
                name: "a.mov",
                byteCount: 1024,
                utType: "public.mpeg-4",
                sha256: Data(repeating: 1, count: 32)
            ),
            posterJPEG: Data(repeating: 0x7F, count: 4096),
            transcodeProgress: 0.42
        )
        let sent = try ELCPFrame.json(.currentFile, current, streamID: 3)

        var framer = ELCPFramer()
        try framer.append(sent.encode())
        let received = try #require(try framer.nextFrame())

        #expect(received.header.streamID == 3)
        let decoded = try received.decode(CurrentFileMessage.self, expecting: .currentFile)
        #expect(decoded.transcodeProgress == 0.42)
        #expect(decoded.posterJPEG?.count == 4096)
    }
}

@Suite("Error taxonomy")
struct ELCPErrorTests {

    @Test("assigns a unique code to every case")
    func codesAreUnique() {
        // Codes cross the network; a collision would make two different faults
        // indistinguishable in the field.
        let all: [ELCPError] = [
            .truncatedHeader(got: 0), .badMagic(0), .unsupportedVersion(0),
            .unknownFrameKind(0), .payloadTooLarge(0), .handshakeTimeout,
            .versionNegotiationFailed(peerVersion: 0), .authenticationFailed,
            .notPaired, .pairingRejected, .pairingExpired, .unknownStream(0),
            .integrityMismatch(itemID: ""), .fileVanished, .rejectedByPeer(reason: ""),
            .cancelled, .flowViolation, .rangeOutOfBounds, .previewUnavailable,
            .peerClosed, .malformedPayload(""), .internalFailure(""),
        ]
        #expect(Set(all.map(\.code)).count == all.count)
    }

    @Test("treats framing faults as fatal and stream faults as recoverable")
    func classifiesFatality() {
        // A corrupt byte stream has no recoverable next header. A vanished file
        // affects one stream and leaves the connection perfectly usable.
        #expect(ELCPError.badMagic(0).isFatal)
        #expect(ELCPError.authenticationFailed.isFatal)
        #expect(ELCPError.flowViolation.isFatal)
        #expect(!ELCPError.fileVanished.isFatal)
        #expect(!ELCPError.cancelled.isFatal)
        #expect(!ELCPError.rangeOutOfBounds.isFatal)
    }

    @Test("carries code and fatality into the wire message")
    func buildsWireMessage() {
        let message = ErrorMessage(.integrityMismatch(itemID: "f1"), message: "checksum mismatch")
        #expect(message.code == 1201)
        #expect(!message.isFatal)
    }
}
