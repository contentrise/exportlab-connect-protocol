import Foundation
import Testing
@testable import ExportlabConnectProtocol

@Suite("Header encoding")
struct ELCPHeaderTests {

    @Test("round-trips every frame kind")
    func roundTripsAllKinds() throws {
        for kind in ELCPFrameKind.allCases {
            let header = ELCPHeader(
                kind: kind,
                flags: .endOfMessage,
                streamID: 0xDEAD_BEEF_CAFE_F00D,
                payloadLength: 4096
            )
            let decoded = try ELCPHeader.decode(header.encode())
            #expect(decoded == header)
        }
    }

    @Test("encodes to exactly the declared header size")
    func encodesFixedSize() {
        let header = ELCPHeader(kind: .ping, payloadLength: 0)
        #expect(header.encode().count == ELCP.headerSize)
    }

    @Test("is big-endian on the wire")
    func isBigEndian() {
        let bytes = ELCPHeader(kind: .ping, streamID: 1, payloadLength: 258).encode()
        #expect(Array(bytes[0..<4]) == [0x45, 0x4C, 0x43, 0x50])  // "ELCP"
        #expect(bytes[4] == ELCP.version)
        #expect(bytes[5] == ELCPFrameKind.ping.rawValue)
        // streamID occupies bytes 8..<16, most significant byte first.
        #expect(Array(bytes[8..<16]) == [0, 0, 0, 0, 0, 0, 0, 1])
        // 258 == 0x0102
        #expect(Array(bytes[16..<20]) == [0, 0, 0x01, 0x02])
    }

    @Test("decodes from a non-zero-based slice")
    func decodesFromSlice() throws {
        // Data slices keep their parent's indices. Indexing from 0 instead of
        // startIndex is the bug this guards: it works in every test that builds
        // Data fresh, and crashes the moment a real buffer is sliced.
        let header = ELCPHeader(kind: .chunk, streamID: 7, payloadLength: 99)
        var padded = Data([0xFF, 0xFF, 0xFF])
        padded.append(header.encode())
        let decoded = try ELCPHeader.decode(padded.dropFirst(3))
        #expect(decoded == header)
    }

    @Test("rejects a bad magic")
    func rejectsBadMagic() {
        var bytes = ELCPHeader(kind: .ping, payloadLength: 0).encode()
        bytes[0] = 0x00
        #expect(throws: ELCPError.self) { try ELCPHeader.decode(bytes) }
    }

    @Test("rejects an unsupported version")
    func rejectsBadVersion() {
        var bytes = ELCPHeader(kind: .ping, payloadLength: 0).encode()
        bytes[4] = 99
        #expect(throws: ELCPError.self) { try ELCPHeader.decode(bytes) }
    }

    @Test("rejects an unknown frame kind rather than trapping")
    func rejectsUnknownKind() {
        var bytes = ELCPHeader(kind: .ping, payloadLength: 0).encode()
        bytes[5] = 200
        #expect(throws: ELCPError.self) { try ELCPHeader.decode(bytes) }
    }

    @Test("rejects an oversized declared payload")
    func rejectsOversizedPayload() {
        let header = ELCPHeader(kind: .chunk, payloadLength: ELCP.maxPayloadLength + 1)
        #expect(throws: ELCPError.self) { try ELCPHeader.decode(header.encode()) }
    }

    @Test("rejects a truncated header at every length")
    func rejectsTruncated() {
        let full = ELCPHeader(kind: .ping, payloadLength: 0).encode()
        for length in 0..<ELCP.headerSize {
            #expect(throws: ELCPError.self) { try ELCPHeader.decode(full.prefix(length)) }
        }
    }
}

@Suite("Framer")
struct ELCPFramerTests {

    private func sampleFrames() -> [ELCPFrame] {
        [
            ELCPFrame(kind: .ping, streamID: 1),
            ELCPFrame(kind: .chunk, streamID: 2, payload: Data(repeating: 0xAB, count: 5000)),
            ELCPFrame(kind: .hello, streamID: 3, payload: Data("hello".utf8)),
            ELCPFrame(kind: .rangeData, streamID: 4, payload: Data(repeating: 0x11, count: 1)),
            ELCPFrame(kind: .pong, streamID: 5),
        ]
    }

    @Test("reads frames delivered whole")
    func readsWholeFrames() throws {
        var framer = ELCPFramer()
        let frames = sampleFrames()
        for frame in frames { try framer.append(frame.encode()) }
        #expect(try framer.drain() == frames)
    }

    @Test("reads several frames arriving in one read")
    func readsCoalescedFrames() throws {
        var framer = ELCPFramer()
        let frames = sampleFrames()
        var blob = Data()
        for frame in frames { blob.append(frame.encode()) }
        try framer.append(blob)

        // Draining must yield all of them. Returning only the first would stall
        // the connection until the peer happened to send more bytes.
        #expect(try framer.drain() == frames)
    }

    @Test("reassembles a stream delivered one byte at a time")
    func readsByteAtATime() throws {
        var framer = ELCPFramer()
        let frames = sampleFrames()
        var blob = Data()
        for frame in frames { blob.append(frame.encode()) }

        var received: [ELCPFrame] = []
        for byte in blob {
            try framer.append(Data([byte]))
            received.append(contentsOf: try framer.drain())
        }
        #expect(received == frames)
    }

    @Test("reassembles across 200 random split patterns", arguments: 0..<200)
    func readsArbitrarySplits(seed: Int) throws {
        // Split points differ between Wi-Fi, loopback and a CI runner. A framer
        // that assumes any boundary passes in testing and fails in the field, so
        // the split pattern is randomised rather than hand-picked.
        var rng = SplitMix64(seed: UInt64(seed))
        let frames = sampleFrames()
        var blob = Data()
        for frame in frames { blob.append(frame.encode()) }

        var framer = ELCPFramer()
        var received: [ELCPFrame] = []
        var cursor = blob.startIndex

        while cursor < blob.endIndex {
            let remaining = blob.distance(from: cursor, to: blob.endIndex)
            let take = Int(rng.next() % UInt64(min(remaining, 300))) + 1
            let end = blob.index(cursor, offsetBy: take)
            try framer.append(Data(blob[cursor..<end]))
            received.append(contentsOf: try framer.drain())
            cursor = end
        }

        #expect(received == frames, "split seed \(seed)")
    }

    @Test("holds a header split across two reads without re-parsing it")
    func handlesSplitHeader() throws {
        var framer = ELCPFramer()
        let frame = ELCPFrame(kind: .chunk, streamID: 9, payload: Data(repeating: 7, count: 64))
        let bytes = frame.encode()

        try framer.append(bytes.prefix(11))          // mid-header
        #expect(try framer.nextFrame() == nil)
        try framer.append(bytes.dropFirst(11).prefix(5))  // header complete, payload short
        #expect(try framer.nextFrame() == nil)
        try framer.append(bytes.dropFirst(16))
        #expect(try framer.nextFrame() == frame)
    }

    @Test("returns nil rather than a partial frame when the payload is short")
    func withholdsIncompletePayload() throws {
        var framer = ELCPFramer()
        let frame = ELCPFrame(kind: .chunk, payload: Data(repeating: 1, count: 1000))
        try framer.append(frame.encode().dropLast(1))
        #expect(try framer.nextFrame() == nil)
        #expect(framer.bufferedByteCount > 0)
    }

    @Test("handles a zero-length payload")
    func handlesEmptyPayload() throws {
        var framer = ELCPFramer()
        let frame = ELCPFrame(kind: .ping)
        try framer.append(frame.encode())
        let decoded = try framer.nextFrame()
        #expect(decoded == frame)
        #expect(decoded?.payload.isEmpty == true)
        #expect(framer.bufferedByteCount == 0)
    }

    @Test("surfaces a framing fault instead of resynchronising")
    func throwsOnGarbage() throws {
        var framer = ELCPFramer()
        try framer.append(Data(repeating: 0x00, count: ELCP.headerSize))
        // There is no way to find the next real header in a corrupt stream —
        // guessing would be worse than closing the connection.
        #expect(throws: ELCPError.self) { try framer.nextFrame() }
    }

    @Test("refuses to buffer beyond one maximum frame")
    func boundsBufferedBytes() throws {
        var framer = ELCPFramer()
        // A peer that opens a connection and dribbles bytes must not be able to
        // pin unbounded memory.
        let oversized = Data(repeating: 0, count: Int(ELCP.maxPayloadLength) + ELCP.headerSize + 1)
        #expect(throws: ELCPError.self) { try framer.append(oversized) }
    }

    @Test("reset discards partial state")
    func resetDiscards() throws {
        var framer = ELCPFramer()
        try framer.append(ELCPFrame(kind: .chunk, payload: Data([1, 2, 3])).encode().prefix(15))
        framer.reset()
        #expect(framer.bufferedByteCount == 0)

        let frame = ELCPFrame(kind: .ping)
        try framer.append(frame.encode())
        #expect(try framer.nextFrame() == frame)
    }
}

/// Small deterministic PRNG so a failing split pattern is reproducible from its
/// seed alone.
struct SplitMix64 {
    private var state: UInt64
    init(seed: UInt64) { state = seed &+ 0x9E37_79B9_7F4A_7C15 }

    mutating func next() -> UInt64 {
        state = state &+ 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
