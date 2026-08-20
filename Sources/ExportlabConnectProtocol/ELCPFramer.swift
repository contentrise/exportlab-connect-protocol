import Foundation

/// Reassembles ELCP frames from an arbitrarily chopped byte stream.
///
/// TCP guarantees order, not boundaries. A single `read` may deliver half a
/// header, three whole frames, or one byte — and the split points differ
/// between a Wi-Fi link, a loopback socket and a CI runner, which is exactly
/// why framers pass in testing and fail in the field. This type therefore
/// assumes nothing: `append` takes whatever arrived, and `nextFrame` returns a
/// frame only once every byte of it is present.
///
/// Not thread-safe by design; it lives inside one connection actor.
public struct ELCPFramer: Sendable {
    /// Bytes received but not yet consumed by a complete frame.
    private var buffer = Data()

    /// Parsed header awaiting its payload. Holding it across calls means a
    /// header split across two reads is parsed once, not re-parsed on every
    /// subsequent byte.
    private var pendingHeader: ELCPHeader?

    /// Guards against a peer that opens a connection and dribbles bytes to pin
    /// memory. The cap is one maximum frame plus its header — anything beyond
    /// that is not a slow link, it is an attack or a bug.
    private let maximumBufferedBytes = Int(ELCP.maxPayloadLength) + ELCP.headerSize

    public init() {}

    /// Number of unparsed bytes currently held. Exposed for tests and metrics.
    public var bufferedByteCount: Int { buffer.count }

    public mutating func append(_ bytes: Data) throws {
        guard buffer.count + bytes.count <= maximumBufferedBytes else {
            throw ELCPError.payloadTooLarge(UInt32(clamping: buffer.count + bytes.count))
        }
        buffer.append(bytes)
    }

    /// Returns the next complete frame, or `nil` if more bytes are needed.
    ///
    /// Call repeatedly after each `append` until it returns `nil` — one read can
    /// carry several frames, and stopping after the first would stall the
    /// connection until the peer happened to send more.
    public mutating func nextFrame() throws -> ELCPFrame? {
        if pendingHeader == nil {
            guard buffer.count >= ELCP.headerSize else { return nil }
            let headerBytes = buffer.prefix(ELCP.headerSize)
            // Decode before consuming: a throw here leaves the buffer intact for
            // diagnostics, and the connection is being torn down anyway.
            let header = try ELCPHeader.decode(headerBytes)
            buffer.removeFirst(ELCP.headerSize)
            pendingHeader = header
        }

        guard let header = pendingHeader else { return nil }

        let needed = Int(header.payloadLength)
        guard buffer.count >= needed else { return nil }

        let payload = needed == 0 ? Data() : Data(buffer.prefix(needed))
        buffer.removeFirst(needed)
        pendingHeader = nil

        return ELCPFrame(header: header, payload: payload)
    }

    /// Drains every frame currently available.
    public mutating func drain() throws -> [ELCPFrame] {
        var frames: [ELCPFrame] = []
        while let frame = try nextFrame() { frames.append(frame) }
        return frames
    }

    /// Discards all buffered state. Used when a connection is reset.
    public mutating func reset() {
        buffer.removeAll(keepingCapacity: false)
        pendingHeader = nil
    }
}
