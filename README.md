# ExportlabConnectProtocol

Wire protocol for **Exportlab Connect** — the local-network transport between
the macOS menu-bar app and the Exportlab iOS app.

This package is consumed by both apps. It exists so the two can never disagree
about the wire format: protocol drift between two independently released apps
is the likeliest source of bad field bugs, so the definitions live in one
versioned place rather than being copied.

It deliberately contains **no networking**. Everything here is pure and
unit-testable; `NWConnection` lives in the apps behind an `ELCPChannel` seam.

## Contents

| File | Purpose |
|---|---|
| `ELCPHeader.swift` | Fixed 20-byte big-endian frame header |
| `ELCPFramer.swift` | Reassembles frames from an arbitrarily chopped byte stream |
| `Messages.swift` | JSON payloads for handshake, transfer and live preview |
| `PairingCode.swift` | Handshake transcript + six-digit short authentication string |
| `SafeFilename.swift` | Sanitises peer-supplied filenames before they touch a filesystem |
| `ELCPError.swift` | Error taxonomy with stable wire codes |

## Wire format

```
 0        4    5     6        8               16          20
 +--------+----+-----+--------+---------------+-----------+
 | "ELCP" | ver| kind| flags  |   streamID    | payloadLen|  payload...
 +--------+----+-----+--------+---------------+-----------+
```

Big-endian throughout. `streamID` multiplexes concurrent logical operations:
AVFoundation routinely requests the moov atom at a file's tail while streaming
from its head, so several ranges are in flight at once.

## Compatibility rules

- **Never renumber** an existing `ELCPFrameKind` or `ELCPError.code` — only append.
- An unknown frame kind must produce an `error` frame, never a connection close,
  so a newer peer degrades gracefully against an older one.
- Frames stay small (≤ 8 MiB). A cancel can only take effect between frames, so
  a large frame is a large cancel latency during scrubbing.

## Testing

```sh
swift test
```

The framer is property-tested against 200 randomised stream fragmentations.
TCP guarantees order, not boundaries, and split points differ between Wi-Fi,
loopback and CI — a framer that assumes any boundary passes in testing and
fails in the field.
