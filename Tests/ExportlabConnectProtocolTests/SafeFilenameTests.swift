import Foundation
import Testing
@testable import ExportlabConnectProtocol

@Suite("Filename sanitisation")
struct SafeFilenameTests {

    @Test("leaves an ordinary name untouched", arguments: [
        "final_grade_v7.mov",
        "campaign-header-v4.jpg",
        "Bildschirmfoto 2026-08-20 um 14.32.11.png",
        "写真.heic",
        "photo 📸.jpg",
    ])
    func preservesOrdinaryNames(name: String) {
        #expect(SafeFilename.sanitize(name) == name)
    }

    @Test("defeats path traversal", arguments: [
        "../../Library/Preferences/com.apple.Terminal.plist",
        "../../../etc/passwd",
        "..\\..\\Windows\\System32\\config",
        "/etc/shadow",
        "foo/../../bar.jpg",
        "....//....//evil.sh",
    ])
    func defeatsTraversal(hostile: String) {
        let safe = SafeFilename.sanitize(hostile)
        // The result must be a single component that cannot escape anywhere.
        #expect(!safe.contains("/"))
        #expect(!safe.contains("\\"))
        #expect(safe != "..")
        #expect(safe != ".")
        #expect(!safe.isEmpty)
        #expect((safe as NSString).pathComponents.count == 1)
    }

    @Test("keeps the basename when traversal is stripped")
    func keepsBasename() {
        #expect(SafeFilename.sanitize("../../etc/passwd") == "passwd")
        #expect(SafeFilename.sanitize("a/b/c/photo.jpg") == "photo.jpg")
    }

    @Test("strips NUL and control characters")
    func stripsControlCharacters() {
        let safe = SafeFilename.sanitize("photo\u{0}.jpg")
        // A NUL truncates C strings: the layer that validates and the layer that
        // opens can otherwise disagree about where the name ends.
        #expect(!safe.unicodeScalars.contains { $0.value == 0 })
        #expect(safe == "photo.jpg")
        #expect(SafeFilename.sanitize("a\nb\tc.jpg") == "abc.jpg")
    }

    @Test("strips bidirectional overrides")
    func stripsBidiOverrides() {
        // "photo\u{202E}gpj.exe" renders as "photo exe.jpg" — the user believes
        // they are opening an image.
        let safe = SafeFilename.sanitize("photo\u{202E}gpj.exe")
        #expect(!safe.unicodeScalars.contains { (0x202A...0x202E).contains($0.value) })
    }

    @Test("strips the HFS+ path separator")
    func stripsColon() {
        #expect(!SafeFilename.sanitize("a:b.jpg").contains(":"))
    }

    @Test("unhides a dotfile")
    func unhidesDotfiles() {
        // A file the user explicitly chose to receive should not arrive invisible.
        let safe = SafeFilename.sanitize(".hidden.jpg")
        #expect(!safe.hasPrefix("."))
        #expect(safe == "hidden.jpg")
    }

    @Test("falls back when nothing survives", arguments: ["", ".", "..", "   ", "\u{0}\u{0}", "/"])
    func fallsBack(degenerate: String) {
        #expect(SafeFilename.sanitize(degenerate) == "Untitled")
    }

    @Test("escapes reserved device stems")
    func escapesReservedNames() {
        #expect(SafeFilename.sanitize("con") == "_con")
        #expect(SafeFilename.sanitize("NUL.txt") == "_NUL.txt")
        #expect(SafeFilename.sanitize("com4.mov") == "_com4.mov")
        // Not reserved — must not be mangled.
        #expect(SafeFilename.sanitize("console.log") == "console.log")
    }

    @Test("clamps to the byte budget and keeps the extension")
    func clampsLongNames() {
        let long = String(repeating: "a", count: 400) + ".mov"
        let safe = SafeFilename.sanitize(long)
        #expect(safe.utf8.count <= SafeFilename.maximumByteCount)
        // Losing the extension means the file will not open — worse than a
        // truncated name.
        #expect(safe.hasSuffix(".mov"))
    }

    @Test("counts the budget in UTF-8 bytes, not characters")
    func clampsMultibyteByBytes() {
        // APFS allows 255 bytes. A name of emoji hits that at roughly 60
        // characters, so a character-based budget would silently overflow.
        let emoji = String(repeating: "📸", count: 200) + ".jpg"
        let safe = SafeFilename.sanitize(emoji)
        #expect(safe.utf8.count <= SafeFilename.maximumByteCount)
    }

    @Test("never splits a grapheme when truncating")
    func truncatesOnGraphemeBoundaries() {
        // Cutting mid-scalar produces invalid UTF-8; cutting mid-grapheme splits
        // a flag or skin-tone emoji into rendering garbage.
        for count in 90...140 {
            let safe = SafeFilename.sanitize(String(repeating: "👨‍👩‍👧‍👦", count: count) + ".jpg")
            #expect(safe.utf8.count <= SafeFilename.maximumByteCount)
            #expect(String(decoding: Array(safe.utf8), as: UTF8.self) == safe)
        }
    }

    @Test("drops a pathological extension rather than spending the budget on it")
    func dropsAbsurdExtension() {
        let safe = SafeFilename.sanitize("x." + String(repeating: "e", count: 300))
        #expect(safe.utf8.count <= SafeFilename.maximumByteCount)
    }

    @Test("output is idempotent")
    func isIdempotent() {
        // The receiver may sanitise at more than one layer; a second pass must
        // not keep changing the name or de-duplication breaks.
        for input in ["../../etc/passwd", ".hidden", "con", "photo\u{0}.jpg", "a/b.jpg"] {
            let once = SafeFilename.sanitize(input)
            #expect(SafeFilename.sanitize(once) == once)
        }
    }

    @Test("flags names worth telling the user about")
    func flagsSuspicious() {
        #expect(SafeFilename.isSuspicious("../../etc/passwd"))
        #expect(SafeFilename.isSuspicious(".hidden"))
        #expect(SafeFilename.isSuspicious("photo\u{202E}gpj.exe"))
        #expect(!SafeFilename.isSuspicious("final_grade_v7.mov"))
    }
}
