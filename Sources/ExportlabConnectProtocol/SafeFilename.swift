import Foundation

/// Reduces a peer-supplied filename to something safe to create on disk.
///
/// The filename in an `OFFER` is attacker-controlled: it comes off the network
/// and is displayed to a user and then written to a filesystem. The classic
/// exploit is `../../Library/Preferences/com.apple.something.plist`. This type
/// exists so that neither app has its own half-remembered version of the rules.
///
/// The output is always a single path component, never empty, and never a name
/// the platform treats specially.
public enum SafeFilename {
    /// Longest permitted result, leaving room for a de-duplication suffix.
    ///
    /// APFS allows 255 *bytes*, and a name of emoji or CJK characters hits that
    /// long before it hits 255 characters — so the budget is counted in UTF-8
    /// bytes, not in `String` length.
    public static let maximumByteCount = 200

    /// Names that are not path traversal but still must not be created:
    /// reserved device names inherited from DOS that some layers still honour.
    private static let reservedStems: Set<String> = [
        "con", "prn", "aux", "nul",
        "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
        "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ]

    public static func sanitize(_ raw: String, fallback: String = "Untitled") -> String {
        // 1. Take the last path component. This defeats traversal outright:
        //    "../../etc/passwd" becomes "passwd". Both separators are stripped,
        //    because a name crafted on one platform may be received on another.
        var name = raw
        for separator in ["/", "\\"] {
            name = name.components(separatedBy: separator).last ?? name
        }

        // 2. Remove control characters, the NUL that truncates C strings, and
        //    the colon that HFS+ still treats as a separator.
        name = String(name.unicodeScalars.filter { scalar in
            !(scalar.properties.generalCategory == .control)
                && scalar != ":"
                && scalar.value != 0
        })

        // 3. Strip Unicode direction overrides. These are invisible and can make
        //    "photo\u{202E}gpj.exe" render as "photo exe.jpg" — the user sees a
        //    harmless image and opens something else entirely.
        name = String(name.unicodeScalars.filter { scalar in
            !(0x202A...0x202E).contains(scalar.value)
                && !(0x2066...0x2069).contains(scalar.value)
        })

        // 4. Normalise. APFS stores what it is given but compares normalised;
        //    settling on NFC here keeps de-duplication checks honest.
        name = name.precomposedStringWithCanonicalMapping

        // 5. Trim whitespace and leading dots. A leading dot only hides the file
        //    from the user — which, for something they just chose to receive, is
        //    a bug rather than a feature.
        name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        while name.hasPrefix(".") { name.removeFirst() }
        name = name.trimmingCharacters(in: .whitespacesAndNewlines)

        // 6. "." and ".." survive every filter above and mean something awful.
        if name.isEmpty || name == "." || name == ".." { return fallback }

        // 7. Reserved device stems, extension notwithstanding.
        let stem = (name as NSString).deletingPathExtension.lowercased()
        if reservedStems.contains(stem) { name = "_" + name }

        // 8. Clamp to the byte budget, preserving the extension — a truncated
        //    name is survivable, a lost extension means the file will not open.
        name = clampToByteBudget(name)

        return name.isEmpty ? fallback : name
    }

    /// True when `raw` would have escaped its directory or named something
    /// reserved. Used to decide whether to tell the user the name was changed.
    public static func isSuspicious(_ raw: String) -> Bool {
        raw.contains("..")
            || raw.contains("/")
            || raw.contains("\\")
            || raw.hasPrefix(".")
            || raw.unicodeScalars.contains { (0x202A...0x202E).contains($0.value) }
            || raw.unicodeScalars.contains { $0.properties.generalCategory == .control }
    }

    private static func clampToByteBudget(_ name: String) -> String {
        guard name.utf8.count > maximumByteCount else { return name }

        let ns = name as NSString
        let ext = ns.pathExtension
        var stem = ns.deletingPathExtension

        // A pathological extension gets dropped rather than eating the budget.
        let suffix = ext.utf8.count <= 16 && !ext.isEmpty ? "." + ext : ""
        let budget = maximumByteCount - suffix.utf8.count

        // Remove whole Characters, never bytes: cutting mid-scalar produces
        // invalid UTF-8, and cutting mid-grapheme can split a flag or a skin-tone
        // emoji into something that renders as garbage.
        while stem.utf8.count > budget, !stem.isEmpty { stem.removeLast() }

        return stem + suffix
    }
}
