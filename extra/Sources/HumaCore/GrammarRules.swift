import Foundation
import NaturalLanguage

/// A spelling or grammar problem in the writer's text: the words, what to type instead and why.
public struct GrammarIssue: Equatable, Sendable {
    public var range: NSRange
    /// The words as they were when the problem was found, so a stale range is never acted on.
    public var original: String
    public var suggestion: String
    public var reason: String
    /// Huma underlines it (misspellings already have the Mac's red underline).
    public var underlined: Bool
    /// Found by the Mac's own checker, whose right-click menu already lists the fix.
    public var fromMac: Bool
    public init(range: NSRange, original: String, suggestion: String, reason: String, underlined: Bool = true, fromMac: Bool = false) {
        self.range = range; self.original = original; self.suggestion = suggestion; self.reason = reason
        self.underlined = underlined; self.fromMac = fromMac
    }
}

/// The checks Huma runs itself (the same on every Mac), and the clean-up of what the on-device model suggests.
public enum GrammarRules {
    /// The text's sentences, as ranges.
    public static func sentences(in text: String) -> [NSRange] {
        let tokenizer = NLTokenizer(unit: .sentence)
        tokenizer.string = text
        return tokenizer.tokens(for: text.startIndex..<text.endIndex).map { NSRange($0, in: text) }
    }

    /// A lowercase "i" on its own, a word typed twice in a row, and a sentence that starts with a lowercase letter.
    public static func issues(in text: String) -> [GrammarIssue] {
        let string = text as NSString, whole = NSRange(location: 0, length: string.length)
        var found: [GrammarIssue] = []
        for match in Self.lowercaseI.matches(in: text, range: whole) {
            found.append(GrammarIssue(range: match.range, original: "i", suggestion: "I", reason: "Write “I” as a capital letter"))
        }
        for match in Self.repeated.matches(in: text, range: whole) {
            let word = string.substring(with: match.range(at: 1))
            guard !["had", "that"].contains(word.lowercased()) else { continue }
            found.append(GrammarIssue(range: match.range, original: string.substring(with: match.range), suggestion: word, reason: "The same word twice"))
        }
        // A sentence starts the text or a line, or follows ". ", "! " or "? " (not after "e.g." or "Dr.").
        for match in Self.sentenceStart.matches(in: text, range: whole) {
            let word = match.range(at: 1), before = string.substring(to: word.location)
            if let stop = before.range(of: "[.!?][\"”’)\\]]?\\s+$", options: .regularExpression) {
                let previous = before[..<stop.lowerBound].split(whereSeparator: { $0.isWhitespace }).last.map(String.init) ?? ""
                if previous.count == 1 || previous.contains(".") || Self.abbreviations.contains(previous.lowercased()) { continue }
            }
            let value = string.substring(with: word)
            // Lowercase words only: not "i" (above), "iPhone", "e.g." or a web address.
            guard value != "i", value.first?.isLowercase == true, !value.dropFirst().contains(where: \.isUppercase),
                  !["http", "https", "www"].contains(value.lowercased()) else { continue }
            let next = NSMaxRange(word)
            if next < string.length, [".", "/", ":", "@"].contains(string.substring(with: NSRange(location: next, length: 1))) { continue }
            found.append(GrammarIssue(range: word, original: value, suggestion: value.prefix(1).uppercased() + value.dropFirst(),
                                      reason: "Start a sentence with a capital letter"))
        }
        return found
    }

    /// Whether a suggested change is a real fix: not empty or the same, not just spelling out a contraction
    /// ("I'm" to "I am") or dropping the final full stop, and small (a fix, not a rewrite).
    public static func isFix(original: String, suggestion: String) -> Bool {
        let from = original.trimmingCharacters(in: .whitespacesAndNewlines), to = suggestion.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !from.isEmpty, !to.isEmpty, from != to, from.count <= 60, to.count <= 80 else { return false }
        // A change of case only ("swayam" to "Swayam") is a fix; spelling out a contraction isn't.
        if from.lowercased() != to.lowercased(), expanded(from) == expanded(to) { return false }
        if from.hasPrefix(to), from.dropFirst(to.count).allSatisfy({ $0.isPunctuation || $0.isWhitespace }) { return false }
        // A fix never turns "don't" into "does": a "not" stays a "not".
        if negated(from) != negated(to) { return false }
        return true
    }

    /// Where a suggested fix's words are in the sentence it was found in.
    public static func place(_ original: String, in text: String, sentence: NSRange) -> NSRange? {
        let string = text as NSString
        guard NSMaxRange(sentence) <= string.length, !original.isEmpty else { return nil }
        for options: NSString.CompareOptions in [[], [.caseInsensitive]] {
            let range = string.range(of: original, options: options, range: sentence)
            if range.location != NSNotFound { return range }
        }
        return nil
    }

    private static let lowercaseI = try! NSRegularExpression(pattern: "(?<![\\p{L}\\p{N}'’.])i(?![\\p{L}\\p{N}])(?!\\.[eE])")
    private static let repeated = try! NSRegularExpression(pattern: "\\b(\\p{L}+)\\s+\\1\\b", options: [.caseInsensitive])
    private static let sentenceStart = try! NSRegularExpression(pattern: "(?:^|(?<=[.!?])[\"”’)\\]]?[ \\t]+)[\"“‘(\\[]?(\\p{L}[\\p{L}'’]*)",
                                                                options: [.anchorsMatchLines])
    private static let abbreviations: Set<String> = ["mr", "mrs", "ms", "dr", "st", "vs", "etc", "jr", "sr", "no", "fig", "approx"]
    private static func negated(_ value: String) -> Bool {
        let words = expanded(value).split(separator: " ")
        return words.contains { ["not", "never", "no"].contains($0) }
    }
    private static func expanded(_ value: String) -> String {
        var text = " " + value.lowercased().replacingOccurrences(of: "’", with: "'") + " "
        for (short, long) in [("won't", "will not"), ("can't", "can not"), ("cannot", "can not"), ("n't", " not"), ("'m", " am"),
                              ("'re", " are"), ("'ve", " have"), ("'ll", " will"), ("'d", " would"), ("'s", " is")] {
            text = text.replacingOccurrences(of: short, with: long)
        }
        return text.split(whereSeparator: \.isWhitespace).joined(separator: " ")
    }
}
