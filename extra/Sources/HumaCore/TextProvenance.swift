import Foundation

/// Where each character of a page came from, rebuilt from its session's edits exactly as readers rebuild it from
/// the replay (frontend/replay-core.mjs): typed, typed on another keyboard, pasted, there before, or another kind of
/// edit. Offsets are UTF-16, as in AppKit and the session log. Undo and redo bring back where text first came from.
public struct TextProvenance: Sendable {
    public enum Origin: UInt8, Sendable { case typed, external, pasted, before, other }
    /// How much of the text came from where, in UTF-16 units.
    public struct Composition: Equatable, Sendable {
        public var typed = 0, external = 0, pasted = 0, before = 0, other = 0
        public var total: Int { typed + external + pasted + before + other }
        public init(typed: Int = 0, external: Int = 0, pasted: Int = 0, before: Int = 0, other: Int = 0) {
            self.typed = typed; self.external = external; self.pasted = pasted; self.before = before; self.other = other
        }
    }
    public private(set) var text: [UInt16]
    public private(set) var origins: [Origin]
    private var removed: [[UInt16]: [Origin]] = [:]
    public private(set) var applied = 0

    public init(initialText: String) {
        text = Array(initialText.utf16); origins = Array(repeating: .before, count: text.count)
    }
    public init(session: SessionLog, through count: Int? = nil) {
        self.init(initialText: session.initialText)
        for event in session.events.prefix(count ?? session.events.count) { apply(event) }
    }

    /// Applies the next edit. An edit that doesn't fit the text (a damaged log) is skipped.
    public mutating func apply(_ event: EditEvent) {
        applied += 1
        let inserted = Array(event.insertedText.utf16)
        guard event.location >= 0, event.removedLength >= 0, event.location + event.removedLength <= text.count else { return }
        let gone = event.location..<(event.location + event.removedLength)
        if !gone.isEmpty { removed[Array(text[gone])] = Array(origins[gone]) }
        let origin: Origin? = switch event.source {
        case "paste": .pasted
        case "typing", "input-method", "format-insert": .typed
        case "typing-external": .external
        default: nil
        }
        let marks = origin.map { Array(repeating: $0, count: inserted.count) }
            ?? (removed[inserted].flatMap { $0.count == inserted.count ? $0 : nil } ?? Array(repeating: .other, count: inserted.count))
        text.replaceSubrange(gone, with: inserted)
        origins.replaceSubrange(gone, with: marks)
    }
    /// Brings it up to date with a session it was built from, applying only the edits it hasn't seen.
    public mutating func catchUp(with session: SessionLog) {
        for event in session.events.dropFirst(applied) { apply(event) }
    }

    public var string: String { String(decoding: text, as: UTF16.self) }
    public var composition: Composition {
        var parts = Composition()
        for origin in origins {
            switch origin {
            case .typed: parts.typed += 1
            case .external: parts.external += 1
            case .pasted: parts.pasted += 1
            case .before: parts.before += 1
            case .other: parts.other += 1
            }
        }
        return parts
    }
    /// The runs of text that came from `origin`, as NSRanges.
    public func ranges(of origin: Origin) -> [NSRange] {
        var found: [NSRange] = [], start: Int?
        for index in 0...origins.count {
            let match = index < origins.count && origins[index] == origin
            if match, start == nil { start = index }
            if !match, let from = start { found.append(NSRange(location: from, length: index - from)); start = nil }
        }
        return found
    }
}
