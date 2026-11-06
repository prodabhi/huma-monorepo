import Foundation

/// A page's Huma score, 0 to 100, worked out the same way here and by readers (humaScore in
/// web/publication-contract.mjs, from the page proof and the replay they check):
/// - typed (70): the share of the final text typed by hand. Typing while a non-Apple keyboard was plugged in counts
///   at 60%, because Huma can't tell it from a device typing by itself; pasted text and other edits count nothing.
///   Without the replay, a reader only knows the share of edits that were typing, counted at 60%.
/// - typing checks (20): the proof's seven typing rules (time, key presses, rhythm, holds, pauses and speed).
/// - Touch ID (10): the share of Touch ID checks answered within 10 seconds (all of it when none were asked).
/// A page whose key timing, holds, rhythm or speed looked like no person's (rules 4, 5, 6 and 8) scores at most 50.
public struct HumaScore: Equatable, Sendable {
    public static let externalWeight = 0.6
    public static let humanTypingRules = [4, 5, 6, 8], typingCap = 50.0
    /// Whole points for each part, adding up to the score.
    public struct Points: Equatable, Sendable { public var typed: Int, checks: Int, touch: Int }
    public var value: Int
    /// The counted share of the text that was typed (0...1), with typing on another keyboard at 60%.
    public var typedShare: Double
    /// What a person is told: the share of the text typed by hand on any keyboard, and on another keyboard
    /// (nil and 0 without the replay, when that can't be seen).
    public var handTyped: Double?
    public var external: Double
    public var checksMet: Int
    /// Held at 50 because its typing looked like no person's.
    public var capped: Bool
    public var presenceOnTime: Int
    public var presenceCount: Int
    public var points: Points

    public init(composition: TextProvenance.Composition?, typingEdits: Int, edits: Int, rules: [Bool], presenceCount: Int, onTime: Int) {
        if let composition {
            typedShare = composition.total == 0 ? 0
                : (Double(composition.typed) + Self.externalWeight * Double(composition.external)) / Double(composition.total)
            handTyped = composition.total == 0 ? nil : Double(composition.typed + composition.external) / Double(composition.total)
            external = composition.total == 0 ? 0 : Double(composition.external) / Double(composition.total)
        } else {
            typedShare = edits == 0 ? 0 : Self.externalWeight * Double(typingEdits) / Double(edits)
            handTyped = nil; external = 0
        }
        checksMet = rules.count == 9 ? rules[2...8].filter { $0 }.count : 0
        self.presenceCount = presenceCount; presenceOnTime = min(onTime, presenceCount)
        let touch = presenceCount == 0 ? 1 : Double(presenceOnTime) / Double(presenceCount)
        capped = rules.count == 9 && Self.humanTypingRules.contains { !rules[$0] }
        var raw = [70 * typedShare, 20 * Double(checksMet) / 7, 10 * touch]
        // Capped, each part shrinks alike, so the parts still add up to the score.
        let sum = raw.reduce(0, +)
        if capped && sum > Self.typingCap { raw = raw.map { $0 * Self.typingCap / sum } }
        value = max(0, min(100, Int((raw[0] + raw[1] + raw[2]).rounded())))
        // Each part rounded down, then the points left over go to the parts with the largest remainders.
        var whole = raw.map { Int($0.rounded(.down)) }
        let order = [0, 1, 2].sorted { (raw[$0] - Double(whole[$0]), $1) > (raw[$1] - Double(whole[$1]), $0) }
        for index in order.prefix(max(0, value - whole.reduce(0, +))) { whole[index] += 1 }
        points = Points(typed: whole[0], checks: whole[1], touch: whole[2])
    }

    /// "100% typed · 7 of 7 typing checks · Touch ID 2 of 2", as readers see it (scoreLine in publication-contract.mjs).
    public var line: String {
        let typed = handTyped.map { Self.percent($0) + " typed" + (external > 0 ? " (\(Self.percent(external)) on another keyboard)" : "") }
            ?? "Replay not shared, so typing counts at 60%"
        return ([typed, "\(checksMet) of 7 typing checks"] + (presenceCount > 0 ? ["Touch ID \(presenceOnTime) of \(presenceCount)"] : []))
            .joined(separator: " · ")
    }
    /// A share as a whole percent that never rounds a part away: "100%" only when it's all, "0%" only when none.
    public static func percent(_ share: Double) -> String {
        if !(share > 0) { return "0%" }
        if share >= 1 { return "100%" }
        return share < 0.01 ? "<1%" : "\(min(99, max(1, Int((share * 100).rounded()))))%"
    }
}

/// What a page proof's public statement says (the fields the score and the report use), read from its final inputs.
public struct PageProofSummary: Equatable, Sendable {
    public var edits: Int, typingEdits: Int, pasteEdits: Int, samples: Int
    public var presenceCount: Int, onTime: Int
    public var rules: [Bool]
    /// When writing started and ended by the Mac's clock (signed readings, not a trusted time), and the time spent.
    public var started: Date, ended: Date, elapsedMilliseconds: Int

    /// `finalInputs` is the long page proof's public inputs: 32-byte fields in the order of `struct Final`.
    public init?(finalInputs: Data) {
        guard finalInputs.count == 1408 || finalInputs.count == 1472 else { return nil }
        let bytes = [UInt8](finalInputs)
        func field(_ index: Int, bytes width: Int = 4) -> Int {
            bytes[(index * 32 + 32 - width)..<(index * 32 + 32)].reduce(0) { $0 << 8 | Int($1) }
        }
        edits = field(16); samples = field(17); typingEdits = field(18); pasteEdits = field(19)
        presenceCount = field(25); onTime = field(27)
        started = Date(timeIntervalSince1970: Double(field(20, bytes: 8)) / 1000); ended = Date(timeIntervalSince1970: Double(field(21, bytes: 8)) / 1000)
        elapsedMilliseconds = field(22, bytes: 8)
        rules = (0..<9).map { bytes[(33 + $0) * 32 + 31] == 1 }
    }
    /// From a page proof as the app keeps it (the proof itself, or the evidence file that wraps it).
    public init?(proof: Data) {
        guard var object = (try? JSONSerialization.jsonObject(with: proof)) as? [String: Any] else { return nil }
        if let inner = object["proof"] as? String, let data = inner.data(using: .utf8),
           let parsed = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] { object = parsed }
        guard let encoded = object["finalInputs"] as? String, let inputs = Data(base64Encoded: encoded) else { return nil }
        self.init(finalInputs: inputs)
    }
    public func score(composition: TextProvenance.Composition?) -> HumaScore {
        HumaScore(composition: composition, typingEdits: typingEdits, edits: edits, rules: rules, presenceCount: presenceCount, onTime: onTime)
    }
}
