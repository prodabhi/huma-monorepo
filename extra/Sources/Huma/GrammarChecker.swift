import AppKit
import HumaCore
#if canImport(FoundationModels)
import FoundationModels
#endif

/// Spelling and grammar suggestions as you write, from four checkers, most precise first: a few exact rules
/// (GrammarRules), Harper (HarperGrammar, offline, on every Mac), the Mac's own spelling and grammar checker, and,
/// where Apple Intelligence is on, the on-device language model, which reads each sentence once you pause and keeps a
/// fix only if it prefers the fixed sentence. Nothing leaves the Mac. A fix is never put in for you: choosing one
/// selects the words and says what to type, so the page stays typed.
@MainActor final class GrammarChecker {
    private(set) var issues: [GrammarIssue] = []
    var enabled = true { didSet { if enabled != oldValue { enabled ? textChanged() : clear() } } }
    var onChange: ((Int) -> Void)?
    private weak var view: NSTextView?
    private var waiting: Task<Void, Never>?
    /// What the model found in each sentence it has read, by the sentence's text, so a sentence is read once.
    private var checked: [String: [Finding]] = [:]
    /// Harper's and the Mac's finds in each sentence, by its text: quick, so they're made as you type, once per sentence.
    private var quick: [String: [GrammarIssue]] = [:]
    private let harper = HarperGrammar.bundled
    /// The caret got where it is by typing, so the word just before it is still being written and isn't judged.
    private var typing = false
    /// Suggestions the writer chose to ignore, by their words and fix.
    private var ignored: Set<String> = []

    init(view: NSTextView) { self.view = view }

    /// After an edit: the rules and what's already known show at once; the rest waits until typing pauses.
    func textChanged() {
        typing = true
        refresh()
        waiting?.cancel()
        waiting = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1.2))
            guard !Task.isCancelled else { return }
            await self?.check()
        }
    }

    private func check() async {
        guard enabled, let view else { return }
        guard Proofreading.available else { return }
        let text = view.string, caret = view.selectedRange().location, string = text as NSString
        for sentence in GrammarRules.sentences(in: text) {
            let key = string.substring(with: sentence).trimmingCharacters(in: .whitespacesAndNewlines)
            guard key.count >= 4, key.count <= 1200, checked[key] == nil else { continue }
            // The sentence still being typed waits until it ends.
            if caret >= sentence.location, caret <= NSMaxRange(sentence), !(key.last.map { ".!?".contains($0) } ?? false) { continue }
            let findings = await Proofreading.check(key)
            guard !Task.isCancelled, enabled else { return }
            if checked.count > 2000 { checked.removeAll() }
            checked[key] = findings
            refresh()
        }
    }

    /// Puts together what's known for the text as it is now, and underlines it.
    func refresh() {
        guard let view else { return }
        guard enabled else { clear(); return }
        let text = view.string, string = text as NSString
        // Each find with its checker's rank: where finds overlap, the earlier one stays, then the more precise checker's.
        var all: [(issue: GrammarIssue, rank: Int)] = GrammarRules.issues(in: text).map { ($0, 0) }
        for sentence in GrammarRules.sentences(in: text) {
            let raw = string.substring(with: sentence)
            for var issue in quickIssues(in: raw) {
                issue.range.location += sentence.location
                all.append((issue, issue.fromMac ? 2 : 1))
            }
            let key = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            for finding in checked[key] ?? [] where GrammarRules.isFix(original: finding.original, suggestion: finding.suggestion) {
                guard let range = GrammarRules.place(finding.original, in: text, sentence: sentence) else { continue }
                all.append((GrammarIssue(range: range, original: string.substring(with: range), suggestion: finding.suggestion, reason: finding.reason), 3))
            }
        }
        // The word being typed isn't judged yet; once the caret is put somewhere by clicking, it is.
        let caret = view.selectedRange()
        var kept: [GrammarIssue] = []
        for issue in all.sorted(by: { ($0.issue.range.location, $0.rank) < ($1.issue.range.location, $1.rank) }).map(\.issue) {
            if typing, caret.length == 0, NSMaxRange(issue.range) == caret.location { continue }
            if ignored.contains(Self.key(issue)) { continue }
            if let last = kept.last, NSIntersectionRange(last.range, issue.range).length > 0 { continue }
            kept.append(issue)
        }
        let changed = kept != issues
        issues = kept
        draw()
        if changed { onChange?(kept.count) }
    }

    /// The right-click items for a suggestion Huma underlined (the Mac lists its own).
    func menuItems(at index: Int, choose: @escaping (GrammarIssue) -> Void) -> [NSMenuItem] {
        guard let issue = issues.first(where: { !$0.fromMac && $0.range.location <= index && index <= NSMaxRange($0.range) }) else { return [] }
        let reason = NSMenuItem(title: issue.reason, action: nil, keyEquivalent: "")
        reason.isEnabled = false
        return [reason, MenuAction.item(title: issue.suggestion) { choose(issue) }]
    }

    /// The caret was put down by a click: every word is judged again, including the one it's next to.
    func caretPlaced() {
        typing = false
        refresh()
    }
    /// The suggestion for the words at `index` (inside them or at either end), if they're still there.
    func issue(at index: Int) -> GrammarIssue? {
        guard let view else { return nil }
        let string = view.string as NSString
        return issues.first { $0.range.location <= index && index <= NSMaxRange($0.range)
            && NSMaxRange($0.range) <= string.length && string.substring(with: $0.range) == $0.original }
    }
    /// Stops suggesting this fix for these words (a misspelling is ignored the Mac's way, for this page).
    func ignore(_ issue: GrammarIssue) {
        if issue.fromMac, issue.reason == "Spelling", let view {
            NSSpellChecker.shared.ignoreWord(issue.original, inSpellDocumentWithTag: view.spellCheckerDocumentTag)
            quick.removeAll()
        }
        ignored.insert(Self.key(issue))
        refresh()
    }
    private static func key(_ issue: GrammarIssue) -> String { issue.original + "\u{1F}" + issue.suggestion }

    /// The next suggestion after `location`, starting over from the top, if its words are still there.
    func next(after location: Int) -> GrammarIssue? {
        guard let view else { return nil }
        let string = view.string as NSString
        let current = issues.filter { NSMaxRange($0.range) <= string.length && string.substring(with: $0.range) == $0.original }
        return current.first { $0.range.location >= location } ?? current.first
    }

    private func clear() {
        waiting?.cancel()
        issues = []
        draw()
        onChange?(0)
    }

    private func draw() {
        guard let view else { return }
        let style = NSUnderlineStyle.thick.rawValue | NSUnderlineStyle.patternDot.rawValue
        if let layout = view.textLayoutManager, let content = layout.textContentManager {
            layout.removeRenderingAttribute(.underlineStyle, for: layout.documentRange)
            layout.removeRenderingAttribute(.underlineColor, for: layout.documentRange)
            for issue in issues where issue.underlined {
                guard let start = content.location(content.documentRange.location, offsetBy: issue.range.location),
                      let end = content.location(start, offsetBy: issue.range.length),
                      let range = NSTextRange(location: start, end: end) else { continue }
                layout.addRenderingAttribute(.underlineStyle, value: style, for: range)
                layout.addRenderingAttribute(.underlineColor, value: NSColor.systemBlue, for: range)
            }
        } else if let layout = view.layoutManager {
            let whole = NSRange(location: 0, length: (view.string as NSString).length)
            layout.removeTemporaryAttribute(.underlineStyle, forCharacterRange: whole)
            layout.removeTemporaryAttribute(.underlineColor, forCharacterRange: whole)
            for issue in issues where issue.underlined {
                layout.addTemporaryAttributes([.underlineStyle: style, .underlineColor: NSColor.systemBlue], forCharacterRange: issue.range)
            }
        }
    }

    private func quickIssues(in sentence: String) -> [GrammarIssue] {
        if let known = quick[sentence] { return known }
        let found = (harper?.issues(in: sentence) ?? []) + systemIssues(in: sentence, tag: view?.spellCheckerDocumentTag ?? 0)
        if quick.count > 4000 { quick.removeAll() }
        quick[sentence] = found
        return found
    }

    /// The Mac's spelling and grammar finds, with its first suggestion. It underlines misspellings itself, but
    /// draws its grammar marks only once it gets to them, so Huma underlines those too.
    private func systemIssues(in text: String, tag: Int) -> [GrammarIssue] {
        let checker = NSSpellChecker.shared, string = text as NSString
        let types = NSTextCheckingResult.CheckingType.spelling.rawValue | NSTextCheckingResult.CheckingType.grammar.rawValue
        var found: [GrammarIssue] = []
        for result in checker.check(text, range: NSRange(location: 0, length: string.length), types: types, options: nil,
                                    inSpellDocumentWithTag: tag, orthography: nil, wordCount: nil) {
            if result.resultType == .spelling {
                // Capitalised words are mostly names (Huma, Swayam); the Mac still underlines them, they just aren't counted.
                guard string.substring(with: result.range).first?.isUppercase != true,
                      let guess = checker.guesses(forWordRange: result.range, in: text, language: nil, inSpellDocumentWithTag: tag)?.first else { continue }
                found.append(GrammarIssue(range: result.range, original: string.substring(with: result.range), suggestion: guess,
                                          reason: "Spelling", underlined: false, fromMac: true))
            }
            for detail in result.grammarDetails ?? [] {
                guard let part = (detail[NSGrammarRange] as? NSValue)?.rangeValue, let fix = (detail[NSGrammarCorrections] as? [String])?.first else { continue }
                let range = NSRange(location: result.range.location + part.location, length: part.length)
                guard NSMaxRange(range) <= string.length else { continue }
                found.append(GrammarIssue(range: range, original: string.substring(with: range), suggestion: fix,
                                          reason: detail[NSGrammarUserDescription] as? String ?? "Grammar", fromMac: true))
            }
        }
        return found
    }
}

/// One mistake the model found in a sentence: the words, the fix and why.
struct Finding: Sendable {
    let original: String
    let suggestion: String
    let reason: String
}

/// The on-device model (Apple Intelligence), when this Mac has it switched on.
enum Proofreading {
    static var available: Bool {
        #if canImport(FoundationModels)
        if #available(macOS 26.0, *), case .available = SystemLanguageModel.default.availability { return true }
        #endif
        return false
    }
    static func check(_ sentence: String) async -> [Finding] {
        #if canImport(FoundationModels)
        if #available(macOS 26.0, *) { return await OnDeviceProofreader.check(sentence) }
        #endif
        return []
    }
}

#if canImport(FoundationModels)
@available(macOS 26.0, *)
@Generable struct ProofreadIssue {
    @Guide(description: "The exact wrong words, copied character for character from the text, as short as possible (one to four words).")
    var original: String
    @Guide(description: "The corrected words that should replace `original`.")
    var suggestion: String
    @Guide(description: "A short plain explanation, under eight words.")
    var reason: String
}
@available(macOS 26.0, *)
@Generable struct ProofreadReport { var issues: [ProofreadIssue] }
@available(macOS 26.0, *)
@Generable struct ProofreadChoice {
    @Guide(description: "A or B: the sentence that is correct standard English. If both are correct, A.", .anyOf(["A", "B"]))
    var correct: String
}

@available(macOS 26.0, *)
enum OnDeviceProofreader {
    static let instructions = """
    You proofread English writing for grammar and spelling mistakes.
    Report only clear mistakes: subject-verb agreement (he go, I has, she don't), wrong verb form or tense, a or an, \
    their/there/they're, its/it's, your/you're, to/too, a lowercase "i" on its own, a sentence that starts with a lowercase letter, \
    the same word twice in a row, and misspelled words.
    For each mistake, make the smallest change that fixes it and keep the writer's own words. Never suggest a synonym, \
    a different word choice, or a rewording. Never report text that is already correct.
    Copy `original` exactly as it appears in the text.
    """
    /// A second look at each proposed fix: the model is eager, and on correct sentences it "fixes" what isn't wrong.
    /// Shown the sentence as written (A) and as fixed (B), it keeps the fix only if it picks B.
    static let review = "You compare two versions of an English sentence and pick the one that is correct standard English. If both are correct, pick A."
    static func check(_ sentence: String) async -> [Finding] {
        let session = LanguageModelSession(instructions: instructions)
        guard let report = try? await session.respond(to: "Text:\n" + sentence, generating: ProofreadReport.self,
                                                      options: GenerationOptions(temperature: 0)).content else { return [] }
        var confirmed: [Finding] = []
        for issue in report.issues where GrammarRules.isFix(original: issue.original, suggestion: issue.suggestion) {
            guard let range = sentence.range(of: issue.original) else { continue }
            let fixed = sentence.replacingCharacters(in: range, with: issue.suggestion)
            guard let choice = try? await LanguageModelSession(instructions: review).respond(to: "A: \(sentence)\nB: \(fixed)",
                      generating: ProofreadChoice.self, options: GenerationOptions(temperature: 0)).content, choice.correct == "B" else { continue }
            confirmed.append(Finding(original: issue.original, suggestion: issue.suggestion, reason: String(issue.reason.prefix(80))))
        }
        return confirmed
    }
}
#endif

/// A menu item that runs a closure. The item holds its target (NSMenuItem keeps targets weakly).
@MainActor private final class MenuAction: NSObject {
    let run: () -> Void
    init(_ run: @escaping () -> Void) { self.run = run }
    @objc func perform(_ sender: Any?) { run() }
    static func item(title: String, run: @escaping () -> Void) -> NSMenuItem {
        let action = MenuAction(run), item = NSMenuItem(title: title, action: #selector(perform(_:)), keyEquivalent: "")
        item.target = action; item.representedObject = action
        return item
    }
}
