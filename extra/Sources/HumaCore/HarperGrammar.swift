import Foundation

/// Harper (Automattic, Apache-2.0), an offline English grammar checker, built from integrations/grammar into
/// Resources/Grammar/libhuma_grammar.dylib. It runs on every Mac, without Apple Intelligence, and finds agreement,
/// tense, a/an, then/than and similar mistakes with few false alarms. Spelling is left to the Mac.
public final class HarperGrammar: @unchecked Sendable {
    // Harper keeps one linter behind a lock (backend/integrations/grammar), so calls from any thread are safe.
    private typealias Lint = @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?
    private typealias Free = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void
    private let library: UnsafeMutableRawPointer
    private let lintFunction: Lint
    private let freeFunction: Free

    /// The library in the app's resources, or nil when this build doesn't have it.
    public static let bundled: HarperGrammar? = Bundle.main.resourceURL
        .flatMap { HarperGrammar(url: $0.appendingPathComponent("Grammar/libhuma_grammar.dylib")) }

    public init?(url: URL) {
        guard url.isFileURL, FileManager.default.fileExists(atPath: url.path),
              let library = dlopen(url.path, RTLD_NOW | RTLD_LOCAL) else { return nil }
        guard let lint = dlsym(library, "huma_grammar_lint"), let free = dlsym(library, "huma_grammar_free") else { dlclose(library); return nil }
        self.library = library
        lintFunction = unsafeBitCast(lint, to: Lint.self); freeFunction = unsafeBitCast(free, to: Free.self)
    }
    deinit { dlclose(library) }

    /// Harper's grammar problems in `text`, with ranges in UTF-16 (as NSRange counts) and the fix where it has one.
    public func issues(in text: String) -> [GrammarIssue] {
        guard !text.isEmpty, text.utf8.count <= 256 * 1024, !text.utf8.contains(0) else { return [] }
        guard let reply = text.withCString({ lintFunction($0) }) else { return [] }
        defer { freeFunction(reply) }
        struct Problem: Decodable { let start: Int; let end: Int; let kind: String; let message: String; let fix: String? }
        guard let problems = try? JSONDecoder().decode([Problem].self, from: Data(bytes: reply, count: strlen(reply))) else { return [] }
        let string = text as NSString
        return problems.compactMap { problem in
            let range = NSRange(location: problem.start, length: problem.end - problem.start)
            guard range.length > 0, NSMaxRange(range) <= string.length, let fix = problem.fix else { return nil }
            let original = string.substring(with: range)
            guard fix != original else { return nil }
            return GrammarIssue(range: range, original: original, suggestion: fix, reason: Self.reason(problem.message))
        }
    }
    /// Harper's message, kept short for the menu and the status bar (its first sentence, without Markdown).
    static func reason(_ message: String) -> String {
        let plain = message.replacingOccurrences(of: "`", with: "")
        let first = plain.split(separator: ".", maxSplits: 1).first.map(String.init) ?? plain
        return String(first.trimmingCharacters(in: .whitespaces).prefix(80))
    }
}
