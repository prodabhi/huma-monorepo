#if DEBUG
import AppKit
import SwiftUI
import HumaCore

/// Development builds only: `HUMA_SNAPSHOTS=<folder> Huma.app/Contents/MacOS/Huma` draws the app's sheets and main
/// window to PNGs in light and dark, then quits before any window opens, so a change to the look can be checked
/// without using the app. Text views and other AppKit pieces show as placeholders; everything SwiftUI draws is real.
@MainActor enum Snapshots {
    static func runIfAsked() {
        guard let folder = ProcessInfo.processInfo.environment["HUMA_SNAPSHOTS"] else { return }
        let out = URL(fileURLWithPath: folder, isDirectory: true)
        try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        let settings = AppSettings()
        var draft = Draft()
        draft.title = "A letter to my sister"
        let views: [(String, AnyView)] = [
            ("onboarding-0", AnyView(onboarding(0))), ("onboarding-1", AnyView(onboarding(1))),
            ("onboarding-2", AnyView(onboarding(2))), ("onboarding-3", AnyView(onboarding(3))),
            ("onboarding-4", AnyView(onboarding(4))),
            ("settings", AnyView(SettingsView {}.environmentObject(settings))),
            ("profile", AnyView(ProfileEditor {})),
            ("score", AnyView(VStack(spacing: 10) {
                let all = Array(repeating: true, count: 9)
                ScoreRow(score: HumaScore(composition: .init(typed: 100), typingEdits: 0, edits: 0, rules: all, presenceCount: 2, onTime: 2))
                ScoreRow(score: HumaScore(composition: .init(typed: 70, external: 11, pasted: 19), typingEdits: 0, edits: 0, rules: all, presenceCount: 2, onTime: 1))
                ScoreRow(score: HumaScore(composition: nil, typingEdits: 50, edits: 50, rules: all, presenceCount: 0, onTime: 0),
                         note: "With the replay on, readers would see 100.")
            }.padding(20).frame(width: 460))),
            ("bubble", AnyView(HStack(alignment: .top, spacing: 0) {
                let issue = GrammarIssue(range: NSRange(location: 0, length: 10), original: "a software", suggestion: "software",
                                         reason: "Don’t use “a” before an uncountable noun")
                SuggestionBubble(issue: issue, typing: false, above: true, choose: {}, ignore: {})
                SuggestionBubble(issue: issue, typing: true, above: false, choose: {}, ignore: {})
            }.padding(10))),
            ("window", AnyView(WritingView(document: .constant(WritingDocument(draft: draft)), fileURL: nil)
                .environmentObject(settings).environmentObject(PageStore.shared)
                .frame(width: 1240, height: 820))),
        ]
        for (name, view) in views {
            for (mode, appearance) in [("light", NSAppearance(named: .aqua)!), ("dark", NSAppearance(named: .darkAqua)!)] {
                NSApp?.appearance = appearance
                window(view.background(Theme.page), appearance: appearance, to: out.appendingPathComponent("\(name)-\(mode).png"))
            }
        }
        grammar(out)
        // HUMA_SNAPSHOT_DOCUMENT=<a .huma page>: its version history and its PDF report too.
        if let path = ProcessInfo.processInfo.environment["HUMA_SNAPSHOT_DOCUMENT"],
           let draft = try? WritingDocument(data: Data(contentsOf: URL(fileURLWithPath: path))).draft {
            for moment in VersionHistoryView.moments(of: draft) {
                let text = moment.text ?? TextProvenance(session: draft.session, through: moment.edits).string
                print("moment:", moment.title, "|", moment.detail, "|", text.count, "characters")
            }
            window(VersionHistoryView(draft: draft) {}.background(Theme.page), appearance: NSAppearance(named: .aqua)!, to: out.appendingPathComponent("history.png"))
            if let proof = draft.replayProof, let summary = PageProofSummary(proof: proof) {
                let provenance = TextProvenance(session: draft.session)
                print("report summary: read | score:", summary.score(composition: provenance.composition).value)
                // The evidence file is made the way Export Report makes it, waited for here.
                var evidence: Data?
                Task { evidence = try? await ReplayProofService.evidenceEnvelope(draft: draft, proof: proof).encoded() }
                let deadline = Date().addingTimeInterval(120)
                while evidence == nil, Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.2)) }
                do {
                    let data = try PageReport.make(.init(title: draft.title, writer: "Swayam", text: draft.text, provenance: provenance, summary: summary,
                        score: summary.score(composition: provenance.composition), composition: provenance.composition,
                        link: URL(string: "https://huma.social/p/Ab3xK9q2#V8nq2LxP0aZt7Ru4"), proof: proof, evidence: evidence ?? proof))
                    try data.write(to: out.appendingPathComponent("report.pdf"))
                    print("report evidence:", evidence == nil ? "proof only (envelope failed)" : "\(evidence!.count) bytes")
                } catch { print("report failed:", error) }
            }
        }
        exit(0)
    }
    /// Draws a view in a real offscreen window at its own size, so text fields, editors and scrolling lists draw too.
    private static func window<V: View>(_ view: V, appearance: NSAppearance, to url: URL) {
        let host = NSHostingView(rootView: view)
        let size = host.fittingSize
        let window = NSWindow(contentRect: NSRect(x: -6000, y: 0, width: max(size.width, 100), height: max(size.height, 100)),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.appearance = appearance; window.contentView = host; window.orderFrontRegardless()
        RunLoop.main.run(until: Date().addingTimeInterval(0.8))
        host.layoutSubtreeIfNeeded()
        if let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
            host.cacheDisplay(in: host.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: url)
        }
        window.orderOut(nil)
    }
    /// The editor with a few mistakes after checking: the suggestions (printed) and their underlines (drawn).
    private static func grammar(_ out: URL) {
        let bounds = NSRect(x: 0, y: 0, width: 760, height: 200)
        let window = NSWindow(contentRect: bounds, styleMask: [.borderless], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: .aqua)
        let text = HumaTextView(frame: bounds.insetBy(dx: 24, dy: 24))
        text.isGrammarCheckingEnabled = true; text.isContinuousSpellCheckingEnabled = true; text.font = .systemFont(ofSize: 17)
        text.string = "He go to school every day. Their going to the park tomorrow. I has a apple and i like it. She don't like the the rain."
        window.contentView?.addSubview(text)
        let checker = GrammarChecker(view: text)
        checker.textChanged()
        var last = -1, stable = 0
        let deadline = Date().addingTimeInterval(90)
        while Date() < deadline, stable < 16 {
            RunLoop.main.run(until: Date().addingTimeInterval(0.5))
            if checker.issues.count == last { stable += 1 } else { stable = 0; last = checker.issues.count }
        }
        print("on-device model:", Proofreading.available ? "on" : "off")
        for issue in checker.issues { print("suggestion:", issue.original, "→", issue.suggestion, "|", issue.reason, issue.underlined ? "(Huma)" : "(Mac)") }
        guard let view = window.contentView, let rep = view.bitmapImageRepForCachingDisplay(in: bounds) else { return }
        view.cacheDisplay(in: bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: out.appendingPathComponent("grammar.png"))
    }
    private static func onboarding(_ step: Int) -> some View {
        Onboarding(startsSession: false, step: step, account: step > 2 ? "you@example.com" : nil,
                   onDone: {}, onSkip: {}, signIn: { "" })
    }
}
#endif
