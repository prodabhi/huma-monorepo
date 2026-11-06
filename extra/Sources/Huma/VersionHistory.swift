import AppKit
import SwiftUI
import HumaCore

/// Version history: the page as it was at each pause in writing and at the end, rebuilt from its recorded edits
/// (TextProvenance), and the versions finished before. Pasted parts are tinted. A version can be copied, but not put
/// back into the page: that text wouldn't be typed.
struct VersionHistoryView: View {
    struct Moment: Identifiable, Hashable {
        let id: String
        let title: String
        let detail: String
        /// How many of the session's edits it includes, or the text of an earlier finished version.
        let edits: Int?
        let text: String?
    }
    let draft: Draft
    let done: () -> Void
    /// Worked out once, when the window opens: a long page has thousands of edits to replay.
    @State private var moments: [Moment] = []
    @State private var selection: String?
    @State private var copied = false
    @State private var loaded = false
    @FocusState private var listFocused: Bool

    init(draft: Draft, done: @escaping () -> Void) { self.draft = draft; self.done = done }
    private var session: SessionLog { draft.session }
    /// Whether anything was ever pasted, so the legend only shows when there's something to explain.
    private var anyPasted: Bool { session.events.contains { $0.source == "paste" } }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SheetTitle(title: "Version History", detail: "Your page at each pause in writing. Copy any version you need.")
            HStack(alignment: .top, spacing: 16) {
                ScrollViewReader { scroller in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(moments) { moment in
                                Button { selection = moment.id } label: {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(moment.title).font(Theme.sans(13, .medium)).foregroundStyle(Theme.text)
                                        Text(moment.detail).font(Theme.sans(11.5)).foregroundStyle(Theme.secondary)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(.horizontal, 10).padding(.vertical, 8)
                                    .background(selection == moment.id ? Theme.callout : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain).id(moment.id)
                                .accessibilityAddTraits(selection == moment.id ? .isSelected : [])
                            }
                        }
                    }
                    // ↑ and ↓ move through the versions, as in a list.
                    .focusable().focused($listFocused).focusEffectDisabled()
                    .onKeyPress(.upArrow) { step(-1, scroller) }
                    .onKeyPress(.downArrow) { step(1, scroller) }
                }
                .frame(width: 210)
                ScrollView {
                    Text(preview).font(Theme.sans(14)).lineSpacing(4).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .topLeading).padding(16)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .humaCard(12)
                .overlay {
                    if loaded, moments.isEmpty {
                        Text("Nothing written yet.").font(Theme.sans(13)).foregroundStyle(Theme.tertiary)
                    }
                }
            }
            .frame(height: 380)
            .padding(.top, 18)
            HStack(spacing: 8) {
                if anyPasted {
                    HStack(spacing: 5) {
                        RoundedRectangle(cornerRadius: 2).fill(Color.orange.opacity(0.35)).frame(width: 10, height: 10)
                        Text("Pasted").font(Theme.sans(12)).foregroundStyle(Theme.secondary)
                    }
                    .accessibilityElement(children: .combine).accessibilityLabel("Pasted text is tinted orange")
                }
                Spacer()
                Button(copied ? "Copied" : "Copy Text") { copy() }.humaButton().disabled(selected == nil)
                Button("Done", action: done).humaButton(.primary).keyboardShortcut(.defaultAction)
            }
            .padding(.top, 18)
        }
        .padding(28).frame(width: 760)
        .humaSheetHeader()
        .presentationBackground(Theme.page)
        .onAppear {
            guard !loaded else { return }
            moments = Self.moments(of: draft); selection = moments.first?.id; loaded = true; listFocused = true
        }
    }

    private func step(_ by: Int, _ scroller: ScrollViewProxy) -> KeyPress.Result {
        guard let index = moments.firstIndex(where: { $0.id == selection }), moments.indices.contains(index + by) else { return .ignored }
        selection = moments[index + by].id
        scroller.scrollTo(selection)
        return .handled
    }
    private var selected: Moment? { moments.first { $0.id == selection } }
    /// The selected version's text, with pasted parts tinted.
    private var preview: AttributedString {
        guard let moment = selected else { return AttributedString("") }
        if let text = moment.text { return AttributedString(text) }
        let provenance = TextProvenance(session: session, through: moment.edits)
        var shown = AttributedString(provenance.string)
        for range in provenance.ranges(of: .pasted) {
            guard let swift = Range(range, in: provenance.string), let lower = AttributedString.Index(swift.lowerBound, within: shown),
                  let upper = AttributedString.Index(swift.upperBound, within: shown) else { continue }
            shown[lower..<upper].backgroundColor = .orange.opacity(0.25)
        }
        return shown
    }
    private func copy() {
        guard let moment = selected else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(moment.text ?? TextProvenance(session: session, through: moment.edits).string, forType: .string)
        copied = true
        Task { try? await Task.sleep(for: .seconds(1.5)); copied = false }
    }

    /// A moment wherever writing paused for 20 seconds or more, every 300 edits in a long stretch, and at the end;
    /// newest first, then the versions finished before.
    static func moments(of draft: Draft) -> [Moment] {
        let session = draft.session, events = session.events
        var cuts: [Int] = [], sinceCut = 0
        for index in events.indices {
            sinceCut += 1
            let next = index + 1 < events.count ? events[index + 1].elapsedMilliseconds : nil
            if next == nil || next! - events[index].elapsedMilliseconds >= 20_000 || sinceCut >= 300 { cuts.append(index + 1); sinceCut = 0 }
        }
        // Times by the Mac's signed clock: the first signed checkpoint, less the writing time it had reached.
        let start = session.signedCheckpoints?.first?.reportedTime.map {
            Date(timeIntervalSince1970: (Double($0.unixMilliseconds) - Double($0.elapsedMilliseconds)) / 1000)
        } ?? session.createdAt
        var provenance = TextProvenance(initialText: session.initialText), applied = 0, previousWords = words(session.initialText)
        var found: [Moment] = []
        for cut in cuts {
            for event in events[applied..<cut] { provenance.apply(event) }
            applied = cut
            let count = words(provenance.string), change = count - previousWords
            previousWords = count
            let at = start.addingTimeInterval(Double(events[cut - 1].elapsedMilliseconds) / 1000)
            let when = Calendar.current.isDateInToday(at) ? at.formatted(date: .omitted, time: .shortened)
                : at.formatted(.dateTime.month(.abbreviated).day().hour().minute())
            let delta = change == 0 ? "edited" : (change > 0 ? "+" : "−") + "\(abs(change)) \(abs(change) == 1 ? "word" : "words")"
            found.append(Moment(id: "edit-\(cut)", title: cut == events.count ? "Latest · \(when)" : when,
                                detail: "\(count) \(count == 1 ? "word" : "words") · \(delta)", edits: cut, text: nil))
        }
        if events.isEmpty, !session.initialText.isEmpty {
            let count = words(session.initialText)
            found.append(Moment(id: "start", title: "Start", detail: "\(count) \(count == 1 ? "word" : "words")", edits: 0, text: nil))
        }
        let earlier = (draft.versions ?? []).enumerated().reversed().map { index, version in
            Moment(id: "version-\(version.id)", title: "Version \(index + 1)",
                   detail: version.finishedAt.map { "Finished " + $0.formatted(date: .abbreviated, time: .shortened) } ?? "Finished",
                   edits: nil, text: version.text)
        }
        return found.reversed() + earlier
    }
    private static func words(_ text: String) -> Int { text.split(whereSeparator: { $0.isWhitespace || $0.isNewline }).count }
}
