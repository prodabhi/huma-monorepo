import SwiftUI
import HumaCore

/// Where a page is in its life: writing, finishing, processing, verified and shared.
enum DocumentStatus: Equatable {
    case draft, writing, finished, processing, verified, shared, edited, interrupted
    var title: String {
        switch self {
        case .draft: return "Draft"
        case .writing: return "Writing"
        case .finished: return "Finished"
        case .processing: return "Processing"
        case .verified: return "Verified"
        case .shared: return "Shared"
        case .edited: return "Edited after finishing"
        case .interrupted: return "Interrupted"
        }
    }
    var tone: Theme.Tone {
        switch self {
        case .draft: return .gray
        case .writing: return .red
        case .finished, .edited, .interrupted: return .orange
        case .processing: return .blue
        case .verified: return .green
        case .shared: return .purple
        }
    }
}

struct TimelineEntry: Identifiable {
    let id: String
    let icon: String
    let tone: Theme.Tone
    let title: String
    var detail: String?
    var date: Date?
    var live = false
}

/// The page's history, read from its signed session. Nothing here is a claim beyond what
/// the session records; live entries describe work happening on this Mac right now.
enum DocumentTimeline {
    static func entries(draft: Draft, status: DocumentStatus, background: String?, verified: Bool) -> [TimelineEntry] {
        var items: [TimelineEntry] = []
        let s = draft.session
        if let prior = draft.priorSessions, !prior.isEmpty {
            let kept = draft.versions?.count ?? 0
            items.append(.init(id: "prior", icon: "clock.arrow.circlepath", tone: .gray,
                               title: prior.count == 1 ? "Continued from an earlier session" : "Continued from \(prior.count) earlier sessions",
                               detail: kept == 0 ? "Kept in this page’s history" : "\(kept) verified \(kept == 1 ? "version" : "versions") saved below"))
        }
        let checkpoints = s.signedCheckpoints ?? []
        guard let first = checkpoints.first else {
            items.append(.init(id: "created", icon: "doc", tone: .gray, title: "Page created", date: s.createdAt))
            return items
        }
        let start = first.reportedTime.map { Date(timeIntervalSince1970: Double($0.unixMilliseconds) / 1_000) }
        let at = { (elapsed: UInt64) in start.map { $0.addingTimeInterval(Double(elapsed) / 1_000) } }
        items.append(.init(id: "start", icon: "record.circle", tone: .red, title: "Writing session started",
                           detail: s.initialText.isEmpty ? "Blank page · Touch ID approved" : "Started from existing text · Touch ID approved",
                           date: start))
        for event in s.presenceEvents ?? [] where event.kind == "response" {
            let latency = event.elapsedMilliseconds - min(event.elapsedMilliseconds, event.issuedElapsedMilliseconds)
            let timely = event.outcome == "approved" && latency <= PresenceEvent.deadlineMilliseconds
            if event.reason == "seal" && timely { continue }
            items.append(.init(id: "presence-\(event.sequence)", icon: timely ? "hand.raised" : "exclamationmark.circle",
                               tone: timely ? .green : .orange,
                               title: timely ? "Touch ID confirmed" : "Touch ID check missed",
                               detail: timely ? "Answered in \(String(format: "%.1f", Double(latency) / 1_000)) s" : "Recorded in the session",
                               date: at(event.elapsedMilliseconds)))
        }
        if let background, status == .writing || status == .finished || status == .processing {
            items.append(.init(id: "background", icon: "gearshape.2", tone: .blue, title: "Processing while you write",
                               detail: background, live: true))
        }
        if status == .writing {
            items.append(.init(id: "now", icon: "pencil", tone: .red, title: "Writing now",
                               detail: "\(checkpoints.count) signed autosaves · pasted text is marked", live: true))
        }
        if let last = checkpoints.last, last.isFinal {
            let minutes = last.reportedTime.map { Int(($0.elapsedMilliseconds + 59_999) / 60_000) }
            items.append(.init(id: "finish", icon: "checkmark.circle", tone: .orange, title: "Session finished",
                               detail: minutes.map { "\($0) min of writing · \(checkpoints.count) signed autosaves" },
                               date: last.reportedTime.map { Date(timeIntervalSince1970: Double($0.unixMilliseconds) / 1_000) }))
        }
        if status == .processing {
            items.append(.init(id: "processing", icon: "gearshape.2", tone: .blue, title: "Processing document",
                               detail: "On this Mac, at low priority", live: true))
        }
        if draft.replayProof != nil {
            items.append(.init(id: "processed", icon: "doc.badge.gearshape", tone: .blue, title: "Document processed",
                               detail: "Proof file created"))
            if verified {
                items.append(.init(id: "verified", icon: "checkmark.seal.fill", tone: .green, title: "Verified on this Mac",
                                   detail: "Text, edits, signatures and timing all match"))
            }
        }
        if let link = draft.publicProof {
            items.append(.init(id: "shared", icon: "link", tone: .purple, title: "Shared", detail: link.url.host ?? link.url.absoluteString))
        }
        if status == .interrupted {
            items.append(.init(id: "interrupted", icon: "exclamationmark.triangle", tone: .orange, title: "Not finished",
                               detail: "Stopped before Finish, so this page can’t be shared"))
        }
        if status == .edited {
            items.append(.init(id: "edited", icon: "pencil.slash", tone: .orange, title: "Edited after finishing",
                               detail: "Start a new page to write more", live: true))
        }
        return items
    }
}

/// Right-hand panel: the page's timeline, newest at the bottom.
struct TimelinePanel<Versions: View, Details: View>: View {
    let entries: [TimelineEntry]
    let close: () -> Void
    @ViewBuilder var versions: Versions
    @ViewBuilder var details: Details
    @State private var showDetails = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("Timeline").monoLabel(11).foregroundStyle(Theme.secondary)
                    Spacer()
                    HeaderIcon(icon: "xmark", help: "Close timeline (⌥⌘T)", action: close)
                }
                .padding(.bottom, 10)
                ForEach(Array(entries.enumerated()), id: \.element.id) { index, entry in
                    HStack(alignment: .top, spacing: 12) {
                        VStack(spacing: 0) {
                            let (background, foreground) = Theme.tag(entry.tone)
                            ZStack {
                                Circle().fill(background)
                                Image(systemName: entry.icon).font(.system(size: 10, weight: .semibold)).foregroundStyle(foreground)
                            }
                            .frame(width: 24, height: 24)
                            .overlay(entry.live ? Circle().strokeBorder(foreground.opacity(0.5), lineWidth: 1.5).padding(-3) : nil)
                            if index < entries.count - 1 { Rectangle().fill(Theme.divider).frame(width: 1.5).frame(maxHeight: .infinity) }
                        }
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.title).font(Theme.sans(13, .medium)).foregroundStyle(Theme.text)
                            if let detail = entry.detail { Text(detail).font(Theme.sans(12)).foregroundStyle(Theme.secondary) }
                            if let date = entry.date {
                                Text(date, format: .dateTime.month(.abbreviated).day().hour().minute())
                                    .monoLabel(10).foregroundStyle(Theme.tertiary)
                            }
                        }
                        .padding(.bottom, 18)
                        Spacer(minLength: 0)
                    }
                }
                versions
                Divider().overlay(Theme.divider).padding(.vertical, 8)
                Button { withAnimation(.easeOut(duration: 0.15)) { showDetails.toggle() } } label: {
                    HStack(spacing: 6) {
                        Image(systemName: showDetails ? "chevron.down" : "chevron.right").font(.system(size: 10, weight: .semibold))
                        Text("Technical details")
                    }.monoLabel(10.5).foregroundStyle(Theme.secondary)
                }.buttonStyle(.plain)
                if showDetails {
                    VStack(alignment: .leading, spacing: 8) { details }
                        .font(Theme.sans(12)).foregroundStyle(Theme.secondary).padding(.top, 10)
                }
            }
            .padding(20)
        }
        .background(Theme.page)
    }
}
