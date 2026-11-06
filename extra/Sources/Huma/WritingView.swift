import AppKit
import SwiftUI
import HumaCore

/// One Huma page: a Docs-style header (title, status, menus, Share), one status line,
/// the writing itself, and an optional timeline of what happened to the page.
struct WritingView: View {
    @Binding var document: WritingDocument
    var fileURL: URL?
    @EnvironmentObject var settings: AppSettings
    @EnvironmentObject var store: PageStore
    @StateObject private var commands = EditorCommands()
    @StateObject private var captureSigner = CaptureSigner()
    @AppStorage("showTimeline") private var showTimeline = true
    @AppStorage("showSidebar") private var showSidebar = true
    @State private var errorMessage: String?
    @State private var busy = false
    @State private var proofStatus = ""
    @State private var showLink = false
    @State private var showShare = false
    @State private var showHistory = false
    @State private var linkURL = "https://"
    private var proofLink: URL? { draft.publicProof.flatMap { $0.matches(draft) ? $0.url : nil } }
    /// What people get when the page is copied or opened: its short link once the host has made it.
    private var shareLink: URL? { proofLink.map { draft.publicProof?.shortURL ?? $0 } }
    @State private var captureSummary: SignedSessionSummary?
    @State private var replayStatus = ""
    @State private var proofTask: Task<Void, Never>?
    @State private var proofStartedAt: Date?
    @State private var verifiedReplayProof: Data?
    @State private var verifiedAssurance: ReplayAssurance?
    @State private var authorizingRecording = false
    /// Why Touch ID is about to ask. Shown first, so the fingerprint prompt never comes unexplained.
    @State private var touchPrompt: TouchPrompt?
    @State private var publicationTask: Task<Void, Never>?
    @State private var publicationStatus = ""
    @State private var versionStatus: [String: String] = [:]
    @State private var notice: String?
    /// Briefly true after processing succeeds, so the popup can show "Verified" before closing.
    @State private var copied = false
    @State private var textCopied = false
    /// Processing estimate: share already done and expected seconds for the rest.
    @State private var proofPlan: (base: Double, seconds: Double)?
    @State private var provingRemotely = false
    @AppStorage("touchIDIntroSeen") private var touchIDIntroSeen = false
    /// Share the writing replay with the page, so readers can watch it being written.
    @AppStorage("shareReplay") private var shareReplay = true
    /// The shared page's replay is being turned on or off.
    @State private var replayChanging = false
    @State private var requestTask: Task<Void, Never>?
    /// nil: hidden. false: welcome on first launch. true: opened by typing, so Continue starts the session.
    @State private var intro: Bool?
    /// A finished page waiting for "Share this page?": sharing publishes it to huma.social.

    private var hasVerifiedReplayProof: Bool { draft.replayProof != nil && verifiedReplayProof == draft.replayProof }

    private var draft: Draft { document.draft }
    private var words: Int { draft.text.split(whereSeparator: \.isWhitespace).count }
    private var bytes: Int { draft.text.utf8.count }
    private var pageTitle: String { draft.title.isEmpty ? "Untitled" : draft.title }
    private var characters: Int { draft.text.unicodeScalars.count }
    private var canProve: Bool {
        !busy && draft.session.signedCheckpoints?.last?.isFinal == true && !draft.text.isEmpty && characters <= 10_000
            && (draft.session.presenceProtocol != "local-presence-v1" || draft.session.experimentalCompactSnapshot != nil
                || draft.session.longCompactSnapshot != nil)
    }
    private var status: DocumentStatus {
        switch sessionState {
        case .recording: return .writing
        case .draft:
            guard hasSignedHistory else { return .draft }
            return draft.session.signedCheckpoints?.last?.isFinal == true ? .edited : .interrupted
        case .sealed:
            if proofTask != nil { return .processing }
            if hasVerifiedReplayProof { return proofLink != nil ? .shared : .verified }
            return .finished
        }
    }

    var body: some View {
        HStack(spacing: 0) {
            if showSidebar {
                Sidebar(currentURL: fileURL, currentTitle: pageTitle, status: status) {
                    withAnimation(.easeOut(duration: 0.15)) { showSidebar = false }
                }
                    .frame(width: 240).background(Theme.sidebar)
                Rectangle().fill(Theme.divider).frame(width: 1)
            }
            VStack(spacing: 0) {
                DocHeader(title: $document.draft.title, subtitle: headerSubtitle, sidebarShown: showSidebar,
                          toggleSidebar: { withAnimation(.easeOut(duration: 0.15)) { showSidebar.toggle() } },
                          actions: { headerActions }, formatBar: { formatBar }, showsFormatBar: !readOnly)
                Rectangle().fill(Theme.divider).frame(height: 1)
                HStack(spacing: 0) {
                    page
                    if showTimeline {
                        Rectangle().fill(Theme.divider).frame(width: 1)
                        TimelinePanel(entries: DocumentTimeline.entries(draft: draft, status: status,
                            background: captureSigner.chunks.status(characters: characters, recording: captureSigner.recording),
                            verified: hasVerifiedReplayProof), close: { withAnimation(.easeOut(duration: 0.15)) { showTimeline = false } }) {
                            versionsList } details: { technicalDetails }
                            .frame(width: 290)
                    }
                }
            }
        }
        .background(Theme.page)
        .ignoresSafeArea(.container, edges: .top)
        .frame(minWidth: 900, minHeight: 560)
        .overlay { if let touchPrompt { touchPromptCard(touchPrompt) } }
        .onChange(of: document.draft.session.head) { _, _ in proofTask?.cancel(); publicationTask?.cancel(); captureSummary = nil; replayStatus = ""; verifiedReplayProof = nil }
        .onChange(of: document.draft.session.id) { _, _ in proofTask?.cancel(); publicationTask?.cancel(); captureSummary = nil; replayStatus = ""; verifiedReplayProof = nil }
        .onAppear { refreshSummary(); if let proof = draft.replayProof { verifyReplayProof(proof) } }
        .onChange(of: document.draft.replayProof) { _, proof in
            if let proof, proof != verifiedReplayProof { verifyReplayProof(proof) }
            else if proof == nil { verifiedReplayProof = nil }
        }
        .onChange(of: status, initial: true) { _, status in
            store.prepareToLeave = { prepareToLeave() }
            store.leaveBlocker = status == .processing ? "This page is still processing. It takes a few seconds." : nil
        }
        .background(WindowCloseGuard(blocked: status == .writing || status == .processing))
        .onDisappear { proofTask?.cancel(); publicationTask?.cancel(); DockProgress.show(nil) }
        .task(id: draft.publicProof?.url) {
            await refreshShortLink()
            await refreshReplayState()
            await refreshReceipt()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
            // Stops the background part too, so its worker doesn't keep running after Huma quits.
            proofTask?.cancel(); publicationTask?.cancel(); captureSigner.chunks.reset(sessionID: nil)
        }
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
            if !busy, captureSigner.presenceDue(sessionID: draft.session.id) { confirmPresence(final: false) }
            else if !busy { captureSigner.idle(draft: draft) }
            DockProgress.show(dockFraction)
        }
        .onReceive(NotificationCenter.default.publisher(for: .humaFinish)) { _ in if status == .writing, !busy { sealSignedSession() } }
        .onReceive(NotificationCenter.default.publisher(for: .humaCopyLink)) { _ in if let shareLink { copyLink(shareLink) } }
        .onReceive(NotificationCenter.default.publisher(for: .humaVersionHistory)) { _ in
            if !draft.session.events.isEmpty || !(draft.versions ?? []).isEmpty { showHistory = true }
        }
        .onReceive(NotificationCenter.default.publisher(for: .humaExportReport)) { _ in if draft.replayProof != nil { exportReport() } }
        // A keyboard plugged in while writing: say so at once, not after the score drops.
        .onReceive(NotificationCenter.default.publisher(for: KeyboardGuard.changed)) { _ in
            if captureSigner.recording, let keyboard = KeyboardGuard.shared.blocked { show(Self.externalKeyboardMessage(keyboard.name)) }
        }
        .sheet(isPresented: $showHistory) { VersionHistoryView(draft: draft) { showHistory = false } }
        .onReceive(NotificationCenter.default.publisher(for: .humaFindPages)) { _ in
            if !showSidebar { withAnimation(.easeOut(duration: 0.15)) { showSidebar = true } }
        }
        // The window's name in the Window menu, Mission Control and the Dock.
        .navigationTitle(pageTitle)
        // While the share window is open, errors show in it, on the step that failed.
        .alert("Huma", isPresented: Binding(get: { errorMessage != nil && !showShare }, set: { if !$0 { errorMessage = nil } })) {
            Button("OK") { errorMessage = nil }
        } message: { Text(errorMessage ?? "") }
        .sheet(isPresented: $showLink) { linkSheet }
    }

    // MARK: Page

    private var page: some View {
        VStack(alignment: .leading, spacing: 0) {
            RichTextEditor(document: $document, commands: commands, captureSigner: captureSigner,
                           requestStart: { typedWhileStopped() },
                           pasteRefused: { show("Type a few words to start recording, then paste. Pasted text is marked on your page.") },
                           untypedRefused: { show("Type \u{201C}\($0.count > 60 ? String($0.prefix(60)) + "…" : $0)\u{201D} to fix it. Fixes you type keep your page typed.") },
                           keyRefused: { show("Only keys typed on a keyboard count. Typing from other apps is ignored.") },
                           oversizedKeyRefused: { show("One key press can add a character or a short word. More than that is written for you, so it wasn’t added.") },
                           pausedRefused: { if captureSigner.paused { show("Paused. Press Resume to keep writing.") } }, readOnly: readOnly) { errorMessage = $0 }
                .disabled(authorizingRecording)
            statusBar
                .sheet(isPresented: $showShare, onDismiss: { errorMessage = nil; copied = false }) { shareSheet }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(Theme.page)
        .onAppear { if !onboarded && !captureSigner.recording { intro = false } }
        .sheet(isPresented: Binding(get: { intro != nil }, set: { if !$0 { intro = nil } })) {
            Onboarding(startsSession: intro == true, step: touchIDIntroSeen ? Onboarding.signInStep : nil, account: settings.account, onDone: {
                let start = intro == true
                touchIDIntroSeen = true; intro = nil
                if start { startSignedSession() }
            }, onSkip: { intro = nil }, signIn: signInFromOnboarding)
        }
    }

    /// Bottom status bar: what is happening now, the one action if any, and a ▮▮▮▯▯ meter
    /// for how much of the page has been processed. The status name itself is the header tag.
    private var statusBar: some View {
        StatusBar(highlighted: captureSigner.presencePending, recording: status == .writing && !captureSigner.presencePending && !captureSigner.paused) {
            if let notice {
                Image(systemName: "info.circle").foregroundStyle(Theme.accent); Text(notice).foregroundStyle(Theme.text)
            } else { statusDetail }
        } trailing: {
            processingMeter
            if commands.composition.pasted > 0, commands.composition.total > 0 {
                let percent = max(1, Int((Double(commands.composition.pasted) / Double(commands.composition.total) * 100).rounded()))
                HStack(spacing: 5) {
                    RoundedRectangle(cornerRadius: 2).fill(Color.orange.opacity(0.35)).frame(width: 10, height: 10)
                    Text("\(percent)% pasted").foregroundStyle(Theme.secondary)
                }
                .help("Pasted text is tinted orange here and marked on your shared page. It doesn’t count toward your score.")
            }
            if commands.suggestions > 0, !readOnly {
                QuietButton(title: commands.suggestions == 1 ? "1 Suggestion" : "\(commands.suggestions) Suggestions", icon: "text.badge.checkmark") {
                    commands.nextSuggestion?()
                }
                .help("Selects the next spelling or grammar fix. Type it, so your page stays typed.")
            }
            if characters > 0 {
                Text("\(words) \(words == 1 ? "word" : "words")").foregroundStyle(Theme.tertiary).help("\(characters) characters")
                if characters > 10_000 { Text("over 10,000 characters").foregroundStyle(Theme.warning) }
            }
        }
    }
    private func headline(_ title: String, _ detail: String? = nil) -> some View {
        HStack(spacing: 6) {
            Text(title).foregroundStyle(Theme.text)
            if let detail { Text("·").foregroundStyle(Theme.tertiary); Text(detail).lineLimit(1) }
        }
    }
    @ViewBuilder private var statusDetail: some View {
        switch status {
        case .draft:
            Image(systemName: "pencil").foregroundStyle(Theme.tertiary)
            headline(isImported ? "Imported page" : "Not recording", isImported ? "can’t be shared" : "type to start")
            if isImported { newPageButton }
        case .writing where captureSigner.paused && !captureSigner.presencePending:
            Image(systemName: "pause.circle.fill").foregroundStyle(Theme.warning)
            headline("Paused", "the timer keeps running")
            QuietButton(title: "Resume", icon: "play.fill", prominent: true) { resumeWriting() }.disabled(busy)
        case .writing where captureSigner.presencePending:
            Image(systemName: "touchid").foregroundStyle(Theme.accent)
            headline("Waiting for Touch ID", "shows it’s still you")
        case .writing:
            RecordingDot()
            headline(Self.writer.map { "Recording \($0)’s writing" } ?? "Recording your writing")
            finishProgress
            if draft.text.isEmpty { QuietButton(title: "Start Over", icon: "arrow.counterclockwise") { startOver() }.disabled(busy) }
            else {
                QuietButton(title: "Pause", icon: "pause.fill") { captureSigner.pause() }.disabled(busy)
            }
        case .finished:
            if draft.replayProof == nil {
                Image(systemName: "checkmark.circle").foregroundStyle(Theme.warning)
                if canProve {
                    headline("Finished")
                    QuietButton(title: "Process Page", icon: "gearshape.2") { generateReplayProof() }
                } else if draft.text.isEmpty { headline("Empty page", "type to start again") }
                else { headline("Can’t be processed"); newPageButton }
            } else if replayStatus == "Verification failed.", let proof = draft.replayProof {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(Theme.warning)
                headline("Couldn’t verify")
                QuietButton(title: "Check Again", icon: "arrow.clockwise") { verifyReplayProof(proof) }
                if canProve { QuietButton(title: "Process Again", icon: "gearshape.2") { generateReplayProof() } }
            } else {
                ProgressView().controlSize(.mini); headline("Checking…")
            }
        case .processing:
            ProgressView().controlSize(.mini)
            headline("Processing", "on this Mac")
            QuietButton(title: "Cancel") { proofTask?.cancel() }
        case .verified, .shared:
            Image(systemName: "checkmark.seal.fill").foregroundStyle(Theme.success)
            headline(status == .shared ? "Verified and published" : "Verified", verificationSummary)
        case .edited:
            Image(systemName: "exclamationmark.circle").foregroundStyle(Theme.warning)
            headline("Changed after finishing"); newPageButton
        case .interrupted:
            Image(systemName: "exclamationmark.triangle").foregroundStyle(Theme.warning)
            headline("Not finished", "can’t be shared"); newPageButton
        }
    }
    /// Key presses typed this session, as the proof counts them (held-key repeats don't count).
    private var keyPresses: Int { draft.session.inputSamples?.filter { $0.kind == "down" && $0.origin?.isRepeat != true }.count ?? 0 }
    /// What Finish needs, live while writing, so it never surprises anyone.
    private var finishProgress: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            let seconds = Int((captureSigner.elapsedMilliseconds(sessionID: draft.session.id) ?? 0) / 1_000)
            if keyPresses >= 30 && seconds >= 20 {
                Label("Ready to finish", systemImage: "checkmark").foregroundStyle(Theme.success).labelStyle(.titleAndIcon)
            } else {
                Text("\(min(keyPresses, 30))/30 keys · \(min(seconds, 20))/20 s").monospacedDigit().foregroundStyle(Theme.tertiary)
                    .help("Finish needs at least 30 key presses and 20 seconds of writing.")
            }
        }
    }
    private var newPageButton: some View {
        QuietButton(title: "New Page", icon: "square.and.pencil") { store.newPage() }.disabled(busy)
    }
    /// How much of the page is processed. Parts proved while writing count as they finish;
    /// during the final step the meter follows the measured time estimate.
    @ViewBuilder private var processingMeter: some View {
        switch status {
        case .writing,
             .finished where draft.replayProof == nil:
            // Share of the proof already built: parts proved while writing, out of all parts plus the final step.
            if status == .writing || canProve {
            let parts = captureSigner.chunks.parts
            let fraction = parts.map { Double($0.done) / Double($0.total + 1) } ?? 0
            let wait = parts.map { NoirWritingProofService.finishSeconds(missingParts: $0.total - $0.done, characters: characters) }
                ?? (NoirWritingProofService.isLongSession(draft) ? NoirWritingProofService.estimatedLongSeconds(draft)
                    : NoirWritingProofService.shortSeconds(characters: characters))
            SegmentedProgress(fraction: fraction, tint: status == .writing ? Theme.danger : Theme.accent, active: status == .writing)
            Text(parts == nil ? "~\(Int(wait)) s at Finish" : "\(Int((fraction * 100).rounded()))% proved").monospacedDigit().foregroundStyle(Theme.text)
                .help(parts.map { "\($0.done) of \($0.total) parts proved · about \(Int(wait)) s left at Finish" } ?? "About \(Int(wait)) s to finish the proof at Finish")
            }
        case .processing:
            if let started = proofStartedAt, let plan = proofPlan {
                TimelineView(.periodic(from: started, by: 0.25)) { context in
                    let elapsed = context.date.timeIntervalSince(started)
                    SegmentedProgress(fraction: plan.base + (1 - plan.base) * min(0.95, elapsed / plan.seconds), active: true)
                    Text(elapsed < plan.seconds ? "about \(Int((plan.seconds - elapsed).rounded(.up))) s left" : "almost done").monospacedDigit()
                }
            }
        case .verified, .shared:
            SegmentedProgress(fraction: 1, tint: Theme.success)
        default: EmptyView()
        }
    }
    /// First name of this Mac's user, used only as a label for the recording.
    private static let writer: String? = NSFullUserName().split(separator: " ").first.map(String.init).flatMap { $0.isEmpty ? nil : $0 }
    private var verificationSummary: String? {
        guard let a = verifiedAssurance else { return nil }
        let rules = a.behavior.satisfied ? "rules met" : "some rules not met"
        return a.presence.map { "\(rules) · \($0.onTime) of \($0.challenges) checks on time" } ?? rules
    }
    private func show(_ message: String) {
        notice = message
        // Long enough to read: about 15 characters a second, and at least 4 seconds.
        Task { try? await Task.sleep(for: .seconds(max(4, Double(message.count) / 15))); if notice == message { notice = nil } }
    }
    /// Typing on a page that isn't recording starts (or continues) a session.
    private func typedWhileStopped() {
        guard !authorizingRecording, !captureSigner.recording else { return }
        if busy || status == .processing { NSSound.beep(); return }
        // Never let the first Touch ID prompt arrive unexplained.
        if !onboarded { intro = true; return }
        startSignedSession()
    }

    // MARK: Toolbar and Share

    // MARK: Header (title, actions, format bar)

    /// How far the proof is, for the Dock icon; nil when nothing is being proved.
    private var dockFraction: Double? {
        guard status == .processing, let started = proofStartedAt, let plan = proofPlan else { return nil }
        return plan.base + (1 - plan.base) * min(0.95, Date().timeIntervalSince(started) / plan.seconds)
    }
    private var headerSubtitle: String {
        let count = "\(words) \(words == 1 ? "word" : "words")"
        let asked = draft.request.map { "For \($0.from) · " } ?? ""
        if status == .writing && captureSigner.paused { return asked + "Paused · " + count }
        return asked + status.title + " · " + count
    }
    /// Notes-style: a glass capsule of small icons, then one main button.
    @ViewBuilder private var headerActions: some View {
        HStack(spacing: 2) {
            AppearanceMenu()
            HeaderIcon(icon: "clock.arrow.circlepath", help: showTimeline ? "Hide Timeline" : "Show Timeline", active: showTimeline) {
                withAnimation(.easeOut(duration: 0.15)) { showTimeline.toggle() }
            }
            moreMenu
        }
        .padding(.horizontal, 6).frame(height: 34).glassCapsule()
        if let action = primaryAction {
            Button(action: action.run) { Label(action.title, systemImage: action.icon) }
                .humaButton(.primary).disabled(action.disabled).help(action.help)
        }
    }
    /// The header's one main action: Finish while writing, Share once proved, New Page when a page can't be shared.
    private var primaryAction: (title: String, icon: String, help: String, disabled: Bool, run: () -> Void)? {
        switch status {
        case .writing:
            return ("Finish", "checkmark", "Finish and get your link", busy, { sealSignedSession() })
        case .processing, .verified, .shared:
            return (sharing ? "Sharing…" : proofLink == nil ? "Share" : "Shared",
                    proofLink == nil ? "square.and.arrow.up" : "globe",
                    "Share this page", false, { showShare = true })
        case .interrupted, .edited:
            return ("New Page", "square.and.pencil", "Write a new page", false, { store.newPage() })
        case .finished where !canProve:
            return ("New Page", "square.and.pencil", "Write a new page", false, { store.newPage() })
        case .draft where isImported:
            return ("New Page", "square.and.pencil", "Write a new page", false, { store.newPage() })
        default: return nil
        }
    }
    /// Everything else, in one menu, as in Notes.
    private var moreMenu: some View {
        Menu {
            switch status {
            case .writing:
                if captureSigner.paused { Button("Resume") { resumeWriting() }.disabled(busy) }
                else if !draft.text.isEmpty { Button("Pause") { captureSigner.pause() }.disabled(busy) }
                if draft.text.isEmpty { Button("Start Over") { startOver() }.disabled(busy) }
                else { Button("Stop Recording…") { confirmStop() }.disabled(busy) }
                Divider()
            case .processing: Button("Cancel Processing") { proofTask?.cancel() }; Divider()
            case .finished where canProve && draft.replayProof == nil: Button("Process Page") { generateReplayProof() }; Divider()
            default: EmptyView()
            }
            Button("New Page") { store.newPage() }
            if !draft.text.isEmpty { Button("Copy Text") { copyText() } }
            if let shareLink { Button("Copy Link") { copyLink(shareLink) } }
            if !draft.text.isEmpty { Button("Export Text…") { exportText() } }
            if !draft.session.events.isEmpty || !(draft.versions ?? []).isEmpty { Button("Version History…") { showHistory = true } }
            if draft.replayProof != nil { Button("Export Report…") { exportReport() } }
            Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([fileURL ?? PageStore.folder]) }
            if proofLink != nil { Divider(); Button("Remove Link…", role: .destructive) { confirmRemoveLink() }.disabled(busy || sharing) }
        } label: {
            Image(systemName: textCopied || copied ? "checkmark" : "ellipsis").font(.system(size: 14, weight: .medium))
                .foregroundStyle(textCopied || copied ? Theme.success : Theme.text).frame(width: 30, height: 28)
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize().help("More")
    }
    /// Docs-style formatting bar. Formatting never changes what is verified: only characters count.
    private var formatBar: some View {
        FormatBar(commands: commands) { showLink = true }
            .disabled(busy && status != .processing)
            .onAppear { commands.requestLink = { showLink = true } }
    }
    private var sharing: Bool { proofTask != nil || publicationTask != nil }
    private enum StepState { case waiting, active, done, failed, skipped }
    private var proveState: StepState {
        if hasVerifiedReplayProof { return .done }
        if proofTask != nil || replayStatus == "Checking…" { return .active }
        if errorMessage != nil || replayStatus == "Verification failed." { return .failed }
        return .waiting
    }
    private var linkState: StepState {
        if proofLink != nil { return .done }
        if publicationTask != nil { return .active }
        if hasVerifiedReplayProof && errorMessage != nil { return .failed }
        return .waiting
    }
    /// Share in one window, like onboarding: prove, then get the link.
    /// It can keep going in the background; the header button opens it again.
    private var shareSheet: some View {
        VStack(spacing: 0) {
            SheetTitle(title: proofLink != nil ? "Your link is ready" : "Sharing your page",
                       detail: "A link anyone can check.")
                .contentTransition(.opacity).animation(.easeOut(duration: 0.25), value: proofLink)
            // The two steps, grouped in one card like a Settings list.
            VStack(alignment: .leading, spacing: 0) {
                shareStep(proveState, "Prove you wrote it") { proveDetail }.padding(14)
                Divider().padding(.leading, 46)
                VStack(alignment: .leading, spacing: 10) {
                    shareStep(linkState, "Get your link") { linkDetail }
                    if let shareLink { linkRow(shareLink).padding(.leading, 32).transition(.opacity.combined(with: .move(edge: .top))) }
                    if let proofLink, let request = draft.request { requestRow(request, link: proofLink).padding(.leading, 32) }
                }
                .padding(14)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .humaCard(14)
            .padding(.top, 20)
            // Each step settles in as the one before it finishes.
            .animation(.spring(duration: 0.4, bounce: 0.15), value: [proveState, linkState])
            .animation(.spring(duration: 0.4, bounce: 0.15), value: proofLink)
            // Whether readers can watch the page being written: chosen before the link exists, and changeable after.
            if proofLink == nil || NoirWritingProofService.isLongSession(draft) {
                Toggle(isOn: replayChoice) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Let Readers Watch You Write").font(Theme.heading(13)).tracking(-0.1).foregroundStyle(Theme.text)
                        Text(replayDetail).font(Theme.sans(12)).foregroundStyle(Theme.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    // The label takes the free space, so the row is as wide as the steps card above it.
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .toggleStyle(.switch).controlSize(.small).tint(Theme.accent).disabled(publicationTask != nil || replayChanging)
                .padding(.horizontal, 14).padding(.vertical, 10)
                .frame(maxWidth: .infinity)
                .humaCard(14)
                .padding(.top, 10)
            }
            // The score readers will see: with the replay they can check every character; without it, typing counts at 60%.
            if let score = pageScore(withReplay: readersSeeReplay) {
                ScoreRow(score: score, note: readersSeeReplay || pageScore(withReplay: true) == score ? nil
                         : "With the replay on, readers would see \(pageScore(withReplay: true)?.value ?? score.value).")
                    .padding(.top, 10)
            }
            if let errorMessage, proveState != .failed, linkState != .failed {
                Text(errorMessage).font(Theme.sans(12.5)).foregroundStyle(Theme.warning)
                    .frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true).padding(.top, 10)
            }
            HStack(spacing: 8) {
                if sharing { Button("Stop") { proofTask?.cancel(); publicationTask?.cancel() }.humaButton() }
                Spacer()
                if let proofLink {
                    Button("Done") { showShare = false }.humaButton()
                    Button { NSWorkspace.shared.open(shareLink ?? proofLink) } label: { Label("Open Link", systemImage: "arrow.up.right").fixedSize() }
                        .humaButton(.primary).keyboardShortcut(.defaultAction)
                } else if sharing {
                    Button("Keep in Background") { showShare = false }.humaButton(.primary).keyboardShortcut(.defaultAction)
                } else {
                    Button("Not Now") { showShare = false }.humaButton()
                    if hasVerifiedReplayProof, let proof = draft.replayProof {
                        Button("Get Link") { errorMessage = nil; finishShare(proof) }.humaButton(.primary).keyboardShortcut(.defaultAction).disabled(busy)
                    } else if let proof = draft.replayProof {
                        Button("Check Again") { errorMessage = nil; verifyReplayProof(proof) }.humaButton(.primary).disabled(busy)
                    } else if canProve {
                        Button("Try Again") { errorMessage = nil; generateReplayProof() }.humaButton(.primary).keyboardShortcut(.defaultAction)
                    }
                }
            }
            .padding(.top, 20)
        }
        .padding(28).frame(width: 460)
        .humaSheetHeader()
        .presentationBackground(Theme.page)
    }
    private func shareStep<Detail: View>(_ state: StepState, _ title: String, @ViewBuilder detail: () -> Detail) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Group {
                switch state {
                case .waiting: Image(systemName: "circle").foregroundStyle(Theme.tertiary)
                case .active: ProgressView().controlSize(.small)
                case .done: Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.success).transition(.scale(scale: 0.4).combined(with: .opacity))
                case .failed: Image(systemName: "exclamationmark.circle.fill").foregroundStyle(Theme.warning)
                case .skipped: Image(systemName: "minus.circle").foregroundStyle(Theme.secondary)
                }
            }
            .font(Theme.sans(17)).frame(width: 20, height: 20)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(Theme.heading(14)).tracking(-0.1).foregroundStyle(state == .waiting ? Theme.tertiary : Theme.text)
                detail().font(Theme.sans(12.5)).foregroundStyle(Theme.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
    @ViewBuilder private var proveDetail: some View {
        switch proveState {
        case .active:
            if let started = proofStartedAt, let plan = proofPlan {
                TimelineView(.periodic(from: started, by: 0.25)) { context in
                    let elapsed = context.date.timeIntervalSince(started)
                    VStack(alignment: .leading, spacing: 8) {
                        Text((provingRemotely ? "Made on the Huma prover, checked on this Mac. " : "Made on this Mac. Nothing is uploaded yet. ")
                             + (elapsed < plan.seconds ? "About \(Int((plan.seconds - elapsed).rounded(.up))) s left." : "Almost done."))
                            .monospacedDigit()
                        SegmentedProgress(fraction: plan.base + (1 - plan.base) * min(0.95, elapsed / plan.seconds), active: true, segments: 26)
                    }
                }
            } else { Text(replayStatus == "Checking…" ? "Checking it on this Mac." : "Starting…") }
        case .done: Text("Checked on this Mac.")
        case .failed: Text(errorMessage ?? "This page couldn’t be checked.").foregroundStyle(Theme.warning)
        default: Text(replayStatus.isEmpty ? "Made on this Mac. Nothing is uploaded yet." : replayStatus)
        }
    }
    @ViewBuilder private var linkDetail: some View {
        switch linkState {
        case .active: Text(publicationStatus.isEmpty || proofLink != nil ? "Uploading your page." : publicationStatus)
        case .done: Text("Copy it and send it to anyone.")
        case .failed: Text(errorMessage ?? "Couldn’t get your link.").foregroundStyle(Theme.warning)
        default:
            Text(!publicationStatus.isEmpty ? publicationStatus
                 : settings.linkedWallet == nil ? "You sign in once in your browser. After that, Huma shares from this Mac." : "Your page goes to huma.social.")
        }
    }
    /// Takes the shared link down after asking. The page stays on this Mac and can be shared again.
    private func confirmRemoveLink() {
        guard let link = draft.publicProof?.url else { return }
        let alert = NSAlert()
        alert.messageText = "Remove this link?"
        alert.informativeText = "No one will be able to open it. Its text and proof are deleted from huma.social."
        alert.addButton(withTitle: "Remove Link"); alert.addButton(withTitle: "Cancel")
        alert.buttons.first?.hasDestructiveAction = true
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let client = try HostedPublicationClient(url: settings.registryURL)
                try await client.remove(link, publicKey: try PublishingKey.publicKeyHex(), sign: PublishingKey.sign)
                if draft.publicProof?.url == link { document.draft.publicProof = nil }
                show("Link removed.")
            } catch { errorMessage = "The link couldn’t be removed. " + error.localizedDescription }
        }
    }
    private func copyText() {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(draft.text, forType: .string)
        textCopied = true
        Task { try? await Task.sleep(for: .seconds(1.5)); textCopied = false }
    }
    /// The link, plus a titled version for rich editors (Mail, Gmail, Docs, Notion): "My Essay — ✓ Typed by a person".
    /// Plain fields (Slack, Messages, the address bar) get the link itself.
    private func copyLink(_ link: URL) {
        let board = NSPasteboard.general, escape = { (value: String) in
            value.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: "\"", with: "&quot;") }
        board.clearContents()
        board.setString(link.absoluteString, forType: .string)
        board.setString("<a href=\"\(escape(link.absoluteString))\">\(escape(pageTitle))</a> — ✓ Typed by a person, verified on Huma", forType: .html)
        copied = true
        Task { try? await Task.sleep(for: .seconds(1.5)); copied = false }
    }
    /// The page answers a writing request: send its link to whoever asked, signed by this Mac.
    @ViewBuilder private func requestRow(_ request: WritingRequest, link: URL) -> some View {
        HStack(spacing: 8) {
            if request.sentLink == link {
                Label("Sent to \(request.from)", systemImage: "checkmark.circle.fill").foregroundStyle(Theme.success)
                    .font(Theme.sans(13, .medium))
            } else {
                Text("\(request.from) asked for this page.").font(Theme.sans(12.5)).foregroundStyle(Theme.secondary)
                Spacer(minLength: 8)
                Button { sendToRequest(request, link: link) } label: {
                    if requestTask != nil { ProgressView().controlSize(.small) } else { Text("Send to \(request.from)") }
                }
                .humaButton(.primary, small: true).disabled(requestTask != nil)
            }
        }
    }
    private func sendToRequest(_ request: WritingRequest, link: URL) {
        guard requestTask == nil else { return }
        requestTask = Task {
            defer { requestTask = nil }
            do {
                try await HostedPublicationClient(url: settings.registryURL).send(link, to: request, sign: PublishingKey.sign)
                if draft.publicProof?.url == link { document.draft.request?.sentLink = link }
            } catch { errorMessage = "Couldn’t send it to \(request.from): " + error.localizedDescription }
        }
    }
    private func linkRow(_ link: URL) -> some View {
        // The link as people will see it: the site and the short link's path, or the start of the page's ID (the
        // whole link, key included, is what's copied).
        let id = link.lastPathComponent, short = link.path.hasPrefix("/p/")
        return HStack(spacing: 8) {
            Image(systemName: "link").font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.secondary)
            (Text(link.host() ?? "huma.social").foregroundStyle(Theme.text)
                + Text(short ? link.path : "/original/" + String(id.prefix(8)) + (id.count > 8 ? "…" : "")).foregroundStyle(Theme.secondary))
                .font(.system(size: 12.5, design: .monospaced)).lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button { copyLink(link) } label: { Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc").fixedSize() }
                .humaButton(small: true).help(link.absoluteString).accessibilityLabel("Copy Link")
        }
        .padding(.leading, 12).padding(.trailing, 4).frame(height: 38)
        .background(Theme.page, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.divider))
    }

    private var linkSheet: some View {
        VStack(spacing: 0) {
            SheetTitle(title: "Add Link")
            TextField("https://", text: $linkURL).textFieldStyle(.plain).font(Theme.sans(13))
                .padding(.horizontal, 12).frame(height: 36)
                .background(Theme.callout, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                .padding(.top, 16)
            HStack(spacing: 8) {
                Spacer()
                Button("Cancel") { showLink = false }.keyboardShortcut(.cancelAction).humaButton()
                Button("Add Link") { commands.link(linkURL); showLink = false }.keyboardShortcut(.defaultAction).humaButton(.primary)
            }
            .padding(.top, 18)
        }
        .padding(24).frame(width: 380).humaSheetHeader().presentationBackground(Theme.page)
    }

    /// The page's Huma score (HumaScore), once it has a proof: from the proof's statement and, when readers get the
    /// replay, from where each character came from.
    /// The replay switch: the choice for the next link, or for this page's link once it's shared.
    private var replayChoice: Binding<Bool> {
        proofLink == nil ? $shareReplay : Binding(get: { draft.publicProof?.replayShared ?? false }, set: { setReplay($0) })
    }
    private var replayDetail: String {
        if proofLink == nil { return "They see every change, including text you deleted." }
        if replayChanging { return "Updating your link…" }
        return draft.publicProof?.replayShared == true ? "They see every change, including text you deleted. You can turn it off at any time."
            : "Turn on to let readers of this link watch."
    }
    /// Turns the shared page's replay on or off for its readers, signed by this Mac. Turning it off deletes it from
    /// huma.social; anyone who already watched may have kept a copy.
    private func setReplay(_ on: Bool) {
        guard let link = draft.publicProof, !replayChanging, let client = try? HostedPublicationClient(url: settings.registryURL) else { return }
        let snapshot = draft
        replayChanging = true; errorMessage = nil
        Task {
            defer { replayChanging = false }
            do {
                let replay = on ? try snapshot.session.replayExport(text: snapshot.text) : nil
                if on, replay == nil { throw HumaError.configuration("This page has no replay to share.") }
                try await client.setReplay(link.url, replay: replay, publicKey: try PublishingKey.publicKeyHex(), sign: PublishingKey.sign)
                guard draft.publicProof?.url == link.url else { return }
                document.draft.publicProof?.replayShared = on
            } catch { errorMessage = error.localizedDescription }
        }
    }
    /// Links shared before the app kept the replay choice: asks the host once whether readers can watch.
    private func refreshReplayState() async {
        guard let link = draft.publicProof, link.replayShared == nil, let client = try? HostedPublicationClient(url: settings.registryURL),
              let receipt = try? await client.receipt(for: link.url), draft.publicProof?.url == link.url else { return }
        document.draft.publicProof?.replayShared = receipt.replay
    }
    /// Whether readers see the replay: as it was shared, or as the toggle says until then.
    private var readersSeeReplay: Bool { proofLink == nil ? shareReplay : (draft.publicProof?.replayShared ?? shareReplay) }
    private func pageScore(withReplay: Bool) -> HumaScore? {
        guard let proof = draft.replayProof, let summary = PageProofSummary(proof: proof) else { return nil }
        return summary.score(composition: withReplay ? TextProvenance(session: draft.session).composition : nil)
    }

    // MARK: Versions (timeline panel)

    @ViewBuilder private var versionsList: some View {
        if let versions = draft.versions, !versions.isEmpty {
            Divider().overlay(Theme.divider).padding(.vertical, 8)
            Text("Versions").monoLabel(11).foregroundStyle(Theme.secondary).padding(.bottom, 8)
            ForEach(Array(versions.enumerated().reversed()), id: \.element.id) { index, version in
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 6) {
                        Text("Version \(index + 1)").font(Theme.sans(13, .medium)).foregroundStyle(Theme.text)
                        Tag(title: version.publicProof == nil ? "Verified" : "Published", tone: version.publicProof == nil ? .green : .purple)
                    }
                    Text(version.text.prefix(90) + (version.text.count > 90 ? "…" : "")).font(Theme.sans(12)).foregroundStyle(Theme.secondary).lineLimit(2)
                    if let date = version.finishedAt {
                        Text(date, format: .dateTime.month(.abbreviated).day().hour().minute()).monoLabel(10).foregroundStyle(Theme.tertiary)
                    }
                    HStack(spacing: 6) {
                        if let link = version.publicProof.map({ $0.shortURL ?? $0.url }) { QuietButton(title: "Open Link") { NSWorkspace.shared.open(link) } }
                        QuietButton(title: versionStatus[version.id] ?? "Check") { checkVersion(version) }
                        QuietButton(title: "Export") { exportVersion(version) }
                    }
                }
                .padding(.bottom, 12)
            }
        }
    }
    private func checkVersion(_ version: PageVersion) {
        guard let old = draft.draft(for: version) else { versionStatus[version.id] = "History missing"; return }
        versionStatus[version.id] = "Checking…"
        Task {
            do { _ = try await ReplayProofService.verify(draft: old, proof: version.proof); versionStatus[version.id] = "Verified ✓" }
            catch { versionStatus[version.id] = "Did not verify" }
        }
    }
    private func exportVersion(_ version: PageVersion) {
        guard let old = draft.draft(for: version) else { errorMessage = "This version’s signed history is missing."; return }
        busy = true
        Task {
            defer { busy = false }
            do {
                let data = try await ReplayProofService.evidenceEnvelope(draft: old, proof: version.proof).encoded()
                let panel = NSSavePanel(); panel.nameFieldStringValue = (version.title.isEmpty ? "Huma" : version.title) + " verification.json"
                if panel.runModal() == .OK, let url = panel.url { try data.write(to: url, options: .atomic) }
            } catch { errorMessage = error.localizedDescription }
        }
    }

    // MARK: Technical details (timeline panel)

    @ViewBuilder private var technicalDetails: some View {
        detail("Edits", String(draft.session.events.count))
        detail("Pastes", String(draft.session.events.filter { $0.source == "paste" }.count))
        detail("Starting text", draft.session.initialText.isEmpty ? "Empty page" : "Imported")
        if let summary = captureSummary {
            detail("Signing key", String(summary.captureKeyHash.prefix(16)) + "…")
            if let time = summary.deviceReportedTime {
                detail("Elapsed", String(format: "%.1f s", Double(time.elapsedMilliseconds) / 1_000))
                if time.clockMovedBackwards { Text("The device clock moved backwards during this session.").foregroundStyle(Theme.warning) }
            }
        }
        if hasVerifiedReplayProof, let a = verifiedAssurance {
            detail("Input origin", "\(a.input.hidStateReported) keyboard · \(a.input.otherStateReported) other · \(a.input.missingOrigin) unknown")
            if let presence = a.presence { detail("Longest gap", presence.longestGapMilliseconds + " ms") }
            detail("Writing rules", a.behavior.satisfied ? "Met (experimental)" : "Not all met (experimental)")
        }
        if let evidence = draft.deviceEvidence { detail("Device evidence", "\(evidence.environment) · assertion \(evidence.signCount)") }
        #if DEBUG
        Button("Attest with device service") { attestSession() }.humaButton(small: true)
            .disabled(busy || settings.deviceBusy || draft.replayProof == nil || draft.session.signedCheckpoints?.last?.isFinal != true
                || draft.replayProof.map(NoirWritingProofService.isNoirProof) == true)
        #endif
        if !proofStatus.isEmpty { Text(proofStatus) }
        Text("Verification checks the signed edit history of this exact text, ignoring only trailing spaces and tabs. It does not by itself establish human typing, trusted calendar time or identity.")
            .font(Theme.sans(11.5)).foregroundStyle(Theme.tertiary).fixedSize(horizontal: false, vertical: true)
    }
    private func detail(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(Theme.secondary).frame(width: 96, alignment: .leading)
            Text(value).foregroundStyle(Theme.text).textSelection(.enabled)
        }
    }

    // MARK: State

    private enum SessionState { case draft, recording, sealed }
    private var sessionState: SessionState { captureSigner.recording ? .recording : sealedSession ? .sealed : .draft }
    /// Pages with text that aren't recording are finished (or can't be continued): read them, don't edit them.
    private var readOnly: Bool { !captureSigner.recording && !draft.text.isEmpty }
    private var hasSignedHistory: Bool { !(draft.session.signedCheckpoints?.isEmpty ?? true) }
    private var isImported: Bool { !hasSignedHistory && !draft.text.isEmpty }
    private var sealedSession: Bool {
        guard let last = draft.session.signedCheckpoints?.last else { return false }
        return last.isFinal && last.captureCount == (draft.session.captureRecords?.count ?? 0)
            && last.textHash == sha256(Data(draft.text.utf8))
    }

    private func refreshSummary() { captureSummary = try? draft.session.signedSummary(finalText: draft.text) }
    /// Starts writing; on a finished page this continues it. The verified version is kept in Versions.
    private func requestNewSession() { if onboarded { startSignedSession() } else { intro = true } }
    /// Onboarding is done once Touch ID was explained and this Mac has signed in.
    private var onboarded: Bool { touchIDIntroSeen && settings.account != nil }
    /// Opens the host's sign-in page and waits (up to ten minutes) for the browser to finish. The wallet also
    /// authorizes this Mac's publishing key there, so this is the only time sharing needs the browser.
    private func signInFromOnboarding() async throws -> String {
        let client = try HostedPublicationClient(url: settings.registryURL)
        let page = client.signInPage(publishingKey: try? PublishingKey.publicKeyHex())
        NSWorkspace.shared.open(page.url)
        let deadline = Date().addingTimeInterval(600)
        while Date() < deadline {
            try await Task.sleep(for: .seconds(1.5))
            // A dropped poll is retried; only the deadline ends the wait.
            guard let result = try? await client.signedIn(code: page.code) else { continue }
            settings.account = result.account
            settings.linkedWallet = result.macLinked ? result.wallet : nil
            NSApp.activate()
            return result.account
        }
        throw HumaError.configuration("Sign-in timed out. Try again.")
    }

    private func startSignedSession() {
        guard !authorizingRecording else { return }
        // Every session starts on an empty page: text from before it (imported, or an earlier session)
        // would count as not typed. So more writing goes on a new page.
        guard draft.text.isEmpty else {
            show(isImported ? "This page was imported, so it can’t be shared. Start a new page and type it in Huma."
                            : "This page is finished. Start a new page to write more.")
            return
        }
        if let keyboard = KeyboardGuard.shared.blocked { show(Self.externalKeyboardMessage(keyboard.name)) }
        let snapshot = draft
        authorizingRecording = true; busy = true
        Task {
            defer { authorizingRecording = false; busy = false; hideTouchPrompt() }
            await explainTouchID(.start)
            do {
                let context = try await TouchIDCaptureKey.authorize(reason: TouchPrompt.start.reason)
                guard sameCapture(as: snapshot) else { throw HumaError.invalidSession }
                try captureSigner.start(draft: &document.draft, context: context)
                // Undo can't bring back text from before this session (such as imported or pasted text).
                commands.editor?.undoManager?.removeAllActions()
                captureSummary = nil; replayStatus = ""
            } catch { if !TouchIDCaptureKey.isCancellation(error) { errorMessage = error.localizedDescription } }
        }
    }
    /// Stops recording without finishing. The page and its text are kept, view-only, and can't be shared.
    private func stopRecording() {
        guard captureSigner.recording, !busy else { return }
        if draft.text.isEmpty { startOver(); return }
        try? captureSigner.checkpoint(draft: &document.draft, force: true)
        captureSigner.cancel()
    }
    private func confirmStop() { if askToStop() { stopRecording() } }
    private func askToStop() -> Bool {
        let alert = NSAlert()
        alert.messageText = "Stop recording this page?"
        alert.informativeText = "You won’t be able to finish or share it. Your text is kept."
        alert.addButton(withTitle: "Keep Writing")
        alert.addButton(withTitle: "Stop Recording")
        return alert.runModal() == .alertSecondButtonReturn
    }
    /// Leaving a recording page: nothing typed starts it over; otherwise ask, and stop only if you say so.
    private func prepareToLeave() -> Bool {
        guard captureSigner.recording else { return true }
        if busy { NSSound.beep(); return false }
        if draft.text.isEmpty { startOver(); return true }
        guard askToStop() else { return false }
        stopRecording()
        return true
    }
    /// Nothing typed yet: end this session without finishing it, so the page is a fresh, empty draft.
    private func startOver() {
        guard captureSigner.recording, draft.text.isEmpty, !busy else { return }
        captureSigner.cancel()
        var fresh = Draft(); fresh.title = draft.title
        document.draft = fresh
        captureSummary = nil; replayStatus = ""
    }
    private func sealSignedSession() {
        // The writing rules need 30 key presses and 20 seconds, so say so before Finish, not after.
        let keys = keyPresses
        let elapsed = captureSigner.elapsedMilliseconds(sessionID: draft.session.id) ?? 0
        guard keys >= 30, elapsed >= 20_000 else {
            var more: [String] = []
            if keys < 30 { more.append("\(30 - keys) more key \(30 - keys == 1 ? "press" : "presses")") }
            if elapsed < 20_000 { let s = Int((20_000 - elapsed + 999) / 1_000); more.append("\(s) more \(s == 1 ? "second" : "seconds")") }
            show("Keep writing: " + more.joined(separator: " and ") + " to finish.")
            return
        }
        guard characters <= 10_000 else {
            show("Pages can be up to 10,000 characters. Remove \((characters - 10_000).formatted()) to finish.")
            return
        }
        confirmPresence(final: true)
    }
    /// Back from a break: Touch ID shows it's still you before typing continues. If it doesn't pass, the page stays paused.
    private func resumeWriting() { confirmPresence(final: false, resuming: true) }
    private func confirmPresence(final: Bool, resuming: Bool = false) {
        guard !authorizingRecording else { return }
        let prompt: TouchPrompt = final ? .finish : resuming ? .resume : .stillWriting
        authorizingRecording = true; busy = true
        Task {
            defer { authorizingRecording = false; busy = false; hideTouchPrompt() }
            // Explain first. The 10 seconds start once the check is issued, right before Touch ID opens.
            await explainTouchID(prompt)
            do { try captureSigner.beginPresence(draft: &document.draft, reason: final ? "seal" : "interval") }
            catch { errorMessage = error.localizedDescription; return }
            let snapshot = draft
            do {
                let context = try await TouchIDCaptureKey.authorize(reason: prompt.reason, timeoutSeconds: 10)
                guard sameCapture(as: snapshot) else { throw HumaError.invalidSession }
                let timely = try captureSigner.finishPresence(draft: &document.draft, context: context)
                if final && !timely { errorMessage = "Touch ID took longer than 10 seconds. Press Finish to try again." }
                if resuming { captureSigner.resume() }
                else if !final && !timely { show(Self.missedCheck) }
                try captureSigner.checkpoint(draft: &document.draft, force: true, final: final && timely)
                if final && timely {
                    captureSummary = try draft.session.signedSummary(finalText: draft.text)
                    // Most of the proof was made while writing; finish it now rather than on request.
                    // Runs after this task ends and clears `busy`.
                    Task { @MainActor in if canProve && draft.replayProof == nil { generateReplayProof() } }
                }
            } catch {
                if captureSigner.presencePending, draft.session.id == snapshot.session.id {
                    let issued = draft.session.presenceEvents?.last?.elapsedMilliseconds ?? 0
                    let elapsed = captureSigner.elapsedMilliseconds(sessionID: draft.session.id) ?? issued
                    _ = try? captureSigner.finishPresence(draft: &document.draft, context: nil,
                        failure: elapsed >= issued && elapsed - issued >= 10_000 ? "timedOut" : "cancelled")
                    try? captureSigner.checkpoint(draft: &document.draft, force: true)
                    if !final && !resuming { show(Self.missedCheck) }
                }
                if !TouchIDCaptureKey.isCancellation(error) { errorMessage = error.localizedDescription }
            }
        }
    }
    static let missedCheck = "You missed a Touch ID check. You can keep writing and share, but readers will see that a check was missed."
    /// Typing on a non-Apple keyboard is recorded and marked: Huma can't tell its key presses from a device that types
    /// by itself (a programmable board can pass as one), so that typing counts for less in the page's score.
    static func externalKeyboardMessage(_ keyboard: String) -> String {
        "Typing on “\(keyboard)” counts for less in your score. Your Mac’s keyboard and Apple keyboards count fully."
    }
    private func explainTouchID(_ prompt: TouchPrompt) async {
        withAnimation(.spring(duration: 0.3, bounce: 0.15)) { touchPrompt = prompt }
        try? await Task.sleep(for: .milliseconds(1200))
    }
    private func hideTouchPrompt() { withAnimation(.easeOut(duration: 0.15)) { touchPrompt = nil } }
    private func touchPromptCard(_ prompt: TouchPrompt) -> some View {
        ZStack {
            Color.black.opacity(0.12).ignoresSafeArea()
            VStack(spacing: 10) {
                Image(systemName: "touchid").font(.system(size: 30)).foregroundStyle(Theme.accent)
                    .symbolEffect(.pulse, options: .repeating)
                    .frame(width: 56, height: 56).overlay(Circle().strokeBorder(Theme.divider))
                Text(prompt.title).font(Theme.heading(17)).tracking(-0.1).foregroundStyle(Theme.text).padding(.top, 6)
                Text(prompt.detail).font(Theme.sans(13)).foregroundStyle(Theme.secondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                Text("Place your finger on Touch ID.").font(Theme.sans(12)).foregroundStyle(Theme.tertiary).padding(.top, 4)
            }
            .padding(28).frame(width: 340)
            .background(Theme.page, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).strokeBorder(Theme.divider))
            .shadow(color: .black.opacity(0.18), radius: 24, y: 8)
        }
        .transition(.opacity.combined(with: .scale(scale: 0.96)))
        .accessibilityElement(children: .combine)
    }
    private func clockDate(_ milliseconds: UInt64) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date(timeIntervalSince1970: Double(milliseconds) / 1_000))
    }
    private func sameCapture(as snapshot: Draft) -> Bool {
        exactTextEqual(draft.text, snapshot.text) && draft.session.id == snapshot.session.id
            && draft.session.captureHead == snapshot.session.captureHead
            && draft.session.signedCheckpoints?.last?.digest == snapshot.session.signedCheckpoints?.last?.digest
    }
    private func generateReplayProof() {
        guard proofTask == nil else { return }
        var snapshot = draft
        let prover = ProverChoice.selectedProver
        busy = true; proofStartedAt = .now; replayStatus = ""; provingRemotely = prover != nil; showShare = true
        proofTask = Task {
            defer { busy = false; proofTask = nil; proofStartedAt = nil; proofPlan = nil; provingRemotely = false }
            do {
                if snapshot.session.longCompactSnapshot != nil {
                    // Parts proved while writing are reused; only the rest and the final step remain.
                    let (fresh, tier) = await captureSigner.chunks.collect(sessionID: snapshot.session.id)
                    // Saved parts made before the text outgrew its tier are proved again.
                    var parts = (snapshot.session.longChunkProofs ?? []).filter { tier == nil || $0.tier == tier }
                    for proof in fresh where !parts.contains(where: { $0.index == proof.index }) {
                        parts.append(proof)
                    }
                    parts.sort { $0.index < $1.index }
                    snapshot.session.longChunkProofs = parts
                    if sameCapture(as: snapshot) { document.draft.session.longChunkProofs = parts }
                    replayStatus = parts.isEmpty ? "" : "\(parts.count) parts were processed while you wrote; finishing the rest."
                }
                let characters = snapshot.text.unicodeScalars.count
                if NoirWritingProofService.isLongSession(snapshot) {
                    let total = NoirWritingProofService.longChunkCount(snapshot)
                    proofPlan = (Double(snapshot.session.longChunkProofs?.count ?? 0) / Double(total + 1),
                                 NoirWritingProofService.estimatedLongSeconds(snapshot))
                } else { proofPlan = (0, NoirWritingProofService.shortSeconds(characters: characters) + 1) }
                proofStartedAt = .now
                let (proof, journal, source) = try await ReplayProofService.proveValidated(snapshot, prover: prover)
                guard sameCapture(as: snapshot) else { replayStatus = "The session changed. Process the current version."; return }
                document.draft.deviceEvidence = nil
                document.draft.publicProof = nil
                document.draft.replayProof = proof
                document.draft.replayProofTextHash = sha256(Data(snapshot.text.utf8))
                // The page proof carries every part's proof, so the ones made while writing aren't kept.
                document.draft.session.longChunkProofs = nil
                verifiedReplayProof = proof
                verifiedAssurance = journal.assurance
                captureSummary = try snapshot.session.signedSummary(finalText: snapshot.text)
                switch source {
                case .mac: replayStatus = "Verified on this Mac."
                case .server: replayStatus = "Proved by the Huma prover and verified on this Mac."
                case .macAfterServer(let reason): replayStatus = "\(reason) Proved and verified on this Mac instead."
                }
                // Finish means share (onboarding says so): on a linked Mac the link comes straight back from the
                // host. Runs after this task ends, so `busy` is already released.
                Task { @MainActor in
                    if draft.replayProof == proof, draft.publicProof == nil, settings.linkedWallet != nil { showShare = true; finishShare(proof) }
                }
            } catch is CancellationError {
                replayStatus = "Processing cancelled. Your writing is unchanged."
            } catch { replayStatus = ""; errorMessage = error.localizedDescription }
        }
    }
    private func verifyReplayProof(_ proof: Data) {
        guard proofTask == nil else { return }
        let snapshot = draft; busy = true
        verifiedReplayProof = nil; replayStatus = "Checking…"
        Task {
            defer { busy = false }
            do {
                let journal = try await ReplayProofService.verify(draft: snapshot, proof: proof)
                guard sameCapture(as: snapshot), draft.replayProof == proof else { return }
                captureSummary = try snapshot.session.signedSummary(finalText: snapshot.text)
                verifiedReplayProof = proof
                verifiedAssurance = journal.assurance
                replayStatus = "Verified on this Mac."
            } catch {
                guard sameCapture(as: snapshot), draft.replayProof == proof else { return }
                verifiedReplayProof = nil; replayStatus = "Verification failed."; errorMessage = error.localizedDescription
            }
        }
    }
    private func exportEvidenceEnvelope(_ proof: Data) {
        let snapshot = draft; busy = true
        Task {
            defer { busy = false }
            do {
                let envelope = try await ReplayProofService.evidenceEnvelope(draft: snapshot, proof: proof)
                let data = try envelope.encoded()
                guard sameCapture(as: snapshot), draft.replayProof == proof else { return }
                let panel = NSSavePanel(); panel.nameFieldStringValue = "Huma-evidence.json"
                if panel.runModal() == .OK, let url = panel.url { try data.write(to: url, options: .atomic) }
            } catch { errorMessage = error.localizedDescription }
        }
    }
    private func exportReplayProof(_ proof: Data, disclosure: Int) {
        let snapshot = draft; busy = true
        Task {
            defer { busy = false }
            do {
                _ = try await ReplayProofService.verify(draft: snapshot, proof: proof)
                guard sameCapture(as: snapshot), draft.replayProof == proof else { return }
                let noir = NoirWritingProofService.isNoirProof(proof)
                var object: [String: Any]
                if noir {
                    object = disclosure == 0 ? (try JSONSerialization.jsonObject(with: proof) as! [String: Any])
                        : ["kind": "huma-writing-disclosure-v1", "proof": String(decoding: proof, as: UTF8.self)]
                } else {
                    object = ["text": snapshot.text, "bundle": try JSONSerialization.jsonObject(with: proof)]
                }
                if disclosure >= 1, let key = snapshot.session.signedCheckpoints?.first?.publicKey {
                    object["capturePublicKey"] = ["format": "p256-x963-base64", "value": key.base64EncodedString()]
                }
                if disclosure >= 2 {
                    object["session"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(snapshot.session))
                }
                let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .prettyPrinted])
                let panel = NSSavePanel()
                panel.nameFieldStringValue = disclosure >= 2 ? "Huma-revealed-session.json" : "Huma-replay-proof.json"
                if panel.runModal() == .OK, let url = panel.url { try data.write(to: url, options: .atomic) }
            } catch { errorMessage = error.localizedDescription }
        }
    }
    private func exportPortableDeviceEvidence(_ proof: Data) {
        let snapshot = draft; busy = true
        Task {
            defer { busy = false }
            do {
                _ = try await ReplayProofService.verify(draft: snapshot, proof: proof)
                guard sameCapture(as: snapshot), draft.replayProof == proof, let evidence = snapshot.deviceEvidence else { return }
                let portable = try evidence.portable(draft: snapshot)
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
                let data = try encoder.encode(portable)
                let panel = NSSavePanel(); panel.nameFieldStringValue = "Huma-device-evidence.json"
                if panel.runModal() == .OK, let url = panel.url { try data.write(to: url, options: .atomic) }
            } catch { errorMessage = error.localizedDescription }
        }
    }
    /// Saves the finished page's PDF report (PageReport), the same as a reader's, with the page's proof inside.
    private func exportReport() {
        guard let proof = draft.replayProof, let summary = PageProofSummary(proof: proof) else { return }
        // A page without a title goes by its first line, as on the shared page's report.
        let line = draft.text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "\n").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        let title = !draft.title.isEmpty ? draft.title : line.count <= 140 ? line : String(line.prefix(140))
        let file = title.count <= 60 ? title : String(title.prefix(60)).replacingOccurrences(of: "\\s+\\S*$", with: "", options: .regularExpression)
        let panel = NSSavePanel(); panel.nameFieldStringValue = (file.isEmpty ? "Untitled" : file) + " – Huma report.pdf"
        panel.allowedContentTypes = [.pdf]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let snapshot = draft, provenance = TextProvenance(session: draft.session)
        // What readers see: the make-up of the text when the replay goes with the link (or will), and the score from it.
        let composition = readersSeeReplay ? provenance.composition : nil
        let name = Profile.shared.name.trimmingCharacters(in: .whitespacesAndNewlines)
        show("Saving the report…")
        Task {
            do {
                // The evidence file readers download goes inside, so the PDF alone can be checked again.
                let evidence = try await ReplayProofService.evidenceEnvelope(draft: snapshot, proof: proof).encoded()
                let data = try PageReport.make(.init(title: title, writer: name.isEmpty ? nil : name, text: snapshot.text, provenance: provenance,
                    summary: summary, score: summary.score(composition: composition), composition: composition, link: shareLink,
                    proof: proof, evidence: evidence))
                try data.write(to: url, options: .atomic)
                notice = nil
                NSWorkspace.shared.activateFileViewerSelecting([url])
            } catch { notice = nil; errorMessage = error.localizedDescription }
        }
    }
    private func exportText() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = (draft.title.isEmpty ? "Untitled" : draft.title) + ".txt"
        if panel.runModal() == .OK, let url = panel.url {
            do { try Data(draft.text.utf8).write(to: url, options: .atomic) } catch { errorMessage = error.localizedDescription }
        }
    }
    private func attestSession() {
        busy = true; settings.deviceBusy = true
        let snapshot = draft
        Task {
            defer { busy = false; settings.deviceBusy = false }
            do {
                let evidence = try await AppAttestClient(url: settings.deviceServiceURL).seal(draft: snapshot)
                guard try AppAttestBinding(draft: draft) == evidence.binding else {
                    proofStatus = "The session changed. Attest the current sealed version."; return
                }
                document.draft.deviceEvidence = evidence
                proofStatus = "Session assertion accepted by the configured device service. This does not establish human authorship."
            } catch { errorMessage = error.localizedDescription }
        }
    }
    /// Asks the host once for the page's short link; until then, or if it can't, the full link is shared.
    private func refreshShortLink() async {
        guard let link = draft.publicProof, link.shortURL == nil, let client = try? HostedPublicationClient(url: settings.registryURL),
              let short = try? await client.shortLink(for: link.url), draft.publicProof?.url == link.url else { return }
        document.draft.publicProof?.shortURL = short
    }
    /// Fetches who signed the published page, as the host says.
    private func refreshReceipt() async {
        guard publicationTask == nil, let link = draft.publicProof, let client = try? HostedPublicationClient(url: settings.registryURL),
              let receipt = try? await client.receipt(for: link.url), draft.publicProof?.url == link.url,
              receipt.signer != link.signer else { return }
        document.draft.publicProof?.signer = receipt.signer
    }
    /// Finish's share: the page goes to the host signed by this Mac's publishing key, which the account linked
    /// at sign-in, so there's no browser. Without a linked Mac, sign in once first.
    private func finishShare(_ proof: Data) {
        guard publicationTask == nil else { return }
        guard let wallet = settings.linkedWallet else { linkThenShare(proof); return }
        let snapshot = draft; busy = true; publicationStatus = "Uploading your page."
        publicationTask = Task {
            defer { busy = false; publicationTask = nil }
            do {
                let client = try HostedPublicationClient(url: settings.registryURL)
                let envelope = try await ReplayProofService.evidenceEnvelope(draft: snapshot, proof: proof), replay = replay(of: snapshot)
                let pending = try await client.prepare(text: snapshot.text, envelope: envelope, replay: replay)
                let download = try await client.publishFromThisMac(pending, wallet: wallet, publicKey: try PublishingKey.publicKeyHex(),
                                                                   profile: Profile.shared.shared, sign: PublishingKey.sign)
                try await adopt(download, snapshot: snapshot, proof: proof, sent: envelope, replayShared: replay != nil)
                publicationStatus = "Your link is ready to copy."
                Notifier.post("Your link is ready", "“\(pageTitle)” is shared. Copy the link in Huma.", page: fileURL)
            } catch is CancellationError { publicationStatus = "Stopped. Your page wasn’t shared." }
            catch { publicationStatus = ""; errorMessage = error.localizedDescription }
        }
    }
    /// Pages from before this Mac was linked: sign in once (it links the Mac), then share as usual.
    private func linkThenShare(_ proof: Data) {
        let snapshot = draft; busy = true
        publicationStatus = "Sign in once in your browser so Huma can share from this Mac." + ((try? PublishingKey.shortCode()).map { " It should show \($0)." } ?? "")
        publicationTask = Task {
            do { _ = try await signInFromOnboarding() } catch { publicationStatus = "" }
            busy = false; publicationTask = nil
            guard settings.linkedWallet != nil, draft.replayProof == proof, sameCapture(as: snapshot) else {
                if settings.linkedWallet == nil { publicationStatus = "Couldn’t connect this Mac. Press Share to try again." }
                return
            }
            finishShare(proof)
        }
    }
    /// The replay readers can watch, when the writer chose to share it and the session is sealed.
    private func replay(of snapshot: Draft) -> Data? {
        shareReplay && NoirWritingProofService.isLongSession(snapshot) ? try? snapshot.session.replayExport(text: snapshot.text) : nil
    }
    /// The nine writing rules a page proof reports, in the words readers see (WRITING_RULES in publication-contract.mjs).
    nonisolated static let writingRules = ["it started from imported text", "some text wasn’t typed", "it was typed for less than 20 seconds",
                               "it has fewer than 30 key presses", "some key presses looked unusual", "key holds looked unusual",
                               "the typing rhythm looked unusual", "there was no natural pause", "the typing speed looked unusual"]
    /// Checks a published page the way a reader would, on this Mac, before saving its link.
    private func adopt(_ download: HostedPublicationClient.Download, snapshot: Draft, proof: Data, sent: EvidenceEnvelope, replayShared: Bool) async throws {
        guard exactTextEqual(String(decoding: download.master, as: UTF8.self), snapshot.text),
              let publicRecord = try JSONSerialization.jsonObject(with: Data(download.envelope.proof.utf8)) as? [String: Any] else { throw HumaError.invalidResponse }
        let downloadedProof: Data
        if NoirWritingProofService.isNoirProof(Data(download.envelope.proof.utf8)) {
            downloadedProof = Data(download.envelope.proof.utf8)
        } else if let bundle = publicRecord["bundle"] {
            downloadedProof = try JSONSerialization.data(withJSONObject: bundle, options: [.sortedKeys])
        } else { throw HumaError.invalidResponse }
        // The host returned exactly the proof this Mac made and verified, so checking it again only adds a wait.
        if download.envelope.proof != sent.proof || proof != verifiedReplayProof {
            _ = try await ReplayProofService.verify(draft: snapshot, proof: downloadedProof)
        }
        try Task.checkCancellation()
        guard sameCapture(as: snapshot), draft.replayProof == proof else { throw CancellationError() }
        document.draft.publicProof = PublicProofLink(url: download.url, proof: proof, draft: snapshot)
        document.draft.publicProof?.replayShared = replayShared
        showShare = true
    }
    private func shareMaster(_ proof: Data) {
        guard publicationTask == nil else { return }
        let snapshot = draft; busy = true; publicationStatus = "Preparing your page."
        publicationTask = Task {
            defer { busy = false; publicationTask = nil }
            do {
                let envelope = try await ReplayProofService.evidenceEnvelope(draft: snapshot, proof: proof)
                let client = try HostedPublicationClient(url: settings.registryURL)
                let replay = replay(of: snapshot)
                let pending = try await client.prepare(text: snapshot.text, envelope: envelope, replay: replay)
                try Task.checkCancellation()
                guard sameCapture(as: snapshot), draft.replayProof == proof else { return }
                publicationStatus = ["r2", "arkiv"].contains(pending.storage)
                    ? "Finishing in your browser."
                    : "Finishing in your browser (preview host)."
                guard NSWorkspace.shared.open(pending.approvalURL) else { throw HumaError.configuration("The approval page could not open.") }
                let download = try await client.waitForApproval(pending)
                guard exactTextEqual(String(decoding: download.master, as: UTF8.self), snapshot.text),
                      let publicRecord = try JSONSerialization.jsonObject(with: Data(download.envelope.proof.utf8)) as? [String: Any] else { throw HumaError.invalidResponse }
                let downloadedProof: Data
                if NoirWritingProofService.isNoirProof(Data(download.envelope.proof.utf8)) {
                    downloadedProof = Data(download.envelope.proof.utf8)
                } else if let bundle = publicRecord["bundle"] {
                    downloadedProof = try JSONSerialization.data(withJSONObject: bundle, options: [.sortedKeys])
                } else { throw HumaError.invalidResponse }
                _ = try await ReplayProofService.verify(draft: snapshot, proof: downloadedProof)
                try Task.checkCancellation()
                guard sameCapture(as: snapshot), draft.replayProof == proof else { return }
                document.draft.publicProof = PublicProofLink(url: download.url, proof: proof, draft: snapshot)
                document.draft.publicProof?.replayShared = replay != nil
                publicationStatus = ""; showShare = true
                await refreshReceipt()
            } catch is CancellationError { publicationStatus = "Stopped. Press Share to try again." }
            catch { publicationStatus = ""; errorMessage = error.localizedDescription }
        }
    }
}

/// Background processing progress while writing: parts done and the expected wait at Finish.
private struct ProofProgress: View {
    @ObservedObject var prover: LongChunkProver
    let characters: Int
    let recording: Bool
    var empty: String?
    var body: some View {
        if let line = prover.status(characters: characters, recording: recording) { Text(line) }
        else if let empty { Text(empty).foregroundStyle(Theme.tertiary) }
    }
}

/// Disables the window's close button (and so ⌘W) while a session is recording or processing,
/// since closing the window would end it.
private struct WindowCloseGuard: NSViewRepresentable {
    let blocked: Bool
    func makeNSView(context: Context) -> NSView { NSView() }
    func updateNSView(_ view: NSView, context: Context) {
        DispatchQueue.main.async { view.window?.standardWindowButton(.closeButton)?.isEnabled = !blocked }
    }
}

/// The three times Huma asks for Touch ID, and what it says first.
private enum TouchPrompt {
    case start, stillWriting, resume, finish
    var title: String {
        switch self {
        case .resume: return "Welcome Back"
        case .start: return "Start Writing with Touch ID"
        case .stillWriting: return "Are You Still Writing?"
        case .finish: return "Sign Your Page"
        }
    }
    var detail: String {
        switch self {
        case .start: return "Touch ID shows that you’re the one typing. Write it in one go: if Huma quits before Finish, the page can’t be shared."
        case .stillWriting: return "Touch ID shows it’s still you. You have 10 seconds."
        case .resume: return "Touch ID shows it’s still you before you keep writing."
        case .finish: return "Touch ID signs your page. After that it’s locked, and you get your link."
        }
    }
    /// The system Touch ID window reads “Huma is trying to …”.
    var reason: String {
        switch self {
        case .start: return "start recording your writing"
        case .stillWriting: return "confirm you’re still writing"
        case .resume: return "confirm it’s you before you keep writing"
        case .finish: return "sign your finished page"
        }
    }
}
