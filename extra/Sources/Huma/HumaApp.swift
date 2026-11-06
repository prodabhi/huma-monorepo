import AppKit
import CoreSpotlight
import SwiftUI
import HumaCore
import UserNotifications

@main
struct HumaApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var settings = AppSettings()
    @StateObject private var store = PageStore.shared
    @AppStorage("showSidebar") private var showSidebar = true
    @AppStorage("showTimeline") private var showTimeline = true
    @State private var showSettings = false
    #if DEBUG
    init() { Snapshots.runIfAsked() }
    #endif
    var body: some Scene {
        // One window, like Notion: the sidebar swaps pages in place.
        Window("Huma", id: "main") {
            Group {
                if store.url != nil {
                    // Keyed by the opened page, not its URL: renaming the file must not rebuild the view,
                    // which would end a recording session.
                    WritingView(document: $store.document, fileURL: store.url).id(store.pageID)
                } else {
                    Theme.page
                }
            }
            .environmentObject(settings).environmentObject(store)
            .tint(Theme.accent)
            .background(WindowChrome())
            // Settings open over the page, in this window, not in a window of their own.
            .sheet(isPresented: $showSettings) { SettingsView { showSettings = false }.environmentObject(settings) }
            .onReceive(NotificationCenter.default.publisher(for: .humaShowSettings)) { _ in showSettings = true }
        }
        .defaultSize(width: 1240, height: 820)
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Huma") { AboutPanel.show() }
                Button("Check for Updates…") { AppUpdater.shared.checkForUpdates() }
            }
            CommandGroup(replacing: .appSettings) {
                Button("Settings…") { showSettings = true }.keyboardShortcut(",")
            }
            CommandGroup(replacing: .newItem) {
                Button("New Page") { store.newPage() }.keyboardShortcut("n")
                Button("Open…") { store.openPanel() }.keyboardShortcut("o")
                Divider()
                Button("Search Pages…") { NotificationCenter.default.post(name: .humaFindPages, object: nil) }
                    .keyboardShortcut("f", modifiers: [.command, .option])
            }
            CommandMenu("Page") {
                Button("Finish") { NotificationCenter.default.post(name: .humaFinish, object: nil) }.keyboardShortcut(.return)
                Button("Copy Link") { NotificationCenter.default.post(name: .humaCopyLink, object: nil) }.keyboardShortcut("c", modifiers: [.command, .shift])
                Divider()
                Button("Version History…") { NotificationCenter.default.post(name: .humaVersionHistory, object: nil) }.keyboardShortcut("y", modifiers: [.command, .option])
                Button("Export Report…") { NotificationCenter.default.post(name: .humaExportReport, object: nil) }.keyboardShortcut("e", modifiers: [.command, .shift])
            }
            CommandGroup(replacing: .sidebar) {
                Button(showSidebar ? "Hide Sidebar" : "Show Sidebar") { withAnimation(.easeOut(duration: 0.15)) { showSidebar.toggle() } }
                    .keyboardShortcut("\\")
                Button(showTimeline ? "Hide Timeline" : "Show Timeline") { withAnimation(.easeOut(duration: 0.15)) { showTimeline.toggle() } }
                    .keyboardShortcut("t", modifiers: [.command, .option])
                // Just you and the page: hides the sidebar and timeline; again brings them back.
                Button(!showSidebar && !showTimeline ? "Exit Focus Mode" : "Focus Mode") {
                    let focus = showSidebar || showTimeline
                    withAnimation(.easeOut(duration: 0.2)) { showSidebar = !focus; showTimeline = !focus }
                }
                .keyboardShortcut("f", modifiers: [.command, .shift])
            }
            CommandGroup(replacing: .help) {
                Button("See a Finished Page") { NSWorkspace.shared.open(Onboarding.exampleURL) }
                Divider()
                Button("Huma Website") { NSWorkspace.shared.open(URL(string: "https://huma.social")!) }
                Button("Privacy Policy") { NSWorkspace.shared.open(URL(string: "https://huma.social/privacy")!) }
                Button("Contact Us") { NSWorkspace.shared.open(URL(string: "mailto:team@huma.social")!) }
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var opened = false
    func applicationDidFinishLaunching(_ notification: Notification) {
        _ = AppUpdater.shared
        NoirWritingProofService.removeLeftoverWorkspaces()
        // Release builds get the 64 MB of proving points once, in the background, so the first proof doesn't wait.
        if let engine = Bundle.main.resourceURL?.appendingPathComponent("NoirEngine") {
            Task { try? await ProvingSetup.shared.ready(engine: engine) }
        }
        Appearance.current.apply()
        UNUserNotificationCenter.current().delegate = NotificationOpener.shared
        // Finder opens arrive just before or after launch; otherwise show the latest page.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            MainActor.assumeIsolated { if !self.opened && PageStore.shared.url == nil { PageStore.shared.openStart() } }
        }
    }
    func application(_ application: NSApplication, open urls: [URL]) {
        // huma://signed-in comes from the browser after onboarding sign-in: opening it brings Huma
        // forward, and the onboarding sheet already knows the account from its own check.
        if urls.contains(where: { $0.scheme == "huma" }) { NSApp.activate() }
        // huma://request?id=… from a writing request's page: start a page titled as asked.
        if let link = urls.last(where: { $0.scheme == "huma" && $0.host == "request" }),
           let id = URLComponents(url: link, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "id" })?.value {
            opened = true
            Task { @MainActor in
                do {
                    let host = UserDefaults.standard.string(forKey: "registryURL") ?? "https://api.huma.social"
                    PageStore.shared.newPage(for: try await HostedPublicationClient(url: host).writingRequest(id))
                } catch {
                    let alert = NSAlert(); alert.messageText = "This request couldn’t be opened."
                    alert.informativeText = error.localizedDescription; alert.runModal()
                }
            }
            return
        }
        guard let url = urls.last(where: { $0.pathExtension == "huma" }) else { return }
        opened = true
        MainActor.assumeIsolated { PageStore.shared.open(url) }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    /// Right-click on the Dock icon.
    func applicationDockMenu(_ sender: NSApplication) -> NSMenu? {
        let menu = NSMenu()
        menu.addItem(withTitle: "New Page", action: #selector(newPageFromDock), keyEquivalent: "").target = self
        return menu
    }
    @objc private func newPageFromDock() { MainActor.assumeIsolated { NSApp.activate(); PageStore.shared.newPage() } }
    /// A page picked in Spotlight.
    func application(_ application: NSApplication, continue userActivity: NSUserActivity,
                     restorationHandler: @escaping ([any NSUserActivityRestoring]) -> Void) -> Bool {
        guard userActivity.activityType == CSSearchableItemActionType,
              let path = userActivity.userInfo?[CSSearchableItemActivityIdentifier] as? String else { return false }
        opened = true
        MainActor.assumeIsolated { PageStore.shared.open(URL(fileURLWithPath: path)) }
        return true
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard MainActor.assumeIsolated({ CaptureSigner.anyRecording }) else { return .terminateNow }
        let alert = NSAlert()
        alert.messageText = "Quit without finishing?"
        alert.informativeText = "If you quit now, this page can’t be shared. Your text is saved."
        alert.addButton(withTitle: "Keep Writing")
        alert.addButton(withTitle: "Quit Anyway")
        return alert.runModal() == .alertSecondButtonReturn ? .terminateNow : .terminateCancel
    }
    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { PageStore.shared.flush() }
    }
}
