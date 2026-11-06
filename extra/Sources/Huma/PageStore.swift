import AppKit
import SwiftUI
import UniformTypeIdentifiers
import HumaCore

/// The one window's page. Pages are .huma files in ~/Documents/Huma: new and imported pages
/// are written there directly, edits save themselves, and the file name follows the title.
/// Picking another page swaps it in place, unless this one is mid-session or processing.
@MainActor
final class PageStore: ObservableObject {
    static let shared = PageStore()

    @Published private(set) var url: URL?
    /// Identity of the opened page; unchanged when its file is renamed.
    @Published private(set) var pageID = UUID()
    @Published var document = WritingDocument() { didSet { scheduleSave() } }
    @Published private(set) var pages: [URL] = []
    /// Set by the open page while it can't be left (recording or processing), with the reason.
    var leaveBlocker: String?
    /// The open page's say before you leave it: a recording page asks to stop first. Returns false to stay.
    var prepareToLeave: (() -> Bool)?
    private var saveTask: Task<Void, Never>?
    private var renameTask: Task<Void, Never>?
    private var watcher: Timer?

    static var folder: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("Huma", isDirectory: true)
    }

    private init() {
        refresh()
        // Pages saved before Spotlight indexing existed.
        for page in pages {
            if let draft = (try? Data(contentsOf: page)).flatMap({ try? WritingDocument(data: $0).draft }) {
                SpotlightIndex.index(page, title: draft.title, text: draft.text)
            }
        }
        watcher = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in
            MainActor.assumeIsolated { PageStore.shared.refresh() }
        }
    }

    // MARK: Pages

    /// Library pages, most recently changed first.
    func refresh() {
        let urls = (try? FileManager.default.contentsOfDirectory(at: Self.folder, includingPropertiesForKeys: [.contentModificationDateKey],
                                                                 options: [.skipsHiddenFiles])) ?? []
        let modified = { (url: URL) in (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast }
        let latest = urls.filter { $0.pathExtension == "huma" }.sorted { modified($0) > modified($1) }
        if latest != pages { pages = latest; SpotlightIndex.keep(only: latest) }
    }
    func inLibrary(_ url: URL) -> Bool {
        url.deletingLastPathComponent().standardizedFileURL.path == Self.folder.standardizedFileURL.path
    }
    func isCurrent(_ other: URL) -> Bool { url?.standardizedFileURL == other.standardizedFileURL }

    /// Opens the most recent page, or a new one when the library is empty.
    func openStart() {
        if let latest = pages.first { open(latest) } else { newPage() }
    }

    func open(_ target: URL) {
        guard !isCurrent(target), canLeave() else { return }
        do {
            let loaded = try WritingDocument(data: Data(contentsOf: target))
            flush()
            url = target
            pageID = UUID()
            saveTask?.cancel()
            document = loaded
            saveTask?.cancel()
            NSDocumentController.shared.noteNewRecentDocumentURL(target)
        } catch { alert("This page couldn’t be opened.", error.localizedDescription) }
    }
    func openPanel() {
        guard canLeave() else { return }
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.humaDocument]
        panel.directoryURL = Self.folder
        if panel.runModal() == .OK, let target = panel.url { open(target) }
    }
    func newPage() { create(Draft(), name: "Untitled") }
    /// A page for a writing request (huma.social/r/<id>), titled as asked.
    func newPage(for request: WritingRequest) {
        var draft = Draft(); draft.title = request.title; draft.request = request
        create(draft, name: request.title)
    }

    func trash(_ target: URL) {
        if isCurrent(target) {
            guard canLeave() else { return }
            saveTask?.cancel(); url = nil
        }
        do { try FileManager.default.trashItem(at: target, resultingItemURL: nil) }
        catch { alert("This page couldn’t be moved to the Trash.", error.localizedDescription) }
        refresh()
        if url == nil { openStart() }
    }

    // MARK: Saving

    private func scheduleSave() {
        saveTask?.cancel()
        saveTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(400))
            guard !Task.isCancelled else { return }
            self?.flush()
        }
        scheduleRename()
    }
    /// Writes the page now. Called before switching pages and when the app quits.
    func flush() {
        saveTask?.cancel(); saveTask = nil
        guard let url else { return }
        do {
            let data = try WritingDocument.encode(document.draft)
            if (try? Data(contentsOf: url)) != data { try data.write(to: url, options: .atomic) }
            if inLibrary(url) { SpotlightIndex.index(url, title: document.draft.title, text: document.draft.text) }
        } catch { NSLog("Huma: page not saved: \(error.localizedDescription)") }
    }
    /// Keeps the file name in step with the title, a moment after typing stops. Library pages only.
    private func scheduleRename() {
        guard let url, inLibrary(url) else { return }
        let name = Self.fileName(for: document.draft.title)
        guard name != url.deletingPathExtension().lastPathComponent else { renameTask?.cancel(); return }
        renameTask?.cancel()
        renameTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1.5))
            guard !Task.isCancelled, let self, let current = self.url, current == url else { return }
            let target = Self.available(name, current: current)
            guard target != current else { return }
            self.flush()
            do { try FileManager.default.moveItem(at: current, to: target); self.url = target; self.refresh() }
            catch { NSLog("Huma: page not renamed: \(error.localizedDescription)") }
        }
    }

    // MARK: Helpers

    private func canLeave() -> Bool {
        if let prepareToLeave, !prepareToLeave() { return false }
        guard let leaveBlocker else { return true }
        alert(leaveBlocker, "Your page stays open until then.")
        return false
    }
    private func create(_ draft: Draft, name: String) {
        guard canLeave() else { return }
        do {
            try FileManager.default.createDirectory(at: Self.folder, withIntermediateDirectories: true)
            let target = Self.available(Self.fileName(for: name), current: nil)
            try WritingDocument.encode(draft).write(to: target, options: .withoutOverwriting)
            refresh()
            open(target)
        } catch { alert("A new page couldn’t be created.", error.localizedDescription) }
    }
    private func alert(_ message: String, _ detail: String) {
        let alert = NSAlert(); alert.messageText = message; alert.informativeText = detail; alert.runModal()
    }
    static func fileName(for title: String) -> String {
        let cleaned = title.components(separatedBy: CharacterSet(charactersIn: "/:\\\n\r\t")).joined(separator: "-")
            .trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return cleaned.isEmpty ? "Untitled" : String(cleaned.prefix(80))
    }
    /// "Name.huma", or "Name 2.huma" and so on; the page's own file counts as free.
    static func available(_ name: String, current: URL?) -> URL {
        var index = 1
        while true {
            let candidate = folder.appendingPathComponent(index == 1 ? name : "\(name) \(index)").appendingPathExtension("huma")
            if let current, candidate.standardizedFileURL.path.lowercased() == current.standardizedFileURL.path.lowercased() { return current }
            if !FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            index += 1
        }
    }
}
