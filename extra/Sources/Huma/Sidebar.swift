import AppKit
import SwiftUI
import HumaCore

/// Notion-like sidebar: search, new page, import, the pages in the Huma folder and settings.
struct Sidebar: View {
    let currentURL: URL?
    let currentTitle: String
    let status: DocumentStatus
    let hide: () -> Void
    @EnvironmentObject var store: PageStore
    @State private var search = ""
    @FocusState private var searching: Bool
    @ObservedObject private var profile = Profile.shared
    @State private var editingProfile = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            // The window buttons' row (the same band as the page header), then search beside the format bar.
            HStack {
                Spacer()
                SidebarToggle(action: hide).help("Hide sidebar (⌘\\)")
            }
            .frame(height: Grid.band)
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.secondary)
                TextField("Search", text: $search).textFieldStyle(.plain).font(Theme.sans(13.5)).focused($searching)
                    .onReceive(NotificationCenter.default.publisher(for: .humaFindPages)) { _ in searching = true }
            }
            .padding(.horizontal, 8).frame(height: 30)
            .background(Theme.hover.opacity(0.6), in: RoundedRectangle(cornerRadius: 6))
            .padding(.vertical, (Grid.gap + Grid.bar - 30) / 2 - 1)
            .padding(.bottom, Grid.bottom - 4)
            SidebarRow(title: "New Page", icon: "square.and.pencil") { store.newPage() }
            // New writers see what a finished page looks like, until they have a few of their own.
            if filtered.count < 2 && search.isEmpty {
                SidebarRow(title: "See an Example", icon: "eye") { NSWorkspace.shared.open(Onboarding.exampleURL) }
            }
            Text("Pages").monoLabel(10.5).foregroundStyle(Theme.tertiary)
                .padding(.horizontal, 8).padding(.top, 16).padding(.bottom, 4)
            ScrollView {
                VStack(alignment: .leading, spacing: 1) {
                    if !currentInLibrary && matches(currentTitle) {
                        SidebarRow(title: currentTitle, icon: icon(for: status), selected: true, trailing: status == .writing ? "●" : nil) {}
                    }
                    ForEach(filtered, id: \.self) { url in
                        let current = url.standardizedFileURL == currentURL?.standardizedFileURL
                        PageRow(title: current ? currentTitle : url.deletingPathExtension().lastPathComponent,
                                icon: current ? icon(for: status) : "doc.text", selected: current,
                                open: { if !current { store.open(url) } }) {
                            Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                            Divider()
                            Button("Move to Trash", role: .destructive) { store.trash(url) }
                        }
                    }
                    if filtered.isEmpty && !search.isEmpty {
                        Text("No pages match").font(Theme.sans(12.5)).foregroundStyle(Theme.tertiary).padding(.horizontal, 8).padding(.top, 4)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8)
        .frame(maxHeight: .infinity, alignment: .top)
        .safeAreaInset(edge: .bottom, spacing: 0) { footer }
        .background(Theme.sidebar)
    }

    /// You, at the bottom like an account: your face and name (click to edit), and Settings beside it.
    /// The same 36-point band, under the same line, as the page's status bar, so the two read as one row.
    private var footer: some View {
        VStack(spacing: 0) {
            Rectangle().fill(Theme.divider).frame(height: 1)
            HStack(spacing: 4) {
                Button { editingProfile = true } label: {
                    HStack(spacing: 8) {
                        FaceView(seed: profile.avatar, size: 22)
                        Text(profile.name.isEmpty ? "Set Up Profile" : profile.name).font(Theme.sans(13.5))
                            .foregroundStyle(profile.name.isEmpty ? Theme.secondary : Theme.text).lineLimit(1)
                        Spacer(minLength: 0)
                    }
                    .frame(maxHeight: .infinity).contentShape(Rectangle())
                }
                .buttonStyle(.plain).help("Your name and face on pages you share")
                Button { NotificationCenter.default.post(name: .humaShowSettings, object: nil) } label: {
                    Image(systemName: "gearshape").font(.system(size: 13)).foregroundStyle(Theme.secondary)
                        .frame(width: 28, height: 28).contentShape(Rectangle())
                }
                .buttonStyle(.plain).help("Settings (⌘,)")
            }
            .padding(.leading, 14).padding(.trailing, 10).frame(height: 36)
        }
        .sheet(isPresented: $editingProfile) { ProfileEditor { editingProfile = false } }
    }

    private var currentInLibrary: Bool { currentURL.map(store.inLibrary) ?? false }
    private var filtered: [URL] { store.pages.filter { matches($0.deletingPathExtension().lastPathComponent) } }
    private func matches(_ title: String) -> Bool { search.isEmpty || title.localizedCaseInsensitiveContains(search) }
    private func icon(for status: DocumentStatus) -> String {
        switch status {
        case .verified, .shared: return "checkmark.seal"
        case .writing: return "pencil.line"
        default: return "doc.text"
        }
    }

}

/// A page in the sidebar with a ⋯ menu that appears on hover (and on right-click).
private struct PageRow<Actions: View>: View {
    let title: String
    let icon: String
    let selected: Bool
    let open: () -> Void
    @ViewBuilder var actions: Actions
    @State private var hovering = false
    var body: some View {
        SidebarRow(title: title, icon: icon, selected: selected, action: open)
            .overlay(alignment: .trailing) {
                Menu { actions } label: {
                    Image(systemName: "ellipsis").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.secondary)
                        .frame(width: 22, height: 22).contentShape(Rectangle())
                }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                .padding(.trailing, 6).opacity(hovering ? 1 : 0).help("More")
            }
            .onHover { hovering = $0 }
            .contextMenu { actions }
    }
}
