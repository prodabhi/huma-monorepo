import AppKit
import CoreText
import SwiftUI

/// Notion-like palette and building blocks. Colors adapt to light and dark appearance.
enum Theme {
    static func nsDynamic(_ light: UInt32, _ dark: UInt32) -> NSColor {
        NSColor(name: nil) { appearance in
            let value = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
            return NSColor(srgbRed: CGFloat((value >> 16) & 0xff) / 255, green: CGFloat((value >> 8) & 0xff) / 255,
                           blue: CGFloat(value & 0xff) / 255, alpha: 1)
        }
    }
    static func dynamic(_ light: UInt32, _ dark: UInt32) -> Color { Color(nsColor: nsDynamic(light, dark)) }
    // The landing page's look (frontend/pages/foundation.css): warm paper, ink text, slate for links and progress,
    // coral for anything wrong. Dark mode is the page's night sections: near-black blue with pale ink.
    /// The desk behind the page, and the page itself.
    static let canvasColor = nsDynamic(0xF6F4F3, 0x0B0F14)
    static let paperColor = nsDynamic(0xFDFCFB, 0x121920)
    static let paperEdge = nsDynamic(0xE2DFDC, 0x222B35)
    static let page = dynamic(0xF6F4F3, 0x0B0F14)
    static let sidebar = dynamic(0xEFEDEB, 0x10151C)
    static let text = dynamic(0x222222, 0xE8EDF2)
    static let secondary = dynamic(0x505050, 0x9AA6B2)
    static let tertiary = dynamic(0x8C8C8C, 0x66727E)
    static let hover = dynamic(0xE9E6E4, 0x18202A)
    static let divider = dynamic(0xDAD7D4, 0x222B35)
    static let callout = dynamic(0xEDEAE8, 0x141B24)
    /// The site's cards (.card in site.css): a lighter sheet of paper with a hairline edge.
    static let card = dynamic(0xFBFAF9, 0x111820)
    static let accent = dynamic(0x50667A, 0x7F9AB3)
    static let accentHover = dynamic(0x43586B, 0x93ACC3)
    static let accentSoft = dynamic(0xE4E9EE, 0x17222E)
    /// Text or icons drawn on an accent fill.
    static let onAccent = dynamic(0xFFFFFF, 0x0B0F14)
    /// The solid buttons: ink on paper, and pale ink at night, as the page's calls to action.
    static let ink = dynamic(0x222222, 0xE8EDF2)
    static let inkHover = dynamic(0x3A3A3A, 0xFFFFFF)
    static let onInk = dynamic(0xF6F4F3, 0x0B0F14)
    static let danger = dynamic(0xB0553B, 0xE0806A)
    static let success = dynamic(0x3E7352, 0x8FD3A8)
    static let warning = dynamic(0x8F6420, 0xE0B877)
    static let disabledFill = dynamic(0xE9E6E4, 0x161D26)

    /// The website's own fonts, bundled in Resources/Fonts: Inter for text and Geist Mono for labels and buttons.
    /// Both are variable, so any weight the site uses (like its 450 headings) is drawn exactly. Without the bundle
    /// (a bare `swift run`), the system fonts stand in.
    private static let bundledFonts: Bool = {
        var loaded = false
        for name in ["inter", "geist-mono"] {
            if let url = Bundle.main.url(forResource: name, withExtension: "woff2", subdirectory: "Fonts"),
               CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil) { loaded = true }
        }
        return loaded
    }()
    private static func variable(_ family: String, _ size: CGFloat, _ weight: CGFloat) -> NSFont? {
        guard bundledFonts else { return nil }
        let descriptor = NSFontDescriptor(fontAttributes: [.family: family,
            NSFontDescriptor.AttributeName(kCTFontVariationAttribute as String): [0x7767_6874: weight]]) // 'wght'
        guard let font = NSFont(descriptor: descriptor, size: size), font.familyName == family else { return nil }
        return font
    }
    private static func number(_ weight: Font.Weight) -> CGFloat {
        switch weight {
        case .ultraLight: 200
        case .thin: 100
        case .light: 300
        case .medium: 500
        case .semibold: 600
        case .bold: 700
        case .heavy: 800
        case .black: 900
        default: 400
        }
    }
    /// Text in Inter, as on huma.social.
    static func sans(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        variable("Inter", size, number(weight)).map(Font.init) ?? .system(size: size, weight: weight)
    }
    /// The page's small labels and buttons in Geist Mono, used uppercase with a little tracking.
    static func mono(_ size: CGFloat = 11) -> Font {
        variable("Geist Mono", size, 400).map(Font.init) ?? .system(size: size, weight: .regular, design: .monospaced)
    }
    /// Headings at the page's 450 weight: a touch above regular, never bold.
    static func heading(_ size: CGFloat) -> Font {
        variable("Inter", size, 450).map(Font.init) ?? .system(size: size, weight: .medium)
    }
    /// The same fonts for AppKit drawing, such as the PDF report's text pages.
    static func sansFont(_ size: CGFloat, weight: CGFloat = 400) -> NSFont {
        variable("Inter", size, weight) ?? .systemFont(ofSize: size, weight: weight >= 500 ? .medium : .regular)
    }
    static func monoFont(_ size: CGFloat) -> NSFont {
        variable("Geist Mono", size, 400) ?? .monospacedSystemFont(ofSize: size, weight: .regular)
    }

    /// Status badge colors (soft fill, strong text), in the page's muted tones.
    enum Tone { case gray, blue, red, orange, green, purple }
    static func tag(_ tone: Tone) -> (Color, Color) {
        switch tone {
        case .gray: return (dynamic(0xEAE7E5, 0x1A2029), dynamic(0x505050, 0xB4BEC8))
        case .blue: return (dynamic(0xE4E9EE, 0x17222E), dynamic(0x4A5F73, 0x9EB5CA))
        case .red: return (dynamic(0xF5E4DE, 0x2C1915), dynamic(0xA24E36, 0xE8967F))
        case .orange: return (dynamic(0xF3EADB, 0x2A2216), dynamic(0x85601F, 0xE0B877))
        case .green: return (dynamic(0xE2EDE5, 0x13261C), dynamic(0x3E7352, 0x8FD3A8))
        case .purple: return (dynamic(0xE8E6EE, 0x1D1C29), dynamic(0x585272, 0xB8B1D6))
        }
    }
}

extension View {
    /// A card as on huma.social: lighter paper, a 1px edge, 14-point corners.
    func humaCard(_ radius: CGFloat = 14) -> some View {
        background(Theme.card, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: radius, style: .continuous).strokeBorder(Theme.divider))
    }
    /// A small mono label in capitals, like the page's ".mono" text.
    func monoLabel(_ size: CGFloat = 11) -> some View { font(Theme.mono(size)).textCase(.uppercase).tracking(0.2) }
}

/// A status badge: a small pill with a soft fill and strong text.
struct Tag: View {
    let title: String
    var tone: Theme.Tone = .gray
    var dot = false
    var body: some View {
        let (background, foreground) = Theme.tag(tone)
        HStack(spacing: 5) {
            if dot { Circle().fill(foreground).frame(width: 6, height: 6) }
            Text(title)
        }
        .monoLabel(10.5).foregroundStyle(foreground)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(background, in: Capsule())
    }
}

/// One page property: muted icon and label on the left, value on the right.
struct PropertyRow<Value: View>: View {
    let icon: String
    let label: String
    @ViewBuilder var value: Value
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            Label {
                Text(label)
            } icon: {
                Image(systemName: icon).frame(width: 16)
            }
            .labelStyle(.titleAndIcon).font(Theme.sans(13.5)).foregroundStyle(Theme.secondary)
            .frame(width: 160, alignment: .leading)
            value.font(Theme.sans(13.5)).foregroundStyle(Theme.text)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 5)
    }
}

/// Notion callout block: icon, text and an optional action.
struct Callout<Content: View>: View {
    let icon: String
    var iconColor: Color = Theme.secondary
    @ViewBuilder var content: Content
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).font(.system(size: 15)).foregroundStyle(iconColor).frame(width: 20).padding(.top, 1)
            VStack(alignment: .leading, spacing: 8) { content }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16).padding(.vertical, 14)
        .humaCard(12)
    }
}

/// The one button look used everywhere outside menus: the landing page's pill buttons, mono capitals, 32 tall
/// for this desktop app and 28 when small. primary: solid ink, the one main action in a place. secondary: a
/// 1px ink outline. plain: slate text, a soft fill on hover. danger: solid coral.
struct HumaButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, plain, danger }
    var kind: Kind
    var small = false
    func makeBody(configuration: Configuration) -> some View {
        HumaButtonBody(configuration: configuration, kind: kind, small: small)
    }
}

private struct HumaButtonBody: View {
    let configuration: ButtonStyle.Configuration
    let kind: HumaButtonStyle.Kind
    let small: Bool
    @Environment(\.isEnabled) private var enabled
    @State private var hovering = false
    var body: some View {
        let shape = Capsule()
        configuration.label
            .labelStyle(HumaButtonLabelStyle())
            .monoLabel(small ? 11 : 11.5)
            .foregroundStyle(foreground)
            .padding(.horizontal, small ? 12 : 16).frame(height: small ? 28 : 32)
            .background(background, in: shape)
            .overlay(kind == .secondary ? shape.strokeBorder(enabled ? Theme.text.opacity(0.8) : Theme.divider) : nil)
            .opacity(configuration.isPressed ? 0.82 : 1)
            .contentShape(shape)
            .onHover { hovering = $0 && enabled }
            .animation(.easeOut(duration: 0.2), value: hovering)
    }
    private var foreground: Color {
        guard enabled else { return Theme.tertiary }
        switch kind {
        case .primary: return Theme.onInk
        case .danger: return .white
        case .plain: return Theme.accent
        case .secondary: return Theme.text
        }
    }
    private var background: Color {
        guard enabled else { return kind == .plain || kind == .secondary ? .clear : Theme.disabledFill }
        switch kind {
        case .primary: return hovering ? Theme.inkHover : Theme.ink
        case .danger: return Theme.danger.opacity(hovering ? 0.88 : 1)
        case .secondary: return hovering ? Theme.text.opacity(0.08) : .clear
        case .plain: return hovering ? Theme.accentSoft : .clear
        }
    }
}

private struct HumaButtonLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) { configuration.icon.font(Theme.sans(11, .regular)); configuration.title }
    }
}

extension ButtonStyle where Self == HumaButtonStyle {
    static func huma(_ kind: HumaButtonStyle.Kind = .secondary, small: Bool = false) -> HumaButtonStyle { .init(kind: kind, small: small) }
}

/// Shorthand for a small Huma button with an optional icon.
struct QuietButton: View {
    let title: String
    var icon: String?
    var prominent = false
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            if let icon { Label(title, systemImage: icon) } else { Text(title) }
        }
        .humaButton(prominent ? .primary : .secondary, small: true)
    }
}

/// Full-width sidebar row with hover and selection highlight.
struct SidebarRow: View {
    let title: String
    let icon: String
    var selected = false
    var trailing: String?
    let action: () -> Void
    @State private var hovering = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon).font(.system(size: 13)).foregroundStyle(Theme.secondary).frame(width: 18)
                Text(title).font(Theme.sans(14, selected ? .medium : .regular)).foregroundStyle(Theme.text).lineLimit(1)
                Spacer(minLength: 0)
                if let trailing { Text(trailing).monoLabel(10).foregroundStyle(Theme.tertiary) }
            }
            .padding(.horizontal, 8).frame(height: 30)
            .background(selected || hovering ? Theme.hover : Color.clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).onHover { hovering = $0 }
    }
}

/// Shared vertical grid for the header and the sidebar, so their rows line up:
/// window buttons with the title, the sidebar name with the menus, search with the format bar.
enum Grid {
    /// Height of the window's top band, a standard unified toolbar; macOS centers the window buttons in it.
    static let band: CGFloat = 52
    static let top: CGFloat = 11
    static let titleRow: CGFloat = 30
    static let menuRow: CGFloat = 24
    static let gap: CGFloat = 6
    static let bar: CGFloat = 38
    static let bottom: CGFloat = 10
    /// Where content may start to the right of the window's close/minimize/zoom buttons, as macOS places them.
    static let windowButtons: CGFloat = 90
}

/// Google Docs-like header: page icon, title and status, a menu row, actions on the right,
/// and a rounded formatting bar underneath.
struct DocHeader<Actions: View, Bar: View>: View {
    @Binding var title: String
    /// The small line under the title, like Notes ("Shared · 120 words").
    let subtitle: String
    let sidebarShown: Bool
    let toggleSidebar: () -> Void
    @ViewBuilder var actions: Actions
    @ViewBuilder var formatBar: Bar
    /// Hidden on finished pages, which are view-only.
    var showsFormatBar = true
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // One row, centered on the window buttons, as in Notes: title and subtitle left, actions right.
            HStack(spacing: 12) {
                if !sidebarShown { SidebarToggle(action: toggleSidebar) }
                // Huma's mark, the head from the website, in ink.
                HumaMarkView(height: 24).foregroundStyle(Theme.text)
                VStack(alignment: .leading, spacing: 2) {
                    TextField("Untitled", text: $title).textFieldStyle(.plain)
                        .font(Theme.heading(15)).tracking(-0.15).foregroundStyle(Theme.text).lineLimit(1)
                    Text(subtitle).monoLabel(10.5).foregroundStyle(Theme.secondary).lineLimit(1)
                }
                Spacer(minLength: 12)
                HStack(spacing: 10) { actions }
            }
            .frame(height: Grid.band)
            if showsFormatBar {
                HStack(spacing: 0) { formatBar }
                    .padding(.horizontal, 6).frame(height: Grid.bar)
                    .background(Theme.callout, in: Capsule())
                    .padding(.bottom, Grid.bottom)
            }
        }
        .padding(.leading, sidebarShown ? 16 : Grid.windowButtons).padding(.trailing, 16)
        .background(Theme.page)
    }
}

extension View {
    /// A floating capsule, like the page's menus: paper, a hairline edge.
    func glassCapsule() -> some View {
        background(Theme.page.opacity(0.94), in: Capsule()).overlay(Capsule().strokeBorder(Theme.divider))
    }
    /// Huma's buttons: the page's flat pills on every macOS version, not the system glass.
    func humaButton(_ kind: HumaButtonStyle.Kind = .secondary, small: Bool = false) -> some View {
        buttonStyle(.huma(kind, small: small))
    }
}

/// Square icon button for the formatting bar and header.
struct HeaderIcon: View {
    let icon: String
    let help: String
    var active = false
    let action: () -> Void
    @State private var hovering = false
    var body: some View {
        Button(action: action) {
            Image(systemName: icon).font(.system(size: 13.5, weight: .medium)).foregroundStyle(Theme.text)
                .frame(width: 30, height: 28)
                .background(hovering || active ? Theme.hover : Color.clear, in: RoundedRectangle(cornerRadius: 5))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain).help(help).onHover { hovering = $0 }
    }
}

struct BarDivider: View {
    var body: some View { Rectangle().fill(Theme.divider).frame(width: 1, height: 20).padding(.horizontal, 5) }
}

/// Moves the window's close, minimize and zoom buttons down to the header's title line,
/// so everything along the top shares one center line. Re-applied after resizing and full screen.
struct WindowChrome: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { context.coordinator.attach(view.window) }
        return view
    }
    func updateNSView(_ view: NSView, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator() }

    @MainActor final class Coordinator {
        private var attached = false
        private var observers: [NSObjectProtocol] = []
        /// A standard unified toolbar band (as in Notes or Finder), empty and see-through: macOS places and
        /// spaces the window buttons in it, and Huma's own header and sidebar draw beneath it.
        func attach(_ window: NSWindow?) {
            guard let window, !attached else { return }
            attached = true
            window.titleVisibility = .hidden
            window.titlebarAppearsTransparent = true
            window.styleMask.insert(.fullSizeContentView)
            if window.toolbar == nil { window.toolbar = NSToolbar(identifier: "huma.window") }
            window.toolbarStyle = .unified
            // Full screen draws the toolbar band as a solid bar over the header; hide it there, as Notes does,
            // and macOS shows the window buttons when the pointer reaches the top of the screen.
            for (name, visible) in [(NSWindow.willEnterFullScreenNotification, false), (NSWindow.didExitFullScreenNotification, true)] {
                observers.append(NotificationCenter.default.addObserver(forName: name, object: window, queue: .main) { [weak window] _ in
                    MainActor.assumeIsolated { window?.toolbar?.isVisible = visible }
                })
            }
            Appearance.refresh(window, NSApp.appearance)
        }
    }
}

/// The sidebar toggle beside the window buttons: a light icon, boxed only on hover.
struct SidebarToggle: View {
    let action: () -> Void
    @State private var hovering = false
    var body: some View {
        Button(action: action) {
            Image(systemName: "sidebar.left").font(.system(size: 13, weight: .regular))
                .foregroundStyle(hovering ? Theme.text : Theme.secondary)
                .frame(width: 26, height: 24)
                .background(hovering ? Theme.hover : Color.clear, in: RoundedRectangle(cornerRadius: 5))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain).onHover { hovering = $0 }.help("Show sidebar (⌘\\)")
    }
}

/// Light, Dark, or follow the Mac. Every Huma color adapts, so this only sets the app's appearance.
enum Appearance: String, CaseIterable, Identifiable {
    case system, light, dark
    static let key = "appearance"
    var id: String { rawValue }
    var title: String { switch self { case .system: "System"; case .light: "Light"; case .dark: "Dark" } }
    var icon: String { switch self { case .system: "circle.lefthalf.filled"; case .light: "sun.max"; case .dark: "moon" } }
    static var current: Appearance { UserDefaults.standard.string(forKey: key).flatMap(Appearance.init) ?? .system }
    @MainActor func apply() {
        let appearance: NSAppearance? = switch self { case .system: nil; case .light: NSAppearance(named: .aqua); case .dark: NSAppearance(named: .darkAqua) }
        NSApp.appearance = appearance
        // Windows that are already open keep their frame and corner border until told directly.
        for window in NSApp.windows { Self.refresh(window, appearance) }
    }
    @MainActor static func refresh(_ window: NSWindow, _ appearance: NSAppearance?) {
        window.appearance = appearance
        window.contentView?.superview?.needsDisplay = true
        window.invalidateShadow()
    }
}

/// The header's appearance menu, top right.
struct AppearanceMenu: View {
    @AppStorage(Appearance.key) private var appearance = Appearance.system.rawValue
    var body: some View {
        let current = Appearance(rawValue: appearance) ?? .system
        Menu {
            Picker("Appearance", selection: $appearance) {
                ForEach(Appearance.allCases) { Label($0.title, systemImage: $0.icon).tag($0.rawValue) }
            }
            .pickerStyle(.inline).labelsHidden()
        } label: {
            Image(systemName: current.icon).font(.system(size: 13.5, weight: .medium)).foregroundStyle(Theme.text)
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        .frame(width: 30, height: 28).help("Appearance: \(current.title)")
        .onChange(of: appearance, initial: true) { _, value in (Appearance(rawValue: value) ?? .system).apply() }
    }
}
