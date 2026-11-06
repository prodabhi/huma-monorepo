import AppKit
import SwiftUI
import HumaCore

/// The suggestion for the words just clicked, in a small bubble right above them: the words, the fix, and why.
/// Choosing the fix selects the words to type over; it's never put in for you, so the page stays typed.
struct SuggestionBubble: View {
    let issue: GrammarIssue
    /// The words are selected and waiting for the fix to be typed.
    let typing: Bool
    /// The bubble sits above the words (its point at the bottom), or below them when there's no room above.
    let above: Bool
    let choose: () -> Void
    let ignore: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            if !above { Pointer().fill(Theme.card).overlay(Pointer().stroke(Theme.divider)).frame(width: 14, height: 7).rotationEffect(.degrees(180)) }
            VStack(alignment: .leading, spacing: 8) {
                if typing {
                    (Text("Type ") + Text("\u{201C}\(issue.suggestion)\u{201D}").fontWeight(.semibold) + Text(" to fix it"))
                        .font(Theme.sans(13)).foregroundStyle(Theme.text)
                    Text("Fixes you type keep your page typed.").font(Theme.sans(11.5)).foregroundStyle(Theme.secondary)
                } else {
                    HStack(spacing: 8) {
                        Text(issue.original).strikethrough(color: Theme.tertiary).foregroundStyle(Theme.tertiary).lineLimit(1)
                        Image(systemName: "arrow.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(Theme.tertiary)
                        Button(action: choose) {
                            Text(issue.suggestion).font(Theme.sans(13, .semibold)).lineLimit(1)
                                .padding(.horizontal, 9).padding(.vertical, 3)
                                .background(Theme.accentSoft, in: Capsule()).foregroundStyle(Theme.accent)
                        }
                        .buttonStyle(.plain).help("Select these words to type the fix")
                    }
                    .font(Theme.sans(13))
                    HStack(spacing: 12) {
                        Text(issue.reason).font(Theme.sans(11.5)).foregroundStyle(Theme.secondary).lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                        Button("Ignore", action: ignore).buttonStyle(.plain).font(Theme.sans(11.5, .medium)).foregroundStyle(Theme.secondary)
                    }
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .frame(minWidth: 180, maxWidth: 320, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.divider))
            if above { Pointer().fill(Theme.card).overlay(Pointer().stroke(Theme.divider)).frame(width: 14, height: 7).offset(y: -1) }
        }
        .fixedSize()
        .shadow(color: .black.opacity(0.14), radius: 10, y: 4)
        .padding(14)   // room for the shadow inside the panel
        .accessibilityElement(children: .contain)
        .accessibilityLabel(typing ? "Type \(issue.suggestion) to fix it" : "Suggestion: \(issue.suggestion). \(issue.reason)")
    }

    /// The bubble's small point toward the words.
    private struct Pointer: Shape {
        func path(in rect: CGRect) -> Path {
            Path { path in
                path.move(to: CGPoint(x: rect.minX, y: rect.minY))
                path.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
                path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY))
            }
        }
    }
}

/// Shows SuggestionBubble in a borderless panel attached to the editor's window. The panel never becomes key, so
/// typing keeps going to the page, and choosing the fix doesn't take the cursor away.
@MainActor final class SuggestionBubbleController {
    private(set) var issue: GrammarIssue?
    private var panel: NSPanel?
    private var observers: [NSObjectProtocol] = []

    func show(_ issue: GrammarIssue, typing: Bool, in text: NSTextView, choose: @escaping () -> Void, ignore: @escaping () -> Void) {
        guard let window = text.window else { return }
        close()
        // The words' place on screen; TextKit gives the first line of them, which is where the bubble points.
        var actual = NSRange()
        let words = text.firstRect(forCharacterRange: issue.range, actualRange: &actual)
        guard words.width > 0 || words.height > 0 else { return }
        let visible = window.convertToScreen(text.convert(text.visibleRect, to: nil))
        let measure = NSHostingView(rootView: SuggestionBubble(issue: issue, typing: typing, above: true, choose: {}, ignore: {}))
        let size = measure.fittingSize
        // Above the words when it fits inside the page's visible area, otherwise below them.
        let above = words.maxY + size.height - 14 <= visible.maxY
        let host = NSHostingView(rootView: SuggestionBubble(issue: issue, typing: typing, above: above, choose: choose, ignore: ignore))
        host.appearance = text.effectiveAppearance
        let panel = NSPanel(contentRect: NSRect(origin: .zero, size: size), styleMask: [.borderless, .nonactivatingPanel],
                            backing: .buffered, defer: true)
        panel.isOpaque = false; panel.backgroundColor = .clear; panel.hasShadow = false
        panel.becomesKeyOnlyIfNeeded = true; panel.isReleasedWhenClosed = false
        panel.contentView = host
        // Centred on the words, its point 2pt from them, kept inside the editor.
        let x = min(max(words.midX - size.width / 2, visible.minX - 8), visible.maxX - size.width + 8)
        let y = above ? words.maxY + 2 - 14 : words.minY - size.height - 2 + 14
        panel.setFrameOrigin(NSPoint(x: x, y: y))
        window.addChildWindow(panel, ordered: .above)
        self.panel = panel; self.issue = issue
        // It points at a spot on the page, so scrolling, resizing or leaving the window closes it.
        let center = NotificationCenter.default
        if let clip = text.enclosingScrollView?.contentView {
            clip.postsBoundsChangedNotifications = true
            observers.append(center.addObserver(forName: NSView.boundsDidChangeNotification, object: clip, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.close() } })
        }
        for name in [NSWindow.didResizeNotification, NSWindow.didResignKeyNotification, NSWindow.willCloseNotification] {
            observers.append(center.addObserver(forName: name, object: window, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.close() } })
        }
        NSAccessibility.post(element: text, notification: .announcementRequested,
                             userInfo: [.announcement: typing ? "Type \(issue.suggestion) to fix it" : "Suggestion: \(issue.suggestion). \(issue.reason)",
                                        .priority: NSAccessibilityPriorityLevel.medium.rawValue])
    }

    func close() {
        for observer in observers { NotificationCenter.default.removeObserver(observer) }
        observers = []
        if let panel { panel.parent?.removeChildWindow(panel); panel.orderOut(nil) }
        panel = nil; issue = nil
    }
}
