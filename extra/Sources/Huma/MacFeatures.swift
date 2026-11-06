import AppKit
import CoreSpotlight
import UniformTypeIdentifiers
@preconcurrency import UserNotifications

/// Menu commands for the open page. The page view listens and acts when they apply.
extension Notification.Name {
    static let humaFinish = Notification.Name("huma.finish")
    static let humaCopyLink = Notification.Name("huma.copyLink")
    static let humaVersionHistory = Notification.Name("huma.versionHistory")
    static let humaExportReport = Notification.Name("huma.exportReport")
    static let humaFindPages = Notification.Name("huma.findPages")
    static let humaShowSettings = Notification.Name("huma.showSettings")
}

/// "Your link is ready", only while Huma isn't the app in front.
/// Permission is asked the first time there's something to say, never at launch.
@MainActor enum Notifier {
    static func post(_ title: String, _ body: String, page: URL?) {
        guard !NSApp.isActive else { return }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = title; content.body = body; content.sound = .default
            if let page { content.userInfo = ["page": page.path] }
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }
}

/// Opens the page a notification was about.
final class NotificationOpener: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    static let shared = NotificationOpener()
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let path = response.notification.request.content.userInfo["page"] as? String
        await MainActor.run {
            NSApp.activate()
            if let path { PageStore.shared.open(URL(fileURLWithPath: path)) }
        }
    }
}

/// A progress bar on Huma's Dock icon while a proof is being made.
@MainActor enum DockProgress {
    private static var bar: NSProgressIndicator?
    static func show(_ fraction: Double?) {
        let tile = NSApp.dockTile
        guard let fraction else {
            if bar != nil { bar = nil; tile.contentView = nil; tile.display() }
            return
        }
        if bar == nil {
            let view = NSImageView(image: NSApp.applicationIconImage)
            let progress = NSProgressIndicator(frame: NSRect(x: 12, y: 8, width: tile.size.width - 24, height: 14))
            progress.style = .bar; progress.isIndeterminate = false; progress.minValue = 0; progress.maxValue = 1
            view.addSubview(progress)
            tile.contentView = view; bar = progress
        }
        bar?.doubleValue = min(max(fraction, 0), 1)
        tile.display()
    }
}

/// Pages in Spotlight (⌘Space): title and text, kept on this Mac. Opening a result opens the page.
@MainActor enum SpotlightIndex {
    private static var indexed: Set<String> = []
    static func index(_ url: URL, title: String, text: String) {
        let attributes = CSSearchableItemAttributeSet(contentType: .text)
        attributes.title = title.isEmpty ? "Untitled" : title
        attributes.contentDescription = String(text.prefix(300))
        attributes.textContent = text
        attributes.contentURL = url
        let item = CSSearchableItem(uniqueIdentifier: url.path, domainIdentifier: "pages", attributeSet: attributes)
        CSSearchableIndex.default().indexSearchableItems([item]) { _ in }
        indexed.insert(url.path)
    }
    /// Drops pages that were renamed, moved or deleted.
    static func keep(only pages: [URL]) {
        let gone = indexed.subtracting(pages.map(\.path))
        guard !gone.isEmpty else { return }
        CSSearchableIndex.default().deleteSearchableItems(withIdentifiers: Array(gone)) { _ in }
        indexed.subtract(gone)
    }
}

/// About Huma, with the version and links.
@MainActor enum AboutPanel {
    static func show() {
        let credits = NSMutableAttributedString(string: "Write it. Prove you wrote it.\n\n",
            attributes: [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor])
        for (title, link) in [("huma.social", "https://huma.social"), ("Privacy", "https://huma.social/privacy"), ("team@huma.social", "mailto:team@huma.social")] {
            if credits.length > 32 { credits.append(NSAttributedString(string: "  ·  ", attributes: [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.tertiaryLabelColor])) }
            credits.append(NSAttributedString(string: title, attributes: [.font: NSFont.systemFont(ofSize: 11), .link: URL(string: link)!]))
        }
        credits.append(NSAttributedString(string: "\n\nFaces: DiceBear “Dylan” by Natalia Spivak, CC BY 4.0",
            attributes: [.font: NSFont.systemFont(ofSize: 10), .foregroundColor: NSColor.tertiaryLabelColor]))
        let centered = NSMutableParagraphStyle(); centered.alignment = .center
        credits.addAttribute(.paragraphStyle, value: centered, range: NSRange(location: 0, length: credits.length))
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits])
        NSApp.activate()
    }
}
