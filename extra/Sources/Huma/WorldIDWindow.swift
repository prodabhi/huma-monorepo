import AppKit
import WebKit

/// World ID inside Huma, which has no World ID screen of its own: a small window showing the host's World ID page
/// (frontend/share/src/WorldSignIn.jsx) for one scan. The page opens a huma:// link as soon as World App answers, with the
/// proof in it (huma://started or huma://finished, ?proof=), for Huma to send to the host; the window takes that as
/// done and closes. Closing it first is a cancel.
@MainActor
final class WorldIDWindow: NSObject, WKNavigationDelegate, NSWindowDelegate {
    private static var open = Set<WorldIDWindow>()
    private var window: NSWindow?
    private var result: CheckedContinuation<URL?, Never>?

    /// Shows `url` and waits: the huma:// link the page opened once the scan is done, or nil if the window is closed first.
    static func scan(_ url: URL) async -> URL? {
        let shown = WorldIDWindow()
        open.insert(shown)
        defer { open.remove(shown) }
        return await withCheckedContinuation { continuation in shown.present(url, result: continuation) }
    }

    /// The proof a scan handed back in its huma:// link: IDKit's result as JSON, from the base64url `proof` in its query.
    static func proof(in link: URL) -> Data? {
        guard let value = URLComponents(url: link, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "proof" })?.value
        else { return nil }
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64), (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else { return nil }
        return data
    }

    private func present(_ url: URL, result: CheckedContinuation<URL?, Never>) {
        self.result = result
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent() // nothing from one scan stays for the next
        let web = WKWebView(frame: NSRect(x: 0, y: 0, width: 480, height: 760), configuration: configuration)
        web.navigationDelegate = self
        let window = NSWindow(contentRect: web.frame, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Verify You’re Human"
        window.contentView = web
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.center()
        self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate()
        web.load(URLRequest(url: url))
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction) async -> WKNavigationActionPolicy {
        guard let link = navigationAction.request.url, link.scheme == "huma" else { return .allow }
        finish(link)
        return .cancel
    }

    func windowWillClose(_ notification: Notification) { finish(nil) }

    private func finish(_ done: URL?) {
        guard let result else { return }
        self.result = nil
        result.resume(returning: done)
        if let window, window.isVisible { window.delegate = nil; window.close() }
        window = nil
    }
}
