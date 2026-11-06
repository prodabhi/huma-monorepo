import SwiftUI
import Security
import HumaCore

struct KeychainStore {
    // Test/preview bundles must not request access to the shipping app's items.
    private static var service: String { Bundle.main.bundleIdentifier ?? "dev.swayam.huma.unbundled" }
    static func read(_ account: String) -> String {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }
    static func save(_ value: String, account: String) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account]
        let data = Data(value.utf8)
        let updated = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updated == errSecSuccess { return }
        guard updated == errSecItemNotFound else { throw HumaError.configuration("Keychain could not update this credential (\(updated)).") }
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw HumaError.configuration("Keychain could not save this credential (\(status)).") }
    }
}

@MainActor
final class AppSettings: ObservableObject {
    @Published var registryURL = UserDefaults.standard.string(forKey: "registryURL") ?? "https://api.huma.social"
    /// The email or username this Mac signed in with during onboarding. Sharing needs it.
    @Published var account = UserDefaults.standard.string(forKey: "signedInAccount") {
        didSet { UserDefaults.standard.set(account, forKey: "signedInAccount") }
    }
    /// The account's wallet, once it has authorized this Mac's publishing key: Finish then shares
    /// without the browser.
    @Published var linkedWallet = UserDefaults.standard.string(forKey: "linkedWallet") {
        didSet { UserDefaults.standard.set(linkedWallet, forKey: "linkedWallet") }
    }
    @Published var deviceServiceURL = UserDefaults.standard.string(forKey: "deviceServiceURL") ?? "http://127.0.0.1:4319"
    @Published var deviceBusy = false
}

/// Settings, inside the app's window like Notion's: your profile, account, look and where pages are kept.
struct SettingsView: View {
    let done: () -> Void
    @EnvironmentObject private var settings: AppSettings
    @ObservedObject private var profile = Profile.shared
    @AppStorage(Appearance.key) private var appearance = Appearance.system.rawValue
    @State private var editingProfile = false
    var body: some View {
        if editingProfile { ProfileEditor { editingProfile = false } }
        else { list }
    }
    private var list: some View {
        VStack(alignment: .leading, spacing: 0) {
            SheetTitle(title: "Settings")
            VStack(spacing: 0) {
                row("Profile") {
                    FaceView(seed: profile.avatar, size: 22)
                    Text(profile.name.isEmpty ? "No name yet" : profile.name).foregroundStyle(profile.name.isEmpty ? Theme.secondary : Theme.text)
                        .lineLimit(1)
                    Spacer(minLength: 8)
                    Button("Edit") { editingProfile = true }.humaButton(small: true)
                }
                line
                row("Account") {
                    Text(settings.account ?? "Not signed in").foregroundStyle(settings.account == nil ? Theme.secondary : Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 8)
                    if settings.account != nil {
                        Button("Sign Out") { settings.account = nil; settings.linkedWallet = nil }.humaButton(small: true)
                    }
                }
                line
                row("Look") {
                    Spacer(minLength: 0)
                    AppearancePicker(selection: $appearance)
                }
                line
                row("Pages") {
                    Text("Kept only on this Mac").foregroundStyle(Theme.secondary).lineLimit(1)
                    Spacer(minLength: 8)
                    Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([PageStore.folder]) }.humaButton(small: true)
                }
                line
                row("Version") {
                    Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—").foregroundStyle(Theme.secondary)
                    Spacer(minLength: 8)
                    Button("Check for Updates") { AppUpdater.shared.checkForUpdates() }.humaButton(small: true)
                }
            }
            .humaCard(14)
            .padding(.top, 18)
            HStack {
                Spacer()
                Button("Done", action: done).humaButton(.primary).keyboardShortcut(.defaultAction)
            }
            .padding(.top, 20)
        }
        .padding(28).frame(width: 500).humaSheetHeader().presentationBackground(Theme.page)
    }
    private func row<Content: View>(_ label: String, @ViewBuilder content: () -> Content) -> some View {
        HStack(spacing: 10) {
            Text(label).monoLabel(10.5).foregroundStyle(Theme.tertiary).frame(width: 78, alignment: .leading)
            content()
        }
        .font(Theme.sans(13.5)).padding(.horizontal, 14).frame(height: 50)
    }
    private var line: some View { Rectangle().fill(Theme.divider).frame(height: 1).padding(.leading, 14) }
}

/// System, Light or Dark as one row of pills, the selected one in ink.
private struct AppearancePicker: View {
    @Binding var selection: String
    var body: some View {
        HStack(spacing: 2) {
            ForEach(Appearance.allCases) { option in
                let selected = option.rawValue == selection
                Button { selection = option.rawValue; option.apply() } label: {
                    Text(option.title).monoLabel(10.5).foregroundStyle(selected ? Theme.onInk : Theme.secondary)
                        .padding(.horizontal, 10).frame(height: 24)
                        .background(selected ? Theme.ink : .clear, in: Capsule()).contentShape(Capsule())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(2).overlay(Capsule().strokeBorder(Theme.divider))
        .animation(.easeOut(duration: 0.15), value: selection)
    }
}
