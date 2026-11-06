import AppKit
import CryptoKit
import LocalAuthentication
import SwiftUI
import HumaCore

/// First-run guide: what Huma gives you, when Touch ID will ask (and a live check that it can),
/// sign-in (required, since links need an account), your name and face, and what Finish and Share do.
/// Huma never shows a Touch ID prompt before step 2 is seen.
struct Onboarding: View {
    static let signInStep = 2
    /// A real shared page to look at before writing one (huma.social sends it on to the current example).
    static let exampleURL = URL(string: "https://huma.social/example")!
    static let profileStep = 3
    private static let steps = 5
    /// Opened by typing: skip the welcome and end by starting the session.
    let startsSession: Bool
    let onDone: () -> Void
    let onSkip: () -> Void
    /// Opens the browser to sign in and returns the account's email or username once it's done.
    let signIn: () async throws -> String
    @State private var step: Int
    @State private var account: String?
    @State private var signingIn: Task<Void, Never>?
    @State private var signInError: String?
    @State private var readiness = Readiness.check()
    @ObservedObject private var profile = Profile.shared
    init(startsSession: Bool, step: Int? = nil, account: String? = nil, onDone: @escaping () -> Void, onSkip: @escaping () -> Void,
         signIn: @escaping () async throws -> String) {
        self.startsSession = startsSession; self.onDone = onDone; self.onSkip = onSkip; self.signIn = signIn
        _step = State(initialValue: step ?? (startsSession ? 1 : 0))
        _account = State(initialValue: account)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Group {
                switch step {
                case 0: welcome
                case 1: touchID
                case 2: signInStep
                case 3: profileStep
                default: sharing
                }
            }
            // One height for every step, so the sheet doesn't jump as you click through.
            .frame(maxWidth: .infinity, minHeight: 330, alignment: .top)
            // Go back on the left, continue on the right.
            HStack(spacing: 8) {
                Group {
                    if step == 0 || (startsSession && step == 1) { Button("Not Now", action: onSkip).keyboardShortcut(.cancelAction) }
                    else { Button("Back") { move(-1) } }
                }
                .humaButton(.plain).frame(width: 120, alignment: .leading)
                Spacer()
                Group {
                    if step == Self.signInStep && account == nil {
                        // The sign-in step's main button signs in; it turns into Continue once you're signed in.
                        Button(signingIn == nil ? "Sign In" : "Waiting…") { startSignIn() }.keyboardShortcut(.defaultAction)
                            .disabled(signingIn != nil)
                    } else if step < Self.steps - 1 {
                        Button("Continue") { if step == Self.profileStep { tidyName() }; move(1) }.keyboardShortcut(.defaultAction)
                            // Your name goes on every page you share, so this step needs one.
                            .disabled(step == Self.profileStep && profile.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    } else {
                        Button(startsSession ? "Start Writing" : "Get Started", action: onDone).keyboardShortcut(.defaultAction)
                    }
                }
                .humaButton(.primary).frame(width: 120, alignment: .trailing)
            }
            .padding(.top, 24)
        }
        .padding(28).frame(width: 480)
        .humaSheetHeader()
        // Without this, macOS draws its own lighter sheet color above and below the content.
        .presentationBackground(Theme.page)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in readiness = Readiness.check() }
        .onDisappear { signingIn?.cancel() }
    }
    private func move(_ by: Int) { withAnimation(.easeOut(duration: 0.15)) { step += by } }

    // MARK: Steps

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 24) {
            title("Welcome to Huma", "Write here. Get a link that shows you wrote it.")
            PageIllustration().frame(maxWidth: .infinity)
        }
    }

    private var touchID: some View {
        VStack(alignment: .leading, spacing: 24) {
            title("Touch ID", "Your fingerprint shows you’re at your Mac as you write. It never leaves this Mac.")
            readinessRow
        }
    }

    private var signInStep: some View {
        VStack(alignment: .leading, spacing: 24) {
            title("Sign In", "Sign in with Google, Apple or email to get your links.")
            signInRow
            Text("It costs nothing.").font(Theme.sans(12.5)).foregroundStyle(Theme.tertiary)
        }
    }

    private var profileStep: some View {
        VStack(alignment: .leading, spacing: 20) {
            title("Your Profile", "Shown on pages you share.")
            ProfileFields(name: $profile.name, picked: $profile.avatar, faceSize: 46)
        }
    }
    private func tidyName() { profile.name = profile.name.trimmingCharacters(in: .whitespacesAndNewlines) }

    private var sharing: some View {
        VStack(alignment: .leading, spacing: 24) {
            title("Share", "Press Finish when you’re done. You get a link anyone can check.")
            Button { NSWorkspace.shared.open(Self.exampleURL) } label: { Label("See a Finished Page", systemImage: "arrow.up.right") }
                .humaButton(small: true)
            Text("Your pages stay on this Mac.").font(Theme.sans(12.5)).foregroundStyle(Theme.tertiary)
        }
    }

    // MARK: Pieces

    @ViewBuilder private var readinessRow: some View {
        HStack(spacing: 10) {
            Image(systemName: readiness == .ready ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(readiness == .ready ? Theme.success : Theme.warning)
            Text(readiness.message).font(Theme.sans(13)).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if readiness == .notEnrolled || readiness == .unavailable {
                QuietButton(title: "Open System Settings", icon: "gearshape") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.Touch-ID-Settings.extension") { NSWorkspace.shared.open(url) }
                }
            }
        }
        .padding(14).humaCard(14)
    }
    /// Signed in, waiting for the browser (with a way to reopen it), or what Sign in will do.
    @ViewBuilder private var signInRow: some View {
        HStack(spacing: 10) {
            if let account {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.success)
                Text("Signed in as \(account).").font(Theme.sans(13)).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
            } else if signingIn != nil {
                ProgressView().controlSize(.small)
                Text((try? PublishingKey.shortCode()).map { "Finish in your browser. It should show \($0)." } ?? "Finish signing in in your browser.")
                    .font(Theme.sans(13)).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
            } else {
                Image(systemName: signInError == nil ? "globe" : "exclamationmark.triangle.fill").foregroundStyle(signInError == nil ? Theme.secondary : Theme.warning)
                Text(signInError ?? "Opens in your browser.").font(Theme.sans(13)).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if account == nil, signingIn != nil {
                Button("Open Again") { startSignIn() }.humaButton(.plain)
            }
        }
        .padding(14).humaCard(14)
    }
    private func startSignIn() {
        signingIn?.cancel(); signInError = nil
        signingIn = Task {
            do { let name = try await signIn(); if !Task.isCancelled { account = name } }
            catch is CancellationError {}
            catch { if !Task.isCancelled { signInError = "Sign-in didn’t finish. Try again." } }
            if !Task.isCancelled { signingIn = nil }
        }
    }
    /// The website's page head: a mono step count, a large 450-weight title and one short line.
    private func title(_ heading: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(String(format: "%02d / %02d", step + 1, Self.steps)).monoLabel(10.5).foregroundStyle(Theme.tertiary)
            Text(heading).font(Theme.heading(28)).tracking(-0.5).foregroundStyle(Theme.text).padding(.top, 14)
            Text(detail).font(Theme.sans(14)).foregroundStyle(Theme.secondary).lineSpacing(2).padding(.top, 10)
        }
        .multilineTextAlignment(.leading).fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Whether this Mac can sign a session, checked without showing a Touch ID prompt.
enum Readiness: Equatable {
    case ready, notEnrolled, unavailable, noSecureEnclave
    static func check() -> Readiness {
        guard SecureEnclave.isAvailable else { return .noSecureEnclave }
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error), context.biometryType == .touchID { return .ready }
        return error?.code == LAError.biometryNotEnrolled.rawValue ? .notEnrolled : .unavailable
    }
    var message: String {
        switch self {
        case .ready: return "Touch ID is ready."
        case .notEnrolled: return "Add a fingerprint in System Settings."
        case .unavailable: return "Touch ID is off. Turn it on in System Settings."
        case .noSecureEnclave: return "This Mac can’t make proofs. It has no Touch ID chip."
        }
    }
}

/// A small verified page, drawn in the app's own style.
private struct PageIllustration: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 8) {
                Text("My essay").font(Theme.heading(15)).tracking(-0.1).foregroundStyle(Theme.text)
                Tag(title: "Verified", tone: .green)
            }
            ForEach([1.0, 0.92, 0.97, 0.6], id: \.self) { width in
                GeometryReader { geometry in
                    Capsule().fill(Theme.divider).frame(width: geometry.size.width * width, height: 6)
                }.frame(height: 6)
            }
            HStack(spacing: 8) {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(Theme.success).font(.system(size: 12))
                Text("You wrote it").font(Theme.sans(11.5)).foregroundStyle(Theme.secondary)
                Spacer()
                SegmentedProgress(fraction: 1, tint: Theme.success, segments: 12)
            }
            .padding(.top, 4)
        }
        .padding(18).frame(width: 300)
        .background(Theme.page, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Theme.divider))
        .shadow(color: .black.opacity(0.08), radius: 12, y: 4)
        .padding(.vertical, 14).frame(maxWidth: .infinity)
        .background(Theme.callout, in: RoundedRectangle(cornerRadius: 10))
    }
}
