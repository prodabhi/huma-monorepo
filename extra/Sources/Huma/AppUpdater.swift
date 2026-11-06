import AppKit
import Sparkle

/// Checks huma.social/appcast.xml for new versions (daily, and from Huma ▸ Check for Updates…) and installs them.
/// An update never restarts Huma in the middle of a writing session: it waits until no page is recording.
@MainActor final class AppUpdater: NSObject, SPUUpdaterDelegate {
    static let shared = AppUpdater()
    private var controller: SPUStandardUpdaterController!

    private override init() {
        super.init()
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: self, userDriverDelegate: nil)
        #if DEBUG
        // Development builds aren't the released app; only check when asked.
        controller.updater.automaticallyChecksForUpdates = false
        #endif
    }

    func checkForUpdates() { controller.checkForUpdates(nil) }

    nonisolated func updater(_ updater: SPUUpdater, shouldPostponeRelaunchForUpdate item: SUAppcastItem,
                             untilInvokingBlock installHandler: @escaping () -> Void) -> Bool {
        // Sparkle calls this on the main thread and accepts the handler from it.
        nonisolated(unsafe) let install = installHandler
        return MainActor.assumeIsolated {
            guard CaptureSigner.anyRecording else { return false }
            Task { @MainActor in
                while CaptureSigner.anyRecording { try? await Task.sleep(for: .seconds(2)) }
                install()
            }
            return true
        }
    }
}
