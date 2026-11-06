import HumaCore

// Huma proves on this Mac. Development builds can still try a remote prover, without a setting in the app:
// defaults write dev.swayam.huma proverMode server (and proverURL); the Mac checks its proof either way.
extension ProverChoice {
    /// The prover to use for the next proof, or nil to prove on this Mac (always, in released builds).
    static var selectedProver: RemoteProver? {
        #if DEBUG
        current == .server ? try? RemoteProver(url: currentAddress) : nil
        #else
        nil
        #endif
    }
}
