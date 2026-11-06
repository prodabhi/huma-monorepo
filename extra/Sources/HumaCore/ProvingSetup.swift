import CryptoKit
import Foundation

/// The proving points: 2^21 compressed BN254 curve points (64 MB) that every proof and every check needs.
/// They are random data and don't compress, so release builds leave them out of the installer. Huma downloads
/// them once into the cache folder the engine reads, checks them against a fixed fingerprint, and only then
/// lets the engine run. Development builds still carry them inside the engine and use those.
public actor ProvingSetup {
    public static let shared = ProvingSetup()
    /// SHA-256 of the points integrations/noir/package.py takes (the first 2^21 of the published setup).
    public static let sha256 = "3e1ac09652ee9df779a4955fb8f7050620c7b1ee7f18566581bd00326b06be37"
    public static let byteCount = (1 << 21) * 32
    /// huma.social sends this on to a short-lived signed R2 link (frontend/registry.mjs, /engine/proving-setup).
    public static let source = URL(string: "https://huma.social/engine/proving-setup")!
    /// Where the engine's worker looks (backend/integrations/noir/worker.mjs, linkSetup), built from HOME the same way.
    public static var file: URL {
        URL(fileURLWithPath: ProcessInfo.processInfo.environment["HOME"] ?? NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent("Library/Caches/dev.swayam.huma/crs/bn254_g1_compressed.dat")
    }

    private var checked = false
    private var download: Task<Void, Error>?

    /// Returns once the points are in place and intact, downloading them first if necessary. Calls that arrive
    /// during a download wait for the same download.
    public func ready(engine: URL) async throws {
        if FileManager.default.fileExists(atPath: engine.appendingPathComponent("crs/bn254_g1_compressed.dat").path) { return }
        // Cheap on later calls; a cache clean-up that removed the file is noticed and repaired.
        if checked && FileManager.default.fileExists(atPath: Self.file.path) { return }
        if Self.intact(Self.file) { checked = true; return }
        let task = download ?? Task { try await Self.fetch() }
        download = task
        do { try await task.value; download = nil; checked = true }
        catch { download = nil; throw error }
    }

    static func intact(_ url: URL) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.size] as? NSNumber)?.intValue == byteCount,
              let data = try? Data(contentsOf: url, options: .alwaysMapped) else { return false }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == sha256
    }

    private static func fetch() async throws {
        let failed = HumaError.configuration("Huma couldn’t get ready to make proofs. Connect to the internet and try again.")
        let (temporary, response) = try await URLSession.shared.download(from: source)
        defer { try? FileManager.default.removeItem(at: temporary) }
        guard (response as? HTTPURLResponse)?.statusCode == 200, intact(temporary) else { throw failed }
        let folder = file.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // Earlier versions linked this name to the points inside the app; the real file replaces the link.
        try? FileManager.default.removeItem(at: file)
        try FileManager.default.moveItem(at: temporary, to: file)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        guard intact(file) else { try? FileManager.default.removeItem(at: file); throw failed }
    }
}
