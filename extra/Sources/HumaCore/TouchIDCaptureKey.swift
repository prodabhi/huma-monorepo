import Foundation
import CryptoKit
import Security
import LocalAuthentication
import Darwin

/// Persists only Apple's enclave-encrypted key representation, never a raw private key.
/// Private key operations additionally require the currently enrolled fingerprint set.
public struct WrappedCaptureKeyStore: Sendable {
    public let file: URL
    public init(file: URL? = nil) {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.file = file ?? support.appendingPathComponent(Bundle.main.bundleIdentifier ?? "dev.swayam.huma.unbundled")
            .appendingPathComponent("Capture/biometric-signing-key-v1.wrapped")
    }
    public func load() throws -> Data? {
        let descriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            if errno == ENOENT { return nil }
            throw HumaError.configuration("Could not read this Mac’s protected capture key.")
        }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(), info.st_size > 0, info.st_size <= 16384 else { throw HumaError.invalidDocument }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        return try handle.readToEnd()
    }
    public func saveNew(_ data: Data) throws {
        guard !data.isEmpty, data.count <= 16384 else { throw HumaError.invalidDocument }
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let descriptor = open(file.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw HumaError.configuration("A capture key already exists or could not be saved. Huma did not replace it.") }
        defer { close(descriptor) }
        do {
            try FileHandle(fileDescriptor: descriptor, closeOnDealloc: false).write(contentsOf: data)
            guard fsync(descriptor) == 0 else { throw HumaError.invalidResponse }
        } catch {
            // Only the incomplete file created by this call is removed; existing keys are never replaced.
            unlink(file.path)
            throw error
        }
    }
    /// Moves an unusable key aside (never deletes it) so a new one can be created.
    public func retire() throws {
        let aside = file.deletingLastPathComponent().appendingPathComponent(
            file.lastPathComponent + ".retired-" + String(Int(Date().timeIntervalSince1970)))
        guard rename(file.path, aside.path) == 0 else { throw HumaError.configuration("Could not replace this Mac’s capture key.") }
    }
    public func publicKey() throws -> Data? {
        guard let wrapped = try load() else { return nil }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrapped).publicKey.x963Representation
    }
}

@MainActor
public enum TouchIDCaptureKey {
    public static func authorize(reason: String, timeoutSeconds: UInt64? = nil) async throws -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        context.localizedCancelTitle = "Cancel"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error),
              context.biometryType == .touchID else {
            throw HumaError.configuration("Touch ID isn’t available. Turn it on in System Settings, then try again.")
        }
        let deadline = timeoutSeconds.map { seconds in Task { @MainActor in
            do { try await Task.sleep(for: .seconds(seconds)); context.invalidate() } catch {}
        } }
        defer { deadline?.cancel() }
        let allowed: Bool = try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
                if success { continuation.resume(returning: true) }
                else if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: false) }
            }
        }
        guard allowed else { throw CancellationError() }
        // Reuse this explicitly approved context for the key operation; never open surprise fallback dialogs.
        context.interactionNotAllowed = true
        return context
    }
    public static func loadOrCreate(context: LAContext, store: WrappedCaptureKeyStore = .init()) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw HumaError.configuration("Secure Enclave signing is unavailable on this Mac.") }
        if let wrapped = try store.load() {
            // Touch ID just approved this context, so a key that still can't sign was invalidated by a fingerprint
            // change (.biometryCurrentSet). Keep the old file aside (older pages name it) and make a new key.
            do {
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrapped, authenticationContext: context)
                _ = try key.signature(for: Data("huma-capture-key-check".utf8))
                return key
            } catch where !isCancellation(error) {
                try store.retire()
            }
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &error) else {
            throw HumaError.configuration("Could not configure the Touch ID capture key.")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        try store.saveNew(key.dataRepresentation)
        return key
    }
    public static func isCancellation(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        guard let error = error as? LAError else { return false }
        return [.userCancel, .appCancel, .systemCancel, .userFallback].contains(error.code)
    }
}
