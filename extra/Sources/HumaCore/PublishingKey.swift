import Foundation
import CryptoKit
import Security

/// This Mac's publishing key: a Secure Enclave P-256 key used without a Touch ID prompt. The account's
/// wallet authorizes it once at sign-in, and from then on Finish shares by signing with it, with no browser.
/// It can only sign publications the host checks against that authorization; it never signs writing sessions.
public enum PublishingKey {
    static var store: WrappedCaptureKeyStore {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return WrappedCaptureKeyStore(file: support.appendingPathComponent(Bundle.main.bundleIdentifier ?? "dev.swayam.huma.unbundled")
            .appendingPathComponent("Capture/publishing-key-v1.wrapped"))
    }
    public static func loadOrCreate() throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard SecureEnclave.isAvailable else { throw HumaError.configuration("Secure Enclave signing is unavailable on this Mac.") }
        if let wrapped = try store.load() { return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: wrapped) }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error) else {
            throw HumaError.configuration("Could not set up this Mac’s publishing key.")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try store.saveNew(key.dataRepresentation)
        return key
    }
    /// The 65-byte x9.63 public key in lowercase hex, as the host and the sign-in page expect it.
    public static func publicKeyHex() throws -> String {
        try loadOrCreate().publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()
    }
    /// The code the sign-in page shows for this key, like "ABCD-1234", so a person only links their own Mac:
    /// the first 4 bytes of SHA-256 over the lowercase hex key (deviceCode in publication-contract.mjs).
    public static func shortCode() throws -> String {
        let hex = SHA256.hash(data: Data(try publicKeyHex().utf8)).prefix(4).map { String(format: "%02X", $0) }.joined()
        return hex.prefix(4) + "-" + hex.suffix(4)
    }
    /// A DER signature over the UTF-8 message, base64.
    public static func sign(_ message: String) throws -> String {
        try loadOrCreate().signature(for: Data(message.utf8)).derRepresentation.base64EncodedString()
    }
}
