import Foundation

public enum VerificationText {
    public static let policy = "trailing-ascii-space-tab-v1"
    // Keep the stored document and capture untouched. Apply only when preparing
    // or comparing the character representation used by a new proof.
    public static func canonical(_ text: String) -> String {
        var bytes = Array(text.utf8)
        while let last = bytes.last, last == 0x20 || last == 0x09 { bytes.removeLast() }
        return String(decoding: bytes, as: UTF8.self)
    }
}
