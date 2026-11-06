import Foundation

/// The page's writing replay, for readers to watch (frontend/replay-core.mjs checks it): every edit with its time,
/// and the final signed checkpoint, whose key is the page proof's capture key. Shared only when the writer
/// chooses to, since it shows deleted text too.
extension SessionLog {
    public static let replayKind = "huma-replay-v1"

    /// The replay for a finished page, or nil if the session isn't sealed with a signed final checkpoint.
    public func replayExport(text: String) throws -> Data? {
        guard let checkpoint = signedCheckpoints?.last, checkpoint.isFinal, checkpoint.version == 2,
              let time = checkpoint.reportedTime, checkpoint.editCount == events.count, checkpoint.verifySignature(),
              checkpoint.editHead == head, checkpoint.textHash == sha256(Data(text.utf8)) else { return nil }
        let object: [String: Any] = [
            "kind": Self.replayKind, "session": id, "initialText": initialText,
            "events": events.map { [$0.elapsedMilliseconds, $0.source, $0.location, $0.removedLength, $0.insertedText] as [Any] },
            "checkpoint": [
                "version": checkpoint.version, "kind": checkpoint.kind, "isFinal": true, "sessionID": checkpoint.sessionID,
                "sequence": checkpoint.sequence, "captureCount": checkpoint.captureCount, "editCount": checkpoint.editCount,
                "sampleCount": checkpoint.sampleCount, "captureHead": checkpoint.captureHead, "editHead": checkpoint.editHead,
                "textHash": checkpoint.textHash, "previousCheckpoint": checkpoint.previousCheckpoint, "challenge": checkpoint.challenge,
                "publicKey": checkpoint.publicKey.base64EncodedString(), "signature": checkpoint.signature.base64EncodedString(),
                "reportedTime": ["unixMilliseconds": time.unixMilliseconds, "elapsedMilliseconds": time.elapsedMilliseconds],
            ] as [String: Any],
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes])
        return data.count <= 4 * 1024 * 1024 ? data : nil
    }
}
