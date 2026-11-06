import Foundation

/// Keeps a native compact producer aligned with one newly started SessionLog.
/// Hardware signing is supplied by the app; tests can supply a disposable key.
@MainActor
public final class ExperimentalCompactRecorder {
    public var info: ExperimentalCompactCapture.Info { capture.info }
    private let sessionID: String
    private let initialText: String
    private let initialUnix: UInt64
    private let presenceProtocol: String?
    private let publicKey: Data
    private let capture: ExperimentalCompactCapture
    private var processed = 0
    private var edits = 0
    private var samples = 0
    private var presence = 0
    private var awaitingPresenceDigest: String?
    private var lastHead: String

    public init(libraryURL: URL, session: SessionLog, publicKey: Data, time: CaptureTime,
                profile: ExperimentalCompactCapture.Profile? = nil) throws {
        guard session.events.isEmpty, (session.inputSamples ?? []).isEmpty,
              session.captureRecords?.isEmpty == true, (session.signedCheckpoints ?? []).isEmpty,
              (session.presenceEvents ?? []).isEmpty, session.experimentalCompactSnapshot == nil,
              session.presenceProtocol == nil || session.presenceProtocol == "local-presence-v1",
              time.elapsedMilliseconds == 0 else { throw HumaError.invalidSession }
        sessionID = session.id; initialText = session.initialText; initialUnix = time.unixMilliseconds
        presenceProtocol = session.presenceProtocol; self.publicKey = publicKey
        lastHead = session.captureSeed
        let selected = profile ?? (session.presenceProtocol == nil ? .replay : .assuranceExtended)
        guard selected.isAssurance == (session.presenceProtocol != nil) else { throw HumaError.invalidSession }
        capture = try ExperimentalCompactCapture(libraryURL: libraryURL, initialText: session.initialText,
            publicKey: publicKey, unixMilliseconds: time.unixMilliseconds,
            profile: selected)
    }
    public func synchronize(_ session: SessionLog, signPresence: ((Data) throws -> Data)? = nil) throws {
        guard session.id == sessionID, exactTextEqual(session.initialText, initialText),
              session.presenceProtocol == presenceProtocol,
              session.signedCheckpoints?.first.map({ $0.publicKey == publicKey }) ?? true,
              let records = session.captureRecords, records.count >= processed,
              (processed == 0 ? session.captureSeed : records[processed - 1].head) == lastHead else { throw HumaError.invalidSession }
        for record in records.dropFirst(processed) {
            guard record.sequence == processed, record.previousHead == lastHead,
                  record.head == (try record.digest()) else { throw HumaError.invalidSession }
            switch record.kind {
            case "edit":
                guard record.index == edits, session.events.indices.contains(edits) else { throw HumaError.invalidSession }
                let event = session.events[edits]
                guard let location = UInt32(exactly: event.location), let removed = UInt32(exactly: event.removedLength),
                      record.payloadHash == event.head, event.sequence == edits,
                      event.head == (try event.digest()) else { throw HumaError.invalidSession }
                try capture.recordEdit(location: location, removedLength: removed, insertedText: event.insertedText,
                    source: Self.provedSource(event.source), elapsedMilliseconds: event.elapsedMilliseconds)
                edits += 1
            case "key":
                guard record.index == samples, let values = session.inputSamples, values.indices.contains(samples) else { throw HumaError.invalidSession }
                let sample = values[samples]
                guard record.payloadHash == (try sample.digest()) else { throw HumaError.invalidSession }
                try capture.recordSample(kind: sample.kind, keyCode: sample.keyCode,
                    modifiers: UInt64(sample.modifiers), elapsedMilliseconds: sample.elapsedMilliseconds, origin: sample.origin)
                samples += 1
            case "presence":
                guard capture.profile.isAssurance, record.index == presence,
                      let events = session.presenceEvents, events.indices.contains(presence) else { throw HumaError.invalidSession }
                try session.validatePresence(requireResolved: false)
                let event = events[presence]
                let digest = try event.digest(sessionID: sessionID)
                guard event.sequence == presence, record.payloadHash == digest else { throw HumaError.invalidSession }
                if event.kind == "challenge" {
                    let bytes = Array(event.nonce.utf8)
                    guard bytes.count == 64 else { throw HumaError.invalidSession }
                    let nonce = try stride(from: 0, to: bytes.count, by: 2).map { index -> UInt8 in
                        guard let value = UInt8(String(decoding: bytes[index..<(index + 2)], as: UTF8.self), radix: 16)
                              else { throw HumaError.invalidSession }
                        return value
                    }
                    try capture.issuePresence(nonce: Data(nonce), reason: event.reason, elapsedMilliseconds: event.elapsedMilliseconds)
                } else if event.outcome == "approved" {
                    // Never defer this signing request to a later checkpoint or
                    // silently re-sign imported histories. The app supplies it
                    // while the fresh biometric approval context is active.
                    guard let signPresence else { throw HumaError.invalidSession }
                    if let awaitingPresenceDigest {
                        guard awaitingPresenceDigest == digest, capture.info.pendingKind == "presence" else { throw HumaError.invalidSession }
                    } else {
                        _ = try capture.respondToPresence(outcome: event.outcome, elapsedMilliseconds: event.elapsedMilliseconds)
                        awaitingPresenceDigest = digest
                    }
                    guard let message = capture.pendingMessage else { throw HumaError.invalidResponse }
                    try capture.acceptSignature(signPresence(message))
                    awaitingPresenceDigest = nil
                } else {
                    guard try capture.respondToPresence(outcome: event.outcome, elapsedMilliseconds: event.elapsedMilliseconds) == nil
                          else { throw HumaError.invalidResponse }
                }
                presence += 1
            default: throw HumaError.invalidSession
            }
            processed += 1; lastHead = record.head
        }
    }
    public var closedChunks: Int { capture.info.closedChunks ?? 0 }
    public var openOperations: Int { capture.info.openOperations ?? 0 }
    public func closeOpenPart() throws { try capture.closeLongPart() }
    public func chunkInput(index: Int) throws -> (input: Data, tier: Int) { try capture.longChunkInput(index: index) }
    /// Returns private proof input only after the final checkpoint was accepted.
    public func checkpoint(session: SessionLog, text: String, time: CaptureTime, final: Bool,
                           sign: (Data) throws -> Data) throws -> Data? {
        try synchronize(session)
        let message: Data
        if capture.info.checkpoints == 0 {
            guard processed == 0, !final, time.unixMilliseconds == initialUnix,
                  time.elapsedMilliseconds == 0, let initial = capture.pendingMessage else { throw HumaError.invalidSession }
            message = initial
        } else {
            message = try capture.prepareCheckpoint(text: text, unixMilliseconds: time.unixMilliseconds,
                elapsedMilliseconds: time.elapsedMilliseconds, final: final)
        }
        try capture.acceptSignature(sign(message))
        return final ? try capture.sealedSnapshot() : nil
    }
    /// Undo, input methods (accents, Chinese and Japanese input), list buttons and typing on another keyboard count as
    /// typing in the proof; the session log (and the replay readers check) keeps the exact label.
    static func provedSource(_ source: String) -> String {
        ["typing", "typing-external", "undo-redo", "input-method", "format-insert"].contains(source) ? "typing" : source
    }
}
