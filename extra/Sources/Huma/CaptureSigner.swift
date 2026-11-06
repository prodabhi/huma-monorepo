import Foundation
import SwiftUI
import CryptoKit
import LocalAuthentication
import Combine
import HumaCore

@MainActor
final class CaptureSigner: ObservableObject {
    @Published private(set) var recording = false
    @Published private(set) var status = "Unsigned capture"
    @Published private(set) var presencePending = false
    /// A break: typing and Touch ID check-ins stop, the session clock keeps running. Resume needs Touch ID.
    @Published private(set) var paused = false
    private var nextPresenceElapsed: UInt64 = .max
    private var key: SecureEnclave.P256.Signing.PrivateKey?
    private var sessionID: String?
    private var clockStart: ContinuousClock.Instant?
    private var compact: ExperimentalCompactRecorder?
    private var compactUnavailable = false
    // Long drafts: recorded alongside the short profile; used only once the short one is outgrown.
    private var long: ExperimentalCompactRecorder?
    private var longUnavailable = false
    let chunks = LongChunkProver()
    private var chunkChanges: AnyCancellable?
    private static let all = NSHashTable<CaptureSigner>.weakObjects()
    /// Whether any open page is mid-session, so quitting can warn first.
    static var anyRecording: Bool { all.allObjects.contains { $0.recording } }
    init() {
        Self.all.add(self)
        // Views read the part count through this object, so a part finishing during a pause still updates them.
        chunkChanges = chunks.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }
    }

    func elapsedMilliseconds(sessionID: String) -> UInt64? {
        guard self.sessionID == sessionID, let clockStart else { return nil }
        let parts = clockStart.duration(to: .now).components
        return UInt64(max(0, parts.seconds)) * 1_000 + UInt64(max(0, parts.attoseconds)) / 1_000_000_000_000_000
    }

    func start(draft: inout Draft, context: LAContext) throws {
        guard SecureEnclave.isAvailable else {
            throw HumaError.configuration("This Mac can’t sign your writing. Huma needs a Mac with Touch ID.")
        }
        let signingKey = try TouchIDCaptureKey.loadOrCreate(context: context)
        var candidate = draft
        candidate.keepVerifiedVersion()
        // Begin an explicit new scope. Existing text is a baseline, never relabeled as typed.
        if !candidate.session.events.isEmpty || !(candidate.session.signedCheckpoints?.isEmpty ?? true) {
            if candidate.priorSessions == nil { candidate.priorSessions = [] }
            candidate.priorSessions!.append(candidate.session)
        }
        candidate.session = SessionLog(initialText: candidate.text)
        candidate.session.presenceProtocol = "local-presence-v1"
        candidate.session.presenceEvents = []
        candidate.deviceEvidence = nil
        candidate.replayProof = nil; candidate.replayProofTextHash = nil; candidate.publicProof = nil
        compact = nil; compactUnavailable = false; long = nil; longUnavailable = false
        chunks.reset(sessionID: candidate.session.id)
        key = signingKey; sessionID = candidate.session.id; clockStart = .now; recording = true
        try checkpoint(draft: &candidate, force: true)
        draft = candidate
        nextPresenceElapsed = PresenceSchedule.next(after: 0)
        presencePending = false
        status = "Touch ID approved · signing locally · device attestation pending"
    }

    func authorizeSeal(context: LAContext) throws {
        guard let key else { throw HumaError.invalidSession }
        self.key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: key.dataRepresentation, authenticationContext: context)
    }

    func pause() { if recording, !presencePending { paused = true } }
    func resume() { paused = false }
    func presenceDue(sessionID: String) -> Bool {
        recording && !paused && !presencePending && (elapsedMilliseconds(sessionID: sessionID) ?? 0) >= nextPresenceElapsed
    }
    func beginPresence(draft: inout Draft, reason: String) throws {
        guard recording, !presencePending, sessionID == draft.session.id,
              let elapsed = elapsedMilliseconds(sessionID: draft.session.id) else { throw HumaError.invalidSession }
        // Finish: close the open part now, so it proves while Touch ID is shown.
        if reason == "seal" { closeOpenPart(draft: &draft, minimum: 1) }
        _ = try draft.session.issuePresence(reason: reason, elapsed: max(elapsed, draft.session.latestCaptureElapsed))
        if let compact {
            do { try compact.synchronize(draft.session) }
            catch { disableCompact(draft: &draft) }
        }
        synchronizeLong(draft: &draft)
        presencePending = true
        status = "Confirm you are still writing · input paused"
    }
    func finishPresence(draft: inout Draft, context: LAContext?, failure: String = "cancelled") throws -> Bool {
        guard presencePending, sessionID == draft.session.id,
              let elapsed = elapsedMilliseconds(sessionID: draft.session.id) else { throw HumaError.invalidSession }
        var response = try draft.session.presenceResponse(outcome: context == nil ? failure : "approved", elapsed: elapsed)
        if let context {
            try authorizeSeal(context: context)
            guard let key else { throw HumaError.invalidSession }
            response.signature = try key.signature(for: response.payload(sessionID: draft.session.id)).derRepresentation
        }
        try draft.session.appendPresence(response)
        if let compact {
            do {
                if response.outcome == "approved", let key {
                    // Sign the V4 commitment during this fresh approval, before
                    // input resumes. The native collector never receives a key.
                    try compact.synchronize(draft.session) { try key.signature(for: $0).derRepresentation }
                } else {
                    try compact.synchronize(draft.session)
                }
            } catch { disableCompact(draft: &draft) }
        }
        synchronizeLong(draft: &draft, sign: response.outcome == "approved" ? key : nil)
        presencePending = false
        nextPresenceElapsed = PresenceSchedule.next(after: elapsed)
        let timely = response.outcome == "approved" && elapsed - response.issuedElapsedMilliseconds <= PresenceEvent.deadlineMilliseconds
        status = timely ? "Presence confirmed · signing locally" : "Presence check missed · recorded in session"
        return timely
    }

    func checkpoint(draft: inout Draft, force: Bool = false, final: Bool = false) throws {
        if let last = draft.session.signedCheckpoints?.last, last.isFinal, last.editCount < draft.session.events.count {
            status = "Text changed after sealing; start a new signed session"
        }
        guard recording, !presencePending, let key, sessionID == draft.session.id else { return }
        let count = draft.session.captureRecords?.count ?? 0
        do {
            let initial = draft.session.signedCheckpoints?.isEmpty ?? true
            let time = CaptureTime(unixMilliseconds: UInt64(max(0, Date().timeIntervalSince1970 * 1_000)),
                elapsedMilliseconds: initial ? 0 : (elapsedMilliseconds(sessionID: draft.session.id) ?? 0))
            // Capture compact operations as input arrives, before the checkpoint
            // cadence guard. Existing signed recordings are never retrofitted.
            if initial, !compactUnavailable,
               let library = Bundle.main.resourceURL?.appendingPathComponent("CompactCapture/libhuma_compact_experiment.dylib"),
               FileManager.default.fileExists(atPath: library.path) {
                do { compact = try ExperimentalCompactRecorder(libraryURL: library, session: draft.session,
                    publicKey: key.publicKey.x963Representation, time: time) }
                catch { compact = nil; compactUnavailable = true }
                do { long = try ExperimentalCompactRecorder(libraryURL: library, session: draft.session,
                    publicKey: key.publicKey.x963Representation, time: time, profile: .assuranceLong) }
                catch { long = nil; longUnavailable = true }
            }
            if let compact {
                do { try compact.synchronize(draft.session) }
                catch { disableCompact(draft: &draft) }
            }
            synchronizeLong(draft: &draft)
            if !force && !final, let last = draft.session.signedCheckpoints?.last {
                guard try CheckpointCadence.shouldCheckpoint(captureCount: count,
                    previousCount: last.captureCount, elapsedMilliseconds: time.elapsedMilliseconds,
                    previousElapsedMilliseconds: last.reportedTime?.elapsedMilliseconds ?? 0) else { return }
            }
            var checkpoint = draft.session.makeCheckpoint(text: draft.text, publicKey: key.publicKey.x963Representation,
                final: final, reportedTime: time)
            checkpoint.signature = try key.signature(for: checkpoint.payload()).derRepresentation
            guard checkpoint.verifySignature() else { throw HumaError.invalidSession }
            if draft.session.signedCheckpoints == nil { draft.session.signedCheckpoints = [] }
            draft.session.signedCheckpoints!.append(checkpoint)
            if let compact {
                do {
                    draft.session.experimentalCompactSnapshot = try compact.checkpoint(session: draft.session,
                        text: draft.text, time: time, final: final) { try key.signature(for: $0).derRepresentation }
                } catch {
                    // A short experimental profile cannot shorten or discard a
                    // session. Keep its complete existing replay/signature path.
                    disableCompact(draft: &draft)
                }
            }
            if let long {
                do {
                    draft.session.longCompactSnapshot = try long.checkpoint(session: draft.session,
                        text: draft.text, time: time, final: final) { try key.signature(for: $0).derRepresentation }
                } catch { disableLong(draft: &draft) }
            }
            if final {
                if let long, draft.session.longCompactSnapshot != nil { chunks.offer(long, sessionID: draft.session.id) }
                long = nil
                try draft.session.validateSignedCheckpoints(requireFinal: true, finalText: draft.text)
                recording = false
                compact = nil
                status = "Session sealed locally · device attestation pending"
            }
        } catch {
            recording = false; status = "Signing stopped; this session is incomplete"
            throw error
        }
    }

    private func disableCompact(draft: inout Draft) {
        // Capacity or optional-bridge failures retain the complete original log.
        compact = nil; compactUnavailable = true; draft.session.experimentalCompactSnapshot = nil
    }
    private func disableLong(draft: inout Draft) {
        long = nil; longUnavailable = true; draft.session.longCompactSnapshot = nil; chunks.reset(sessionID: nil)
    }
    /// Keeps the long recorder current. Once the short profile is outgrown, closed
    /// chunks start proving in the background.
    private func synchronizeLong(draft: inout Draft, sign key: SecureEnclave.P256.Signing.PrivateKey? = nil) {
        guard let long else { return }
        do {
            if let key { try long.synchronize(draft.session) { try key.signature(for: $0).derRepresentation } }
            else { try long.synchronize(draft.session) }
        } catch { disableLong(draft: &draft); return }
        chunks.offer(long, sessionID: draft.session.id)
    }
    /// Ends a session that has nothing typed yet, without finishing it, so the page can start over.
    func cancel() {
        recording = false; presencePending = false; paused = false; key = nil; sessionID = nil; clockStart = nil
        compact = nil; long = nil; nextPresenceElapsed = .max
        chunks.reset(sessionID: nil)
        status = "Unsigned capture"
    }
    /// Called every second while writing: after a 3-second pause, prove what is written so far once the open part is
    /// three-quarters full (450 of its 600 operations), so a page has few, full parts and a small proof.
    /// Reads the draft only; recording state lives in the recorders, so the document is not touched.
    func idle(draft: Draft) {
        guard recording, !presencePending, sessionID == draft.session.id,
              let now = elapsedMilliseconds(sessionID: draft.session.id),
              now >= draft.session.latestCaptureElapsed + 3_000 else { return }
        var copy = draft
        closeOpenPart(draft: &copy, minimum: 450)
    }
    private func closeOpenPart(draft: inout Draft, minimum: Int) {
        synchronizeLong(draft: &draft)
        guard let long, compact == nil || draft.text.unicodeScalars.count >= LongChunkProver.startCharacters,
              long.openOperations >= minimum else { return }
        do { try long.closeOpenPart() } catch { disableLong(draft: &draft); return }
        chunks.offer(long, sessionID: draft.session.id)
    }
}

/// Proves closed chunks of a long recording one at a time at low priority, so that
/// finishing a long draft only proves the last chunk and the final step.
@MainActor
final class LongChunkProver: ObservableObject {
    /// Parts close at pauses once a draft reaches this many characters.
    static let startCharacters = 50
    private var sessionID: String?
    private var recorder: ExperimentalCompactRecorder?
    private var next = 0
    private var failures = 0
    /// Set at Finish: the part being proved may finish, and nothing new starts.
    private var stopped = false
    private var task: Task<Void, Never>? { didSet { proving = task != nil } }
    @Published private(set) var proofs: [LongChunkProof] = []
    @Published private(set) var closed = 0
    @Published private(set) var open = 0
    @Published private(set) var proving = false

    /// One status line: parts ready while writing and the expected wait at Finish.
    func status(characters: Int, recording: Bool) -> String? {
        guard sessionID != nil, recorder != nil || !proofs.isEmpty else { return nil }
        let total = closed + (open > 0 ? 1 : 0)
        let wait = NoirWritingProofService.finishSeconds(missingParts: max(0, total - proofs.count), characters: characters, tier: proofs.first?.tier)
        return "\(proofs.count) of \(total) parts processed" + (proving ? " · working on part \(proofs.count + 1)" : "")
            + " · about \(Int(wait)) s left at Finish"
    }

    /// Parts proved so far out of the parts recorded; nil until background proving applies.
    var parts: (done: Int, total: Int, working: Bool)? {
        guard sessionID != nil, recorder != nil || !proofs.isEmpty else { return nil }
        return (proofs.count, max(proofs.count, closed + (open > 0 ? 1 : 0)), proving)
    }

    func reset(sessionID: String?) {
        task?.cancel(); task = nil
        self.sessionID = sessionID; recorder = nil; next = 0; failures = 0; stopped = false; proofs = []; closed = 0; open = 0
    }
    func offer(_ recorder: ExperimentalCompactRecorder, sessionID: String) {
        guard self.sessionID == sessionID else { return }
        // A newly closed part gets fresh tries, so a few failures (offline, say) don't stop proving for the session.
        if recorder.closedChunks > closed { failures = 0 }
        self.recorder = recorder; closed = recorder.closedChunks; open = recorder.openOperations; startIfIdle()
    }
    private func startIfIdle() {
        let thermal = ProcessInfo.processInfo.thermalState
        guard task == nil, !stopped, failures < 3, thermal != .serious, thermal != .critical, let recorder, let sessionID,
              next < recorder.closedChunks, let service = try? ReplayProofService.noirService(),
              var part = try? recorder.chunkInput(index: next) else { return }
        // The text outgrew its tier: every part is proved again at the next one, from the first.
        if let proved = proofs.first?.tier, proved != part.tier {
            proofs = []; next = 0
            guard let first = try? recorder.chunkInput(index: 0) else { return }
            part = first
        }
        let index = next, (input, tier) = part
        task = Task { [weak self] in
            let result = try? await service.proveChunk(input, index: index, tier: tier)
            guard let self, self.sessionID == sessionID, !Task.isCancelled else { return }
            self.task = nil
            if let result { self.proofs.append(result); self.next += 1; self.failures = 0 } else { self.failures += 1 }
            self.startIfIdle()
        }
    }
    /// Stops background work and returns this session's part proofs made at the page's current tier, and that tier.
    /// The part being proved finishes rather than being proved again at Finish.
    func collect(sessionID: String) async -> (proofs: [LongChunkProof], tier: Int?) {
        guard self.sessionID == sessionID else { return ([], nil) }
        stopped = true
        await task?.value
        // Parts made before the text outgrew its tier don't fit the page proof any more.
        let tier = (try? recorder?.chunkInput(index: 0))?.tier
        return (proofs.filter { $0.tier == tier }, tier)
    }
}
