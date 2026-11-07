import Foundation
import CryptoKit
import HumaCore

// Fully simulated input through the real Swift recorder. This never loads a user
// draft, device key or authentication context. Times are fixture values.
@main struct LiveAssuranceFixture {
    @MainActor static func main() throws {
        let mode = CommandLine.arguments.count == 4 ? CommandLine.arguments[3] : ""
        guard (3...4).contains(CommandLine.arguments.count), ["", "--short", "--slow", "--checkpoint-boundary", "--adaptive-short", "--adaptive-medium", "--long", "--long-big", "--long-medium"].contains(mode) else { throw HumaError.invalidResponse }
        let adaptive = mode.hasPrefix("--adaptive-")
        let short = mode == "--short" || adaptive, boundary = mode == "--checkpoint-boundary"
        // Long modes record like the app: the short profile is dropped once outgrown, the long one continues.
        let longMode = mode.hasPrefix("--long")
        let count = mode == "--long-big" ? 3000 : mode == "--long" ? 600 : mode == "--long-medium" ? 120 : mode == "--adaptive-medium" ? 120 : boundary ? 30 : short ? 40 : 250
        let library = URL(fileURLWithPath: CommandLine.arguments[1])
        let directory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
        let key = P256.Signing.PrivateKey()
        let unix: UInt64 = 1_792_627_200_000
        var draft = Draft(), elapsed: UInt64 = 0
        draft.session.presenceProtocol = "local-presence-v1"; draft.session.presenceEvents = []
        let recorder = try ExperimentalCompactRecorder(libraryURL: library, session: draft.session,
            publicKey: key.publicKey.x963Representation, time: CaptureTime(unixMilliseconds: unix, elapsedMilliseconds: 0),
            profile: mode == "--slow" || boundary || adaptive ? .assuranceExtended : .assurance)
        let long = longMode ? try ExperimentalCompactRecorder(libraryURL: library, session: draft.session,
            publicKey: key.publicKey.x963Representation, time: CaptureTime(unixMilliseconds: unix, elapsedMilliseconds: 0),
            profile: .assuranceLong) : nil
        var shortAlive = true
        func sync(_ sign: ((Data) throws -> Data)? = nil) throws {
            if shortAlive { do { try recorder.synchronize(draft.session, signPresence: sign) } catch { shortAlive = false; draft.session.experimentalCompactSnapshot = nil } }
            try long?.synchronize(draft.session, signPresence: sign)
        }
        let clock = ContinuousClock.now
        func checkpoint(final: Bool = false) throws {
            let time = CaptureTime(unixMilliseconds: unix + elapsed, elapsedMilliseconds: elapsed)
            var cp = draft.session.makeCheckpoint(text: draft.text, publicKey: key.publicKey.x963Representation,
                final: final, reportedTime: time)
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            draft.session.signedCheckpoints!.append(cp)
            if shortAlive {
                do { draft.session.experimentalCompactSnapshot = try recorder.checkpoint(session: draft.session,
                    text: draft.text, time: time, final: final) { try key.signature(for: $0).derRepresentation } }
                catch { guard longMode else { throw error }; shortAlive = false; draft.session.experimentalCompactSnapshot = nil }
            }
            if let long {
                draft.session.longCompactSnapshot = try long.checkpoint(session: draft.session,
                    text: draft.text, time: time, final: final) { try key.signature(for: $0).derRepresentation }
            }
        }
        func automatic() throws {
            guard let last = draft.session.signedCheckpoints?.last else { throw HumaError.invalidSession }
            if try CheckpointCadence.shouldCheckpoint(captureCount: draft.session.captureRecords?.count ?? 0,
                previousCount: last.captureCount, elapsedMilliseconds: elapsed,
                previousElapsedMilliseconds: last.reportedTime?.elapsedMilliseconds ?? 0) { try checkpoint() }
        }
        func presence(_ reason: String) throws {
            elapsed += 10
            _ = try draft.session.issuePresence(reason: reason, elapsed: elapsed)
            try sync()
            elapsed += 100
            var response = try draft.session.presenceResponse(outcome: "approved", elapsed: elapsed)
            response.signature = try key.signature(for: response.payload(sessionID: draft.session.id)).derRepresentation
            try draft.session.appendPresence(response)
            try sync { try key.signature(for: $0).derRepresentation }
        }
        try checkpoint()
        let alphabet = Array("Simulated V4 software-key fixture; no human, Touch ID or hardware attestation claim. ")
        let origin = InputOrigin(sourceUnixProcessID: -1, sourceStateID: 1, keyboardType: 40, isRepeat: false)
        for i in 0..<count {
            elapsed += boundary ? 10_050 : mode == "--slow" ? 850 : short ? 550 : (i > 0 && i % 60 == 0) ? 1020 : 120
            try draft.session.recordSample(InputSample(kind: "down", keyCode: UInt16(i % 128), modifiers: 0,
                elapsedMilliseconds: elapsed, origin: origin))
            try sync(); try automatic()
            elapsed += 1
            if longMode && i % 97 == 96 { try draft.updateText(String(draft.text.dropLast()), source: "typing", elapsed: elapsed) }
            else { try draft.updateText(draft.text + String(alphabet[i % alphabet.count]), source: "typing", elapsed: elapsed) }
            try sync(); try automatic()
            elapsed += 65
            try draft.session.recordSample(InputSample(kind: "up", keyCode: UInt16(i % 128), modifiers: 0,
                elapsedMilliseconds: elapsed, origin: origin))
            try sync(); try automatic()
            if longMode ? i % 900 == 450 : i == count / 2 - 1 { try presence("interval") }
            // A pause, as the app's idle check closes the open part.
            if longMode && i % 150 == 149 && long!.openOperations >= 450 { try long!.closeOpenPart() } // as the app: a pause, ¾ full
        }
        if let long, long.openOperations > 0 { try long.closeOpenPart() } // Finish closes the open part
        try presence("seal")
        elapsed += 1
        try checkpoint(final: true)
        try draft.session.validateSignedCheckpoints(requireFinal: true, finalText: draft.text)
        try draft.validate()
        if let long {
            // The first closed chunks' private inputs, for the background-proof reuse check.
            // Medium drafts keep both recordings; longer ones outgrow the short profile.
            guard shortAlive == (mode == "--long-medium"), draft.session.longCompactSnapshot != nil, long.closedChunks >= 1 else { throw HumaError.invalidSession }
            for index in 0..<long.closedChunks { try long.chunkInput(index: index).input.write(to: directory.appendingPathComponent("chunk-\(index).json"), options: [.withoutOverwriting]) }
        }
        guard let snapshot = longMode ? draft.session.longCompactSnapshot : draft.session.experimentalCompactSnapshot else { throw HumaError.invalidSession }
        let saved = try JSONEncoder().encode(draft)
        let reopened = try JSONDecoder().decode(Draft.self, from: saved)
        try reopened.validate()
        guard (longMode ? reopened.session.longCompactSnapshot : reopened.session.experimentalCompactSnapshot) == snapshot else { throw HumaError.invalidDocument }
        for (name, data) in [("snapshot.json", snapshot), ("document.huma", saved)] {
            let path = directory.appendingPathComponent(name)
            try data.write(to: path, options: [.withoutOverwriting])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        }
        let duration = clock.duration(to: .now).components
        struct Report: Encodable {
            let softwareKeyOnly = true, simulatedInputAndTimes = true, manufacturerAttestation = false
            let saveReopen = true
            let profile: String
            let captureAndSignMilliseconds: Double
            let operations: Int, captures: Int, checkpoints: Int
        }
        let milliseconds = Double(duration.seconds) * 1000 + Double(duration.attoseconds) / 1e15
        let info = long?.info ?? recorder.info
        FileHandle.standardOutput.write(try JSONEncoder().encode(Report(profile: info.profile,
            captureAndSignMilliseconds: milliseconds, operations: info.operations,
            captures: info.captures, checkpoints: info.checkpoints)))
    }
}
