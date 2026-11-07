import Foundation
import CryptoKit
import HumaCore

// Drives the actual Swift bridge with a disposable SOFTWARE key while input is
// appended. Never reads a draft, Keychain or Secure Enclave, and never asks Touch ID.
@main struct LiveCompactCaptureFixture {
    struct Legacy: Encodable { let text: String; let session: SessionLog }
    @MainActor static func main() throws {
        let library = URL(fileURLWithPath: CommandLine.arguments[1])
        let directory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
        let key = P256.Signing.PrivateKey()
        let unix: UInt64 = 1_792_627_200_000
        var session = SessionLog(), text = "", elapsed: UInt64 = 0
        let capture = try ExperimentalCompactRecorder(libraryURL: library, session: session,
            publicKey: key.publicKey.x963Representation, time: CaptureTime(unixMilliseconds: unix, elapsedMilliseconds: 0))
        let clock = ContinuousClock.now
        var previousCount = 0, previousElapsed: UInt64 = 0
        func sign(final: Bool = false, initial: Bool = false) throws {
            var cp = session.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation,
                final: final, reportedTime: CaptureTime(unixMilliseconds: unix + elapsed, elapsedMilliseconds: elapsed))
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            session.signedCheckpoints!.append(cp)
            session.experimentalCompactSnapshot = try capture.checkpoint(session: session, text: text,
                time: CaptureTime(unixMilliseconds: unix + elapsed, elapsedMilliseconds: elapsed), final: final) {
                    try key.signature(for: $0).derRepresentation
                }
            previousCount = capture.info.captures; previousElapsed = elapsed
        }
        func automatic() throws {
            if try CheckpointCadence.shouldCheckpoint(captureCount: capture.info.captures, previousCount: previousCount,
                elapsedMilliseconds: elapsed, previousElapsedMilliseconds: previousElapsed) { try sign() }
        }
        try sign(initial: true)
        let alphabet = Array("Simulated live software-key fixture; no human or hardware claim. ")
        for i in 0..<250 {
            elapsed += 80
            try session.recordSample(InputSample(kind: "down", keyCode: UInt16(i % 128), modifiers: 0, elapsedMilliseconds: elapsed))
            try capture.synchronize(session)
            try automatic()
            elapsed += 1
            let next = text + String(alphabet[i % alphabet.count])
            try session.record(before: text, after: next, source: "typing", elapsed: elapsed)
            try capture.synchronize(session)
            text = next; try automatic()
            elapsed += 65
            try session.recordSample(InputSample(kind: "up", keyCode: UInt16(i % 128), modifiers: 0, elapsedMilliseconds: elapsed))
            try capture.synchronize(session)
            try automatic()
        }
        try sign(final: true)
        try session.validateSignedCheckpoints(requireFinal: true, finalText: text)
        let snapshot = try XCTMessage(session.experimentalCompactSnapshot)
        var document = Draft(); document.text = text; document.session = session
        try document.validate()
        let savedDocument = try JSONEncoder().encode(document)
        let reopened = try JSONDecoder().decode(Draft.self, from: savedDocument)
        try reopened.validate()
        guard reopened.session.experimentalCompactSnapshot == snapshot else { throw HumaError.invalidDocument }
        let duration = clock.duration(to: .now).components
        let milliseconds = Double(duration.seconds) * 1_000 + Double(duration.attoseconds) / 1e15
        for (name, data) in [("SwiftLive250-snapshot.json", snapshot), ("SwiftLive250-legacy.json", try JSONEncoder().encode(Legacy(text: text, session: session))), ("SwiftLive250-document.huma", savedDocument)] {
            let path = directory.appendingPathComponent(name)
            guard !FileManager.default.fileExists(atPath: path.path) else { throw HumaError.configuration("Use a new fixture directory; existing evidence was not overwritten.") }
            try data.write(to: path, options: [.withoutOverwriting])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        }
        struct Report: Encodable {
            let captureAndSignMilliseconds: Double
            let operations: Int, captures: Int, checkpoints: Int
            let softwareKeyOnly = true
            let hardwareAttestation = false
            let recorderAdapterAndSaveReopen = true
        }
        FileHandle.standardOutput.write(try JSONEncoder().encode(Report(captureAndSignMilliseconds: milliseconds,
            operations: capture.info.operations, captures: capture.info.captures, checkpoints: capture.info.checkpoints)))
    }
    static func XCTMessage(_ data: Data?) throws -> Data {
        guard let data else { throw HumaError.invalidResponse }; return data
    }
}
