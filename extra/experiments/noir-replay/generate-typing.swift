import Foundation
import CryptoKit
import HumaCore

// Simulated input with disposable SOFTWARE keys. Not a human/device attestation.
@main struct GenerateTypingFixtures {
    struct Witness: Encodable { var text: String; var session: SessionLog }
    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            throw HumaError.configuration("Usage: generate-typing OUTPUT_DIRECTORY")
        }
        let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for policy in ["legacy32", "current"] {
          for length in [50, 250, 1024] {
            let key = P256.Signing.PrivateKey()
            var session = SessionLog()
            var text = ""
            var elapsed: UInt64 = 0
            func checkpoint(final: Bool = false) throws {
                let count = session.captureRecords?.count ?? 0
                let previousCount = session.signedCheckpoints?.last?.captureCount ?? 0
                if !final, session.signedCheckpoints?.isEmpty == false {
                    let needed = policy == "legacy32" ? count - previousCount >= 32 :
                        try CheckpointCadence.shouldCheckpoint(captureCount: count, previousCount: previousCount,
                            elapsedMilliseconds: elapsed,
                            previousElapsedMilliseconds: session.signedCheckpoints?.last?.reportedTime?.elapsedMilliseconds ?? 0)
                    guard needed else { return }
                }
                var cp = session.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation,
                    final: final, reportedTime: CaptureTime(unixMilliseconds: 1_792_627_200_000 + elapsed,
                                                          elapsedMilliseconds: elapsed))
                cp.signature = try key.signature(for: cp.payload()).derRepresentation
                session.signedCheckpoints!.append(cp)
            }
            try checkpoint()
            let sentence = Array("Simulated software-key typing fixture; no human or hardware claim. ".utf8)
            for i in 0..<length {
                elapsed += 80
                try session.recordSample(InputSample(kind: "down", keyCode: UInt16(i % 40), modifiers: 0, elapsedMilliseconds: elapsed))
                try checkpoint()
                let after = text + String(UnicodeScalar(sentence[i % sentence.count]))
                elapsed += 1
                try session.record(before: text, after: after, source: "typing", elapsed: elapsed)
                text = after
                try checkpoint()
                elapsed += 65
                try session.recordSample(InputSample(kind: "up", keyCode: UInt16(i % 40), modifiers: 0, elapsedMilliseconds: elapsed))
                try checkpoint()
            }
            try checkpoint(final: true)
            try session.validateSignedCheckpoints(requireFinal: true, finalText: text)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            let suffix = policy == "current" ? "-current" : ""
            try encoder.encode(Witness(text: text, session: session)).write(to: directory.appendingPathComponent("typing-\(length)\(suffix).json"), options: .atomic)
            print("\(length) bytes (\(policy)): \(session.events.count) edits, \(session.inputSamples?.count ?? 0) samples, \(session.captureRecords?.count ?? 0) records, \(session.signedCheckpoints?.count ?? 0) checkpoints")
          }
        }
    }
}
