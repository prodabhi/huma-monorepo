import Foundation
import CryptoKit
import HumaCore

// Disposable software-key fixtures only. No Keychain, Secure Enclave, UI or network.
@main struct PresenceFixtures {
    struct Witness: Encodable { let text: String; let session: SessionLog }
    static func main() throws {
        let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for (name, paste, missed) in [("presence-typed", false, false), ("presence-paste-missed", true, true)] {
            let key = P256.Signing.PrivateKey()
            var session = SessionLog(); session.presenceProtocol = "local-presence-v1"
            var text = ""
            func checkpoint(_ elapsed: UInt64, final: Bool = false) throws {
                var cp = session.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation, final: final,
                    reportedTime: .init(unixMilliseconds: 1_792_627_200_000 + elapsed, elapsedMilliseconds: elapsed))
                cp.signature = try key.signature(for: cp.payload()).derRepresentation
                session.signedCheckpoints!.append(cp)
            }
            func challenge(_ reason: String, _ issued: UInt64, _ answered: UInt64, _ outcome: String) throws {
                _ = try session.issuePresence(reason: reason, elapsed: issued)
                var response = try session.presenceResponse(outcome: outcome, elapsed: answered)
                if outcome == "approved" { response.signature = try key.signature(for: response.payload(sessionID: session.id)).derRepresentation }
                try session.appendPresence(response)
            }
            try checkpoint(0)
            for i in 0..<40 {
                let elapsed = UInt64(100 + i * 550)
                let origin = InputOrigin(sourceUnixProcessID: paste ? 123 : 0, sourceStateID: paste ? -1 : 1, keyboardType: 41, isRepeat: false)
                try session.recordSample(.init(kind: "down", keyCode: UInt16(i % 26), modifiers: 0, elapsedMilliseconds: elapsed, origin: origin))
                let next = text + String(UnicodeScalar(97 + i % 26)!)
                try session.record(before: text, after: next, source: paste ? "paste" : "typing", elapsed: elapsed + 1)
                text = next
                try session.recordSample(.init(kind: "up", keyCode: UInt16(i % 26), modifiers: 0, elapsedMilliseconds: elapsed + 65, origin: origin))
            }
            try challenge("interval", 22_500, missed ? 32_501 : 22_900, missed ? "timedOut" : "approved")
            try challenge("seal", 34_000, 34_400, "approved")
            try checkpoint(34_401, final: true)
            try session.validateSignedCheckpoints(requireFinal: true, finalText: text)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            try encoder.encode(Witness(text: text, session: session)).write(to: directory.appendingPathComponent(name + ".json"), options: .withoutOverwriting)
        }
    }
}
