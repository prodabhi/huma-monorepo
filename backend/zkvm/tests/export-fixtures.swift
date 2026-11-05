import Foundation
import CryptoKit

// Ordinary software test keys. These fixtures do not claim hardware or human origin.
@main struct ExportReplayFixtures {
    struct Witness: Encodable { var text: String; var session: SessionLog }
    static func main() throws {
        let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let key = P256.Signing.PrivateKey()
        var session = SessionLog()
        session.id = "12345678-1234-1234-1234-123456789ABC"
        var text = ""
        var time: UInt64 = 0
        let reported = CommandLine.arguments.contains("--reported-time")
        func sign(final: Bool = false) throws {
            let reading = reported ? CaptureTime(unixMilliseconds: 1_792_627_200_000 + time,
                elapsedMilliseconds: time) : nil
            var cp = session.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation, final: final, reportedTime: reading)
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            session.signedCheckpoints!.append(cp)
        }
        try sign()
        let versions = ["Café 👩🏽‍💻", "Cafe\u{301} 👩🏽‍💻", "Cafe\u{301} / \"quoted\"\n\t👩🏽‍💻\u{2028}", "Cafe\u{301} / \"quoted\"\n\t👨🏽‍💻\u{2028}", "Cafe\u{301} / \"quoted\"\n  revised 👨🏽‍💻\u{2028} \t"]
        for (index, value) in versions.enumerated() {
            time += 1
            try session.recordSample(InputSample(kind: "down", keyCode: UInt16(index), modifiers: 0, elapsedMilliseconds: time))
            time += 1
            try session.record(before: text, after: value, source: index == 2 ? "paste" : "typing", elapsed: time)
            text = value
            time += 1
            try session.recordSample(InputSample(kind: "up", keyCode: UInt16(index), modifiers: 0, elapsedMilliseconds: time))
            if index == 2 { try sign() }
        }
        try sign(final: true)
        try session.validateSignedCheckpoints(requireFinal: true, finalText: text)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        try encoder.encode(Witness(text: text, session: session)).write(to: directory.appendingPathComponent(reported ? "swift-timed.json" : "swift-signed.json"))
        if reported { return }
        session.signedCheckpoints = []
        try encoder.encode(Witness(text: text, session: session)).write(to: directory.appendingPathComponent("swift-unsigned.json"))
        session.captureRecords = nil
        try encoder.encode(Witness(text: text, session: session)).write(to: directory.appendingPathComponent("swift-legacy.json"))
    }
}
