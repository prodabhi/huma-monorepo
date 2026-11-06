import CryptoKit
import XCTest
@testable import HumaCore

final class ReplayExportTests: XCTestCase {
    /// A sealed session with edits that stress the encoding the browser recomputes: slashes, quotes, tabs,
    /// line breaks, emoji (surrogate pairs), a paste, a deletion and an undo that restores it.
    static func sealedSession() throws -> (SessionLog, String, P256.Signing.PrivateKey) {
        let key = P256.Signing.PrivateKey()
        var log = SessionLog(initialText: "Intro/\n")
        func sign(_ text: String, elapsed: UInt64, final: Bool = false) throws {
            var cp = log.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation, final: final,
                reportedTime: CaptureTime(unixMilliseconds: 1_760_000_000_000 + elapsed, elapsedMilliseconds: elapsed))
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            if log.signedCheckpoints == nil { log.signedCheckpoints = [] }
            log.signedCheckpoints!.append(cp)
        }
        try sign("Intro/\n", elapsed: 0)
        var text = "Intro/\n"
        for (after, source) in [("Intro/\nH", "typing"), ("Intro/\nHi", "typing"), ("Intro/\nHi \"a/b\"\t😀", "paste"),
                                ("Intro/\nHi", "typing"), ("Intro/\nHi \"a/b\"\t😀", "undo-redo"), ("Intro/\nHi \"a/b\"\t😀\u{2028}é!", "typing")] {
            try log.record(before: text, after: after, source: source, elapsed: UInt64(log.events.count + 1) * 400)
            text = after
        }
        try sign(text, elapsed: 4000, final: true)
        return (log, text, key)
    }

    func testReplayExportCarriesTheSignedFinalCheckpoint() throws {
        let (log, text, key) = try Self.sealedSession()
        let data = try XCTUnwrap(try log.replayExport(text: text))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["kind"] as? String, SessionLog.replayKind)
        XCTAssertEqual((object["events"] as? [Any])?.count, 6)
        let checkpoint = try XCTUnwrap(object["checkpoint"] as? [String: Any])
        XCTAssertEqual(checkpoint["publicKey"] as? String, key.publicKey.x963Representation.base64EncodedString())
        XCTAssertNil(try log.replayExport(text: text + "x"), "Another text isn't this session's replay.")
        var open = log; open.signedCheckpoints!.removeLast()
        XCTAssertNil(try open.replayExport(text: text), "Only a sealed session has a replay.")
        // frontend/test/replay.test.mjs checks this file in the browser's verifier.
        if let out = ProcessInfo.processInfo.environment["HUMA_REPLAY_FIXTURE"] {
            try data.write(to: URL(fileURLWithPath: out))
            try Data(text.utf8).write(to: URL(fileURLWithPath: out + ".txt"))
        }
    }

    /// A longer, realistic session for looking at the reader's player (written only when asked).
    func testWritesALongReplayForThePlayer() throws {
        guard let out = ProcessInfo.processInfo.environment["HUMA_REPLAY_LONG"] else { throw XCTSkip("Set HUMA_REPLAY_LONG to write it.") }
        let key = P256.Signing.PrivateKey()
        var log = SessionLog()
        var text = "", elapsed: UInt64 = 0
        func sign(final: Bool = false) throws {
            var cp = log.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation, final: final,
                reportedTime: CaptureTime(unixMilliseconds: 1_760_000_000_000 + elapsed, elapsedMilliseconds: elapsed))
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            if log.signedCheckpoints == nil { log.signedCheckpoints = [] }
            log.signedCheckpoints!.append(cp)
        }
        func edit(_ after: String, _ source: String, wait: UInt64) throws {
            elapsed += wait; try log.record(before: text, after: after, source: source, elapsed: elapsed); text = after
        }
        try sign()
        var seed: UInt64 = 7
        func gap() -> UInt64 { seed = seed &* 6364136223846793005 &+ 1442695040888963407; return 60 + (seed >> 33) % 180 }
        func type(_ words: String) throws { for c in words { try edit(text + String(c), "typing", wait: gap() + (c == " " ? 90 : 0)) } }
        try type("I started writing this on a slow Sunday morning. The coffee was still too hot to drink")
        for _ in 0..<5 { try edit(String(text.dropLast()), "typing", wait: 110) }
        try type("drink, so I wrote instead.\n\nHere is the quote I kept coming back to: ")
        try edit(text + "“The first draft is just you telling yourself the story.”", "paste", wait: 2400)
        try type("\n\nIt is true. Most of what I wrote first got cut, and that is fine.")
        elapsed += 9000
        try type(" The rest is mine.")
        try sign(final: true)
        try XCTUnwrap(try log.replayExport(text: text)).write(to: URL(fileURLWithPath: out))
        try Data(text.utf8).write(to: URL(fileURLWithPath: out + ".txt"))
    }
}
