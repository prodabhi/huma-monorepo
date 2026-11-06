import Foundation
import XCTest
@testable import HumaCore

final class HumaScoreTests: XCTestCase {
    // The same cases as web/test/score.test.mjs, so the Mac and readers agree on every page's score.
    func testTheScoreWeighsTypedTextTypingChecksAndTouchID() {
        let all = Array(repeating: true, count: 9)
        typealias Parts = TextProvenance.Composition
        func score(_ parts: Parts?, typing: Int = 0, edits: Int = 0, rules: [Bool] = all, presence: Int = 2, onTime: Int = 2) -> Int {
            HumaScore(composition: parts, typingEdits: typing, edits: edits, rules: rules, presenceCount: presence, onTime: onTime).value
        }
        XCTAssertEqual(score(Parts(typed: 100)), 100)
        XCTAssertEqual(score(Parts(external: 100)), 72)
        XCTAssertEqual(score(Parts(typed: 80, pasted: 20)), 86)
        XCTAssertEqual(score(nil, typing: 50, edits: 50), 72) // no replay: typing counted at 60%
        var rules = all; rules[2] = false; rules[5] = false; rules[8] = false
        // Unusual holds and speed (typing no person makes) keep it at 50; a short or unpaused page isn't capped.
        XCTAssertEqual(score(Parts(typed: 100), rules: rules, onTime: 1), 50)
        var plain = all; plain[2] = false; plain[7] = false
        XCTAssertEqual(score(Parts(typed: 100), rules: plain, onTime: 1), 89)
        XCTAssertEqual(score(Parts(typed: 100), presence: 0, onTime: 0), 100)
        XCTAssertEqual(score(Parts(pasted: 100), rules: Array(repeating: false, count: 9), presence: 3, onTime: 0), 0)
    }
    // The same cases as "the score splits into whole points…" in web/test/score.test.mjs.
    func testTheScoreSplitsIntoWholePointsAndOnePlainLine() {
        typealias Parts = TextProvenance.Composition
        let all = Array(repeating: true, count: 9)
        var some = all; some[3] = false; some[6] = false
        for (parts, rules, presence, onTime) in [(Parts(typed: 97, pasted: 3), all, 3, 2), (Parts(typed: 50, external: 50), some, 2, 1), (nil, some, 0, 0)] {
            let score = HumaScore(composition: parts, typingEdits: 40, edits: 41, rules: rules, presenceCount: presence, onTime: onTime)
            XCTAssertEqual(score.points.typed + score.points.checks + score.points.touch, score.value)
            XCTAssertTrue(score.points.typed <= 70 && score.points.checks <= 20 && score.points.touch <= 10)
        }
        func line(_ parts: Parts?, rules: [Bool] = all) -> String {
            HumaScore(composition: parts, typingEdits: 9, edits: 10, rules: rules, presenceCount: 2, onTime: 1).line
        }
        XCTAssertEqual(line(Parts(typed: 100)), "100% typed · 7 of 7 typing checks · Touch ID 1 of 2")
        XCTAssertEqual(line(Parts(typed: 995, pasted: 5)), "99% typed · 7 of 7 typing checks · Touch ID 1 of 2")
        XCTAssertEqual(line(Parts(typed: 60, external: 40), rules: some), "100% typed (40% on another keyboard) · 5 of 7 typing checks · Touch ID 1 of 2")
        XCTAssertEqual(line(nil), "Replay not shared, so typing counts at 60% · 7 of 7 typing checks · Touch ID 1 of 2")
        XCTAssertEqual([0, 0.004, 0.5, 0.996, 1].map(HumaScore.percent), ["0%", "<1%", "50%", "99%", "100%"])
    }
    func testEveryCharacterKeepsWhereItCameFromThroughEditsAndUndo() throws {
        var session = SessionLog(initialText: "Hi")
        try session.record(before: "Hi", after: "Hi there", source: "typing", elapsed: 1)
        try session.record(before: "Hi there", after: "Hi there, friend", source: "paste", elapsed: 2)
        try session.record(before: "Hi there, friend", after: "Hi there, friend!", source: "typing-external", elapsed: 3)
        try session.record(before: "Hi there, friend!", after: "Hi there!", source: "typing", elapsed: 4)       // delete the paste
        try session.record(before: "Hi there!", after: "Hi there, friend!", source: "undo-redo", elapsed: 5)   // undo brings it back, still pasted
        let provenance = TextProvenance(session: session)
        XCTAssertEqual(provenance.string, "Hi there, friend!")
        XCTAssertEqual(provenance.composition, TextProvenance.Composition(typed: 6, external: 1, pasted: 8, before: 2))
        XCTAssertEqual(provenance.ranges(of: .pasted), [NSRange(location: 8, length: 8)])
        // The page as it was after the second edit, for version history.
        XCTAssertEqual(TextProvenance(session: session, through: 2).string, "Hi there, friend")
        var live = TextProvenance(session: session, through: 1)
        live.catchUp(with: session)
        XCTAssertEqual(live.string, provenance.string)
    }
    func testThePageProofSaysHowItWasWritten() throws {
        var inputs = [UInt8](repeating: 0, count: 46 * 32)
        func set(_ index: Int, _ value: Int) { inputs[index * 32 + 31] = UInt8(value) }
        set(16, 40); set(18, 38); set(19, 2); set(25, 3); set(27, 2)
        for rule in 0..<9 where rule != 1 { set(33 + rule, 1) }
        let summary = try XCTUnwrap(PageProofSummary(finalInputs: Data(inputs)))
        XCTAssertEqual(summary.edits, 40); XCTAssertEqual(summary.typingEdits, 38); XCTAssertEqual(summary.pasteEdits, 2)
        XCTAssertEqual(summary.rules, [true, false, true, true, true, true, true, true, true])
        XCTAssertEqual(summary.score(composition: TextProvenance.Composition(typed: 90, pasted: 10)).value, 90)
        let wrapped = try JSONSerialization.data(withJSONObject: ["proof": String(decoding: try JSONSerialization.data(withJSONObject:
            ["kind": "huma-long-assurance-public-proof-v2", "finalInputs": Data(inputs).base64EncodedString()]), as: UTF8.self)])
        XCTAssertEqual(PageProofSummary(proof: wrapped), summary)
    }
}
