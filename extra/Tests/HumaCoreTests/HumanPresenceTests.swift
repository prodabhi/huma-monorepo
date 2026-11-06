import XCTest
import CryptoKit
@testable import HumaCore

final class HumanPresenceTests: XCTestCase {
    func sign(_ session: inout SessionLog, key: P256.Signing.PrivateKey, text: String, elapsed: UInt64, final: Bool = false) throws {
        var cp = session.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation, final: final,
            reportedTime: .init(unixMilliseconds: 1_792_627_200_000 + elapsed, elapsedMilliseconds: elapsed))
        cp.signature = try key.signature(for: cp.payload()).derRepresentation
        session.signedCheckpoints!.append(cp)
    }
    func response(_ session: inout SessionLog, key: P256.Signing.PrivateKey, outcome: String, elapsed: UInt64) throws {
        var event = try session.presenceResponse(outcome: outcome, elapsed: elapsed)
        if outcome == "approved" { event.signature = try key.signature(for: event.payload(sessionID: session.id)).derRepresentation }
        try session.appendPresence(event)
    }
    func testOriginIsSignedAndLegacySamplesKeepTheirDigest() throws {
        let key = P256.Signing.PrivateKey()
        var session = SessionLog()
        try sign(&session, key: key, text: "", elapsed: 0)
        let old = InputSample(kind: "down", keyCode: 0, modifiers: 0, elapsedMilliseconds: 1)
        XCTAssertEqual(try old.digest(), sha256(try JSONEncoder().encode(["down", "0", "0", "1"])))
        var sample = old
        sample.origin = .init(sourceUnixProcessID: 0, sourceStateID: 1, keyboardType: 41, isRepeat: false)
        XCTAssertNotEqual(try sample.digest(), try old.digest())
        try session.recordSample(sample)
        try session.record(before: "", after: "x", source: "typing", elapsed: 2)
        try sign(&session, key: key, text: "x", elapsed: 3, final: true)
        try session.validateSignedCheckpoints(requireFinal: true, finalText: "x")
        session.inputSamples![0].origin!.sourceUnixProcessID = 123
        XCTAssertThrowsError(try session.validateSignedCheckpoints(requireFinal: true, finalText: "x"))
    }
    func testPresenceFreezesInputBindsResponseAndSurvivesSave() throws {
        let key = P256.Signing.PrivateKey()
        var session = SessionLog()
        session.presenceProtocol = "local-presence-v1"
        try sign(&session, key: key, text: "", elapsed: 0)
        try session.record(before: "", after: "hello", source: "typing", elapsed: 5)
        _ = try session.issuePresence(reason: "interval", elapsed: 6)
        XCTAssertThrowsError(try session.record(before: "hello", after: "hello!", source: "typing", elapsed: 7))
        XCTAssertThrowsError(try session.recordSample(.init(kind: "up", keyCode: 0, modifiers: 0, elapsedMilliseconds: 7)))
        XCTAssertThrowsError(try session.issuePresence(reason: "seal", elapsed: 7))
        try response(&session, key: key, outcome: "cancelled", elapsed: 100)
        _ = try session.issuePresence(reason: "seal", elapsed: 200)
        try response(&session, key: key, outcome: "approved", elapsed: 500)
        try sign(&session, key: key, text: "hello", elapsed: 501, final: true)
        let reopened = try JSONDecoder().decode(SessionLog.self, from: JSONEncoder().encode(session))
        try reopened.validateSignedCheckpoints(requireFinal: true, finalText: "hello")
        XCTAssertEqual(reopened.presenceEvents?.count, 4)
        XCTAssertEqual(reopened.presenceEvents?[1].outcome, "cancelled")
        var tampered = reopened
        tampered.presenceEvents![3].nonce = String(repeating: "0", count: 64)
        XCTAssertThrowsError(try tampered.validateSignedCheckpoints(requireFinal: true, finalText: "hello"))
        tampered = reopened
        tampered.presenceEvents![3].signature = try P256.Signing.PrivateKey().signature(for: reopened.presenceEvents![3].payload(sessionID: reopened.id)).derRepresentation
        XCTAssertThrowsError(try tampered.validateSignedCheckpoints(requireFinal: true, finalText: "hello"))
    }
    func testPendingLateAndUncoveredSealCannotBecomeFinalEvidence() throws {
        let key = P256.Signing.PrivateKey()
        var session = SessionLog(initialText: "x")
        session.presenceProtocol = "local-presence-v1"
        try sign(&session, key: key, text: "x", elapsed: 0)
        _ = try session.issuePresence(reason: "seal", elapsed: 5)
        XCTAssertThrowsError(try session.validatePresence(requireResolved: true))
        try response(&session, key: key, outcome: "approved", elapsed: 10_006)
        XCTAssertThrowsError(try session.validatePresence(requireResolved: true))
        _ = try session.issuePresence(reason: "seal", elapsed: 10_010)
        try response(&session, key: key, outcome: "approved", elapsed: 10_020)
        try session.validatePresence(requireResolved: true)
        try session.record(before: "x", after: "xx", source: "typing", elapsed: 10_021)
        XCTAssertThrowsError(try session.validatePresence(requireResolved: true))
    }
    func testScheduleHasFloorAndSpecifiedMeanWithoutFixedIntervals() {
        struct Random: RandomNumberGenerator {
            var state: UInt64 = 42
            mutating func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state }
        }
        var random = Random()
        let delays = (0..<10_000).map { _ in PresenceSchedule.delayMilliseconds(using: &random) }
        XCTAssertGreaterThanOrEqual(delays.min()!, 180_000)
        XCTAssertGreaterThan(Set(delays).count, 9_000)
        let mean = delays.reduce(0.0) { $0 + Double($1) } / Double(delays.count)
        XCTAssertTrue((720_000...780_000).contains(mean))
    }
}
