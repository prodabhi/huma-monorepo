import Foundation
import CryptoKit
import XCTest
@testable import HumaCore

final class ExperimentalCompactCaptureTests: XCTestCase {
    private func library() throws -> URL {
        guard let path = ProcessInfo.processInfo.environment["HUMA_COMPACT_TEST_LIBRARY"] else {
            throw XCTSkip("Build the compact native dylib and set HUMA_COMPACT_TEST_LIBRARY for bridge acceptance.")
        }
        return URL(fileURLWithPath: path)
    }
    @MainActor func testLiveSwiftCaptureSignsBeforeFurtherInputAndExportsExactHistory() throws {
        let key = P256.Signing.PrivateKey() // Disposable software fixture, never a device key.
        let capture = try ExperimentalCompactCapture(libraryURL: library(), initialText: "a😀z",
            publicKey: key.publicKey.x963Representation, unixMilliseconds: 100)
        XCTAssertThrowsError(try capture.recordSample(kind: "down", keyCode: 1, modifiers: 0, elapsedMilliseconds: 1))
        try capture.acceptSignature(key.signature(for: XCTUnwrap(capture.pendingMessage)).derRepresentation)
        try capture.recordSample(kind: "down", keyCode: 65535, modifiers: 0x8000000100000002, elapsedMilliseconds: 1 << 40)
        try capture.recordEdit(location: 1, removedLength: 2, insertedText: "e\u{301}", source: "composition", elapsedMilliseconds: (1 << 40) + 70_000)
        let message = try capture.prepareCheckpoint(text: "ae\u{301}z", unixMilliseconds: 99,
            elapsedMilliseconds: UInt64.max, final: true)
        let other = P256.Signing.PrivateKey()
        XCTAssertThrowsError(try capture.acceptSignature(other.signature(for: message).derRepresentation))
        XCTAssertFalse(capture.info.sealed)
        try capture.acceptSignature(key.signature(for: message).derRepresentation)
        XCTAssertTrue(capture.info.sealed)
        XCTAssertEqual(capture.info.checkpoints, 2)
        let raw = try capture.sealedSnapshot()
        struct Snapshot: Decodable {
            struct Contents: Decodable {
                struct Capsule: Decodable {
                    struct Journal: Decodable { let elapsed: UInt64; let clock_back: Bool }
                    let journal: Journal
                }
                let capsule: Capsule
                let text: String
            }
            let result: Contents
        }
        let reopened = try JSONDecoder().decode(Snapshot.self, from: raw).result
        XCTAssertEqual(reopened.text, "ae\u{301}z")
        XCTAssertEqual(reopened.capsule.journal.elapsed, UInt64.max)
        XCTAssertTrue(reopened.capsule.journal.clock_back)
        XCTAssertThrowsError(try capture.recordEdit(location: 0, removedLength: 0, insertedText: "!", source: "typing", elapsedMilliseconds: UInt64.max))
    }
    @MainActor func testRejectedUTF16EditAndProfileOverflowDoNotAdvanceCapture() throws {
        let key = P256.Signing.PrivateKey()
        let initial = String(repeating: "😀", count: 256)
        let capture = try ExperimentalCompactCapture(libraryURL: library(), initialText: initial,
            publicKey: key.publicKey.x963Representation, unixMilliseconds: 0)
        try capture.acceptSignature(key.signature(for: XCTUnwrap(capture.pendingMessage)).derRepresentation)
        let before = capture.info.operations
        XCTAssertThrowsError(try capture.recordEdit(location: 1, removedLength: 0, insertedText: "x", source: "typing", elapsedMilliseconds: 0))
        XCTAssertThrowsError(try capture.recordEdit(location: 512, removedLength: 0, insertedText: "x", source: "typing", elapsedMilliseconds: 0))
        XCTAssertEqual(capture.info.operations, before)
        XCTAssertEqual(capture.info.captures, 0)
        let message = try capture.prepareCheckpoint(text: initial, unixMilliseconds: 0, elapsedMilliseconds: 0, final: true)
        try capture.acceptSignature(key.signature(for: message).derRepresentation)
        XCTAssertNoThrow(try capture.sealedSnapshot())
    }
    @MainActor func testRecorderSaveReopenAndTextChangesPreserveTheRightSession() throws {
        let key = P256.Signing.PrivateKey()
        var draft = Draft()
        let recorder = try ExperimentalCompactRecorder(libraryURL: library(), session: draft.session,
            publicKey: key.publicKey.x963Representation, time: CaptureTime(unixMilliseconds: 100, elapsedMilliseconds: 0))
        func checkpoint(_ elapsed: UInt64, final: Bool = false) throws {
            let time = CaptureTime(unixMilliseconds: 100 + elapsed, elapsedMilliseconds: elapsed)
            var cp = draft.session.makeCheckpoint(text: draft.text, publicKey: key.publicKey.x963Representation, final: final, reportedTime: time)
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            draft.session.signedCheckpoints!.append(cp)
            draft.session.experimentalCompactSnapshot = try recorder.checkpoint(session: draft.session, text: draft.text,
                time: time, final: final) { try key.signature(for: $0).derRepresentation }
        }
        try checkpoint(0)
        try draft.session.recordSample(InputSample(kind: "down", keyCode: 1, modifiers: 0, elapsedMilliseconds: 1))
        try recorder.synchronize(draft.session)
        try draft.updateText("a😀z", source: "typing", elapsed: 2)
        try recorder.synchronize(draft.session)
        try checkpoint(2)
        try draft.session.recordSample(InputSample(kind: "up", keyCode: 1, modifiers: 0, elapsedMilliseconds: 3))
        try recorder.synchronize(draft.session)
        try checkpoint(3, final: true)
        let snapshot = try XCTUnwrap(draft.session.experimentalCompactSnapshot)
        try draft.validate()
        let reopened = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(draft))
        try reopened.validate()
        XCTAssertEqual(reopened.session.experimentalCompactSnapshot, snapshot)
        try draft.session.recordSample(InputSample(kind: "down", keyCode: 8, modifiers: 0, elapsedMilliseconds: 4))
        XCTAssertEqual(draft.session.experimentalCompactSnapshot, snapshot) // A navigation key after sealing changes no text.
        try draft.updateText("a😀z!", source: "typing", elapsed: 5)
        XCTAssertNil(draft.session.experimentalCompactSnapshot)
        XCTAssertEqual(reopened.session.experimentalCompactSnapshot, snapshot)
        XCTAssertThrowsError(try ExperimentalCompactRecorder(libraryURL: library(), session: reopened.session,
            publicKey: key.publicKey.x963Representation, time: CaptureTime(unixMilliseconds: 200, elapsedMilliseconds: 0)))
    }
    @MainActor func testRecorderRejectsReplacedSessionAndMissingCaptureOrder() throws {
        let key = P256.Signing.PrivateKey(), time = CaptureTime(unixMilliseconds: 0, elapsedMilliseconds: 0)
        var session = SessionLog()
        let recorder = try ExperimentalCompactRecorder(libraryURL: library(), session: session, publicKey: key.publicKey.x963Representation, time: time)
        _ = try recorder.checkpoint(session: session, text: "", time: time, final: false) { try key.signature(for: $0).derRepresentation }
        XCTAssertThrowsError(try recorder.synchronize(SessionLog()))
        try session.recordSample(InputSample(kind: "down", keyCode: 1, modifiers: 0, elapsedMilliseconds: 1))
        session.captureRecords![0].index = 1
        XCTAssertThrowsError(try recorder.synchronize(session))
    }

    @MainActor func testAssuranceBridgeKeepsOriginAndAllPresenceOutcomes() throws {
        let key = P256.Signing.PrivateKey()
        let capture = try ExperimentalCompactCapture(libraryURL: library(), initialText: "x",
            publicKey: key.publicKey.x963Representation, unixMilliseconds: 100, profile: .assurance)
        func signPending() throws {
            try capture.acceptSignature(key.signature(for: XCTUnwrap(capture.pendingMessage)).derRepresentation)
        }
        try signPending()
        let origin = InputOrigin(sourceUnixProcessID: -1, sourceStateID: 1, keyboardType: Int64(UInt32.max), isRepeat: true)
        try capture.recordSample(kind: "down", keyCode: 1, modifiers: UInt64.max, elapsedMilliseconds: 1, origin: origin)
        let before = capture.info.captures
        XCTAssertThrowsError(try capture.recordSample(kind: "up", keyCode: 1, modifiers: 0, elapsedMilliseconds: 2,
            origin: InputOrigin(sourceUnixProcessID: Int64(Int32.max) + 1, sourceStateID: 1, keyboardType: 0, isRepeat: false)))
        XCTAssertThrowsError(try capture.recordSample(kind: "up", keyCode: 256, modifiers: 0, elapsedMilliseconds: 2))
        XCTAssertEqual(capture.info.captures, before)
        try capture.issuePresence(nonce: Data(repeating: 1, count: 32), reason: "interval", elapsedMilliseconds: 3)
        XCTAssertThrowsError(try capture.recordEdit(location: 1, removedLength: 0, insertedText: "y", source: "typing", elapsedMilliseconds: 4))
        XCTAssertNil(try capture.respondToPresence(outcome: "cancelled", elapsedMilliseconds: 4))
        try capture.recordSample(kind: "up", keyCode: 1, modifiers: 0, elapsedMilliseconds: 5) // Missing origin is retained explicitly.
        try capture.issuePresence(nonce: Data(repeating: 2, count: 32), reason: "seal", elapsedMilliseconds: 6)
        let late = try XCTUnwrap(capture.respondToPresence(outcome: "approved", elapsedMilliseconds: 10_007))
        let other = P256.Signing.PrivateKey()
        XCTAssertThrowsError(try capture.acceptSignature(other.signature(for: late).derRepresentation))
        XCTAssertEqual(capture.info.pendingKind, "presence")
        try signPending()
        XCTAssertThrowsError(try capture.prepareCheckpoint(text: "x", unixMilliseconds: 90, elapsedMilliseconds: 10_008, final: true))
        try capture.issuePresence(nonce: Data(repeating: 3, count: 32), reason: "seal", elapsedMilliseconds: 10_009)
        _ = try capture.respondToPresence(outcome: "approved", elapsedMilliseconds: 10_010)
        try signPending()
        _ = try capture.prepareCheckpoint(text: "x", unixMilliseconds: 90, elapsedMilliseconds: 10_011, final: true)
        try signPending()
        let raw = try capture.sealedSnapshot()
        let result = try XCTUnwrap((JSONSerialization.jsonObject(with: raw) as? [String: Any])?["result"] as? [String: Any])
        let privateInput = try XCTUnwrap(result["private"] as? [String: Any])
        let origins = try XCTUnwrap(privateInput["origins"] as? [[String: Any]])
        XCTAssertEqual(origins.count, 2)
        XCTAssertEqual((origins[0]["pid"] as? NSNumber)?.uint32Value, UInt32.max)
        XCTAssertEqual(origins[0]["repeated"] as? Bool, true)
        XCTAssertEqual(origins[1]["present"] as? Bool, false)
        let capsule = try XCTUnwrap(result["capsule"] as? [String: Any])
        let journal = try XCTUnwrap(capsule["journal"] as? [String: Any])
        XCTAssertEqual(journal["presence_count"] as? Int, 3)
        XCTAssertEqual(journal["approved"] as? Int, 2)
        XCTAssertEqual(journal["on_time"] as? Int, 1)
        XCTAssertEqual(journal["missed"] as? Int, 2)
        XCTAssertEqual((capsule["presence_signatures"] as? [[UInt8]])?.count, 2)
    }

    @MainActor func testAssuranceRecorderSignsLivePolicyHistoryAndSaveReopen() throws {
        let key = P256.Signing.PrivateKey()
        var draft = Draft()
        draft.session.presenceProtocol = "local-presence-v1"; draft.session.presenceEvents = []
        XCTAssertThrowsError(try ExperimentalCompactRecorder(libraryURL: library(), session: draft.session,
            publicKey: key.publicKey.x963Representation, time: CaptureTime(unixMilliseconds: 1000, elapsedMilliseconds: 0), profile: .replay))
        let recorder = try ExperimentalCompactRecorder(libraryURL: library(), session: draft.session,
            publicKey: key.publicKey.x963Representation, time: CaptureTime(unixMilliseconds: 1000, elapsedMilliseconds: 0))
        func checkpoint(_ elapsed: UInt64, final: Bool = false) throws {
            let time = CaptureTime(unixMilliseconds: 1000 + elapsed, elapsedMilliseconds: elapsed)
            var cp = draft.session.makeCheckpoint(text: draft.text, publicKey: key.publicKey.x963Representation, final: final, reportedTime: time)
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            draft.session.signedCheckpoints!.append(cp)
            draft.session.experimentalCompactSnapshot = try recorder.checkpoint(session: draft.session, text: draft.text,
                time: time, final: final) { try key.signature(for: $0).derRepresentation }
        }
        try checkpoint(0)
        XCTAssertEqual(recorder.info.profile, "assurance256-cp32-v1")
        let origin = InputOrigin(sourceUnixProcessID: -1, sourceStateID: 1, keyboardType: 40, isRepeat: false)
        for i in 0..<40 {
            let elapsed = UInt64(100 + i * 550)
            try draft.session.recordSample(InputSample(kind: "down", keyCode: UInt16(i % 8), modifiers: 0,
                elapsedMilliseconds: elapsed, origin: origin))
            try draft.updateText(draft.text + "a", source: "typing", elapsed: elapsed + 1)
            try draft.session.recordSample(InputSample(kind: "up", keyCode: UInt16(i % 8), modifiers: 0,
                elapsedMilliseconds: elapsed + 65, origin: origin))
            try recorder.synchronize(draft.session)
            if i == 20 { try checkpoint(elapsed + 65) }
        }
        _ = try draft.session.issuePresence(reason: "seal", elapsed: 26_000)
        try recorder.synchronize(draft.session)
        var response = try draft.session.presenceResponse(outcome: "approved", elapsed: 26_100)
        response.signature = try key.signature(for: response.payload(sessionID: draft.session.id)).derRepresentation
        try draft.session.appendPresence(response)
        // Approval must be signed now, rather than silently during a later checkpoint.
        XCTAssertThrowsError(try recorder.synchronize(draft.session))
        var signed = 0
        try recorder.synchronize(draft.session) { message in
            signed += 1
            XCTAssertTrue(message.starts(with: Data("HUMA_COMPACT_ASSURANCE_PRESENCE_V4\0".utf8)))
            return try key.signature(for: message).derRepresentation
        }
        XCTAssertEqual(signed, 1)
        try checkpoint(26_200, final: true)
        try draft.validate()
        let snapshot = try XCTUnwrap(draft.session.experimentalCompactSnapshot)
        let reopened = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(draft))
        try reopened.validate()
        XCTAssertEqual(reopened.session.experimentalCompactSnapshot, snapshot)
        let result = try XCTUnwrap((JSONSerialization.jsonObject(with: snapshot) as? [String: Any])?["result"] as? [String: Any])
        let capsule = try XCTUnwrap(result["capsule"] as? [String: Any])
        let journal = try XCTUnwrap(capsule["journal"] as? [String: Any])
        XCTAssertEqual(journal["policy_satisfied"] as? Bool, true)
        XCTAssertEqual(journal["origin_present"] as? Int, 80)
        XCTAssertEqual(journal["origin_hid"] as? Int, 80)
        XCTAssertEqual((capsule["signatures"] as? [[UInt8]])?.count, 3)
        XCTAssertThrowsError(try ExperimentalCompactRecorder(libraryURL: library(), session: reopened.session,
            publicKey: key.publicKey.x963Representation, time: CaptureTime(unixMilliseconds: 50_000, elapsedMilliseconds: 0)))
        try draft.updateText(draft.text + "!", source: "typing", elapsed: 26_201)
        XCTAssertNil(draft.session.experimentalCompactSnapshot)
    }

    @MainActor func testV3CannotSilentlyDropAssuranceAndRecorderRetriesSamePendingApproval() throws {
        let key = P256.Signing.PrivateKey()
        let v3 = try ExperimentalCompactCapture(libraryURL: library(), initialText: "x",
            publicKey: key.publicKey.x963Representation, unixMilliseconds: 0)
        try v3.acceptSignature(key.signature(for: XCTUnwrap(v3.pendingMessage)).derRepresentation)
        XCTAssertThrowsError(try v3.recordSample(kind: "down", keyCode: 1, modifiers: 0, elapsedMilliseconds: 0,
            origin: InputOrigin(sourceUnixProcessID: 0, sourceStateID: 1, keyboardType: 0, isRepeat: false)))
        XCTAssertThrowsError(try v3.issuePresence(nonce: Data(repeating: 1, count: 32), reason: "seal", elapsedMilliseconds: 0))
        XCTAssertEqual(v3.info.captures, 0)
        var session = SessionLog(initialText: "x")
        session.presenceProtocol = "local-presence-v1"; session.presenceEvents = []
        let time = CaptureTime(unixMilliseconds: 0, elapsedMilliseconds: 0)
        let recorder = try ExperimentalCompactRecorder(libraryURL: library(), session: session, publicKey: key.publicKey.x963Representation, time: time)
        var cp = session.makeCheckpoint(text: "x", publicKey: key.publicKey.x963Representation, reportedTime: time)
        cp.signature = try key.signature(for: cp.payload()).derRepresentation
        session.signedCheckpoints!.append(cp)
        _ = try recorder.checkpoint(session: session, text: "x", time: time, final: false) { try key.signature(for: $0).derRepresentation }
        _ = try session.issuePresence(reason: "seal", elapsed: 1)
        try recorder.synchronize(session)
        var response = try session.presenceResponse(outcome: "approved", elapsed: 2)
        response.signature = try key.signature(for: response.payload(sessionID: session.id)).derRepresentation
        try session.appendPresence(response)
        let other = P256.Signing.PrivateKey()
        XCTAssertThrowsError(try recorder.synchronize(session) { try other.signature(for: $0).derRepresentation })
        XCTAssertEqual(recorder.info.pendingKind, "presence")
        XCTAssertEqual(recorder.info.presenceCount, 0)
        try recorder.synchronize(session) { try key.signature(for: $0).derRepresentation }
        XCTAssertEqual(recorder.info.presenceCount, 1)
        XCTAssertNil(recorder.info.pendingMessage)
        var replaced = session; replaced.presenceProtocol = nil
        XCTAssertThrowsError(try recorder.synchronize(replaced))
    }
}
