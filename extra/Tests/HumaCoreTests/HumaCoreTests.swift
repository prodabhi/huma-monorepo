import XCTest
import Foundation
import CryptoKit
@testable import HumaCore

final class SessionTests: XCTestCase {
    func testUnicodeEditsReplayAndRoundTrip() throws {
        var draft = Draft()
        let variants = ["Café 👩🏽‍💻", "Cafe\u{301} 👩🏽‍💻", "Cafe\u{301} 👨🏽‍💻", "Hello\r\n\t  Cafe\u{301} 👨🏽‍💻\n", "Hello\r\n\t  👨🏽‍💻\n", ""]
        for (i, value) in variants.enumerated() {
            try draft.updateText(value, source: "typing", elapsed: UInt64(i))
            try draft.validate()
        }
        let restored = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(draft))
        try restored.validate()
        XCTAssertEqual(restored.session.events.count, variants.count)
    }
    func testVerificationIgnoresOnlyTrailingASCIIWhitespace() throws {
        XCTAssertTrue(exactTextEqual(VerificationText.canonical("hello \t "), "hello"))
        XCTAssertEqual(VerificationText.canonical(" \t "), "")
        for value in [" hello", "hello  world", "hello \n", "hello\r\n", "hello\u{00a0}", "e\u{301}"] {
            XCTAssertTrue(exactTextEqual(VerificationText.canonical(value), value))
        }
        XCTAssertTrue(exactTextEqual(VerificationText.canonical("hello\n \t"), "hello\n"))
        var draft = Draft()
        try draft.updateText("hello \t", source: "typing", elapsed: 1)
        XCTAssertTrue(exactTextEqual(draft.text, "hello \t"))
        XCTAssertTrue(exactTextEqual(draft.session.events[0].insertedText, "hello \t"))
        draft.replayProof = Data("test proof".utf8)
        draft.replayProofTextHash = sha256(Data(draft.text.utf8))
        try draft.updateText("hello \t ", source: "typing", elapsed: 2)
        XCTAssertNil(draft.replayProof) // Raw capture changed, even though the verification text matches.
        try draft.validate()
    }
    func testCanonicalEquivalentTextStillCountsAsChange() throws {
        var draft = Draft()
        try draft.updateText("é", source: "typing", elapsed: 1)
        try draft.updateText("e\u{301}", source: "typing", elapsed: 2)
        XCTAssertEqual(draft.session.events.count, 2)
        XCTAssertFalse(exactTextEqual("é", "e\u{301}"))
        try draft.validate()
    }
    func testDeletedOrChangedHistoryFailsValidation() throws {
        var draft = Draft()
        try draft.updateText("hello", source: "typing", elapsed: 10)
        try draft.updateText("hello world", source: "paste", elapsed: 20)
        var changed = draft
        changed.session.events[0].insertedText = "different"
        XCTAssertThrowsError(try changed.validate())
        changed = draft; changed.session.events.removeFirst()
        XCTAssertThrowsError(try changed.validate())
        changed = draft; changed.text += "!"
        XCTAssertThrowsError(try changed.validate())
    }
    func testTextChangeInvalidatesProof() throws {
        var draft = Draft()
        try draft.updateText("hello", source: "typing", elapsed: 1)
        draft.replayProof = Data("replay proof".utf8)
        draft.replayProofTextHash = sha256(Data(draft.text.utf8))
        try draft.updateText("hello!", source: "typing", elapsed: 2)
        XCTAssertNil(draft.replayProof)
        XCTAssertNil(draft.replayProofTextHash)
    }
    func testFormattingDoesNotChangeTextOrProof() throws {
        var draft = Draft()
        try draft.updateText("hello", source: "typing", elapsed: 1)
        draft.replayProof = Data("proof".utf8)
        draft.replayProofTextHash = sha256(Data(draft.text.utf8))
        draft.richText = Data("display only".utf8)
        try draft.updateText("hello", source: "format", elapsed: 2)
        XCTAssertEqual(draft.session.events.count, 1)
        XCTAssertNotNil(draft.replayProof)
        try draft.validate()
    }
    func testSignedCheckpointsBindKeystrokesEditsAndFinalSeal() throws {
        let key = P256.Signing.PrivateKey() // Test key; this does not assert hardware origin.
        var log = SessionLog()
        func sign(_ session: inout SessionLog, text: String, final: Bool = false) throws {
            var checkpoint = session.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation, final: final)
            checkpoint.signature = try key.signature(for: checkpoint.payload()).derRepresentation
            session.signedCheckpoints!.append(checkpoint)
        }
        try sign(&log, text: "")
        try log.recordSample(InputSample(kind: "down", keyCode: 0, modifiers: 0, elapsedMilliseconds: 1))
        try log.record(before: "", after: "a", source: "typing", elapsed: 2)
        try log.recordSample(InputSample(kind: "up", keyCode: 0, modifiers: 0, elapsedMilliseconds: 3))
        try sign(&log, text: "a", final: true)
        try log.validateSignedCheckpoints(requireFinal: true, finalText: "a")
        let sealedCount = log.captureRecords!.count
        try log.recordSample(InputSample(kind: "down", keyCode: 1, modifiers: 0, elapsedMilliseconds: 4))
        XCTAssertEqual(log.captureRecords!.count, sealedCount)
        try log.validateSignedCheckpoints(requireFinal: true, finalText: "a")
        var altered = log
        altered.inputSamples![0].keyCode = 1
        XCTAssertThrowsError(try altered.validateSignedCheckpoints(requireFinal: true, finalText: "a"))
        altered = log; altered.signedCheckpoints!.removeLast()
        XCTAssertThrowsError(try altered.validateSignedCheckpoints(requireFinal: true, finalText: "a"))
        altered = log; altered.signedCheckpoints![1].signature[0] ^= 1
        XCTAssertThrowsError(try altered.validateSignedCheckpoints(requireFinal: true, finalText: "a"))
        altered = log; altered.id = UUID().uuidString
        XCTAssertThrowsError(try altered.validateSignedCheckpoints(requireFinal: true, finalText: "a"))
        altered = log; altered.captureRecords!.removeLast()
        XCTAssertThrowsError(try altered.validateSignedCheckpoints(requireFinal: true, finalText: "a"))
    }
    func testSignedDeviceReportedTimeBindsWindowAndFlagsRollback() throws {
        let key = P256.Signing.PrivateKey()
        var log = SessionLog()
        func sign(_ session: inout SessionLog, text: String, unix: UInt64, elapsed: UInt64, final: Bool = false) throws {
            var cp = session.makeCheckpoint(text: text, publicKey: key.publicKey.x963Representation,
                final: final, reportedTime: CaptureTime(unixMilliseconds: unix, elapsedMilliseconds: elapsed))
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            session.signedCheckpoints!.append(cp)
        }
        try sign(&log, text: "", unix: 1_000_000, elapsed: 0)
        try log.recordSample(InputSample(kind: "down", keyCode: 0, modifiers: 0, elapsedMilliseconds: 1))
        try log.record(before: "", after: "a", source: "typing", elapsed: 2)
        try log.recordSample(InputSample(kind: "up", keyCode: 0, modifiers: 0, elapsedMilliseconds: 3))
        try sign(&log, text: "a", unix: 999_900, elapsed: 4, final: true)
        let summary = try log.signedSummary(finalText: "a")
        XCTAssertEqual(summary.captureKeyHash, sha256(key.publicKey.x963Representation))
        XCTAssertEqual(summary.deviceReportedTime?.startUnixMilliseconds, 1_000_000)
        XCTAssertEqual(summary.deviceReportedTime?.endUnixMilliseconds, 999_900)
        XCTAssertEqual(summary.deviceReportedTime?.elapsedMilliseconds, 4)
        XCTAssertEqual(summary.deviceReportedTime?.clockMovedBackwards, true)
        var changed = log
        changed.signedCheckpoints![1].reportedTime!.unixMilliseconds += 1
        XCTAssertThrowsError(try changed.signedSummary(finalText: "a"))
        changed = log
        changed.signedCheckpoints![1].reportedTime!.elapsedMilliseconds = 2
        changed.signedCheckpoints![1].signature = try key.signature(for: changed.signedCheckpoints![1].payload()).derRepresentation
        XCTAssertThrowsError(try changed.signedSummary(finalText: "a")) // Signed time must cover captured events.
        changed = log
        changed.signedCheckpoints![1].reportedTime = nil
        XCTAssertThrowsError(try changed.signedSummary(finalText: "a"))
        changed = log
        changed.signedCheckpoints![1].version = 1
        XCTAssertThrowsError(try changed.signedSummary(finalText: "a")) // V1 cannot carry unsigned time fields.
        changed = log
        changed.createdAt = Date(timeIntervalSince1970: 0)
        XCTAssertEqual(try changed.signedSummary(finalText: "a").deviceReportedTime, summary.deviceReportedTime)
        let restored = try JSONDecoder().decode(SessionLog.self, from: JSONEncoder().encode(log))
        XCTAssertEqual(try restored.signedSummary(finalText: "a").deviceReportedTime, summary.deviceReportedTime)
    }
    func testDeviceEvidenceBindsFinalCaptureTextProofAndChallenge() throws {
        let key = P256.Signing.PrivateKey()
        var draft = Draft()
        func checkpoint(_ value: inout Draft, final: Bool) throws {
            var cp = value.session.makeCheckpoint(text: value.text, publicKey: key.publicKey.x963Representation, final: final)
            cp.signature = try key.signature(for: cp.payload()).derRepresentation
            value.session.signedCheckpoints!.append(cp)
        }
        try checkpoint(&draft, final: false)
        try draft.updateText("Typed here", source: "typing", elapsed: 1)
        XCTAssertThrowsError(try AppAttestBinding(draft: draft)) // Not sealed, no proof.
        try checkpoint(&draft, final: true)
        draft.replayProof = Data("public-replay-test-proof".utf8)
        draft.replayProofTextHash = sha256(Data(draft.text.utf8))
        XCTAssertThrowsError(try AppAttestBinding(draft: draft)) // V2 needs a replay envelope.
        let binding = try AppAttestBinding(draft: draft, useLegacyProofHash: true)
        XCTAssertEqual(binding.proofHash, sha256(draft.replayProof!))
        XCTAssertNil(binding.version)
        let nonce = Data(repeating: 255, count: 32).base64EncodedString()
        let keyID = Data(repeating: 7, count: 32).base64EncodedString()
        let challengeID = String(repeating: "a", count: 32)
        let clientData = try JSONEncoder().encode(["huma-app-attest-assert-v1", challengeID, nonce, keyID] + binding.fields)
        try binding.validateClientData(clientData, challengeID: challengeID, nonce: nonce, keyID: keyID)
        XCTAssertThrowsError(try binding.validateClientData(clientData, challengeID: String(repeating: "b", count: 32), nonce: nonce, keyID: keyID))
        draft.deviceEvidence = AppAttestEvidence(binding: binding, serviceURL: "http://127.0.0.1:4319", keyID: keyID,
            environment: "development", signCount: 1, challengeID: challengeID, clientData: clientData,
            assertion: Data("synthetic-test-assertion".utf8), verifiedAt: "2026-10-21T00:00:00Z")
        try draft.validate() // Structural check only; server cryptographic tests are separate.
        let roundTrip = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(draft))
        try roundTrip.validate()
        var changed = draft; changed.replayProof = Data("another-proof".utf8)
        XCTAssertThrowsError(try changed.validate())
        changed = draft; changed.session.signedCheckpoints![1].signature[0] ^= 1
        XCTAssertThrowsError(try changed.validate())
        draft.richText = Data("presentation".utf8)
        try draft.validate()
        try draft.updateText("Changed", source: "typing", elapsed: 2)
        XCTAssertNil(draft.deviceEvidence)
    }
    func testPortableReplayIdentitySurvivesJSONEncodingAndSeparatesBindingVersions() throws {
        let object: [String: Any] = ["version": 1, "system": "risc0-3.0.6", "imageId": ReplayProofIdentity.imageID,
            "receipt": ["journal": ["bytes": [1, 2, 3]], "ignoredMetadata": "presentation"]]
        let compact = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let pretty = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted])
        XCTAssertNotEqual(sha256(compact), sha256(pretty))
        let identity = try ReplayProofIdentity(proof: compact)
        XCTAssertEqual(identity.value, "a29af7a0f073bd6641fe1b9a6979ae2f1919d5a23809435f0202ddd9e16d4792")
        XCTAssertEqual(try ReplayProofIdentity(proof: pretty), identity)
        var previous = object; previous["imageId"] = ReplayProofIdentity.previousImageID
        XCTAssertEqual(try ReplayProofIdentity(proof: JSONSerialization.data(withJSONObject: previous)).value,
            "f1d67abb7f63fb0c110ca6d1dda470dd6ed556d434d28b45ba1938956c6a732b")
        var legacy = object; legacy["imageId"] = ReplayProofIdentity.legacyImageID
        XCTAssertEqual(try ReplayProofIdentity(proof: JSONSerialization.data(withJSONObject: legacy)).value,
            "3b857399fa71199ada3889faf755523407ef634b8f618925f936b6c0d50b6566")
        var bad = object; bad["imageId"] = String(repeating: "0", count: 64)
        XCTAssertThrowsError(try ReplayProofIdentity(proof: JSONSerialization.data(withJSONObject: bad)))
        bad = object; bad["receipt"] = ["journal": ["bytes": [256]]]
        XCTAssertThrowsError(try ReplayProofIdentity(proof: JSONSerialization.data(withJSONObject: bad)))

        let key = P256.Signing.PrivateKey()
        var draft = Draft()
        var checkpoint = draft.session.makeCheckpoint(text: "", publicKey: key.publicKey.x963Representation, final: true)
        checkpoint.signature = try key.signature(for: checkpoint.payload()).derRepresentation
        draft.session.signedCheckpoints!.append(checkpoint)
        draft.replayProof = compact; draft.replayProofTextHash = sha256(Data())
        let binding = try AppAttestBinding(draft: draft)
        XCTAssertEqual(binding.version, 2); XCTAssertEqual(binding.proofHash, identity.value)
        let nonce = Data(repeating: 7, count: 32).base64EncodedString()
        let id = String(repeating: "a", count: 32)
        let v2 = try JSONEncoder().encode(["huma-app-attest-assert-v2", id, nonce, nonce] + binding.fields)
        try binding.validateClientData(v2, challengeID: id, nonce: nonce, keyID: nonce)
        let v1 = try JSONEncoder().encode(["huma-app-attest-assert-v1", id, nonce, nonce] + binding.fields)
        XCTAssertThrowsError(try binding.validateClientData(v1, challengeID: id, nonce: nonce, keyID: nonce))
        var evidence = AppAttestEvidence(binding: binding, serviceURL: "http://127.0.0.1:4319", keyID: nonce,
            environment: "development", signCount: 1, challengeID: id, clientData: v2,
            assertion: Data([1]), verifiedAt: "2026-10-22T00:00:00Z")
        XCTAssertThrowsError(try evidence.portable(draft: draft)) // Old enrollment cannot fabricate missing Apple material.
        let enrollmentData = try JSONEncoder().encode(["huma-app-attest-enroll-v1", id, nonce, nonce])
        evidence.enrollment = AppAttestEnrollment(attestation: Data([2]), clientData: enrollmentData)
        evidence.appID = "ABCDE12345.dev.swayam.huma"
        let portable = try evidence.portable(draft: draft)
        XCTAssertEqual(portable.binding, binding)
        let exported = String(data: try JSONEncoder().encode(portable), encoding: .utf8)!
        XCTAssertFalse(exported.contains("serviceURL")); XCTAssertFalse(exported.contains("verifiedAt"))
        XCTAssertFalse(exported.contains("inputSamples")); XCTAssertFalse(exported.contains("initialText"))
        draft.replayProof = pretty
        try evidence.validate(draft: draft) // Structural compatibility, not a valid ZK/Apple fixture.
        let old = try AppAttestBinding(draft: draft, useLegacyProofHash: true)
        evidence.binding = old
        evidence.clientData = try JSONEncoder().encode(["huma-app-attest-assert-v1", id, nonce, nonce] + old.fields)
        try evidence.validate(draft: draft)
        draft.replayProof = compact
        XCTAssertThrowsError(try evidence.validate(draft: draft)) // Original V1 byte identity is unchanged.
    }
    func testRetiredCommitmentDocumentPreservesWritingWithoutTrustingOldEvidence() throws {
        var draft = Draft()
        draft.title = "Saved writing"
        try draft.updateText("Original é text \t", source: "typing", elapsed: 1)
        draft.richText = Data("presentation".utf8)
        var old = try JSONSerialization.jsonObject(with: JSONEncoder().encode(draft)) as! [String: Any]
        old["proof"] = Data("retired commitment".utf8).base64EncodedString()
        old["proofTextHash"] = sha256(Data(draft.text.utf8))
        old["deviceEvidence"] = ["retired": true]
        old["publicProof"] = ["kind": "commitment"]
        let restored = try JSONDecoder().decode(Draft.self, from: JSONSerialization.data(withJSONObject: old))
        try restored.validate()
        XCTAssertEqual(restored.title, draft.title)
        XCTAssertTrue(exactTextEqual(restored.text, draft.text))
        XCTAssertEqual(restored.richText, draft.richText)
        XCTAssertEqual(restored.session.head, draft.session.head)
        XCTAssertNil(restored.deviceEvidence)
        XCTAssertNil(restored.publicProof)
        let saved = try JSONSerialization.jsonObject(with: JSONEncoder().encode(restored)) as! [String: Any]
        XCTAssertNil(saved["proof"])
        XCTAssertNil(saved["proofTextHash"])
    }
    func testLegacyPublishingMetadataDoesNotBlockWritingOrProofs() throws {
        var original = Draft()
        try original.updateText("Saved writing stays intact", source: "typing", elapsed: 1)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
        object["cast"] = ["retired": true]
        object["publishAttemptID"] = ["retired": true]
        object["publishAttemptFingerprint"] = 123
        let restored = try JSONDecoder().decode(Draft.self, from: JSONSerialization.data(withJSONObject: object))
        try restored.validate()
        XCTAssertEqual(restored.text, original.text)
        XCTAssertEqual(restored.session.events, original.session.events)
        let saved = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(restored)) as? [String: Any])
        for field in ["cast", "publishAttemptID", "publishAttemptFingerprint"] { XCTAssertNil(saved[field]) }
    }
    func testRandomEditSequence() throws {
        var draft = Draft()
        var seed: UInt64 = 45
        let tokens = ["a", "é", "e\u{301}", "👩🏽‍💻", "\r\n", "\t", " ", "中"]
        for i in 0..<400 {
            seed = seed &* 6364136223846793005 &+ 1
            var characters = Array(draft.text)
            if seed % 3 == 0, !characters.isEmpty { characters.remove(at: Int(seed % UInt64(characters.count))) }
            else { characters.insert(contentsOf: Array(tokens[Int(seed % UInt64(tokens.count))]), at: Int(seed % UInt64(characters.count + 1))) }
            try draft.updateText(String(characters), source: "typing", elapsed: UInt64(i))
            try draft.validate()
        }
    }
}

