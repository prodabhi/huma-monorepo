import XCTest
@testable import HumaCore

final class RemoteProverTests: XCTestCase {
    func testOnlyHTTPSOrLoopbackProvers() {
        XCTAssertNoThrow(try RemoteProver(url: "https://prover.example"))
        XCTAssertNoThrow(try RemoteProver(url: "http://127.0.0.1:4330"))
        XCTAssertThrowsError(try RemoteProver(url: "http://prover.example"))
        XCTAssertThrowsError(try RemoteProver(url: "https://user:pass@prover.example"))
        XCTAssertThrowsError(try RemoteProver(url: "https://prover.example/v1?x=1"))
    }

    func testDefaultsToThisMac() {
        let defaults = UserDefaults.standard, saved = defaults.string(forKey: ProverChoice.defaultsKey)
        defer { defaults.set(saved, forKey: ProverChoice.defaultsKey) }
        defaults.removeObject(forKey: ProverChoice.defaultsKey)
        XCTAssertEqual(ProverChoice.current, .mac)
        defaults.set("server", forKey: ProverChoice.defaultsKey)
        XCTAssertEqual(ProverChoice.current, .server)
        defaults.set("elsewhere", forKey: ProverChoice.defaultsKey)
        XCTAssertEqual(ProverChoice.current, .mac)
    }

    /// The request carries exactly the worker's fields, minus the local work directory.
    func testRequestShape() throws {
        let body = try RemoteProver.body(command: "prove-long", input: Data("{}".utf8),
            chunkProofs: [LongChunkProof(index: 0, proof: "p", publicInputs: "i", tier: 1024), nil])
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["command", "input", "chunkProofs"])
        XCTAssertEqual(object["input"] as? String, "e30=")
        XCTAssertEqual((object["chunkProofs"] as? [Any])?.count, 2)
        // The prover's ChunkProof (backend/prover/src/page.rs) accepts exactly these fields.
        XCTAssertEqual(Set(((object["chunkProofs"] as? [Any])?.first as? [String: Any])?.keys ?? [:].keys), ["index", "proof", "publicInputs", "tier"])
    }

    func testEarlierRecordingsSayWhyTheyCantBeProcessed() {
        var draft = Draft()
        draft.session.presenceProtocol = "local-presence-v1"
        draft.session.longCompactSnapshot = Data(#"{"ok":true,"result":{"profile":"assurance-long-v1","sealed":true}}"#.utf8)
        XCTAssertThrowsError(try NoirWritingProofService.longInput(draft)) { error in
            XCTAssertTrue(error.localizedDescription.contains("earlier version of Huma"), error.localizedDescription)
        }
    }

    func testFinishTimeUsesTheLongestTheTextHasBeen() {
        let now = NoirWritingProofService.finishSeconds(missingParts: 0, characters: 500)
        XCTAssertGreaterThan(NoirWritingProofService.finishSeconds(missingParts: 0, characters: 500, tier: 10_000), now)
        XCTAssertEqual(NoirWritingProofService.finishSeconds(missingParts: 0, characters: 500, tier: 1024), now)
    }

    func testRepliesMapToPlainErrors() throws {
        XCTAssertEqual(try RemoteProver.proof(status: 200, reply: Data(#"{"proof":"{\"kind\":1}"}"#.utf8)), Data(#"{"kind":1}"#.utf8))
        XCTAssertThrowsError(try RemoteProver.proof(status: 200, reply: Data("{}".utf8)))
        for status in [429, 503] {
            XCTAssertThrowsError(try RemoteProver.proof(status: status, reply: Data())) { XCTAssertTrue($0.localizedDescription.contains("busy")) }
        }
        XCTAssertThrowsError(try RemoteProver.proof(status: 422, reply: Data()))
    }

    /// A real page proved by a running prover and verified locally:
    /// HUMA_PROVER_E2E_URL=http://127.0.0.1:4330 swift test --filter RemoteProverTests
    func testProvesOnTheServerAndVerifiesHere() async throws {
        guard let url = ProcessInfo.processInfo.environment["HUMA_PROVER_E2E_URL"] else { throw XCTSkip("Set HUMA_PROVER_E2E_URL to a running prover.") }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let name = ProcessInfo.processInfo.environment["HUMA_PROVER_E2E_FIXTURE"] ?? "live-adaptive-short-v1"
        let fixture = root.appendingPathComponent("build/research/noir-assurance-native/\(name)/document.huma")
        let draft = try JSONDecoder().decode(Draft.self, from: Data(contentsOf: fixture))
        let service = NoirWritingProofService(engineURL: root.appendingPathComponent("build/prover-engine"))
        let started = Date()
        let result = try await service.prove(draft, using: try RemoteProver(url: url))
        XCTAssertTrue(result.report.verified)
        XCTAssertEqual(result.report.statement.contentHash, sha256(Data(VerificationText.canonical(draft.text).utf8)))
        print("server proof verified locally in \(String(format: "%.1f", Date().timeIntervalSince(started))) s, profile \(result.report.proofReport.profile)")
        // A proof of a different draft is refused by the local check.
        var other = draft; other.text += "!"
        await XCTAssertThrowsErrorAsync(try await service.verify(other, proof: result.proof))
    }
}

private func XCTAssertThrowsErrorAsync(_ expression: @autoclosure () async throws -> some Any, file: StaticString = #filePath, line: UInt = #line) async {
    do { _ = try await expression(); XCTFail("Expected an error", file: file, line: line) } catch {}
}

/// A real Mac recording proved part by part (v3) and verified, short recordings proved, and a page from 0.1 refused:
/// HUMA_LONG_E2E=1 HUMA_LONG_E2E_DOCUMENT=<a v3 recording> swift test --filter FoldedLongProofTests
final class FoldedLongProofTests: XCTestCase {
    /// Pages from Huma 0.1 carry v1 proofs, which are refused everywhere (frontend/publication-verifier.mjs too): the writer
    /// is told plainly and the text is untouched.
    func testPagesFromHuma01AreRefusedPlainly() async throws {
        guard ProcessInfo.processInfo.environment["HUMA_LONG_E2E"] != nil else { throw XCTSkip("Set HUMA_LONG_E2E=1.") }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let draft = try JSONDecoder().decode(Draft.self, from: Data(contentsOf: root.appendingPathComponent("build/research/noir-long/acceptance/long600-v3/document.huma")))
        let engine = ProcessInfo.processInfo.environment["HUMA_ENGINE_DIR"].map { URL(fileURLWithPath: $0) } ?? root.appendingPathComponent("build/prover-engine")
        let proof = try XCTUnwrap(draft.replayProof)
        XCTAssertEqual((try JSONSerialization.jsonObject(with: proof) as? [String: Any])?["kind"] as? String, NoirWritingProofService.longProofKind)
        do {
            _ = try await NoirWritingProofService(engineURL: engine).verify(draft, proof: proof)
            XCTFail("A v1 page verified.")
        } catch HumaError.configuration(let message) {
            XCTAssertTrue(message.hasPrefix("This page was written with an earlier version of Huma"))
        }
    }
    func testOneProofPerPage() async throws {
        guard ProcessInfo.processInfo.environment["HUMA_LONG_E2E"] != nil else { throw XCTSkip("Set HUMA_LONG_E2E=1.") }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        // HUMA_LONG_E2E_DOCUMENT proves another recorded page, e.g. a 3,000-character one for the 4,096 tier.
        let document = ProcessInfo.processInfo.environment["HUMA_LONG_E2E_DOCUMENT"].map { URL(fileURLWithPath: $0) }
            ?? root.appendingPathComponent("build/research/noir-long/acceptance/long600-v3/document.huma")
        var draft = try JSONDecoder().decode(Draft.self, from: Data(contentsOf: document))
        draft.session.longChunkProofs = nil // proofs from the earlier format are never reused
        // HUMA_ENGINE_DIR checks a shipped app's engine, e.g. build/release/Huma.app/Contents/Resources/NoirEngine.
        let engine = ProcessInfo.processInfo.environment["HUMA_ENGINE_DIR"].map { URL(fileURLWithPath: $0) } ?? root.appendingPathComponent("build/prover-engine")
        let service = NoirWritingProofService(engineURL: engine)
        let started = Date()
        let result = try await service.prove(draft)
        print("folded proof in \(Int(Date().timeIntervalSince(started))) s, \(result.proof.count) bytes")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: result.proof) as? [String: Any])
        XCTAssertEqual(object["kind"] as? String, NoirWritingProofService.pageProofKind)
        XCTAssertEqual((object["chunks"] as? [Any])?.count, NoirWritingProofService.longChunkCount(draft)) // one proof per part
        let checked = try await service.verify(draft, proof: result.proof)
        XCTAssertTrue(checked.report.verified)
        // HUMA_LONG_E2E_OUT keeps the evidence file, to check it in a browser (huma.social/verify).
        if let out = ProcessInfo.processInfo.environment["HUMA_LONG_E2E_OUT"] { try result.envelope.encoded().write(to: URL(fileURLWithPath: out)) }
    }
    /// Recordings without a long-session capture still get the single short proof, at each size it comes in.
    func testShortPagesProve() async throws {
        guard ProcessInfo.processInfo.environment["HUMA_LONG_E2E"] != nil else { throw XCTSkip("Set HUMA_LONG_E2E=1.") }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let engine = ProcessInfo.processInfo.environment["HUMA_ENGINE_DIR"].map { URL(fileURLWithPath: $0) } ?? root.appendingPathComponent("build/prover-engine")
        let service = NoirWritingProofService(engineURL: engine)
        for name in ["adaptive-short-v1-adaptive-v1", "adaptive-medium-v1-adaptive-v1", "cp32-slow-v1", "v5-v1"] {
            let draft = try JSONDecoder().decode(Draft.self, from: Data(contentsOf: root.appendingPathComponent("build/research/noir-native-app-\(name)/document.huma")))
            XCTAssertFalse(NoirWritingProofService.isLongSession(draft))
            let result = try await service.prove(draft)
            let checked = try await service.verify(draft, proof: result.proof)
            XCTAssertTrue(checked.report.verified, name)
        }
    }
}
