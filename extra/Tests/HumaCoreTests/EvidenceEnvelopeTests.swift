import Foundation
import XCTest
@testable import HumaCore

final class EvidenceEnvelopeTests: XCTestCase {
    private struct Vectors: Decodable {
        struct Vector: Decodable { var name: String; var statement: EvidenceStatement; var payload: String; var sha256: String }
        var vectors: [Vector]
    }
    private func vectors() throws -> [Vectors.Vector] {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: root.appendingPathComponent("frontend/verify-core/fixtures/statements.json"))).vectors
    }
    func testCrossLanguageStatementPayloadsAndExactLargeIntegers() throws {
        for vector in try vectors() {
            XCTAssertEqual(try vector.statement.payload(), Data(vector.payload.utf8), vector.name)
            XCTAssertEqual(try vector.statement.digest(), vector.sha256, vector.name)
            let roundTrip = try JSONDecoder().decode(EvidenceStatement.self, from: JSONEncoder().encode(vector.statement))
            XCTAssertEqual(roundTrip, vector.statement)
        }
    }
    func testStatementRejectsUnsupportedClaimsAndNoncanonicalScalars() throws {
        let original = try vectors()[1].statement
        for change: (inout EvidenceStatement) -> Void in [
            { $0.version = 2 }, { $0.contentKind = "document" }, { $0.contentPolicy = "remove-all-spaces" },
            { $0.contentHash += "\n" }, { $0.byteLength = "01" }, { $0.byteLength = "18446744073709551616" },
            { $0.byteLength = "1\n" }, { $0.captureScheme = "producer-supplied" }, { $0.captureHead = "0" },
            { $0.checkpointBinding = nil }, { $0.captureKeyHash = nil }, { $0.policyID = "arbitrary\n" },
            { $0.policySatisfied = nil }, { $0.policyID = nil }
        ] {
            var altered = original; change(&altered)
            XCTAssertThrowsError(try altered.payload())
        }
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
        object["trustedHuman"] = true
        XCTAssertThrowsError(try JSONDecoder().decode(EvidenceStatement.self, from: JSONSerialization.data(withJSONObject: object)))
        object.removeValue(forKey: "trustedHuman"); object.removeValue(forKey: "policyID")
        XCTAssertThrowsError(try JSONDecoder().decode(EvidenceStatement.self, from: JSONSerialization.data(withJSONObject: object)))
    }
    func testEnvelopePreservesOpaqueProofIntegersAndRejectsUnknownAttachments() throws {
        let proof = "{\"opaqueTestInteger\":18446744073709551615}"
        let envelope = try EvidenceEnvelope(statement: vectors()[0].statement, proof: proof)
        let roundTrip = try EvidenceEnvelope.decode(envelope.encoded())
        XCTAssertEqual(roundTrip, envelope); XCTAssertEqual(roundTrip.proof, proof)
        XCTAssertThrowsError(try EvidenceEnvelope(statement: envelope.statement, proof: "[]"))
        XCTAssertThrowsError(try EvidenceEnvelope(statement: envelope.statement, proof: proof, attachments: ["witness": "{}"] ))
        XCTAssertThrowsError(try EvidenceEnvelope(statement: envelope.statement, proof: proof, attachments: ["account": "{}"] ))
        XCTAssertThrowsError(try EvidenceEnvelope(statement: envelope.statement, proof: proof, attachments: ["device": "x"] ))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: envelope.encoded()) as? [String: Any])
        object["policy"] = ["satisfied": true]
        XCTAssertThrowsError(try EvidenceEnvelope.decode(JSONSerialization.data(withJSONObject: object)))
        object.removeValue(forKey: "policy"); object["kind"] = "huma-evidence-envelope-v2"
        XCTAssertThrowsError(try EvidenceEnvelope.decode(JSONSerialization.data(withJSONObject: object)))
    }
}
