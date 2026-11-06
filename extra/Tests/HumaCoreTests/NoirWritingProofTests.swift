import Foundation
import XCTest
@testable import HumaCore

final class NoirWritingProofTests: XCTestCase {
    func testNativeWirePreservesFullUnsignedClocksWithoutEmbeddingSnapshotTwice() throws {
        var draft = Draft(); draft.session.presenceProtocol = "local-presence-v1"
        draft.session.inputSamples = [.init(kind: "down", keyCode: 0, modifiers: 0, elapsedMilliseconds: .max)]
        struct Input: Decodable {
            struct Witness: Decodable { var session: SessionLog }
            struct Snapshot: Decodable { struct Result: Decodable { var clock: UInt64 }; var result: Result }
            var witness: Witness; var snapshot: Snapshot
        }
        for profile in ["assurance256-v1", "assurance256-cp32-v1"] {
            draft.session.experimentalCompactSnapshot = Data("{\"ok\":true,\"result\":{\"profile\":\"\(profile)\",\"sealed\":true,\"clock\":18446744073709551615}}".utf8)
            let input = try JSONDecoder().decode(Input.self, from: NoirWritingProofService.completeInput(draft))
            XCTAssertEqual(input.witness.session.inputSamples?.first?.elapsedMilliseconds, .max)
            XCTAssertEqual(input.snapshot.result.clock, .max)
            XCTAssertNil(input.witness.session.experimentalCompactSnapshot)
            XCTAssertEqual(draft.session.experimentalCompactSnapshot?.isEmpty, false)
        }
    }
    func testMissingPartialAndLegacySnapshotsCannotStartTheNoirBackend() {
        var draft = Draft()
        XCTAssertThrowsError(try NoirWritingProofService.completeInput(draft))
        draft.session.presenceProtocol = "local-presence-v1"
        for source in ["{}", "{\"ok\":false,\"result\":{\"profile\":\"assurance256-v1\",\"sealed\":true}}",
            "{\"ok\":true,\"result\":{\"profile\":\"cast256-v1\",\"sealed\":true}}",
            "{\"ok\":true,\"result\":{\"profile\":\"assurance256-v1\",\"sealed\":false}}"] {
            draft.session.experimentalCompactSnapshot = Data(source.utf8)
            XCTAssertThrowsError(try NoirWritingProofService.completeInput(draft))
        }
    }
}
