import XCTest
@testable import HumaCore

final class PageVersionTests: XCTestCase {
    func testVerifiedVersionIsKeptOnceAndSurvivesSaveAndReopen() throws {
        var draft = Draft()
        draft.title = "Essay"; draft.text = "Final words"
        draft.session.signedCheckpoints = [draft.session.makeCheckpoint(text: draft.text, publicKey: Data(), final: true,
            reportedTime: CaptureTime(unixMilliseconds: 1_800_000_000_000, elapsedMilliseconds: 60_000))]
        draft.replayProof = Data("{\"kind\":\"x\"}".utf8); draft.replayProofTextHash = sha256(Data(draft.text.utf8))
        draft.keepVerifiedVersion(); draft.keepVerifiedVersion()
        XCTAssertEqual(draft.versions?.count, 1)
        XCTAssertEqual(draft.versions?.first?.text, "Final words")
        let reopened = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(draft))
        XCTAssertEqual(reopened.versions?.first?.sessionID, draft.session.id)
        // The version's signed session lives in priorSessions once writing continues.
        var continued = reopened; continued.priorSessions = [reopened.session]
        XCTAssertEqual(continued.draft(for: continued.versions![0])?.text, "Final words")
    }
    func testChangedOrUnfinishedTextIsNotKept() {
        var draft = Draft(); draft.text = "a"
        draft.replayProof = Data("{}".utf8); draft.replayProofTextHash = sha256(Data("b".utf8))
        draft.keepVerifiedVersion()
        XCTAssertEqual(draft.versions?.count ?? 0, 0)
    }
}
