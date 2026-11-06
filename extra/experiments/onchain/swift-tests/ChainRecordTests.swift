import XCTest
@testable import HumaCore

final class ChainRecordTests: XCTestCase {
    private func record(network: String = "base-sepolia", explorer: String = "https://sepolia.basescan.org/tx/0x" + String(repeating: "f", count: 64),
                        owner: String = "0x" + String(repeating: "c", count: 40), block: Int = 42) throws -> ChainRecord {
        let json = """
        {"network":"\(network)","contract":"0x\(String(repeating: "b", count: 40))","statement":"0x\(String(repeating: "1", count: 64))",
         "owner":"\(owner)","blockNumber":\(block),"transactionHash":"0x\(String(repeating: "f", count: 64))","explorer":"\(explorer)"}
        """
        return try JSONDecoder().decode(ChainRecord.self, from: Data(json.utf8))
    }

    func testValidRecordPasses() throws {
        XCTAssertNoThrow(try record().validate())
        XCTAssertEqual(try record().networkName, "Base Sepolia")
    }

    func testExplorerOwnerAndBlockAreChecked() throws {
        XCTAssertThrowsError(try record(explorer: "https://evil.example/tx").validate())
        XCTAssertThrowsError(try record(network: "base").validate()) // Sepolia explorer on mainnet.
        XCTAssertThrowsError(try record(owner: "0x1234").validate())
        XCTAssertThrowsError(try record(block: 0).validate())
    }

    func testOlderPublishedLinksStillDecode() throws {
        // Links saved while pages were batched carry a `batch` field; it is ignored.
        let json = #"{"url":"https://h.example/original/x","proofHash":"p","textHash":"t","sessionID":"s","captureHead":"c","batch":{"root":"0x"}}"#
        let link = try JSONDecoder().decode(PublicProofLink.self, from: Data(json.utf8))
        XCTAssertNil(link.chain); XCTAssertNil(link.signer)
    }

    func testChainProofCarriesTheStatementThenTheOwner() {
        let statement = Data(repeating: 7, count: 45 * 32), owner = Data(repeating: 0, count: 12) + Data(hexAddress: "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a")!
        let proof = ChainProof(proof: Data(count: ChainProof.proofBytes), publicInputs: statement + owner, lastPart: nil)
        XCTAssertEqual(proof.statement, statement)
        XCTAssertEqual(proof.publicInputs.count, ChainProof.inputBytes)
        XCTAssertNil(Data(hexAddress: "0x12"))
    }
}
