import XCTest
@testable import HumaCore

final class PublicProofLinkTests: XCTestCase {
    func testOlderPublishedLinksStillDecode() throws {
        // Links saved while pages were batched carry `batch`, and links from 0.1 may carry a Base record in `chain`; both are ignored.
        let json = #"{"url":"https://h.example/original/x","proofHash":"p","textHash":"t","sessionID":"s","captureHead":"c","batch":{"root":"0x"},"#
            + #""chain":{"network":"base-sepolia","blockNumber":7},"signer":"0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"}"#
        let link = try JSONDecoder().decode(PublicProofLink.self, from: Data(json.utf8))
        XCTAssertEqual(link.url.absoluteString, "https://h.example/original/x")
        XCTAssertEqual(link.signer, "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a")
    }
}
