import XCTest
@testable import HumaCore

/// The app's on-chain step for a page that is already published, run outside the app:
/// HUMA_CHAIN_E2E_PAGE=~/Documents/Huma/Page.huma [HUMA_CHAIN_E2E_HOST=https://api.huma.social] swift test --filter ChainRecordE2ETests
final class ChainRecordE2ETests: XCTestCase {
    func testRecordsAPublishedPageOnChain() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let path = environment["HUMA_CHAIN_E2E_PAGE"] else { throw XCTSkip("Set HUMA_CHAIN_E2E_PAGE to a published .huma page.") }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let draft = try JSONDecoder().decode(Draft.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
        let link = try XCTUnwrap(draft.publicProof?.url, "This page has not been published.")
        let client = try HostedPublicationClient(url: environment["HUMA_CHAIN_E2E_HOST"] ?? "https://api.huma.social")
        let receipt = try await client.receipt(for: link)
        if let chain = receipt.chain { print("already recorded: block \(chain.blockNumber)"); return }
        XCTAssertTrue(receipt.recordable, "The host does not record pages on-chain.")
        let signer = try XCTUnwrap(receipt.signer, "The page was published without a wallet signature.")
        let started = Date()
        let proof = try await NoirWritingProofService(engineURL: root.appendingPathComponent("build/prover-engine")).proveForChain(draft, owner: signer)
        print("on-chain proof made in \(String(format: "%.1f", Date().timeIntervalSince(started))) s")
        let record = try await client.recordOnChain(link, proof: proof)
        print("recorded: block \(record.blockNumber), tx \(record.transactionHash ?? "none")")
    }
}
