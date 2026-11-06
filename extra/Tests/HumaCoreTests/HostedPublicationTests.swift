import Foundation
import XCTest
@testable import HumaCore

final class HostedPublicationTests: XCTestCase {
    func testExactMasterAndProofAreBoundToExpectedSession() throws {
        let master = Data("Hello \t".utf8), proof = Data("{\"public\":true}".utf8)
        let statement = try EvidenceStatement(contentKind: "text", contentPolicy: "trailing-ascii-space-tab-v1",
            contentHash: sha256(Data("Hello".utf8)), byteLength: "5", sessionBinding: String(repeating: "1", count: 64),
            captureScheme: "sha256-capture-v3", captureHead: String(repeating: "2", count: 64))
        let source = try JSONSerialization.data(withJSONObject: ["kind": "huma-publication-v1", "publicationNonce": String(repeating: "3", count: 64),
            "access": "link", "master": ["hash": sha256(master), "byteLength": master.count, "mediaType": "text/plain;charset=utf-8"],
            "proof": ["hash": sha256(proof), "byteLength": proof.count], "statement": JSONSerialization.jsonObject(with: JSONEncoder().encode(statement)),
            "statementHash": statement.digest()])
        let id = sha256(source)
        XCTAssertNoThrow(try PublicationManifest.check(source: source, id: id, master: master, proof: proof,
            expectedMasterHash: sha256(master), expectedStatement: statement))
        // The proof ignores final ASCII whitespace; the master transport still binds every byte.
        XCTAssertThrowsError(try PublicationManifest.check(source: source, id: id, master: Data("Hello".utf8), proof: proof,
            expectedMasterHash: sha256(master), expectedStatement: statement))
        XCTAssertThrowsError(try PublicationManifest.check(source: source, id: id, master: master, proof: Data("{}".utf8),
            expectedMasterHash: sha256(master), expectedStatement: statement))
        var other = statement; other.sessionBinding = String(repeating: "4", count: 64)
        XCTAssertThrowsError(try PublicationManifest.check(source: source, id: id, master: master, proof: proof,
            expectedMasterHash: sha256(master), expectedStatement: other))
        XCTAssertThrowsError(try PublicationManifest.check(source: source + Data(" ".utf8), id: id, master: master, proof: proof,
            expectedMasterHash: sha256(master), expectedStatement: statement))
    }
    func testLinksUseTheSiteWhileTheAppTalksToTheAPIHost() throws {
        let client = try HostedPublicationClient(url: "https://api.huma.social")
        XCTAssertEqual(client.site.absoluteString, "https://huma.social")
        XCTAssertTrue(client.signInPage().url.absoluteString.hasPrefix("https://huma.social/share/signin#"))
        XCTAssertEqual(try HostedPublicationClient(url: "http://127.0.0.1:4318").site.absoluteString, "http://127.0.0.1:4318")
    }
    func testShortLinksStayOnTheSiteAndKeepTheirKeyAfterTheHash() throws {
        let client = try HostedPublicationClient(url: "https://api.huma.social")
        XCTAssertEqual(client.shortURL("/p/Ab3xK9q2#V8nq2LxP0aZt7Ru4")?.absoluteString, "https://huma.social/p/Ab3xK9q2#V8nq2LxP0aZt7Ru4")
        XCTAssertEqual(client.shortURL("/p/Ab3xK9q2")?.absoluteString, "https://huma.social/p/Ab3xK9q2")
        for path in ["https://evil.example/p/Ab3xK9q2", "/p/Ab3x", "/p/Ab3xK9q2#short", "/original/Ab3xK9q2", "/p/Ab3xK9q2/../x"] {
            XCTAssertNil(client.shortURL(path), path)
        }
    }
    func testSharingHostMustUseHTTPSOrLocalhostAndNoCredentials() {
        for value in ["http://remote.invalid", "https://user:password@remote.invalid", "https://remote.invalid/path", "https://remote.invalid#token"] {
            XCTAssertThrowsError(try HostedPublicationClient(url: value))
        }
        XCTAssertNoThrow(try HostedPublicationClient(url: "https://share.example"))
        XCTAssertNoThrow(try HostedPublicationClient(url: "http://127.0.0.1:4318"))
    }
}
