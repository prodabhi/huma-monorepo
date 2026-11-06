import XCTest
@testable import HumaCore

final class PageFileTests: XCTestCase {
    func testPagesAreSavedCompressedAndOpenAsTheSameJSON() throws {
        let json = try JSONEncoder().encode(Array(repeating: "c0ffee" + String(repeating: "ab", count: 29), count: 2000))
        let packed = try PageFile.pack(json)
        XCTAssertTrue(packed.starts(with: Data("HUMA".utf8)))
        XCTAssertLessThan(packed.count, json.count / 4)
        XCTAssertEqual(try PageFile.unpack(packed), json)
    }

    func testPagesFromHuma01StillOpen() throws {
        let plain = Data(#"{"text":"Hello"}"#.utf8)
        XCTAssertEqual(try PageFile.unpack(plain), plain)
    }

    func testAPageThatExpandsPastTheLimitIsRefused() throws {
        let packed = try PageFile.pack(Data(count: 4 * 1024 * 1024))
        XCTAssertLessThan(packed.count, 64 * 1024)
        XCTAssertThrowsError(try PageFile.unpack(packed, limit: 1024 * 1024))
        XCTAssertThrowsError(try PageFile.unpack(PageFile.magic + Data([1, 2, 3, 4])))
    }
}
