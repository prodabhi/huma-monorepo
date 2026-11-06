import Foundation
import XCTest
@testable import HumaCore

final class ProvingSetupTests: XCTestCase {
    func testOnlyTheExactPinnedPointsCount() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let short = folder.appendingPathComponent("short.dat"), wrong = folder.appendingPathComponent("wrong.dat")
        try Data(repeating: 1, count: 1024).write(to: short)
        try Data(repeating: 1, count: ProvingSetup.byteCount).write(to: wrong)
        XCTAssertFalse(ProvingSetup.intact(short), "a file of the wrong size must not be used")
        XCTAssertFalse(ProvingSetup.intact(wrong), "a file of the right size but other points must not be used")
        XCTAssertFalse(ProvingSetup.intact(folder.appendingPathComponent("missing.dat")))
        let link = folder.appendingPathComponent("link.dat")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: wrong)
        XCTAssertFalse(ProvingSetup.intact(link), "only a real file counts, never a link")
    }
    func testTheRealPointsAreAcceptedWhenBuilt() throws {
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("build/research/noir-crs/bn254_g1_compressed.dat")
        guard let handle = try? FileHandle(forReadingFrom: source) else { throw XCTSkip("Proving setup not built") }
        defer { try? handle.close() }
        let points = try XCTUnwrap(handle.readData(ofLength: ProvingSetup.byteCount))
        let copy = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".dat")
        defer { try? FileManager.default.removeItem(at: copy) }
        try points.write(to: copy)
        XCTAssertTrue(ProvingSetup.intact(copy))
    }
}
