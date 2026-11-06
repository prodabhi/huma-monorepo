import Foundation
import XCTest
@testable import HumaCore

final class WrappedCaptureKeyStoreTests: XCTestCase {
    func testWrappedKeyPersistenceIsPrivateAndNeverOverwritesAnExistingIdentity() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = WrappedCaptureKeyStore(file: directory.appendingPathComponent("capture/key.wrapped"))
        XCTAssertNil(try store.load())
        let fixture = Data("opaque test fixture; not a private key".utf8)
        try store.saveNew(fixture)
        XCTAssertEqual(try store.load(), fixture)
        let attributes = try FileManager.default.attributesOfItem(atPath: store.file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertThrowsError(try store.saveNew(Data("replacement".utf8)))
        XCTAssertEqual(try store.load(), fixture)
    }
    func testWrappedKeyPersistenceRejectsSymlinksEmptyAndOversizedFiles() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target")
        let file = directory.appendingPathComponent("key.wrapped")
        let store = WrappedCaptureKeyStore(file: file)
        try Data("fixture".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.saveNew(Data("replacement".utf8)))
        XCTAssertEqual(try Data(contentsOf: target), Data("fixture".utf8))
        try FileManager.default.removeItem(at: file)
        for fixture in [Data(), Data(repeating: 0, count: 16385)] {
            try fixture.write(to: file)
            XCTAssertThrowsError(try store.load())
        }
    }
}
