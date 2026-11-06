import XCTest
@testable import HumaCore

final class CheckpointCadenceTests: XCTestCase {
    func testTimeAndRecordBoundaries() throws {
        XCTAssertFalse(try CheckpointCadence.shouldCheckpoint(captureCount: 255, previousCount: 0,
            elapsedMilliseconds: 9_999, previousElapsedMilliseconds: 0))
        XCTAssertTrue(try CheckpointCadence.shouldCheckpoint(captureCount: 256, previousCount: 0,
            elapsedMilliseconds: 1, previousElapsedMilliseconds: 0))
        XCTAssertTrue(try CheckpointCadence.shouldCheckpoint(captureCount: 1, previousCount: 0,
            elapsedMilliseconds: 10_000, previousElapsedMilliseconds: 0))
    }

    func testIdleDoesNotCreateDuplicateCheckpoints() throws {
        XCTAssertFalse(try CheckpointCadence.shouldCheckpoint(captureCount: 50, previousCount: 50,
            elapsedMilliseconds: UInt64.max, previousElapsedMilliseconds: 0))
        XCTAssertTrue(try CheckpointCadence.shouldCheckpoint(captureCount: 51, previousCount: 50,
            elapsedMilliseconds: 25_000, previousElapsedMilliseconds: 10_000))
        XCTAssertFalse(try CheckpointCadence.shouldCheckpoint(captureCount: 51, previousCount: 50,
            elapsedMilliseconds: 25_000, previousElapsedMilliseconds: 20_000))
    }

    func testRollbackAndInvalidCountsReject() {
        XCTAssertThrowsError(try CheckpointCadence.shouldCheckpoint(captureCount: 1, previousCount: 2,
            elapsedMilliseconds: 10, previousElapsedMilliseconds: 0))
        XCTAssertThrowsError(try CheckpointCadence.shouldCheckpoint(captureCount: 1, previousCount: -1,
            elapsedMilliseconds: 10, previousElapsedMilliseconds: 0))
        XCTAssertThrowsError(try CheckpointCadence.shouldCheckpoint(captureCount: 2, previousCount: 1,
            elapsedMilliseconds: 9, previousElapsedMilliseconds: 10))
    }
}
