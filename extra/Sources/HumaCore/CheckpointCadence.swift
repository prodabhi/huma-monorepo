import Foundation

/// Automatic durability checkpoints, separate from biometric presence challenges.
/// Start and seal are always signed by the caller. Every event stays hash-chained.
public enum CheckpointCadence {
    public static let maximumNewRecords = 256
    public static let intervalMilliseconds: UInt64 = 10_000

    public static func shouldCheckpoint(captureCount: Int, previousCount: Int,
                                        elapsedMilliseconds: UInt64,
                                        previousElapsedMilliseconds: UInt64) throws -> Bool {
        guard previousCount >= 0, captureCount >= previousCount,
              elapsedMilliseconds >= previousElapsedMilliseconds else {
            throw HumaError.invalidSession
        }
        let newRecords = captureCount - previousCount
        return newRecords > 0 && (newRecords >= maximumNewRecords ||
            elapsedMilliseconds - previousElapsedMilliseconds >= intervalMilliseconds)
    }
}
