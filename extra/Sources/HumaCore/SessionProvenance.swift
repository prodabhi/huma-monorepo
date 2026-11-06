import Foundation

/// Values supplied by the capture app. Signatures bind them; they are not trusted UTC.
public struct CaptureTime: Codable, Sendable, Equatable {
    public var unixMilliseconds: UInt64
    public var elapsedMilliseconds: UInt64
    public init(unixMilliseconds: UInt64, elapsedMilliseconds: UInt64) {
        self.unixMilliseconds = unixMilliseconds; self.elapsedMilliseconds = elapsedMilliseconds
    }
    public var isValid: Bool { unixMilliseconds <= 253_402_300_799_999 }
}

public struct DeviceReportedWindow: Codable, Sendable, Equatable {
    public var startUnixMilliseconds: UInt64
    public var endUnixMilliseconds: UInt64
    public var elapsedMilliseconds: UInt64
    public var clockMovedBackwards: Bool
}

public struct SignedSessionSummary: Codable, Sendable {
    public var captureKeyHash: String
    public var deviceReportedTime: DeviceReportedWindow?
}

extension SessionLog {
    public func signedSummary(finalText: String) throws -> SignedSessionSummary {
        try validateSignedCheckpoints(requireFinal: true, finalText: finalText)
        guard let first = signedCheckpoints?.first, let last = signedCheckpoints?.last else { throw HumaError.invalidSession }
        var window: DeviceReportedWindow?
        if let start = first.reportedTime, let end = last.reportedTime {
            let times = (signedCheckpoints ?? []).compactMap(\.reportedTime)
            let rollback = zip(times, times.dropFirst()).contains { $1.unixMilliseconds < $0.unixMilliseconds }
            window = DeviceReportedWindow(startUnixMilliseconds: start.unixMilliseconds,
                endUnixMilliseconds: end.unixMilliseconds, elapsedMilliseconds: end.elapsedMilliseconds,
                clockMovedBackwards: rollback)
        }
        return SignedSessionSummary(captureKeyHash: sha256(first.publicKey), deviceReportedTime: window)
    }
}
