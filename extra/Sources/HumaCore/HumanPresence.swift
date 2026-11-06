import Foundation
import CryptoKit

/// OS-reported metadata, not an assertion of physical input. Raw values stay private.
public struct InputOrigin: Codable, Sendable, Equatable {
    public var sourceUnixProcessID: Int64
    public var sourceStateID: Int64
    public var keyboardType: Int64
    public var isRepeat: Bool
    public init(sourceUnixProcessID: Int64, sourceStateID: Int64, keyboardType: Int64, isRepeat: Bool) {
        self.sourceUnixProcessID = sourceUnixProcessID; self.sourceStateID = sourceStateID
        self.keyboardType = keyboardType; self.isRepeat = isRepeat
    }
    var digestFields: [String] { ["mac-event-origin-v1", String(sourceUnixProcessID), String(sourceStateID),
                                  String(keyboardType), String(isRepeat)] }
}

/// Challenge issuance and resolution are separate, append-only capture records.
/// A signature establishes key use; biometric gating additionally needs trusted app/device evidence.
public struct PresenceEvent: Codable, Sendable {
    public var sequence: Int
    public var kind: String
    public var nonce: String
    public var reason: String
    public var captureHead: String
    public var issuedElapsedMilliseconds: UInt64
    public var elapsedMilliseconds: UInt64
    public var outcome: String
    public var signature: Data
    public static let deadlineMilliseconds: UInt64 = 10_000
    public func payload(sessionID: String) throws -> Data {
        try JSONEncoder().encode(["huma-presence-v1", sessionID, String(sequence), kind, nonce, reason, captureHead,
            String(issuedElapsedMilliseconds), String(elapsedMilliseconds), outcome, String(Self.deadlineMilliseconds)])
    }
    func digest(sessionID: String) throws -> String { sha256(try payload(sessionID: sessionID) + signature) }
}

public enum PresenceSchedule {
    /// Shifted exponential: 3-minute floor, 12.5-minute mean. Drawn locally, not verifiably random.
    public static func delayMilliseconds<R: RandomNumberGenerator>(using random: inout R) -> UInt64 {
        let unit = Double.random(in: 0..<1, using: &random)
        return 180_000 + UInt64(-log1p(-unit) * 570_000)
    }
    public static func next(after elapsed: UInt64) -> UInt64 {
        var random = SystemRandomNumberGenerator()
        let sum = elapsed.addingReportingOverflow(delayMilliseconds(using: &random))
        return sum.overflow ? UInt64.max : sum.partialValue
    }
}

extension SessionLog {
    public mutating func issuePresence(reason: String, elapsed: UInt64) throws -> PresenceEvent {
        guard presenceProtocol == "local-presence-v1", ["interval", "seal"].contains(reason),
              presenceEvents?.last?.kind != "challenge", !(signedCheckpoints?.last?.isFinal ?? false),
              elapsed >= latestCaptureElapsed, (presenceEvents?.count ?? 0) < 2048 else { throw HumaError.invalidSession }
        var random = SystemRandomNumberGenerator()
        let nonce = (0..<32).map { _ in UInt8.random(in: 0...255, using: &random) }.map { String(format: "%02x", $0) }.joined()
        let event = PresenceEvent(sequence: presenceEvents?.count ?? 0, kind: "challenge", nonce: nonce, reason: reason,
            captureHead: captureHead, issuedElapsedMilliseconds: elapsed, elapsedMilliseconds: elapsed,
            outcome: "pending", signature: Data())
        try appendPresence(event)
        return event
    }
    public func presenceResponse(outcome: String, elapsed: UInt64) throws -> PresenceEvent {
        guard let issue = presenceEvents?.last, issue.kind == "challenge", elapsed >= issue.elapsedMilliseconds,
              ["approved", "cancelled", "timedOut", "interrupted"].contains(outcome) else { throw HumaError.invalidSession }
        return PresenceEvent(sequence: issue.sequence + 1, kind: "response", nonce: issue.nonce, reason: issue.reason,
            captureHead: issue.captureHead, issuedElapsedMilliseconds: issue.elapsedMilliseconds,
            elapsedMilliseconds: elapsed, outcome: outcome, signature: Data())
    }
    public mutating func appendPresence(_ event: PresenceEvent) throws {
        guard event.sequence == (presenceEvents?.count ?? 0) else { throw HumaError.invalidSession }
        if presenceEvents == nil { presenceEvents = [] }
        presenceEvents!.append(event)
        try appendCapture(kind: "presence", index: event.sequence, payloadHash: event.digest(sessionID: id))
    }
    public var latestCaptureElapsed: UInt64 {
        max(events.last?.elapsedMilliseconds ?? 0, inputSamples?.last?.elapsedMilliseconds ?? 0,
            presenceEvents?.last?.elapsedMilliseconds ?? 0)
    }
    public func validatePresence(requireResolved: Bool) throws {
        let values = presenceEvents ?? []
        guard presenceProtocol == nil || presenceProtocol == "local-presence-v1",
              values.isEmpty || presenceProtocol != nil, values.count <= 2048 else { throw HumaError.invalidSession }
        var pending: PresenceEvent?
        var nonces = Set<String>()
        var index = 0
        for record in captureRecords ?? [] {
            if record.kind != "presence" {
                guard pending == nil else { throw HumaError.invalidSession }
                continue
            }
            guard values.indices.contains(index), record.index == index else { throw HumaError.invalidSession }
            let event = values[index]
            guard event.sequence == index, event.nonce.count == 64,
                  event.nonce.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  ["interval", "seal"].contains(event.reason) else { throw HumaError.invalidSession }
            if event.kind == "challenge" {
                guard pending == nil, nonces.insert(event.nonce).inserted, event.captureHead == record.previousHead,
                      event.issuedElapsedMilliseconds == event.elapsedMilliseconds, event.outcome == "pending",
                      event.signature.isEmpty else { throw HumaError.invalidSession }
                pending = event
            } else {
                guard event.kind == "response", let issue = pending, event.nonce == issue.nonce,
                      event.reason == issue.reason, event.captureHead == issue.captureHead,
                      event.issuedElapsedMilliseconds == issue.elapsedMilliseconds,
                      event.elapsedMilliseconds >= issue.elapsedMilliseconds else { throw HumaError.invalidSession }
                if event.outcome == "approved" {
                    guard let first = signedCheckpoints?.first,
                          let key = try? P256.Signing.PublicKey(x963Representation: first.publicKey),
                          let signature = try? P256.Signing.ECDSASignature(derRepresentation: event.signature),
                          key.isValidSignature(signature, for: try event.payload(sessionID: id)) else { throw HumaError.invalidSession }
                } else {
                    guard ["cancelled", "timedOut", "interrupted"].contains(event.outcome), event.signature.isEmpty else { throw HumaError.invalidSession }
                }
                pending = nil
            }
            index += 1
        }
        guard index == values.count else { throw HumaError.invalidSession }
        if requireResolved, presenceProtocol != nil {
            guard pending == nil, let last = values.last, last.kind == "response", last.reason == "seal",
                  last.outcome == "approved", last.elapsedMilliseconds - last.issuedElapsedMilliseconds <= PresenceEvent.deadlineMilliseconds,
                  captureRecords?.last?.kind == "presence" else { throw HumaError.invalidSession }
        }
    }
}
