import Foundation
import CryptoKit

public func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

public func exactTextEqual(_ lhs: String, _ rhs: String) -> Bool {
    lhs.utf8.elementsEqual(rhs.utf8)
}

public struct EditEvent: Codable, Sendable, Equatable {
    public var sequence: Int
    public var elapsedMilliseconds: UInt64
    public var source: String
    public var location: Int
    public var removedLength: Int
    public var insertedText: String
    public var previousHead: String
    public var textHash: String
    public var head: String

    func digest() throws -> String {
        let values = [String(sequence), String(elapsedMilliseconds), source,
                      String(location), String(removedLength), insertedText, previousHead, textHash]
        return sha256(try JSONEncoder().encode(values))
    }
}

public struct InputSample: Codable, Sendable {
    public var kind: String
    public var keyCode: UInt16
    public var modifiers: UInt
    public var elapsedMilliseconds: UInt64
    public var origin: InputOrigin?
    public init(kind: String, keyCode: UInt16, modifiers: UInt, elapsedMilliseconds: UInt64, origin: InputOrigin? = nil) {
        self.kind = kind; self.keyCode = keyCode; self.modifiers = modifiers; self.elapsedMilliseconds = elapsedMilliseconds
        self.origin = origin
    }
}

/// One proved chunk of a long session. Public proof bytes only; never private input.
public struct LongChunkProof: Codable, Sendable, Equatable {
    public let index: Int
    public let proof: String
    public let publicInputs: String
    /// The text tier it was proved at (v3); a page that outgrows it is proved again at the next tier.
    public var tier: Int?
    public init(index: Int, proof: String, publicInputs: String, tier: Int? = nil) {
        self.index = index; self.proof = proof; self.publicInputs = publicInputs; self.tier = tier
    }
}

public struct SessionLog: Codable, Sendable {
    public var id = UUID().uuidString
    public var initialText: String
    public var events: [EditEvent] = []
    public var inputSamples: [InputSample]? = []
    public var captureRecords: [CaptureRecord]? = []
    public var signedCheckpoints: [SignedCheckpoint]? = []
    public var presenceProtocol: String?
    public var presenceEvents: [PresenceEvent]?
    // Private experimental input, created only by signing a new live compact
    // session. It is not a proof and is not included in public proof exports.
    public var experimentalCompactSnapshot: Data?
    // Long drafts: the sealed long-profile capture (private, like the snapshot above)
    // and the zero-knowledge chunk proofs made in the background while writing.
    public var longCompactSnapshot: Data?
    public var longChunkProofs: [LongChunkProof]?
    public var createdAt = Date()
    public var initialHead: String { sha256(Data(("huma-session-v1:" + id + ":" + initialText).utf8)) }
    public var head: String { events.last?.head ?? initialHead }

    public init(initialText: String = "") { self.initialText = initialText }

    public mutating func record(before: String, after: String, source: String, elapsed: UInt64) throws {
        guard presenceEvents?.last?.kind != "challenge" else { throw HumaError.invalidSession }
        guard !exactTextEqual(before, after) else { return }
        // Diff in UTF-16 offsets, matching AppKit. Never split a surrogate pair.
        let a = Array(before.utf16), b = Array(after.utf16)
        var prefix = 0
        while prefix < min(a.count, b.count), a[prefix] == b[prefix] { prefix += 1 }
        if prefix > 0, prefix < a.count, (0xDC00...0xDFFF).contains(a[prefix]) { prefix -= 1 }
        var suffix = 0
        while suffix < min(a.count, b.count) - prefix,
              a[a.count - 1 - suffix] == b[b.count - 1 - suffix] { suffix += 1 }
        if suffix > 0, (0xDC00...0xDFFF).contains(a[a.count - suffix]) { suffix -= 1 }
        let replacement = String(decoding: b[prefix..<(b.count - suffix)], as: UTF16.self)
        var event = EditEvent(sequence: events.count, elapsedMilliseconds: elapsed,
                              source: source, location: prefix, removedLength: a.count - prefix - suffix,
                              insertedText: replacement, previousHead: head,
                              textHash: sha256(Data(after.utf8)), head: "")
        event.head = try event.digest()
        events.append(event)
        try appendCapture(kind: "edit", index: events.count - 1, payloadHash: event.head)
    }

    public func validate(finalText: String) throws {
        var text = initialText
        var previous = initialHead
        var elapsed: UInt64 = 0
        for (index, event) in events.enumerated() {
            guard event.sequence == index, event.previousHead == previous,
                  event.elapsedMilliseconds >= elapsed, event.head == (try event.digest()),
                  event.location >= 0, event.removedLength >= 0,
                  event.location <= (text as NSString).length,
                  event.removedLength <= (text as NSString).length - event.location,
                  let range = Range(NSRange(location: event.location, length: event.removedLength), in: text)
            else { throw HumaError.invalidSession }
            text.replaceSubrange(range, with: event.insertedText)
            guard event.textHash == sha256(Data(text.utf8)) else { throw HumaError.invalidSession }
            previous = event.head
            elapsed = event.elapsedMilliseconds
        }
        guard exactTextEqual(text, finalText) else { throw HumaError.invalidSession }
        try validateCapture()
    }
}

public enum HumaError: LocalizedError {
    case invalidSession, invalidDocument, unsupportedVersion, emptyText, invalidResponse
    case configuration(String)
    public var errorDescription: String? {
        switch self {
        case .invalidSession: "The edit history does not match this text. Import it into a new session before proving."
        case .invalidDocument: "This Huma document is invalid or its formatting disagrees with its text."
        case .unsupportedVersion: "This document was created by a newer version of Huma."
        case .emptyText: "Write something before creating a proof."
        case .invalidResponse: "The service returned an unexpected response. No success was recorded."
        case .configuration(let message): message
        }
    }
}
