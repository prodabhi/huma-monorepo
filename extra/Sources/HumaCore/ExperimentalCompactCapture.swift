import Foundation
import Darwin

/// Optional native producer for NEW experimental sessions. This bridge never opens a
/// device key, prompts for authentication, signs, writes files or contacts a server.
@MainActor
public final class ExperimentalCompactCapture {
    public enum Profile: String, Sendable {
        case replay = "cast256-v1"
        case assurance = "assurance256-v1"
        case assuranceExtended = "assurance256-cp32-v1"
        /// Up to 10,000 characters, proved as a chain of chunks.
        case assuranceLong = "assurance-long-v1"
        var isAssurance: Bool { self != .replay }
        var checkpointLimit: Int { self == .assuranceLong ? 65_536 : self == .assuranceExtended ? 32 : 8 }
        var operationLimit: Int { self == .assuranceLong ? 1 << 20 : 1536 }
        var sampleLimit: Int { self == .assuranceLong ? 1 << 19 : 516 }
        var presenceLimit: Int { self == .assuranceLong ? 64 : 8 }
    }
    public struct Info: Decodable {
        public let profile: String
        public let sealed: Bool
        public let operations: Int
        public let captures: Int
        public let checkpoints: Int
        public let pendingMessage: [UInt8]?
        public let origins: Int?
        public let presenceCount: Int?
        public let presencePending: Bool?
        public let pendingKind: String?
        public let closedChunks: Int?
        public let openOperations: Int?
        public let keyHash: String
        let experimental: Bool
        let attestationVerified: Bool
        let trustedTime: Bool
    }
    public private(set) var info: Info
    public let profile: Profile
    public var pendingMessage: Data? { info.pendingMessage.map { Data($0) } }
    private let native: CompactNativeLibrary
    private let expectedKeyHash: String

    /// `sessionNonce` (long profile only): 16 bytes the host issued at Start, the session's public nonce, so the World ID
    /// scanned there and the page's proof name the same session. Without it the session picks its own.
    public init(libraryURL: URL, initialText: String, publicKey: Data, unixMilliseconds: UInt64,
                profile: Profile = .replay, sessionNonce: Data? = nil) throws {
        struct Config: Encodable {
            let profile: String
            let initial_text: String
            let public_key: [UInt8]
            let unix: UInt64
            let nonce: [UInt8]?
        }
        guard sessionNonce == nil || (profile == .assuranceLong && sessionNonce?.count == 16) else { throw HumaError.invalidSession }
        let native = try CompactNativeLibrary(url: libraryURL)
        let request = try JSONEncoder().encode(Config(profile: profile.rawValue, initial_text: initialText,
            public_key: Array(publicKey), unix: unixMilliseconds, nonce: sessionNonce.map(Array.init)))
        let response = try native.create(request)
        let info = try JSONDecoder().decode(Envelope<Info>.self, from: response).result
        let keyHash = sha256(publicKey)
        try Self.validate(info, keyHash: keyHash, profile: profile)
        guard !info.sealed, info.captures == 0, info.checkpoints == 0, info.pendingMessage != nil else { throw HumaError.invalidResponse }
        self.native = native; self.info = info; self.expectedKeyHash = keyHash; self.profile = profile
    }

    public func recordEdit(location: UInt32, removedLength: UInt32, insertedText: String, source: String, elapsedMilliseconds: UInt64) throws {
        struct Edit: Encodable {
            let command = "edit"
            let location: UInt32, removed: UInt32
            let inserted: String, source: String
            let elapsed: UInt64
        }
        try update(Edit(location: location, removed: removedLength, inserted: insertedText, source: source, elapsed: elapsedMilliseconds))
    }
    public func recordSample(kind: String, keyCode: UInt16, modifiers: UInt64, elapsedMilliseconds: UInt64,
                             origin: InputOrigin? = nil) throws {
        if let origin {
            guard profile.isAssurance, let pid = Int32(exactly: origin.sourceUnixProcessID),
                  let state = Int32(exactly: origin.sourceStateID),
                  let keyboard = UInt32(exactly: origin.keyboardType) else { throw HumaError.invalidSession }
            struct Origin: Encodable {
                let present = true
                let pid: UInt32, state: UInt32, keyboard: UInt32
                let repeated: Bool
            }
            struct Sample: Encodable {
                let command = "sample_origin"
                let kind: String
                let key: UInt16
                let modifiers: UInt64, elapsed: UInt64
                let origin: Origin
            }
            try update(Sample(kind: kind, key: keyCode, modifiers: modifiers, elapsed: elapsedMilliseconds,
                origin: Origin(pid: UInt32(bitPattern: pid), state: UInt32(bitPattern: state),
                    keyboard: keyboard, repeated: origin.isRepeat)))
            return
        }
        struct Sample: Encodable {
            let command = "sample"
            let kind: String
            let key: UInt16
            let modifiers: UInt64, elapsed: UInt64
        }
        try update(Sample(kind: kind, key: keyCode, modifiers: modifiers, elapsed: elapsedMilliseconds))
    }
    public func issuePresence(nonce: Data, reason: String, elapsedMilliseconds: UInt64) throws {
        guard profile.isAssurance, nonce.count == 32,
              let reasonCode = ["interval": UInt8(1), "seal": UInt8(2)][reason] else { throw HumaError.invalidSession }
        struct Issue: Encodable {
            let command = "presence_issue"
            let nonce: [UInt8]
            let reason: UInt8
            let elapsed: UInt64
        }
        try update(Issue(nonce: Array(nonce), reason: reasonCode, elapsed: elapsedMilliseconds))
    }
    /// An approved response exposes a signing request. Other outcomes are retained
    /// without a response signature and covered by the next signed checkpoint.
    public func respondToPresence(outcome: String, elapsedMilliseconds: UInt64) throws -> Data? {
        guard profile.isAssurance,
              let code = ["approved": UInt8(1), "cancelled": UInt8(2), "timedOut": UInt8(3), "interrupted": UInt8(4)][outcome]
              else { throw HumaError.invalidSession }
        struct Response: Encodable {
            let command = "presence_response"
            let outcome: UInt8
            let elapsed: UInt64
        }
        try update(Response(outcome: code, elapsed: elapsedMilliseconds))
        return pendingMessage
    }
    public func prepareCheckpoint(text: String, unixMilliseconds: UInt64, elapsedMilliseconds: UInt64, final: Bool) throws -> Data {
        struct Checkpoint: Encodable {
            let command = "checkpoint"
            let unix: UInt64, elapsed: UInt64
            let is_final: Bool
            let text: String
        }
        try update(Checkpoint(unix: unixMilliseconds, elapsed: elapsedMilliseconds, is_final: final, text: text))
        guard let message = pendingMessage else { throw HumaError.invalidResponse }
        return message
    }
    public func acceptSignature(_ signature: Data) throws {
        struct Acceptance: Encodable { let command = "accept"; let signature: [UInt8] }
        try update(Acceptance(signature: Array(signature)))
    }
    /// Closes the open part at the current end (a pause, or Finish) so it can be proved now.
    public func closeLongPart() throws {
        struct Request: Encodable { let command = "long_cut" }
        guard profile == .assuranceLong else { throw HumaError.invalidSession }
        try update(Request())
    }
    /// Private input for one closed chunk of a long session, as exact JSON for the local prover, and the text tier
    /// it's for (the session's tier so far: once the text outgrows it, every part's input is made again at the next).
    public func longChunkInput(index: Int) throws -> (input: Data, tier: Int) {
        struct Request: Encodable { let command = "long_chunk"; let index: Int }
        struct Reply: Decodable { let index: Int; let input: String; let tier: Int }
        guard profile == .assuranceLong, index >= 0, index < (info.closedChunks ?? 0) else { throw HumaError.invalidSession }
        let reply = try JSONDecoder().decode(Envelope<Reply>.self, from: native.call(JSONEncoder().encode(Request(index: index)))).result
        guard reply.index == index, [1024, 4096, 10000].contains(reply.tier) else { throw HumaError.invalidResponse }
        return (Data(reply.input.utf8), reply.tier)
    }
    /// Private proof input and its public signature capsule. Contains raw writing
    /// history; never use this response as a public proof export.
    public func sealedSnapshot() throws -> Data {
        struct Snapshot: Encodable { let command = "snapshot" }
        struct Summary: Decodable { let profile: String; let sealed: Bool }
        guard info.sealed else { throw HumaError.invalidSession }
        let data = try native.call(JSONEncoder().encode(Snapshot()))
        let result = try JSONDecoder().decode(Envelope<Summary>.self, from: data).result
        guard result.sealed, result.profile == profile.rawValue else { throw HumaError.invalidResponse }
        return data
    }
    private func update(_ request: some Encodable) throws {
        let response = try native.call(JSONEncoder().encode(request))
        let updated = try JSONDecoder().decode(Envelope<Info>.self, from: response).result
        try Self.validate(updated, keyHash: expectedKeyHash, profile: profile)
        info = updated
    }
    private static func validate(_ info: Info, keyHash: String, profile: Profile) throws {
        guard info.profile == profile.rawValue, info.experimental, !info.attestationVerified, !info.trustedTime,
              info.keyHash == keyHash, (1...profile.operationLimit).contains(info.operations),
              (0...profile.operationLimit).contains(info.captures), (0...profile.checkpointLimit).contains(info.checkpoints),
              (info.closedChunks != nil) == (profile == .assuranceLong) else { throw HumaError.invalidResponse }
        let domain: Data
        switch profile {
        case .replay:
            guard info.origins == nil, info.presenceCount == nil, info.presencePending == nil,
                  info.pendingKind == nil else { throw HumaError.invalidResponse }
            domain = Data("HUMA_COMPACT_EXPERIMENT_CHECKPOINT_V3\0".utf8)
        case .assurance, .assuranceExtended, .assuranceLong:
            let long = profile == .assuranceLong
            guard let origins = info.origins, let count = info.presenceCount, let pending = info.presencePending,
                  (0...profile.sampleLimit).contains(origins), origins <= info.captures, (0...profile.presenceLimit).contains(count),
                  !info.sealed || (!pending && count > 0),
                  (info.pendingMessage == nil) == (info.pendingKind == nil) else { throw HumaError.invalidResponse }
            if info.pendingKind == "presence" {
                guard pending else { throw HumaError.invalidResponse }
                domain = Data((long ? "HUMA_LONG_ASSURANCE_PRESENCE_V1\0" : "HUMA_COMPACT_ASSURANCE_PRESENCE_V4\0").utf8)
            } else {
                guard info.pendingKind == nil || info.pendingKind == "checkpoint",
                      info.pendingKind != "checkpoint" || !pending else { throw HumaError.invalidResponse }
                domain = Data((long ? "HUMA_LONG_ASSURANCE_CHECKPOINT_V1\0" : "HUMA_COMPACT_ASSURANCE_CHECKPOINT_V4\0").utf8)
            }
        }
        if let pending = info.pendingMessage {
            guard !info.sealed, pending.count == domain.count + 32,
                  Data(pending.prefix(domain.count)) == domain else { throw HumaError.invalidResponse }
        }
    }
}

private struct Envelope<Result: Decodable>: Decodable { let result: Result }

// The MainActor owner serializes all calls. The Sendable marker permits final
// resource cleanup after that unique owner dies; native handles are never shared.
private final class CompactNativeLibrary: @unchecked Sendable {
    typealias Create = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> UnsafeMutableRawPointer?
    typealias Call = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) -> UnsafeMutablePointer<CChar>?
    typealias Destroy = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias Free = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void
    private let library: UnsafeMutableRawPointer
    private let createFunction: Create
    private let callFunction: Call
    private let destroyFunction: Destroy
    private let freeFunction: Free
    private var capture: UnsafeMutableRawPointer?

    init(url: URL) throws {
        guard url.isFileURL, let library = dlopen(url.path, RTLD_NOW | RTLD_LOCAL) else {
            throw HumaError.configuration("The experimental compact capture library is unavailable.")
        }
        guard let create = dlsym(library, "huma_compact_create"), let call = dlsym(library, "huma_compact_call"),
              let destroy = dlsym(library, "huma_compact_destroy"), let free = dlsym(library, "huma_compact_response_free") else {
            dlclose(library); throw HumaError.invalidResponse
        }
        self.library = library
        createFunction = unsafeBitCast(create, to: Create.self); callFunction = unsafeBitCast(call, to: Call.self)
        destroyFunction = unsafeBitCast(destroy, to: Destroy.self); freeFunction = unsafeBitCast(free, to: Free.self)
    }
    deinit { destroyFunction(capture); dlclose(library) }
    func create(_ request: Data) throws -> Data {
        guard capture == nil, !request.isEmpty, request.count <= 128 * 1024 else { throw HumaError.invalidResponse }
        var reply: UnsafeMutablePointer<CChar>?
        capture = request.withUnsafeBytes { createFunction($0.bindMemory(to: UInt8.self).baseAddress, request.count, &reply) }
        let response = try read(reply)
        guard capture != nil else { throw HumaError.invalidResponse }
        return response
    }
    func call(_ request: Data) throws -> Data {
        guard let capture, !request.isEmpty, request.count <= 128 * 1024 else { throw HumaError.invalidResponse }
        return try request.withUnsafeBytes { try read(callFunction(capture, $0.bindMemory(to: UInt8.self).baseAddress, request.count)) }
    }
    private func read(_ reply: UnsafeMutablePointer<CChar>?) throws -> Data {
        guard let reply else { throw HumaError.invalidResponse }
        defer { freeFunction(reply) }
        let count = strnlen(reply, 64 * 1024 * 1024 + 1)
        guard count <= 64 * 1024 * 1024 else { throw HumaError.invalidResponse }
        let data = Data(bytes: reply, count: count)
        struct Status: Decodable { let ok: Bool; let error: String? }
        let status = try JSONDecoder().decode(Status.self, from: data)
        guard status.ok else { throw HumaError.configuration(status.error ?? "Compact capture failed.") }
        return data
    }
}
