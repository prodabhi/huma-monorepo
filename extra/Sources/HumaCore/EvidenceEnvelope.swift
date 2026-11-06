import Foundation

/// Portable data contract. Decoding or hashing these values is NOT verification.
/// Readers must derive the statement from their independently verified evidence.
public struct EvidenceStatement: Codable, Sendable, Equatable {
    public var version: Int = 1
    public var contentKind: String
    public var contentPolicy: String
    public var contentHash: String
    public var byteLength: String
    public var sessionBinding: String
    public var captureScheme: String
    public var captureHead: String
    public var checkpointBinding: String?
    public var captureKeyHash: String?
    public var policyID: String?
    public var policySatisfied: Bool?

    public init(contentKind: String, contentPolicy: String, contentHash: String, byteLength: String,
                sessionBinding: String, captureScheme: String, captureHead: String,
                checkpointBinding: String? = nil, captureKeyHash: String? = nil,
                policyID: String? = nil, policySatisfied: Bool? = nil) throws {
        self.contentKind = contentKind; self.contentPolicy = contentPolicy; self.contentHash = contentHash
        self.byteLength = byteLength; self.sessionBinding = sessionBinding; self.captureScheme = captureScheme
        self.captureHead = captureHead; self.checkpointBinding = checkpointBinding; self.captureKeyHash = captureKeyHash
        self.policyID = policyID; self.policySatisfied = policySatisfied
        try validate()
    }
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version, contentKind, contentPolicy, contentHash, byteLength, sessionBinding, captureScheme,
             captureHead, checkpointBinding, captureKeyHash, policyID, policySatisfied
    }
    public init(from decoder: Decoder) throws {
        try evidenceFields(decoder, required: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        contentKind = try c.decode(String.self, forKey: .contentKind)
        contentPolicy = try c.decode(String.self, forKey: .contentPolicy)
        contentHash = try c.decode(String.self, forKey: .contentHash)
        byteLength = try c.decode(String.self, forKey: .byteLength)
        sessionBinding = try c.decode(String.self, forKey: .sessionBinding)
        captureScheme = try c.decode(String.self, forKey: .captureScheme)
        captureHead = try c.decode(String.self, forKey: .captureHead)
        checkpointBinding = try c.decodeIfPresent(String.self, forKey: .checkpointBinding)
        captureKeyHash = try c.decodeIfPresent(String.self, forKey: .captureKeyHash)
        policyID = try c.decodeIfPresent(String.self, forKey: .policyID)
        policySatisfied = try c.decodeIfPresent(Bool.self, forKey: .policySatisfied)
        try validate()
    }
    public func encode(to encoder: Encoder) throws {
        try validate()
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(version, forKey: .version); try c.encode(contentKind, forKey: .contentKind)
        try c.encode(contentPolicy, forKey: .contentPolicy); try c.encode(contentHash, forKey: .contentHash)
        try c.encode(byteLength, forKey: .byteLength); try c.encode(sessionBinding, forKey: .sessionBinding)
        try c.encode(captureScheme, forKey: .captureScheme); try c.encode(captureHead, forKey: .captureHead)
        // Null slots are explicit, matching the JS object schema.
        try c.encode(checkpointBinding, forKey: .checkpointBinding); try c.encode(captureKeyHash, forKey: .captureKeyHash)
        try c.encode(policyID, forKey: .policyID); try c.encode(policySatisfied, forKey: .policySatisfied)
    }
    public func validate() throws {
        let kinds = ["text", "image", "audio", "video"]
        let schemes = ["sha256-capture-v2", "sha256-capture-v3", "poseidon2-capture-v3", "poseidon2-capture-v4", "poseidon2-capture-long-v1", "sha256-media-v1"]
        let expectedPolicy = contentKind == "text" ? "trailing-ascii-space-tab-v1" : "exact-bytes-v1"
        guard version == 1, kinds.contains(contentKind), contentPolicy == expectedPolicy,
              [contentHash, sessionBinding, captureHead].allSatisfy(evidenceHex), schemes.contains(captureScheme),
              let length = UInt64(byteLength), String(length) == byteLength,
              [checkpointBinding, captureKeyHash].allSatisfy({ $0 == nil || evidenceHex($0!) }),
              (checkpointBinding == nil) == (captureKeyHash == nil),
              policyID == nil ? policySatisfied == nil : (evidencePolicyID(policyID!) && policySatisfied != nil) else {
            throw HumaError.invalidResponse
        }
    }
    public func payload() throws -> Data {
        try validate()
        let fields = ["huma-evidence-statement-v1", "1", contentKind, contentPolicy, contentHash, byteLength,
            sessionBinding, captureScheme, captureHead, checkpointBinding ?? "", captureKeyHash ?? "", policyID ?? "",
            policySatisfied.map { $0 ? "true" : "false" } ?? ""]
        return try JSONSerialization.data(withJSONObject: fields, options: [.withoutEscapingSlashes])
    }
    public func digest() throws -> String { sha256(try payload()) }
}

public struct EvidenceEnvelope: Codable, Sendable, Equatable {
    public static let kind = "huma-evidence-envelope-v1"
    public static let maximumBytes = 32 * 1024 * 1024
    public var kind: String = Self.kind
    public var statement: EvidenceStatement
    /// Original public proof JSON, preserved as text to keep all u64 values exact.
    public var proof: String
    public var attachments: [String: String]
    public init(statement: EvidenceStatement, proof: String, attachments: [String: String] = [:]) throws {
        self.statement = statement; self.proof = proof; self.attachments = attachments
        try validate()
    }
    private enum CodingKeys: String, CodingKey, CaseIterable { case kind, statement, proof, attachments }
    public init(from decoder: Decoder) throws {
        try evidenceFields(decoder, required: Set(CodingKeys.allCases.map(\.rawValue)))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decode(String.self, forKey: .kind); statement = try c.decode(EvidenceStatement.self, forKey: .statement)
        proof = try c.decode(String.self, forKey: .proof); attachments = try c.decode([String: String].self, forKey: .attachments)
        try validate()
    }
    public func validate() throws {
        guard kind == Self.kind, attachments.keys.allSatisfy({ $0 == "device" }) else { throw HumaError.invalidResponse }
        try statement.validate(); try evidenceJSON(proof, limit: Self.maximumBytes)
        for value in attachments.values { try evidenceJSON(value, limit: 256 * 1024) }
    }
    public func encoded() throws -> Data {
        try validate()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        guard data.count <= Self.maximumBytes else { throw HumaError.invalidResponse }
        return data
    }
    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= maximumBytes else { throw HumaError.invalidResponse }
        return try JSONDecoder().decode(Self.self, from: data)
    }
}

private struct EvidenceKey: CodingKey {
    var stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}
private func evidenceFields(_ decoder: Decoder, required: Set<String>) throws {
    let c = try decoder.container(keyedBy: EvidenceKey.self)
    guard Set(c.allKeys.map(\.stringValue)) == required else { throw HumaError.invalidResponse }
}
private func evidenceHex(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
private func evidencePolicyID(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    guard let first = bytes.first, bytes.count <= 96, (48...57).contains(first) || (97...122).contains(first) else { return false }
    return bytes.allSatisfy { (48...57).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }
}
private func evidenceJSON(_ value: String, limit: Int) throws {
    let data = Data(value.utf8)
    guard data.count <= limit, (try JSONSerialization.jsonObject(with: data)) is [String: Any] else { throw HumaError.invalidResponse }
}
