import Foundation

public struct AppAttestBinding: Codable, Sendable, Equatable {
    // Absence preserves the original V1 raw-proof-byte hash. V2 is exclusively
    // the canonical replay statement identity; its challenge has a new domain.
    public var version: Int?
    public var sessionID: String
    public var captureHead: String
    public var editHead: String
    public var textHash: String
    public var proofHash: String
    public var checkpointHash: String
    public var captureKeyHash: String

    public init(draft: Draft, useLegacyProofHash: Bool = false) throws {
        try draft.session.validateSignedCheckpoints(requireFinal: true, finalText: draft.text)
        guard let proof = draft.replayProof, draft.replayProofTextHash == sha256(Data(draft.text.utf8)),
              let checkpoint = draft.session.signedCheckpoints?.last else { throw HumaError.invalidSession }
        sessionID = draft.session.id; captureHead = draft.session.captureHead; editHead = draft.session.head
        version = useLegacyProofHash ? nil : 2
        textHash = sha256(Data(draft.text.utf8))
        proofHash = version == 2 ? try ReplayProofIdentity(proof: proof).value : sha256(proof)
        checkpointHash = checkpoint.digest; captureKeyHash = sha256(checkpoint.publicKey)
    }
    public var fields: [String] { [sessionID, captureHead, editHead, textHash, proofHash, checkpointHash, captureKeyHash] }

    public func validateClientData(_ data: Data, challengeID: String, nonce: String, keyID: String) throws {
        guard version == nil || version == 2,
              challengeID.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
              let random = Data(base64Encoded: nonce), random.count == 32, random.base64EncodedString() == nonce,
              let key = Data(base64Encoded: keyID), key.count == 32, key.base64EncodedString() == keyID,
              let values = try? JSONDecoder().decode([String].self, from: data),
              values == ["huma-app-attest-assert-v\(version ?? 1)", challengeID, nonce, keyID] + fields else {
            throw HumaError.invalidResponse
        }
    }
}

// Stores the configured service transaction. Its verdict alone is not a portable
// certificate. Retained enrollment material can be exported for independent
// Apple-root and assertion verification under the reader's own app policy.
public struct AppAttestEvidence: Codable, Sendable {
    public var enrollment: AppAttestEnrollment?
    public var appID: String?
    public var binding: AppAttestBinding
    public var serviceURL: String
    public var keyID: String
    public var environment: String
    public var signCount: UInt32
    public var challengeID: String
    public var clientData: Data
    public var assertion: Data
    public var verifiedAt: String

    public init(binding: AppAttestBinding, serviceURL: String, keyID: String, environment: String, signCount: UInt32,
                challengeID: String, clientData: Data, assertion: Data, verifiedAt: String,
                enrollment: AppAttestEnrollment? = nil, appID: String? = nil) {
        self.enrollment = enrollment; self.appID = appID
        self.binding = binding; self.serviceURL = serviceURL; self.keyID = keyID; self.environment = environment
        self.signCount = signCount; self.challengeID = challengeID; self.clientData = clientData
        self.assertion = assertion; self.verifiedAt = verifiedAt
    }
    public func validate(draft: Draft) throws {
        guard binding.version == nil || binding.version == 2,
              try binding == AppAttestBinding(draft: draft, useLegacyProofHash: binding.version == nil), signCount > 0,
              ["development", "production"].contains(environment), !assertion.isEmpty,
              let values = try? JSONDecoder().decode([String].self, from: clientData), values.count == 11 else { throw HumaError.invalidSession }
        try binding.validateClientData(clientData, challengeID: challengeID, nonce: values[2], keyID: keyID)
        if let enrollment { try enrollment.validate(keyID: keyID) }
    }
    public func portable(draft: Draft) throws -> PortableDeviceEvidence {
        try validate(draft: draft)
        guard binding.version == 2, let enrollment, let appID,
              appID.range(of: "^[A-Z0-9]{10}\\.[A-Za-z0-9.-]{3,255}$", options: .regularExpression) != nil else {
            throw HumaError.configuration("Portable device evidence needs a retained Apple enrollment and a replay proof. Older enrollments require an explicit restart in Connections.")
        }
        return PortableDeviceEvidence(appID: appID, environment: environment, keyID: keyID, enrollment: enrollment,
            binding: binding, clientData: clientData, assertion: assertion)
    }
}
