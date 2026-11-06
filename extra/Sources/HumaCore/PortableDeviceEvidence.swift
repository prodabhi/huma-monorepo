import Foundation

public struct AppAttestEnrollment: Codable, Sendable {
    public var attestation: Data
    public var clientData: Data
    public init(attestation: Data, clientData: Data) { self.attestation = attestation; self.clientData = clientData }
    public func validate(keyID: String) throws {
        guard !attestation.isEmpty, attestation.count <= 65536, clientData.count <= 4096,
              let fields = try? JSONDecoder().decode([String].self, from: clientData), fields.count == 4,
              fields[0] == "huma-app-attest-enroll-v1", fields[3] == keyID,
              fields[1].range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
              let nonce = Data(base64Encoded: fields[2]), nonce.count == 32, nonce.base64EncodedString() == fields[2],
              let key = Data(base64Encoded: keyID), key.count == 32, key.base64EncodedString() == keyID else { throw HumaError.invalidResponse }
    }
}

// A separate, opt-in public artifact. A reader must validate Apple's certificate
// roots, app policy and signatures; no Huma service verdict is included here.
public struct PortableDeviceEvidence: Codable, Sendable {
    public var version = 1
    public var appID: String
    public var environment: String
    public var keyID: String
    public var enrollment: AppAttestEnrollment
    public var binding: AppAttestBinding
    public var clientData: Data
    public var assertion: Data
}
