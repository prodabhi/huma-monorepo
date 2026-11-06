import Foundation
import DeviceCheck
import CryptoKit
import HumaCore

private final class DeviceServiceRedirectPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

@MainActor
struct AppAttestClient {
    struct Info: Decodable {
        var version: Int; var kind: String; var platform: String; var appID: String; var environment: String; var versions: [String]
        var bindingVersions: [Int]?
    }
    struct Challenge: Codable {
        var id: String; var nonce: String; var purpose: String; var keyID: String; var expiresAt: Double; var clientData: Data
    }
    struct Enrollment: Codable {
        var keyID: String
        var enrolled = false
        var challenge: Challenge?
        var attestation: Data?
        var publicEnrollment: AppAttestEnrollment?
    }
    private static let session = URLSession(configuration: .ephemeral, delegate: DeviceServiceRedirectPolicy(), delegateQueue: nil)
    let base: URL
    init(url: String) throws {
        guard let value = URL(string: url), value.host != nil, value.user == nil, value.password == nil, value.query == nil, value.fragment == nil,
              value.path.isEmpty || value.path == "/",
              value.scheme == "https" || (value.scheme == "http" && ["localhost", "127.0.0.1"].contains(value.host ?? "")) else {
            throw HumaError.configuration("Use an HTTPS device service, or localhost for development.")
        }
        base = value
    }
    func request<T: Decodable>(_ path: String, body: Data? = nil) async throws -> T {
        var request = URLRequest(url: base.appendingPathComponent(path))
        request.timeoutInterval = 30
        if let body { request.httpMethod = "POST"; request.httpBody = body; request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let (data, response) = try await Self.session.data(for: request)
        guard let response = response as? HTTPURLResponse, response.url?.host == base.host,
              response.url?.scheme == base.scheme, response.url?.port == base.port, response.statusCode == 200 else {
            throw HumaError.configuration("Device evidence was not accepted. Check the service identity, enrollment and challenge freshness.")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
    func info() async throws -> Info {
        let info: Info = try await request("v1/info")
        let expected = Bundle.main.bundleIdentifier ?? "dev.swayam.huma"
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"
        guard info.version == 1, info.kind == "apple-app-attest", info.platform == "macOS",
              info.appID.hasSuffix("." + expected), info.appID.split(separator: ".").first?.count == 10,
              ["development", "production"].contains(info.environment), info.versions.contains(version) else {
            throw HumaError.configuration("The device service is configured for a different app, version or environment.")
        }
        return info
    }
    private func account(_ info: Info) -> String { "app-attest-" + sha256(Data((base.absoluteString + "|" + info.appID + "|" + info.environment).utf8)) }
    private func save(_ state: Enrollment, info: Info) throws {
        try KeychainStore.save(try JSONEncoder().encode(state).base64EncodedString(), account: account(info))
    }
    private func state(_ info: Info) throws -> Enrollment? {
        let value = KeychainStore.read(account(info))
        guard !value.isEmpty else { return nil }
        guard let data = Data(base64Encoded: value) else { throw HumaError.invalidResponse }
        return try JSONDecoder().decode(Enrollment.self, from: data)
    }
    func enroll() async throws -> String {
        guard DCAppAttestService.shared.isSupported else {
            throw HumaError.configuration("App Attest is unavailable for this Mac build. Use supported macOS, an Apple-provisioned App ID and the App Attest entitlement.")
        }
        let info = try await info()
        var state: Enrollment
        if let existing = try self.state(info) { state = existing }
        else {
            state = Enrollment(keyID: try await DCAppAttestService.shared.generateKey())
            try save(state, info: info) // Preserve the identifier before any network request.
        }
        if state.enrolled { return state.keyID }
        if state.challenge == nil {
            struct Request: Encodable { let purpose = "enroll"; var keyID: String }
            state.challenge = try await request("v1/challenges", body: JSONEncoder().encode(Request(keyID: state.keyID)))
            try save(state, info: info)
        }
        guard let challenge = state.challenge,
              challenge.purpose == "enroll", challenge.keyID == state.keyID,
              challenge.id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
              let nonce = Data(base64Encoded: challenge.nonce), nonce.count == 32, nonce.base64EncodedString() == challenge.nonce,
              let values = try? JSONDecoder().decode([String].self, from: challenge.clientData),
              values == ["huma-app-attest-enroll-v1", challenge.id, challenge.nonce, state.keyID] else { throw HumaError.invalidResponse }
        if state.attestation == nil {
            guard challenge.expiresAt > Date().timeIntervalSince1970 * 1000 else {
                throw HumaError.configuration("The pending enrollment challenge expired. Restart enrollment explicitly in Connections.")
            }
            // Preserve inputs on Apple/network failures. Never loop generating new device keys.
            state.attestation = try await DCAppAttestService.shared.attestKey(state.keyID, clientDataHash: Data(SHA256.hash(data: challenge.clientData)))
            try save(state, info: info)
        }
        struct Request: Encodable { var challengeID: String; var keyID: String; var attestation: Data }
        struct Result: Decodable { var verified: Bool; var kind: String; var keyID: String; var environment: String }
        let result: Result = try await request("v1/enroll", body: JSONEncoder().encode(Request(challengeID: challenge.id, keyID: state.keyID, attestation: state.attestation!)))
        guard result.verified, result.kind == "apple-app-attest-enrollment", result.keyID == state.keyID, result.environment == info.environment else { throw HumaError.invalidResponse }
        state.publicEnrollment = AppAttestEnrollment(attestation: state.attestation!, clientData: challenge.clientData)
        state.enrolled = true; state.challenge = nil; state.attestation = nil
        try save(state, info: info)
        return state.keyID
    }
    func restartEnrollment() async throws {
        let info = try await info()
        // An empty value forgets only this service's local enrollment reference.
        // The server retains counters for the old key; this does not reset them.
        try KeychainStore.save("", account: account(info))
    }
    func seal(draft: Draft) async throws -> AppAttestEvidence {
        // Validate the relation before asking a device key to bind it.
        guard let proof = draft.replayProof else { throw HumaError.configuration("Generate a replay proof before requesting device evidence.") }
        guard !NoirWritingProofService.isNoirProof(proof) else {
            throw HumaError.configuration("This device-evidence service supports legacy replay proofs. Noir capture signatures verify locally; its Apple evidence adapter is not configured yet.")
        }
        _ = try await ReplayProofService.verify(draft: draft, proof: proof)
        let binding = try AppAttestBinding(draft: draft)
        // Never certify an imported software-signed history through the genuine app.
        // The capture checkpoint key must be this Mac's persisted enclave key.
        guard SecureEnclave.isAvailable, let publicKey = try WrappedCaptureKeyStore().publicKey(),
              sha256(publicKey) == binding.captureKeyHash else {
            throw HumaError.configuration("Only sessions signed by this Mac’s capture key can be attested. Start and seal a signed session here first.")
        }
        let expectedInfo = try await info()
        guard binding.version != 2 || expectedInfo.bindingVersions?.contains(2) == true else {
            throw HumaError.configuration("Update the device service to support portable replay proof bindings. This proof will not be silently downgraded.")
        }
        let keyID = try await enroll()
        struct Request: Encodable { let purpose = "assert"; var keyID: String; var binding: AppAttestBinding }
        let challenge: Challenge = try await request("v1/challenges", body: JSONEncoder().encode(Request(keyID: keyID, binding: binding)))
        guard challenge.keyID == keyID, challenge.purpose == "assert", challenge.expiresAt > Date().timeIntervalSince1970 * 1000 else { throw HumaError.invalidResponse }
        try binding.validateClientData(challenge.clientData, challengeID: challenge.id, nonce: challenge.nonce, keyID: keyID)
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyID, clientDataHash: Data(SHA256.hash(data: challenge.clientData)))
        struct Submit: Encodable { var challengeID: String; var keyID: String; var assertion: Data }
        struct Result: Decodable {
            var verified: Bool; var kind: String; var keyID: String; var environment: String; var signCount: UInt32
            var binding: AppAttestBinding; var challengeID: String; var clientData: Data; var assertion: Data; var verifiedAt: String
        }
        let result: Result = try await request("v1/assert", body: JSONEncoder().encode(Submit(challengeID: challenge.id, keyID: keyID, assertion: assertion)))
        guard result.verified, result.kind == "apple-app-attest-session", result.keyID == keyID, result.binding == binding,
              result.challengeID == challenge.id, result.clientData == challenge.clientData, result.assertion == assertion,
              result.signCount > 0, result.environment == expectedInfo.environment else { throw HumaError.invalidResponse }
        let evidence = AppAttestEvidence(binding: binding, serviceURL: base.absoluteString, keyID: keyID, environment: result.environment,
            signCount: result.signCount, challengeID: challenge.id, clientData: challenge.clientData, assertion: assertion, verifiedAt: result.verifiedAt,
            enrollment: try state(expectedInfo)?.publicEnrollment, appID: expectedInfo.appID)
        try evidence.validate(draft: draft)
        return evidence
    }
}
