import Foundation

/// Where a page proof is made. The proof is the same either way, and the Mac verifies it before use.
public enum ProverChoice: String, Sendable, CaseIterable {
    /// Private: the signed recording never leaves this Mac.
    case mac
    /// Opt-in: the signed recording (text and typing timeline) is sent to a Huma prover.
    case server

    public static let defaultsKey = "proverMode"
    public static let addressKey = "proverURL"
    public static let defaultAddress = "http://127.0.0.1:4330"
    public static var current: ProverChoice {
        UserDefaults.standard.string(forKey: defaultsKey).flatMap(ProverChoice.init(rawValue:)) ?? .mac
    }
    public static var currentAddress: String { UserDefaults.standard.string(forKey: addressKey) ?? defaultAddress }
}

/// Client for a Huma prover (`backend/prover/` in this repository). It sends exactly the request the
/// bundled worker would receive and returns only the public proof, which the caller must verify.
public struct RemoteProver: Sendable {
    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        // Long pages wait in line and then prove; the server stops a proof after at most ~35 minutes.
        configuration.timeoutIntervalForRequest = 900; configuration.timeoutIntervalForResource = 2_400
        return URLSession(configuration: configuration, delegate: RegistryRedirectPolicy(), delegateQueue: nil)
    }()
    static let replyLimit = 8 * 1024 * 1024
    public let base: URL

    public init(url: String) throws {
        guard let value = URL(string: url), value.host != nil, value.user == nil, value.password == nil,
              value.query == nil, value.fragment == nil, value.path.isEmpty || value.path == "/",
              value.scheme == "https" || (value.scheme == "http" && ["localhost", "127.0.0.1", "[::1]"].contains(value.host ?? "")) else {
            throw HumaError.configuration("Use an HTTPS prover address, or localhost for local testing.")
        }
        base = value
    }

    struct Request: Encodable { var command: String; var input: String; var chunkProofs: [LongChunkProof?]? }

    static func body(command: String, input: Data, chunkProofs: [LongChunkProof?]?) throws -> Data {
        try JSONEncoder().encode(Request(command: command, input: input.base64EncodedString(), chunkProofs: chunkProofs))
    }

    /// The public proof JSON made by the prover. Not yet trusted: verify it against the draft.
    public func prove(command: String, input: Data, chunkProofs: [LongChunkProof?]?) async throws -> Data {
        var post = URLRequest(url: base.appendingPathComponent("v1/pages/prove")); post.httpMethod = "POST"
        post.setValue("application/json", forHTTPHeaderField: "Content-Type")
        post.httpBody = try Self.body(command: command, input: input, chunkProofs: chunkProofs)
        let (bytes, response) = try await Self.session.bytes(for: post)
        guard let response = response as? HTTPURLResponse, response.url?.host == base.host, response.url?.scheme == base.scheme,
              response.url?.port == base.port else { throw HumaError.invalidResponse }
        var data = Data()
        for try await byte in bytes {
            guard data.count < Self.replyLimit else { throw HumaError.invalidResponse }
            data.append(byte)
        }
        return try Self.proof(status: response.statusCode, reply: data)
    }

    static func proof(status: Int, reply: Data) throws -> Data {
        struct Reply: Decodable { var proof: String?; var error: String? }
        let decoded = try? JSONDecoder().decode(Reply.self, from: reply)
        switch status {
        case 200:
            guard let proof = decoded?.proof else { throw HumaError.invalidResponse }
            return Data(proof.utf8)
        case 429, 503: throw HumaError.configuration("The Huma prover is busy right now.")
        case 422: throw HumaError.configuration("The Huma prover could not make a proof from this recording.")
        default: throw HumaError.configuration("The Huma prover did not respond as expected (\(status)).")
        }
    }
}
