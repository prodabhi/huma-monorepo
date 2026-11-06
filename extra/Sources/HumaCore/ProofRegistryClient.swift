import Foundation

final class RegistryRedirectPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

public struct PublicProofLink: Codable, Sendable, Equatable {
    public var url: URL
    /// The same page's short link (huma.social/p/<code>#<key>), for copying and sharing. The full link above is
    /// still the one the app uses with the host. Pages shared before short links get one when next opened.
    public var shortURL: URL?
    /// The wallet that signed the publication, when it was signed.
    public var signer: String?
    /// Whether readers got the writing replay with the link (nil for links shared before this was kept).
    public var replayShared: Bool?
    /// The host's verdict on the page's typing when it was shared (nil for links shared before it was kept).
    public var hostVerdict: HostVerdict?
    public var proofHash: String
    public var textHash: String
    public var sessionID: String
    public var captureHead: String
    public var checkpointHash: String?

    public init(url: URL, proof: Data, draft: Draft) {
        self.url = url; proofHash = sha256(proof); textHash = sha256(Data(draft.text.utf8))
        sessionID = draft.session.id; captureHead = draft.session.captureHead
        checkpointHash = draft.session.signedCheckpoints?.last?.digest
    }
    public func matches(_ draft: Draft) -> Bool {
        guard sessionID == draft.session.id, captureHead == draft.session.captureHead,
              checkpointHash == draft.session.signedCheckpoints?.last?.digest,
              textHash == sha256(Data(draft.text.utf8)), let proof = draft.replayProof else { return false }
        return proofHash == sha256(proof)
    }
}

public struct ProofRegistryClient: Sendable {
    public struct Upload: Sendable { public let url: URL; public let proof: Data }
    private static let limit = 2 * 1024 * 1024
    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20; configuration.timeoutIntervalForResource = 30
        return URLSession(configuration: configuration, delegate: RegistryRedirectPolicy(), delegateQueue: nil)
    }()
    public let base: URL
    public init(url: String) throws {
        guard let value = URL(string: url), value.host != nil, value.user == nil, value.password == nil,
              value.query == nil, value.fragment == nil, value.path.isEmpty || value.path == "/",
              value.scheme == "https" || (value.scheme == "http" && ["localhost", "127.0.0.1", "[::1]"].contains(value.host ?? "")) else {
            throw HumaError.configuration("Use an HTTPS registry, or localhost for local testing.")
        }
        base = value
    }
    private func request(_ request: URLRequest, status: Int) async throws -> Data {
        let (bytes, response) = try await Self.session.bytes(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == status,
              response.url?.host == base.host, response.url?.scheme == base.scheme, response.url?.port == base.port,
              response.expectedContentLength <= Self.limit else { throw HumaError.configuration("The registry did not accept this proof. Check its address and try again.") }
        var data = Data()
        for try await byte in bytes {
            guard data.count < Self.limit else { throw HumaError.invalidResponse }
            data.append(byte)
        }
        return data
    }
    // The caller verifies this proof locally before upload and verifies the returned
    // public proof again before saving the link. No edit history enters the request.
    public func store(text: String, proof: Data) async throws -> Upload {
        let bundle = try JSONSerialization.jsonObject(with: proof)
        var post = URLRequest(url: base.appendingPathComponent("api/proofs")); post.httpMethod = "POST"
        post.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = try JSONSerialization.data(withJSONObject: ["text": text, "bundle": bundle], options: [.sortedKeys])
        guard body.count <= Self.limit else { throw HumaError.configuration("This proof exceeds the registry's 2 MB limit. Export it as a file instead.") }
        post.httpBody = body
        struct Response: Decodable { var id: String }
        let id = try JSONDecoder().decode(Response.self, from: await request(post, status: 201)).id
        guard id.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw HumaError.invalidResponse }
        let record = try await request(URLRequest(url: base.appendingPathComponent("api/proofs/" + id)), status: 200)
        guard sha256(record) == id, let object = try JSONSerialization.jsonObject(with: record) as? [String: Any],
              let receivedText = object["text"] as? String, exactTextEqual(receivedText, text), let publicBundle = object["bundle"] else {
            throw HumaError.invalidResponse
        }
        return Upload(url: base.appendingPathComponent("verify/" + id), proof: try JSONSerialization.data(withJSONObject: publicBundle, options: [.sortedKeys]))
    }
}
