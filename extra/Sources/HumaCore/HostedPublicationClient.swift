import Foundation

public struct PublicationManifest: Codable, Sendable {
    public struct File: Codable, Sendable { public let hash: String; public let byteLength: Int; public let mediaType: String? }
    public let kind: String
    public let publicationNonce: String
    public let master: File
    public let proof: File
    public let statement: EvidenceStatement
    public let statementHash: String
    public let access: String

    public func validate() throws {
        try statement.validate()
        guard kind == "huma-publication-v1", ["link", "public"].contains(access),
              [publicationNonce, master.hash, proof.hash, statementHash].allSatisfy(publicationHash),
              (1...32 * 1024 * 1024).contains(master.byteLength), (1...8 * 1024 * 1024).contains(proof.byteLength),
              proof.mediaType == nil, statementHash == (try statement.digest()) else { throw HumaError.invalidResponse }
        let types = ["text": ["text/plain;charset=utf-8"], "image": ["image/png", "image/avif"], "audio": ["audio/flac"], "video": ["video/mp4", "video/webm"]]
        guard types[statement.contentKind]?.contains(master.mediaType ?? "") == true else { throw HumaError.invalidResponse }
    }
    /// Transport integrity and expected-session binding. The caller must still
    /// verify the downloaded proof with its pinned cryptographic verifier.
    public static func check(source: Data, id: String, master: Data, proof: Data,
                             expectedMasterHash: String, expectedStatement: EvidenceStatement) throws -> Self {
        guard source.count <= 8192, publicationHash(id), sha256(source) == id else { throw HumaError.invalidResponse }
        let manifest = try JSONDecoder().decode(Self.self, from: source)
        try manifest.validate()
        guard manifest.master.hash == expectedMasterHash, manifest.statement == expectedStatement,
              master.count == manifest.master.byteLength, proof.count == manifest.proof.byteLength,
              sha256(master) == manifest.master.hash, sha256(proof) == manifest.proof.hash else { throw HumaError.invalidResponse }
        return manifest
    }
}

private final class PublicationRedirectPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) { completionHandler(nil) }
}

public struct HostedPublicationClient: Sendable {
    public struct Prepared: Sendable {
        public let approvalURL: URL
        public let storage: String
        let id: String, ticket: String
        let expiresAt: Date
        let expectedMasterHash: String
        let statement: EvidenceStatement
    }
    public struct Download: Sendable {
        public let url: URL
        public let master: Data
        public let envelope: EvidenceEnvelope
    }
    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        // A host keeping pages on Arkiv answers a share only once its transactions are confirmed (several seconds each).
        configuration.timeoutIntervalForRequest = 120; configuration.timeoutIntervalForResource = 180
        return URLSession(configuration: configuration, delegate: PublicationRedirectPolicy(), delegateQueue: nil)
    }()
    public let base: URL
    /// Where people open pages (sign-in, approval, public links): the API host without its "api."
    /// prefix, so the app talks to api.huma.social while links read huma.social.
    public let site: URL
    public init(url: String) throws { base = try ProofRegistryClient(url: url).base; site = Self.site(for: base) }
    public static func site(for base: URL) -> URL {
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false), let host = components.host,
              host.hasPrefix("api."), host.count > 4 else { return base }
        components.host = String(host.dropFirst(4))
        return components.url ?? base
    }
    private func request(path: String, token: String? = nil, body: Data? = nil, headers: [String: String] = [:], limit: Int, status: Int = 200) async throws -> Data {
        var request = URLRequest(url: base.appendingPathComponent(path))
        if let token { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
        if let body { request.httpMethod = "POST"; request.httpBody = body; request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let (bytes, response) = try await Self.session.bytes(for: request)
        guard let response = response as? HTTPURLResponse,
              response.url?.host == base.host, response.url?.scheme == base.scheme, response.url?.port == base.port
        else { throw HumaError.configuration("The sharing host could not complete this request. Check its configuration and try again.") }
        guard response.statusCode == status, response.expectedContentLength <= limit else {
            // Show the host's own reason (its JSON "error"), which says what to fix.
            var reply = Data()
            for try await byte in bytes { guard reply.count < 4096 else { break }; reply.append(byte) }
            struct Failure: Decodable { let error: String }
            let reason = (try? JSONDecoder().decode(Failure.self, from: reply))?.error.prefix(300)
            throw HumaError.configuration(reason.map(String.init) ?? "The sharing host could not complete this request (\(response.statusCode)). Try again.")
        }
        var data = Data()
        for try await byte in bytes {
            try Task.checkCancellation()
            guard data.count < limit else { throw HumaError.invalidResponse }; data.append(byte)
        }
        return data
    }
    /// `replay` is the page's writing replay (SessionLog.replayExport), shared only when the writer chose to.
    public func prepare(text: String, envelope: EvidenceEnvelope, access: String = "link", replay: Data? = nil) async throws -> Prepared {
        let master = Data(text.utf8), proof = try envelope.encoded()
        guard !master.isEmpty, master.count <= 65536, proof.count <= 8 * 1024 * 1024, (replay?.count ?? 0) <= 4 * 1024 * 1024,
              envelope.statement.contentKind == "text", envelope.attachments.isEmpty,
              ["link", "public"].contains(access), let source = String(data: proof, encoding: .utf8) else { throw HumaError.invalidResponse }
        struct Upload: Encodable {
            struct Master: Encodable { let base64: String; let mediaType = "text/plain;charset=utf-8" }
            let kind = "huma-publication-upload-v1"
            let master: Master
            let proof: String
            let access: String
            let replay: String?
        }
        let body = try JSONEncoder().encode(Upload(master: .init(base64: master.base64EncodedString()), proof: source, access: access,
                                                   replay: replay.map { String(decoding: $0, as: UTF8.self) }))
        struct Response: Decodable { let id: String; let ticket: String; let expiresAt: Double; let storage: String }
        let value = try JSONDecoder().decode(Response.self, from: await request(path: "api/publications/prepare", body: body, limit: 4096, status: 201))
        let expiry = Date(timeIntervalSince1970: value.expiresAt / 1000)
        // Where the host keeps pages: a folder (a preview host), Cloudflare R2, or Arkiv (frontend/arkiv-store.mjs).
        guard publicationHash(value.id), publicationHash(value.ticket), ["local", "r2", "arkiv"].contains(value.storage),
              expiry > .now, expiry.timeIntervalSinceNow <= 15 * 60 else { throw HumaError.invalidResponse }
        var url = URLComponents(url: site.appendingPathComponent("share/" + value.id), resolvingAgainstBaseURL: false)!
        url.fragment = value.ticket
        guard let approval = url.url else { throw HumaError.invalidResponse }
        return Prepared(approvalURL: approval, storage: value.storage, id: value.id, ticket: value.ticket,
            expiresAt: expiry, expectedMasterHash: sha256(master), statement: envelope.statement)
    }
    /// Waits only for the user's browser approval. It never signs in, creates a
    /// wallet, approves publication or submits a transaction on their behalf.
    public func waitForApproval(_ prepared: Prepared) async throws -> Download {
        struct Status: Decodable { let status: String; let path: String?; let approvalError: String? }
        while Date.now < prepared.expiresAt {
            try Task.checkCancellation()
            let value = try JSONDecoder().decode(Status.self, from: await request(path: "api/publications/pending/" + prepared.id,
                token: prepared.ticket, limit: 128 * 1024))
            if value.status == "published" {
                guard let path = value.path else { throw HumaError.invalidResponse }
                let pieces = path.split(separator: "#", omittingEmptySubsequences: false)
                let prefix = "/original/"
                guard pieces.count <= 2, pieces[0].hasPrefix(prefix) else { throw HumaError.invalidResponse }
                let id = String(pieces[0].dropFirst(prefix.count)), token = pieces.count == 2 ? String(pieces[1]) : nil
                guard publicationHash(id), token == nil || publicationHash(token!) else { throw HumaError.invalidResponse }
                let manifest = try await request(path: "api/publications/" + id, token: token, limit: 8192)
                let master = try await request(path: "api/publications/" + id + "/master", token: token, limit: 65536)
                let proof = try await request(path: "api/publications/" + id + "/proof", token: token, limit: 8 * 1024 * 1024)
                _ = try PublicationManifest.check(source: manifest, id: id, master: master, proof: proof,
                    expectedMasterHash: prepared.expectedMasterHash, expectedStatement: prepared.statement)
                let envelope = try EvidenceEnvelope.decode(proof)
                guard envelope.statement == prepared.statement, envelope.attachments.isEmpty else { throw HumaError.invalidResponse }
                var url = URLComponents(url: site.appendingPathComponent("original/" + id), resolvingAgainstBaseURL: false)!
                url.fragment = token
                guard let link = url.url else { throw HumaError.invalidResponse }
                return Download(url: link, master: master, envelope: envelope)
            }
            guard value.status == "awaiting-approval" else { throw HumaError.invalidResponse }
            if value.approvalError == "daily-limit" {
                throw HumaError.configuration("The host’s daily sharing allowance has been reached. Your files are still saved locally. Try again after the next UTC day.")
            }
            try await Task.sleep(for: .seconds(2))
        }
        throw HumaError.configuration("The sharing request expired. Start again when you are ready to approve it.")
    }
}

extension HostedPublicationClient {
    public struct Receipt: Sendable {
        public let signer: String?
        /// Whether readers can watch the page being written now.
        public var replay = false
    }
    private func publicationID(_ link: URL) throws -> String {
        let pieces = link.path.split(separator: "/")
        guard pieces.count == 2, pieces[0] == "original", publicationHash(String(pieces[1])),
              [site.host, base.host].contains(link.host), link.scheme == base.scheme else { throw HumaError.invalidResponse }
        return String(pieces[1])
    }
    /// Onboarding sign-in: a fresh secret code, and the host's sign-in page that carries it (and this Mac's
    /// publishing key, which the wallet then authorizes) in its fragment.
    public func signInPage(publishingKey: String? = nil) -> (code: String, url: URL) {
        var generator = SystemRandomNumberGenerator()
        let code = (0..<32).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &generator)) }.joined()
        var components = URLComponents(url: site.appendingPathComponent("share/signin"), resolvingAgainstBaseURL: false)!
        components.fragment = publishingKey.map { code + "." + $0 } ?? code
        return (code, components.url!)
    }
    public struct SignedIn: Sendable { public let account: String; public let wallet: String?; public let macLinked: Bool }
    /// Who signed in with `code` (email or username, wallet, and whether this Mac may now share), or nil while waiting.
    public func signedIn(code: String) async throws -> SignedIn? {
        struct Body: Decodable { let status: String; let account: String?; let wallet: String?; let device: Bool? }
        let body = try JSONDecoder().decode(Body.self, from: try await request(path: "api/publications/signin", headers: ["X-Huma-Signin": code], limit: 4096))
        guard body.status == "signed-in" else { return nil }
        let wallet = body.wallet.flatMap { $0.range(of: "^0x[0-9a-fA-F]{40}$", options: .regularExpression) != nil ? $0 : nil }
        return SignedIn(account: body.account.flatMap { $0.isEmpty || $0.count > 200 ? nil : $0 } ?? "your account",
                        wallet: wallet, macLinked: body.device == true && wallet != nil)
    }
    /// Shares a prepared page without the browser: this Mac's publishing key signs the same statement the
    /// wallet would, and the host accepts it because the wallet authorized that key at sign-in.
    /// `profile` is the writer's name and face seed shown on the page ({"name", "avatar"}), if they chose one.
    public func publishFromThisMac(_ prepared: Prepared, wallet: String, publicKey: String, profile: [String: String]? = nil,
                                   sign: (String) throws -> String) async throws -> Download {
        struct Pending: Decodable { struct Manifest: Decodable { struct Master: Decodable { let hash: String }; let statementHash: String; let master: Master; let publicationNonce: String; let access: String }; let manifest: Manifest }
        let manifest = try JSONDecoder().decode(Pending.self, from: try await request(path: "api/publications/pending/" + prepared.id,
            token: prepared.ticket, limit: 128 * 1024)).manifest
        guard manifest.master.hash == prepared.expectedMasterHash, publicationHash(manifest.statementHash),
              publicationHash(manifest.publicationNonce), manifest.access == "link" else { throw HumaError.invalidResponse }
        let message = "Huma publication v2\nstatement \(manifest.statementHash)\nmaster \(manifest.master.hash)\nnonce \(manifest.publicationNonce)\naccess \(manifest.access)"
        var fields: [String: Any] = ["wallet": wallet, "publicKey": publicKey, "signature": try sign(message)]
        if let profile { fields["profile"] = profile }
        let body = try JSONSerialization.data(withJSONObject: fields)
        _ = try await request(path: "api/publications/pending/" + prepared.id + "/publish-device", body: body,
            headers: ["X-Huma-Ticket": prepared.ticket], limit: 128 * 1024)
        return try await waitForApproval(prepared)
    }
    /// Takes a link down, signed by this Mac's publishing key (only the Mac that shared it can). The page's text
    /// and proof are deleted from the host.
    public func remove(_ link: URL, publicKey: String, sign: (String) throws -> String) async throws {
        let id = try publicationID(link)
        let body = try JSONSerialization.data(withJSONObject: ["publicKey": publicKey, "signature": try sign("Huma remove v1\npublication \(id)")])
        _ = try await request(path: "api/publications/" + id + "/remove", body: body, limit: 4096)
    }
    /// Turns the page's replay on (with `replay`) or off (nil), signed by this Mac's publishing key: only the Mac
    /// that shared the page can. The host checks a replay is this page's before readers get it.
    public func setReplay(_ link: URL, replay: Data?, publicKey: String, sign: (String) throws -> String) async throws {
        let id = try publicationID(link)
        let message = "Huma replay v1\npublication \(id)\nreplay " + (replay.map(sha256) ?? "none")
        var fields: [String: Any] = ["publicKey": publicKey, "signature": try sign(message), "replay": NSNull()]
        if let replay { fields["replay"] = String(decoding: replay, as: UTF8.self) }
        _ = try await request(path: "api/publications/" + id + "/replay", body: try JSONSerialization.data(withJSONObject: fields), limit: 4096)
    }
    /// A writing request's title and who asked (huma.social/r/<id>).
    public func writingRequest(_ id: String) async throws -> WritingRequest {
        guard id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else { throw HumaError.invalidResponse }
        struct Body: Decodable { let title: String; let from: String }
        let body = try JSONDecoder().decode(Body.self, from: await request(path: "api/requests/" + id, limit: 8192))
        guard !body.title.isEmpty, body.title.count <= 120, !body.from.isEmpty, body.from.count <= 60 else { throw HumaError.invalidResponse }
        return WritingRequest(id: id, title: body.title, from: body.from)
    }
    /// Sends a shared page to a writing request, signed by this Mac's publishing key so the inbox shows it came from here.
    public func send(_ link: URL, to writingRequest: WritingRequest, sign: (String) throws -> String) async throws {
        let id = try publicationID(link)
        let body = try JSONSerialization.data(withJSONObject: ["link": link.absoluteString,
            "signature": try sign("Huma request v1\nrequest \(writingRequest.id)\npublication \(id)")])
        _ = try await request(path: "api/requests/" + writingRequest.id + "/submit", body: body, limit: 4096)
    }
    /// Who signed a published link, as the host says (its fragment is the access token).
    public func receipt(for link: URL) async throws -> Receipt {
        let id = try publicationID(link)
        struct Body: Decodable {
            struct Owner: Decodable { let wallet: String }
            let owner: Owner?
            let replay: Bool?
        }
        let data = try await request(path: "api/publications/" + id + "/receipt", token: link.fragment, limit: 32 * 1024)
        let body = try JSONDecoder().decode(Body.self, from: data)
        if let wallet = body.owner?.wallet, !(wallet.count == 42 && wallet.hasPrefix("0x")) { throw HumaError.invalidResponse }
        return Receipt(signer: body.owner?.wallet, replay: body.replay ?? false)
    }
    /// The page's short link, for sharing: the host works it out from the full link's token, so it's the same each time.
    public func shortLink(for link: URL) async throws -> URL {
        let id = try publicationID(link)
        struct Body: Decodable { let path: String }
        let body = try JSONDecoder().decode(Body.self, from: await request(path: "api/publications/" + id + "/short", token: link.fragment,
            body: Data("{}".utf8), limit: 4096))
        guard let url = shortURL(body.path) else { throw HumaError.invalidResponse }
        return url
    }
    /// A short link's path from the host ("/p/<code>#<key>", or no key for a public page) on this site.
    func shortURL(_ path: String) -> URL? {
        guard path.range(of: "^/p/[A-Za-z0-9]{8,12}(#[A-Za-z0-9]{16})?$", options: .regularExpression) != nil,
              var components = URLComponents(url: site, resolvingAgainstBaseURL: false) else { return nil }
        let pieces = path.split(separator: "#", maxSplits: 1)
        components.path = String(pieces[0]); components.fragment = pieces.count == 2 ? String(pieces[1]) : nil
        return components.url
    }
}

private func publicationHash(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
