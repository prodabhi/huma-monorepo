import Foundation

/// A finished, verified version of a page, kept when writing continues. Its signed session
/// stays in `priorSessions`; the verification file and any published link stay here.
public struct PageVersion: Codable, Sendable, Identifiable {
    public var id: String { sessionID }
    public let sessionID: String
    public let title: String
    public let text: String
    public let proof: Data
    public let publicProof: PublicProofLink?
    public let finishedAt: Date?
}

/// A writing request this page answers (huma.social/r/<id>): who asked, and the link it was sent with, once sent.
public struct WritingRequest: Codable, Sendable, Equatable {
    public let id: String
    public let title: String
    public let from: String
    public var sentLink: URL?
    public init(id: String, title: String, from: String) { self.id = id; self.title = title; self.from = from }
}

public struct Draft: Codable, Sendable {
    public var version = 1
    public var title = "Untitled"
    public var text = ""
    public var richText: Data?
    public var session = SessionLog()
    public var priorSessions: [SessionLog]? = []
    public var deviceEvidence: AppAttestEvidence?
    public var replayProof: Data?
    public var replayProofTextHash: String?
    public var publicProof: PublicProofLink?
    public var versions: [PageVersion]? = []
    public var request: WritingRequest?

    public init() {}

    private enum CodingKeys: String, CodingKey {
        case version, title, text, richText, session, priorSessions, deviceEvidence,
             replayProof, replayProofTextHash, publicProof, versions, request
    }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        title = try values.decode(String.self, forKey: .title)
        text = try values.decode(String.self, forKey: .text)
        richText = try values.decodeIfPresent(Data.self, forKey: .richText)
        session = try values.decode(SessionLog.self, forKey: .session)
        priorSessions = try values.decodeIfPresent([SessionLog].self, forKey: .priorSessions)
        replayProof = try values.decodeIfPresent(Data.self, forKey: .replayProof)
        replayProofTextHash = try values.decodeIfPresent(String.self, forKey: .replayProofTextHash)
        // Retired compact proofs are ignored when opening old documents. Preserve
        // their writing/history, but never display their device evidence as replay evidence.
        deviceEvidence = replayProof == nil ? nil : try values.decodeIfPresent(AppAttestEvidence.self, forKey: .deviceEvidence)
        publicProof = replayProof == nil ? nil : try values.decodeIfPresent(PublicProofLink.self, forKey: .publicProof)
        versions = try values.decodeIfPresent([PageVersion].self, forKey: .versions)
        request = try values.decodeIfPresent(WritingRequest.self, forKey: .request)
    }

    /// Before continuing a page, keep its current verified version (text, verification, link).
    public mutating func keepVerifiedVersion() {
        guard let proof = replayProof, replayProofTextHash == sha256(Data(text.utf8)),
              session.signedCheckpoints?.last?.isFinal == true,
              !(versions ?? []).contains(where: { $0.sessionID == session.id }) else { return }
        let finished = session.signedCheckpoints?.last?.reportedTime.map { Date(timeIntervalSince1970: Double($0.unixMilliseconds) / 1_000) }
        if versions == nil { versions = [] }
        versions!.append(PageVersion(sessionID: session.id, title: title, text: text, proof: proof,
                                     publicProof: publicProof, finishedAt: finished))
    }
    /// A read-only page for one earlier version, for checking or exporting its verification.
    public func draft(for version: PageVersion) -> Draft? {
        guard let session = priorSessions?.first(where: { $0.id == version.sessionID }) else { return nil }
        var value = Draft()
        value.title = version.title; value.text = version.text; value.session = session
        value.replayProof = version.proof; value.replayProofTextHash = sha256(Data(version.text.utf8))
        return value
    }

    public mutating func updateText(_ value: String, source: String, elapsed: UInt64) throws {
        guard !exactTextEqual(text, value) else { return }
        try session.record(before: text, after: value, source: source, elapsed: elapsed)
        text = value
        deviceEvidence = nil
        replayProof = nil; replayProofTextHash = nil; publicProof = nil
    }

    public func validate() throws {
        guard version == 1 else { throw HumaError.unsupportedVersion }
        try session.validate(finalText: text)
        if !(session.signedCheckpoints?.isEmpty ?? true) {
            try session.validateSignedCheckpoints(finalText: text)
        }
        if replayProof != nil, replayProofTextHash != sha256(Data(text.utf8)) { throw HumaError.invalidDocument }
        try deviceEvidence?.validate(draft: self)
    }
}
