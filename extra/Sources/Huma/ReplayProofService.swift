import Foundation
import HumaCore

struct ReplayAssurance: Decodable, Sendable {
    struct Input: Decodable, Sendable { var hidStateReported: Int; var otherStateReported: Int; var missingOrigin: Int }
    struct Presence: Decodable, Sendable {
        var challenges: Int; var onTime: Int; var missed: Int
        var longestGapMilliseconds: String; var medianResponseMilliseconds: String?
    }
    struct Behavior: Decodable, Sendable { var policyID: String; var experimental: Bool; var satisfied: Bool }
    var input: Input; var presence: Presence?; var behavior: Behavior
}

enum VerifiedWritingProof: Sendable {
    case noir(NoirWritingProofResult)
    var assurance: ReplayAssurance? {
        switch self {
        case .noir(let result):
            let j = result.report.proofReport.journal
            return ReplayAssurance(input: .init(hidStateReported: j.origin_hid,
                otherStateReported: j.origin_present - j.origin_hid, missingOrigin: j.sampleCount - j.origin_present),
                presence: .init(challenges: j.presence_count, onTime: j.on_time, missed: j.missed,
                    longestGapMilliseconds: j.longest_gap, medianResponseMilliseconds: j.median_response),
                behavior: .init(policyID: "huma-writing-rules-v1", experimental: true, satisfied: j.policy_satisfied))
        }
    }
}

struct ReplayProofService: Sendable {
    static func noirService() throws -> NoirWritingProofService {
        guard let resources = Bundle.main.resourceURL else { throw HumaError.invalidResponse }
        return NoirWritingProofService(engineURL: resources.appendingPathComponent("NoirEngine"))
    }
    static func prove(_ draft: Draft) async throws -> Data {
        try await proveValidated(draft).proof
    }
    /// Where a finished proof was made. Server proofs were verified on this Mac before being returned.
    enum Source: Sendable { case mac, server, macAfterServer(String) }
    /// Proves on this Mac, or on the Huma prover when the writer chose it. A prover that is
    /// unreachable or busy falls back to this Mac, which never sends anything further.
    static func proveValidated(_ draft: Draft, prover: RemoteProver? = nil) async throws -> (proof: Data, journal: VerifiedWritingProof, source: Source) {
        guard draft.session.presenceProtocol == "local-presence-v1" else {
            throw HumaError.configuration("Record and seal this draft before creating a proof.")
        }
        var source = Source.mac
        if let prover {
            do {
                let result = try await noirService().prove(draft, using: prover)
                return (result.proof, .noir(result), .server)
            } catch is CancellationError { throw CancellationError() }
            catch { try Task.checkCancellation(); source = .macAfterServer(error.localizedDescription) }
        }
        let result = try await noirService().prove(draft)
        return (result.proof, .noir(result), source)
    }
    static func verify(draft: Draft, proof: Data) async throws -> VerifiedWritingProof {
        guard NoirWritingProofService.isNoirProof(proof) else {
            throw HumaError.configuration("This test proof uses an earlier format. Create a new recording with the current app.")
        }
        return .noir(try await noirService().verify(draft, proof: proof))
    }
    /// Wraps an already verified Noir export; never signs or re-attests it.
    static func evidenceEnvelope(draft: Draft, proof: Data) async throws -> EvidenceEnvelope {
        let verified = try await verify(draft: draft, proof: proof)
        switch verified {
        case .noir(let result): return result.envelope
        }
    }
}
