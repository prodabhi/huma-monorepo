import Foundation

/// V4 and V5 profiles share the signed capture construction and its Poseidon commitments. It is never decoded
/// as a legacy SHA-256 replay journal or used as legacy device evidence.
public struct NoirWritingProofResult: Sendable {
    public let proof: Data
    public let envelope: EvidenceEnvelope
    public let report: Report
    public let elapsedMilliseconds: Double
    public let serviceMilliseconds: Double
    public let timings: [String: Double]
    public struct Report: Decodable, Sendable {
        public let verified: Bool
        public let statement: EvidenceStatement
        public let statementHash: String
        public let proofReport: ProofReport
    }
    public struct ProofReport: Decodable, Sendable {
        public let version: Int?
        public let profile: String
        public let proofIdentity: String
        public let keyHash: String
        public let signaturesVerified: Int
        public let presenceSignaturesVerified: Int
        public let journal: Journal
    }
    public struct Journal: Decodable, Sendable {
        public struct Replay: Decodable, Sendable { public let samples: Int }
        // Short proofs nest the replay counters; long proofs report them directly.
        public let replay: Replay?
        public let samples: Int?
        public var sampleCount: Int { replay?.samples ?? samples ?? 0 }
        public let origin_present: Int
        public let origin_hid: Int
        public let presence_count: Int
        public let on_time: Int
        public let missed: Int
        public let median_response: String
        public let longest_gap: String
        public let policy_satisfied: Bool
    }
}

public struct NoirWritingProofService: Sendable {
    public static let proofKind = "huma-compact-assurance-public-proof-v4"
    public static let optimizedProofKind = "huma-compact-assurance-public-proof-v5"
    public static let longProofKind = "huma-long-assurance-public-proof-v1"
    /// 0.1's one proof per page: parts folded while writing, every capture signature checked in-circuit. Read only.
    public static let foldedProofKind = "huma-long-assurance-public-proof-v2"
    /// Every page proof made now: each part proved on its own while writing, plus the final step, at the text's tier.
    public static let pageProofKind = "huma-long-assurance-public-proof-v3"
    public let engineURL: URL
    public init(engineURL: URL) { self.engineURL = engineURL }
    public static func isNoirProof(_ proof: Data) -> Bool {
        guard proof.count <= EvidenceEnvelope.maximumBytes, let object = try? JSONSerialization.jsonObject(with: proof) as? [String: Any] else { return false }
        let kind = object["kind"] as? String ?? ""
        return [longProofKind, foldedProofKind, pageProofKind].contains(kind) || (proof.count <= 65_536 && [proofKind,optimizedProofKind].contains(kind))
    }
    static func isLongProof(_ proof: Data) -> Bool {
        isNoirProof(proof) && [longProofKind, foldedProofKind, pageProofKind].contains(((try? JSONSerialization.jsonObject(with: proof) as? [String: Any])?["kind"] as? String) ?? "")
    }
    /// Uses the long-session proof (parts and a final step) whenever that capture exists.
    /// The single short proof remains for recordings without it.
    public static func isLongSession(_ draft: Draft) -> Bool { draft.session.longCompactSnapshot != nil }
    /// Seconds still needed at Finish: unproved parts plus the final step, on the Finish thread count.
    public static func estimatedLongSeconds(_ draft: Draft) -> Double {
        finishSeconds(missingParts: max(0, longChunkCount(draft) - (draft.session.longChunkProofs?.count ?? 0)),
                      characters: draft.text.unicodeScalars.count, tier: draft.session.longChunkProofs?.first?.tier)
    }
    /// `tier` is the session's text tier when known: the final step is sized by the longest the text has been.
    public static func finishSeconds(missingParts: Int, characters: Int, tier: Int? = nil) -> Double {
        finishingScale * (Double(missingParts) * partSeconds + finalSeconds(characters: max(characters, tier ?? 0))) + 1
    }
    /// Measured: a part takes 1.75 / 1.06 / 0.69 s to prove on 2 / 4 / 8 threads, about (threads / 2)^-0.7.
    public static var finishingScale: Double { pow(Double(LocalProofWorker.finishingThreads()) / 2, -0.7) }
    /// Seconds for the single short proof at its 64 / 128 / larger tiers.
    public static func shortSeconds(characters: Int) -> Double { characters <= 64 ? 3 : characters <= 128 ? 6 : 11 }
    /// A 600-operation part on two threads: about 0.6 s to build its witness and 5.5 s to prove it (1,024 tier).
    public static let partSeconds: Double = 6
    /// The final step on two threads at the 1,024 / 4,096 / 10,000-character tiers: 205k / 486k / 1.03M gates
    /// (measured 1.2 s + 1.95 s at 1,024; the others scaled by size).
    public static func finalSeconds(characters: Int) -> Double { characters <= 1024 ? 3 : characters <= 4096 ? 7 : 14 }
    /// Proves one closed part of a long session in the background, on its own (no other proof goes in).
    /// `input` is private and never stored; `tier` is the text tier it was made for.
    public func proveChunk(_ input: Data, index: Int, tier: Int) async throws -> LongChunkProof {
        guard index >= 0, [1024, 4096, 10000].contains(tier) else { throw HumaError.invalidSession }
        try requireEngine()
        let work = try workspace()
        defer { try? FileManager.default.removeItem(at: work) }
        struct Request: Encodable { var command = "chunk"; var input: Data; var workDirectory: String }
        struct Response: Decodable { var ok: Bool; var proof: String; var publicInputs: String; var tier: Int }
        let response = try JSONDecoder().decode(Response.self, from: try await worker(JSONEncoder().encode(
            Request(input: input, workDirectory: work.path)), timeout: 120, proving: true))
        guard response.ok, response.tier == tier, Data(base64Encoded: response.proof)?.count == 14_656,
              Data(base64Encoded: response.publicInputs)?.count == 96 else { throw HumaError.invalidResponse }
        return LongChunkProof(index: index, proof: response.proof, publicInputs: response.publicInputs, tier: tier)
    }
    private func requireEngine() throws {
        let runtime = [scriptHost.path, engineURL.appendingPathComponent("node").path].contains { FileManager.default.isExecutableFile(atPath: $0) }
        guard runtime, ["bb", "capture-input", "witness"].allSatisfy({ FileManager.default.isExecutableFile(atPath: engineURL.appendingPathComponent($0).path) }) else {
            throw HumaError.configuration("The local Noir engine is not bundled. Rebuild Huma with its proof assets.")
        }
    }
    /// Release engines run the worker on macOS's own JavaScriptCore (extra/Sources/HumaScriptHost); engines that still
    /// carry Node.js (older builds, the server prover) run it there.
    private var scriptHost: URL { engineURL.appendingPathComponent("HumaScriptHost") }
    /// Removes proof workspaces (they hold private writing history) left behind when Huma quit mid-proof. Ones
    /// changed in the last ten minutes are kept, in case another Huma process is still using them.
    public static func removeLeftoverWorkspaces() {
        let files = FileManager.default, temporary = files.temporaryDirectory
        for name in (try? files.contentsOfDirectory(atPath: temporary.path)) ?? [] where name.hasPrefix("huma-noir-") {
            let folder = temporary.appendingPathComponent(name, isDirectory: true)
            let changed = (try? files.attributesOfItem(atPath: folder.path)[.modificationDate] as? Date) ?? .distantFuture
            if changed < Date(timeIntervalSinceNow: -600) { try? files.removeItem(at: folder) }
        }
    }
    private func workspace() throws -> URL {
        let work = FileManager.default.temporaryDirectory.appendingPathComponent("huma-noir-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return work
    }
    private func worker(_ request: Data, timeout: TimeInterval, proving: Bool, waiting: Bool = false) async throws -> Data {
        try await ProvingSetup.shared.ready(engine: engineURL)
        let runtime = FileManager.default.isExecutableFile(atPath: scriptHost.path)
            ? [scriptHost.path, engineURL.appendingPathComponent("worker.js").path]
            : [engineURL.appendingPathComponent("node").path, "--no-addons", "--disable-proto=throw", "--max-old-space-size=2048",
               engineURL.appendingPathComponent("worker.mjs").path]
        return try await LocalProofWorker.run(executable: URL(fileURLWithPath: "/usr/bin/sandbox-exec"),
            arguments: ["-p", "(version 1)(allow default)(deny network-outbound)"] + runtime,
            request: request, timeout: timeout, workload: !proving ? .standard : waiting ? .finishing : .proving)
    }
    public func prove(_ draft: Draft) async throws -> NoirWritingProofResult { try await run(draft, proof: nil) }
    public func verify(_ draft: Draft, proof: Data) async throws -> NoirWritingProofResult { try await run(draft, proof: proof) }
    /// Proves on a Huma prover the user chose, then verifies the result here exactly like an imported proof.
    /// The prover receives the same private request this Mac's worker would; nothing it returns is trusted unchecked.
    public func prove(_ draft: Draft, using prover: RemoteProver) async throws -> NoirWritingProofResult {
        let prepared = try Self.prepare(draft, proof: nil)
        let proof = try await prover.prove(command: prepared.long ? "prove-long" : "prove", input: prepared.input, chunkProofs: prepared.cached)
        guard Self.isNoirProof(proof) else { throw HumaError.invalidResponse }
        return try await verify(draft, proof: proof)
    }

    private struct Prepared { var summary: SignedSessionSummary; var long: Bool; var input: Data; var cached: [LongChunkProof?]? }
    /// The validated private worker input for a draft, and the parts already proved while writing.
    private static func prepare(_ draft: Draft, proof: Data?) throws -> Prepared {
        try draft.validate()
        try draft.session.validateSignedCheckpoints(requireFinal: true, finalText: draft.text)
        let summary = try draft.session.signedSummary(finalText: draft.text)
        if let proof, !isNoirProof(proof) { throw HumaError.invalidDocument }
        let long = proof.map(isLongProof) ?? isLongSession(draft)
        let input = try long ? longInput(draft) : completeInput(draft)
        var cached: [LongChunkProof?]?
        if long && proof == nil {
            var aligned = [LongChunkProof?](repeating: nil, count: longChunkCount(draft))
            for chunk in draft.session.longChunkProofs ?? [] where aligned.indices.contains(chunk.index) { aligned[chunk.index] = chunk }
            cached = aligned
        }
        return Prepared(summary: summary, long: long, input: input, cached: cached)
    }

    private func run(_ draft: Draft, proof: Data?) async throws -> NoirWritingProofResult {
        let started = ContinuousClock.now
        let prepared = try Self.prepare(draft, proof: proof)
        let (summary, long, input, cached) = (prepared.summary, prepared.long, prepared.input, prepared.cached)
        try requireEngine()
        let work = try workspace()
        // Parent cleanup also runs after the complete owned child group is killed.
        defer { try? FileManager.default.removeItem(at: work) }
        struct Request: Encodable { var command: String; var input: Data; var proof: String?; var workDirectory: String; var chunkProofs: [LongChunkProof?]? }
        let missing = cached.map { $0.filter { $0 == nil }.count } ?? 0
        let request = Request(command: proof == nil ? (long ? "prove-long" : "prove") : "verify", input: input,
            proof: proof.flatMap { String(data: $0, encoding: .utf8) }, workDirectory: work.path, chunkProofs: cached)
        // About 3 s per remaining part and up to 14 s for the final step on two threads; verification is fast.
        let timeout: TimeInterval = proof == nil ? (long ? 120 + 10 * Double(missing) : 180) : (long ? 300 : 30)
        let response = try await worker(JSONEncoder().encode(request), timeout: timeout, proving: proof == nil, waiting: true)
        struct Response: Decodable {
            var ok: Bool; var proof: String; var envelope: String; var report: NoirWritingProofResult.Report
            var elapsedMs: Double; var backend: String
            var timings: [String: Double]?
        }
        let value = try JSONDecoder().decode(Response.self, from: response)
        let envelope = try EvidenceEnvelope.decode(Data(value.envelope.utf8))
        let version = value.report.proofReport.version
        // New long proofs are always v3; proofs made before it (v1, v2) still verify.
        let backendOK = long ? (value.backend == "noir-long-v3" || (proof != nil && ["noir-long-v1", "noir-long-v2"].contains(value.backend))) && version == nil
            : version.map { [4,5].contains($0) && value.backend == "noir-assurance-v\($0)" } ?? false
        guard value.ok, backendOK, value.report.verified,
              value.report.statement.captureScheme == (long ? "poseidon2-capture-long-v1" : "poseidon2-capture-v4"),
              value.report.statement.captureKeyHash == summary.captureKeyHash,
              value.report.proofReport.keyHash == summary.captureKeyHash,
              value.report.statement.contentHash == sha256(Data(VerificationText.canonical(draft.text).utf8)),
              envelope.statement == value.report.statement, try envelope.statement.digest() == value.report.statementHash,
              envelope.proof == value.proof, Self.isNoirProof(Data(value.proof.utf8)) else { throw HumaError.invalidSession }
        let duration = started.duration(to: .now).components
        return NoirWritingProofResult(proof: Data(value.proof.utf8), envelope: envelope,
            report: value.report, elapsedMilliseconds: value.elapsedMs,
            serviceMilliseconds: Double(duration.seconds)*1_000 + Double(duration.attoseconds)/1e15,
            timings: value.timings ?? [:])
    }
    public static func longChunkCount(_ draft: Draft) -> Int {
        struct Header: Decodable { struct Result: Decodable { var chunks: Int }; var result: Result }
        guard let snapshot = draft.session.longCompactSnapshot,
              let count = try? JSONDecoder().decode(Header.self, from: snapshot).result.chunks, (1...2048).contains(count) else { return 0 }
        return count
    }
    /// The long-session counterpart of `completeInput`: the complete signed session and its sealed long capture.
    static func longInput(_ draft: Draft) throws -> Data {
        guard draft.session.presenceProtocol == "local-presence-v1", let snapshot = draft.session.longCompactSnapshot,
              snapshot.count <= 40 * 1024 * 1024 else {
            throw HumaError.configuration("This recording has no complete long-session capture. Its history is saved; start a new recording to prove it.")
        }
        struct Header: Decodable {
            struct Result: Decodable { var profile: String; var sealed: Bool; var format: String? }
            var ok: Bool; var result: Result
        }
        let header = try JSONDecoder().decode(Header.self, from: snapshot)
        guard header.ok, header.result.profile == "assurance-long-v1", header.result.sealed else { throw HumaError.invalidSession }
        // Recordings from Huma 0.1 (no format) need the earlier page proof, which this version no longer makes.
        guard header.result.format == "v3" else {
            throw HumaError.configuration("This page was written with an earlier version of Huma and can’t be processed now. Your text is unchanged.")
        }
        return try splice(draft, snapshot: snapshot, limit: 48 * 1024 * 1024)
    }
    private static func splice(_ draft: Draft, snapshot: Data, limit: Int) throws -> Data {
        struct Witness: Encodable { var text: String; var session: SessionLog }
        var session = draft.session
        session.experimentalCompactSnapshot = nil; session.longCompactSnapshot = nil; session.longChunkProofs = nil
        let witness = try JSONEncoder().encode(Witness(text: draft.text, session: session))
        var result = Data("{\"witness\":".utf8); result.append(witness)
        result.append(Data(",\"snapshot\":".utf8)); result.append(snapshot); result.append(Data("}".utf8))
        guard result.count <= limit else { throw HumaError.invalidSession }
        return result
    }
    /// Splice two already encoded JSON objects so private UInt64 values never
    /// pass through Foundation/JavaScript floating-point object conversions.
    static func completeInput(_ draft: Draft) throws -> Data {
        guard draft.session.presenceProtocol == "local-presence-v1", let snapshot = draft.session.experimentalCompactSnapshot,
              snapshot.count <= 2 * 1024 * 1024 else {
            throw HumaError.configuration("This recording has no complete Noir snapshot. Its history is saved; start a new short recording to use the current prover.")
        }
        struct Header: Decodable {
            struct Result: Decodable { var profile: String; var sealed: Bool }
            var ok: Bool; var result: Result
        }
        let header = try JSONDecoder().decode(Header.self, from: snapshot)
        guard header.ok, ["assurance256-v1","assurance256-cp32-v1"].contains(header.result.profile), header.result.sealed else { throw HumaError.invalidSession }
        return try splice(draft, snapshot: snapshot, limit: 4 * 1024 * 1024)
    }
}
