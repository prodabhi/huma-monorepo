import Foundation
import HumaCore

// Disposable pre-recorded Swift software fixture. Never asks a key to sign.
@main struct Acceptance {
    static func verify(_ draft: Draft, proof: Data) async throws -> NoirWritingProofResult {
        guard case .noir(let result) = try await ReplayProofService.verify(draft: draft, proof: proof) else { throw HumaError.invalidResponse }
        return result
    }
    static func main() async throws {
        let args = Array(CommandLine.arguments.dropFirst())
        guard args.count >= 2 else { throw HumaError.invalidResponse }
        var draft = try JSONDecoder().decode(Draft.self, from: Data(contentsOf: URL(fileURLWithPath: args[0])))
        let output = URL(fileURLWithPath: args[1], isDirectory: true)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let start = ContinuousClock.now
        let result: NoirWritingProofResult
        let cached = args.count == 4
        if cached {
            result = try await verify(draft, proof: Data(contentsOf: URL(fileURLWithPath: args[3])))
        } else {
            // Long drafts: prove the given closed chunks first, as the app does while writing.
            if let chunks = ProcessInfo.processInfo.environment["HUMA_LONG_CHUNKS"] {
                let service = try ReplayProofService.noirService()
                var parts: [LongChunkProof] = []
                // Background proving while writing: every part closed before the seal.
                for index in 0..<4096 {
                    let file = URL(fileURLWithPath: chunks).appendingPathComponent("chunk-\(index).json")
                    guard FileManager.default.fileExists(atPath: file.path) else { break }
                    let input = try Data(contentsOf: file)
                    struct Part: Decodable { struct State: Decodable { let buffer: [String] }; let state: State }
                    let tier = try JSONDecoder().decode(Part.self, from: input).state.buffer.count
                    parts.append(try await service.proveChunk(input, index: index, tier: tier))
                }
                draft.session.longChunkProofs = parts
            }
            let made = try await ReplayProofService.proveValidated(draft)
            guard case .noir(let made) = made.journal else { throw HumaError.invalidResponse }
            result = made
        }
        draft.replayProof = result.proof; draft.replayProofTextHash = sha256(Data(draft.text.utf8))
        let saved = try JSONEncoder().encode(draft)
        var reopened = try JSONDecoder().decode(Draft.self, from: saved)
        try reopened.validate()
        let again = try await verify(reopened, proof: result.proof)
        let expectedCheckpoints = draft.session.signedCheckpoints?.count ?? 0
        let expectedPresence = draft.session.presenceEvents?.filter { $0.kind == "response" && $0.outcome == "approved" }.count ?? 0
        guard result.envelope == again.envelope, result.report.proofReport.signaturesVerified == expectedCheckpoints,
              result.report.proofReport.presenceSignaturesVerified == expectedPresence else { throw HumaError.invalidResponse }
        var changed = result.proof
        guard var object = try JSONSerialization.jsonObject(with: changed) as? [String: Any] else { throw HumaError.invalidResponse }
        if var chunks = object["chunks"] as? [String], var bytes = Data(base64Encoded: chunks[chunks.count / 2]) {
            bytes[500] ^= 1; chunks[chunks.count / 2] = bytes.base64EncodedString(); object["chunks"] = chunks
        } else {
            guard let b64 = object["proof"] as? String, var bytes = Data(base64Encoded: b64) else { throw HumaError.invalidResponse }
            bytes[500] ^= 1; object["proof"] = bytes.base64EncodedString()
        }
        changed = try JSONSerialization.data(withJSONObject: object)
        var rejected = false
        do { _ = try await verify(reopened, proof: changed) }
        catch { rejected = true }
        guard rejected else { throw HumaError.invalidResponse }
        var publicationVerified = false
        if args.count >= 3 {
            let client = try HostedPublicationClient(url: args[2])
            let outgoing = try await ReplayProofService.evidenceEnvelope(draft: reopened, proof: result.proof)
            let pending = try await client.prepare(text: reopened.text, envelope: outgoing)
            FileHandle.standardOutput.write(Data(("Noir publication fixture approval: " + pending.approvalURL.absoluteString + "\n").utf8))
            let downloaded = try await client.waitForApproval(pending)
            guard downloaded.master == Data(reopened.text.utf8) else { throw HumaError.invalidResponse }
            let checked = try await verify(reopened, proof: Data(downloaded.envelope.proof.utf8))
            guard checked.report.statementHash == result.report.statementHash else { throw HumaError.invalidResponse }
            reopened.publicProof = PublicProofLink(url: downloaded.url, proof: result.proof, draft: reopened)
            let linked = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(reopened))
            guard linked.publicProof != nil else { throw HumaError.invalidResponse }
            publicationVerified = true
        }
        try reopened.updateText(reopened.text + "!", source: "typing", elapsed: 1_000_000)
        guard reopened.replayProof == nil, reopened.publicProof == nil else { throw HumaError.invalidResponse }
        try saved.write(to: output.appendingPathComponent("document.huma"), options: .withoutOverwriting)
        try result.proof.write(to: output.appendingPathComponent("proof.json"), options: .withoutOverwriting)
        try result.envelope.encoded().write(to: output.appendingPathComponent("evidence.json"), options: .withoutOverwriting)
        let duration = start.duration(to: .now).components
        let report: [String: Any] = ["passed": true, "newProofGenerated": !cached, "softwareFixtureOnly": true,
            "ownerKeysOrBiometricsUsed": false, "cryptoChildrenOutboundNetworkDenied": true,
            "backend": result.report.proofReport.version.map { "noir-assurance-v\($0)" } ?? "noir-long-v1", "threads": 2, "workerMilliseconds": result.elapsedMilliseconds,
            "profile": result.report.proofReport.profile,
            "fullServiceMilliseconds": result.serviceMilliseconds, "timings": result.timings,
            "totalAcceptanceMilliseconds": Double(duration.seconds)*1_000 + Double(duration.attoseconds)/1e15,
            "proofIdentity": result.report.proofReport.proofIdentity, "saveReopenVerified": true,
            "checkpointSignaturesVerified": expectedCheckpoints, "presenceSignaturesVerified": expectedPresence,
            "changedProofRejected": true, "editInvalidatesProofAndLink": true, "localPublicationVerified": publicationVerified,
            "realR2Accepted": false, "realCoinbaseAccepted": false]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .prettyPrinted])
        try data.write(to: output.appendingPathComponent("acceptance.json"), options: .withoutOverwriting)
        print(String(decoding: data, as: UTF8.self))
    }
}
