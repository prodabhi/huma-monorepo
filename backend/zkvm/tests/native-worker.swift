import Foundation
import HumaCore

// Runs the same Mac service adapters in a minimal app bundle using public test fixtures.
@main struct NativeWorkerProbe {
    struct Witness: Decodable { var text: String; var session: SessionLog }
    static func main() async {
        do { try await check() }
        catch { print("Native service probe failed: \(String(reflecting: error))"); exit(1) }
    }
    static func check() async throws {
        let source = URL(fileURLWithPath: CommandLine.arguments[1])
        let witness = try JSONDecoder().decode(Witness.self, from: Data(contentsOf: source))
        var draft = Draft(); draft.text = witness.text; draft.session = witness.session
        print("Native replay service starting; resources: \(Bundle.main.resourceURL?.lastPathComponent ?? "missing")")
        let proof: Data
        if CommandLine.arguments.count > 3 {
            let cached = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[3]))) as! [String: Any]
            proof = try JSONSerialization.data(withJSONObject: cached["bundle"]!)
            print("Using an existing proof fixture; no new proof is generated")
        } else { proof = try await ReplayProofService.prove(draft) }
        print("Replay receipt obtained")
        draft.replayProof = proof; draft.replayProofTextHash = sha256(Data(draft.text.utf8))
        let restored = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(draft))
        try restored.validate()
        print("Document round-trip validated")
        guard case .riscZero(let journal) = try await ReplayProofService.verify(draft: restored, proof: proof) else { throw HumaError.invalidResponse }
        guard journal.deviceReportedTime == (try restored.session.signedSummary(finalText: restored.text)).deviceReportedTime else { throw HumaError.invalidResponse }
        if let registry = ProcessInfo.processInfo.environment["HUMA_TEST_REGISTRY"] {
            let upload = try await ProofRegistryClient(url: registry).store(text: restored.text, proof: proof)
            _ = try await ReplayProofService.verify(draft: restored, proof: upload.proof)
            var fetched = restored; fetched.replayProof = upload.proof
            guard try AppAttestBinding(draft: fetched) == AppAttestBinding(draft: restored) else { throw HumaError.invalidResponse }
            var linked = restored
            linked.publicProof = PublicProofLink(url: upload.url, proof: proof, draft: restored)
            let reopened = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(linked))
            guard reopened.publicProof?.matches(reopened) == true else { throw HumaError.invalidResponse }
            try linked.updateText(linked.text + "!", source: "typing", elapsed: 16)
            guard linked.publicProof == nil else { throw HumaError.invalidResponse }
            print("PASS: native registry upload, content-hash fetch, replay re-verification, persisted link and edit invalidation")
            print("Shared replay reader: \(upload.url.absoluteString)")
            try Data(upload.url.absoluteString.utf8).write(to: URL(fileURLWithPath: CommandLine.arguments[2]).deletingLastPathComponent().appendingPathComponent("Huma-shared-proof-url.txt"), options: .atomic)
        }
        let binding = try AppAttestBinding(draft: restored)
        guard binding.version == 2, binding.proofHash == (try ReplayProofIdentity(proof: proof)).value,
              try AppAttestBinding(draft: restored, useLegacyProofHash: true).proofHash == sha256(proof) else { throw HumaError.invalidResponse }
        let output = URL(fileURLWithPath: CommandLine.arguments[2])
        let data = try JSONSerialization.data(withJSONObject: ["text": restored.text,
            "bundle": try JSONSerialization.jsonObject(with: proof)], options: [.sortedKeys])
        try data.write(to: output, options: .atomic)
        let envelope = try await ReplayProofService.evidenceEnvelope(draft: restored, proof: proof)
        let envelopeData = try envelope.encoded()
        guard try EvidenceEnvelope.decode(envelopeData) == envelope else { throw HumaError.invalidResponse }
        let envelopeOutput = output.deletingPathExtension().appendingPathExtension("evidence.json")
        try envelopeData.write(to: envelopeOutput, options: .atomic)
        print("Portable evidence export: \(envelopeData.count) bytes; statement \(try envelope.statement.digest())")
        if let host = ProcessInfo.processInfo.environment["HUMA_TEST_PUBLICATION"] {
            let client = try HostedPublicationClient(url: host)
            let prepared = try await client.prepare(text: restored.text, envelope: envelope)
            // The local test harness approves this disposable request. The
            // production client only waits; it never approves for the user.
            print("Publication fixture approval: \(prepared.approvalURL.absoluteString)")
            fflush(stdout)
            let download = try await client.waitForApproval(prepared)
            guard exactTextEqual(String(decoding: download.master, as: UTF8.self), restored.text),
                  download.envelope.statement == envelope.statement,
                  let record = try JSONSerialization.jsonObject(with: Data(download.envelope.proof.utf8)) as? [String: Any],
                  let bundle = record["bundle"] else { throw HumaError.invalidResponse }
            _ = try await ReplayProofService.verify(draft: restored, proof: JSONSerialization.data(withJSONObject: bundle))
            var shared = restored
            shared.publicProof = PublicProofLink(url: download.url, proof: proof, draft: restored)
            let reopened = try JSONDecoder().decode(Draft.self, from: JSONEncoder().encode(shared))
            guard reopened.publicProof?.matches(reopened) == true else { throw HumaError.invalidResponse }
            try shared.updateText(shared.text + "!", source: "typing", elapsed: 16)
            guard shared.publicProof == nil else { throw HumaError.invalidResponse }
            print("PASS: native master/proof prepare, simulated approval, download, exact file hashes, RISC Zero re-verification, saved link and edit invalidation")
        }
        var polluted = try JSONSerialization.jsonObject(with: proof) as! [String: Any]
        var receipt = polluted["receipt"] as! [String: Any]
        receipt["privateHistory"] = "PRIVATE-NATIVE-MARKER"; polluted["receipt"] = receipt
        let cleaned = try await ReplayProofService.evidenceEnvelope(draft: restored,
            proof: JSONSerialization.data(withJSONObject: polluted))
        guard !cleaned.proof.contains("PRIVATE-NATIVE-MARKER"), cleaned.statement == envelope.statement else { throw HumaError.invalidResponse }
        print("PASS: native replay verification, document round-trip, signed time, evidence export and attestation binding")
        print("Public replay export: \(data.count) bytes")
    }
}
