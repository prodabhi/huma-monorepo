import Foundation
import CryptoKit

public struct CaptureRecord: Codable, Sendable {
    public var sequence: Int
    public var kind: String
    public var index: Int
    public var payloadHash: String
    public var previousHead: String
    public var head: String

    func digest() throws -> String {
        sha256(try JSONEncoder().encode([String(sequence), kind, String(index), payloadHash, previousHead]))
    }
}

public struct SignedCheckpoint: Codable, Sendable {
    public var version = 1
    public var kind = "unattested-p256"
    public var isFinal = false
    public var sessionID: String
    public var sequence: Int
    public var captureCount: Int
    public var editCount: Int
    public var sampleCount: Int
    public var captureHead: String
    public var editHead: String
    public var textHash: String
    public var previousCheckpoint: String
    public var challenge: String
    public var publicKey: Data
    public var signature: Data
    public var reportedTime: CaptureTime?

    public func payload() throws -> Data {
        guard (version == 1 && reportedTime == nil) || (version == 2 && reportedTime?.isValid == true) else {
            throw HumaError.invalidSession
        }
        var fields = ["huma-signed-checkpoint-v\(version)", kind, sessionID, String(sequence),
            String(isFinal), String(captureCount), String(editCount), String(sampleCount), captureHead, editHead,
            textHash, previousCheckpoint, challenge, publicKey.base64EncodedString()]
        if let time = reportedTime {
            fields += ["device-clock-v1", String(time.unixMilliseconds), String(time.elapsedMilliseconds)]
        }
        return try JSONEncoder().encode(fields)
    }
    public var digest: String {
        // Payload encoding cannot fail for strings; failed encoding invalidates the checkpoint.
        sha256(((try? payload()) ?? Data()) + signature)
    }
    public func verifySignature() -> Bool {
        guard [1, 2].contains(version), kind == "unattested-p256",
              let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              let bytes = try? payload() else { return false }
        return key.isValidSignature(sig, for: bytes)
    }
}

extension SessionLog {
    public var captureSeed: String { sha256(Data(("huma-capture-v1:" + id + ":" + initialHead).utf8)) }
    public var captureHead: String { captureRecords?.last?.head ?? captureSeed }

    public mutating func recordSample(_ sample: InputSample) throws {
        guard presenceEvents?.last?.kind != "challenge" else { throw HumaError.invalidSession }
        // Navigation/save keystrokes after a seal do not reopen an otherwise unchanged session.
        if let last = signedCheckpoints?.last, last.isFinal, last.editCount == events.count { return }
        if inputSamples == nil { inputSamples = [] }
        inputSamples!.append(sample)
        try appendCapture(kind: "key", index: inputSamples!.count - 1, payloadHash: sample.digest())
    }

    mutating func appendCapture(kind: String, index: Int, payloadHash: String) throws {
        experimentalCompactSnapshot = nil
        guard captureRecords != nil else { return }
        var record = CaptureRecord(sequence: captureRecords!.count, kind: kind, index: index,
                                   payloadHash: payloadHash, previousHead: captureHead, head: "")
        record.head = try record.digest()
        captureRecords!.append(record)
    }

    public func makeCheckpoint(text: String, publicKey: Data, challenge: String = "", final: Bool = false, reportedTime: CaptureTime? = nil) -> SignedCheckpoint {
        SignedCheckpoint(version: reportedTime == nil ? 1 : 2, isFinal: final, sessionID: id, sequence: signedCheckpoints?.count ?? 0,
                         captureCount: captureRecords?.count ?? 0, editCount: events.count,
                         sampleCount: inputSamples?.count ?? 0, captureHead: captureHead,
                         editHead: head, textHash: sha256(Data(text.utf8)),
                         previousCheckpoint: signedCheckpoints?.last?.digest ?? "", challenge: challenge,
                         publicKey: publicKey, signature: Data(), reportedTime: reportedTime)
    }

    public func validateCapture() throws {
        guard let records = captureRecords else { return } // Legacy unsigned document.
        var previous = captureSeed
        var edits = 0, samples = 0, presence = 0
        var elapsed: UInt64 = 0
        for (sequence, record) in records.enumerated() {
            guard record.sequence == sequence, record.previousHead == previous,
                  record.head == (try record.digest()) else { throw HumaError.invalidSession }
            if record.kind == "edit" {
                guard record.index == edits, edits < events.count,
                      record.payloadHash == events[edits].head else { throw HumaError.invalidSession }
                edits += 1
                guard events[edits - 1].elapsedMilliseconds >= elapsed else { throw HumaError.invalidSession }
                elapsed = events[edits - 1].elapsedMilliseconds
            } else if record.kind == "key" {
                guard record.index == samples, let values = inputSamples, samples < values.count,
                      record.payloadHash == (try values[samples].digest()) else { throw HumaError.invalidSession }
                samples += 1
                guard values[samples - 1].elapsedMilliseconds >= elapsed else { throw HumaError.invalidSession }
                elapsed = values[samples - 1].elapsedMilliseconds
            } else if record.kind == "presence" {
                guard let values = presenceEvents, record.index == presence, values.indices.contains(presence),
                      record.payloadHash == (try values[presence].digest(sessionID: id)) else { throw HumaError.invalidSession }
                presence += 1
                guard values[presence - 1].elapsedMilliseconds >= elapsed else { throw HumaError.invalidSession }
                elapsed = values[presence - 1].elapsedMilliseconds
            } else { throw HumaError.invalidSession }
            previous = record.head
        }
        // Empty legacy capture arrays with old unsigned events are not signed evidence.
        if !records.isEmpty || !(signedCheckpoints?.isEmpty ?? true) {
            guard edits == events.count, samples == (inputSamples?.count ?? 0), presence == (presenceEvents?.count ?? 0) else { throw HumaError.invalidSession }
        }
        try validatePresence(requireResolved: false)
    }

    public func validateSignedCheckpoints(requireFinal: Bool = false, finalText: String) throws {
        try validate(finalText: finalText)
        let values = signedCheckpoints ?? []
        guard !requireFinal || !values.isEmpty else { throw HumaError.invalidSession }
        var previous = ""
        var previousCount = 0
        var key: Data?
        var previousElapsed: UInt64 = 0
        for (index, checkpoint) in values.enumerated() {
            guard checkpoint.sequence == index, checkpoint.sessionID == id,
                  checkpoint.previousCheckpoint == previous, checkpoint.verifySignature(),
                  checkpoint.version == values.first?.version,
                  checkpoint.captureCount >= previousCount, checkpoint.captureCount <= (captureRecords?.count ?? 0),
                  checkpoint.editCount >= 0, checkpoint.editCount <= events.count,
                  checkpoint.sampleCount >= 0, checkpoint.sampleCount <= (inputSamples?.count ?? 0),
                  key == nil || key == checkpoint.publicKey else { throw HumaError.invalidSession }
            let prefix = Array((captureRecords ?? []).prefix(checkpoint.captureCount))
            let edits = prefix.filter { $0.kind == "edit" }.count
            let samples = prefix.filter { $0.kind == "key" }.count
            let expectedHead = prefix.last?.head ?? captureSeed
            let expectedEditHead = edits == 0 ? initialHead : events[edits - 1].head
            let expectedTextHash = edits == 0 ? sha256(Data(initialText.utf8)) : events[edits - 1].textHash
            guard checkpoint.captureHead == expectedHead, checkpoint.editCount == edits,
                  checkpoint.sampleCount == samples, checkpoint.editHead == expectedEditHead,
                  checkpoint.textHash == expectedTextHash else { throw HumaError.invalidSession }
            if let time = checkpoint.reportedTime {
                let lastEdit = edits == 0 ? 0 : events[edits - 1].elapsedMilliseconds
                let lastSample = samples == 0 ? 0 : (inputSamples ?? [])[samples - 1].elapsedMilliseconds
                let lastPresence = prefix.last(where: { $0.kind == "presence" }).map { (presenceEvents ?? [])[$0.index].elapsedMilliseconds } ?? 0
                guard time.elapsedMilliseconds >= previousElapsed,
                      time.elapsedMilliseconds >= max(lastEdit, lastSample, lastPresence),
                      index != 0 || (checkpoint.captureCount == 0 && time.elapsedMilliseconds == 0) else {
                    throw HumaError.invalidSession
                }
                previousElapsed = time.elapsedMilliseconds
            }
            key = checkpoint.publicKey; previous = checkpoint.digest; previousCount = checkpoint.captureCount
        }
        if requireFinal {
            guard values.first?.captureCount == 0, values.last?.isFinal == true, values.last?.captureCount == (captureRecords?.count ?? 0),
                  values.last?.textHash == sha256(Data(finalText.utf8)) else { throw HumaError.invalidSession }
            try validatePresence(requireResolved: true)
        }
    }
}

extension InputSample {
    func digest() throws -> String {
        var fields = [kind, String(keyCode), String(modifiers), String(elapsedMilliseconds)]
        if let origin { fields += origin.digestFields }
        return sha256(try JSONEncoder().encode(fields))
    }
}
