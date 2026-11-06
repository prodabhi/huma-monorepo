import Foundation
import CryptoKit

/// Shared Mac/iOS media-capture contract. Integrity/signature verification only;
/// sensor consistency, device attestation and permitted-edit ZK proofs are separate.
public enum MediaCapture {
    public enum Kind: String, Codable, Sendable { case image, audio, video }
    public enum Stream: String, Codable, Sendable { case camera, depth, motion, microphone, probe }
    public struct Record: Codable, Sendable {
        public var sequence: Int
        public var stream: Stream
        public var elapsedNanoseconds: UInt64
        public var encoding: String
        public var byteLength: Int
        public var contentHash: String
        public var previousHead: String
        public var head: String
        fileprivate func digest() throws -> String {
            hash(try fields(["huma-media-record-v1", String(sequence), stream.rawValue,
                String(elapsedNanoseconds), encoding, String(byteLength), contentHash, previousHead]))
        }
    }
    public struct Checkpoint: Codable, Sendable {
        public var sequence: Int
        public var recordCount: Int
        public var head: String
        public var reason: String
        public var previousCheckpoint: String
        public var signature: Data
        public func payload(manifest: Manifest) throws -> Data {
            try fields(["huma-media-checkpoint-v1", manifest.sessionID, manifest.kind.rawValue,
                manifest.nonce.base64EncodedString(), manifest.publicKey.base64EncodedString(),
                String(sequence), String(recordCount), head, reason, previousCheckpoint])
        }
        fileprivate func digest(manifest: Manifest) throws -> String { hash(try payload(manifest: manifest) + signature) }
    }
    public struct Manifest: Codable, Sendable {
        public var format = "huma-media-capture-v1"
        public var sessionID: String
        public var kind: Kind
        public var nonce: Data
        public var publicKey: Data
        public var records: [Record] = []
        public var checkpoints: [Checkpoint] = []
        public var seed: String {
            // These exact header fields are authenticated even for an empty start.
            hash((try? fields(["huma-media-session-v1", sessionID, kind.rawValue,
                nonce.base64EncodedString(), publicKey.base64EncodedString()])) ?? Data())
        }
        public var head: String { records.last?.head ?? seed }
    }
    public struct Probe: Codable, Sendable {
        public var format = "huma-media-probe-v1"
        public var sessionID: String
        public var captureHead: String
        public var nonce: Data
        public var modality: String
        public var sequence: Int
    }
    public struct Inspection: Sendable {
        public let recordCount: Int
        public let byteLength: Int
        public let streams: Set<Stream>
        public let captureKeyHash: String
        public let sealed: Bool
    }
    public enum Failure: Error { case invalid, capacity, sealed, unsealed, missingBlob }
    public static let maximumRecords = 4096
    public static let maximumBlobBytes = 2 * 1024 * 1024
    public static let maximumTotalBytes = 64 * 1024 * 1024
    fileprivate static func hash(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
    fileprivate static func fields(_ strings: [String]) throws -> Data { try JSONEncoder().encode(strings) }
    fileprivate static func randomNonce() -> Data {
        var random = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in UInt8.random(in: 0...255, using: &random) })
    }

    /// A serial owner supplies signatures; this never loads a device key or records a sensor.
    public struct Recorder {
        public private(set) var manifest: Manifest
        private var totalBytes = 0
        public init(kind: Kind, publicKey: Data) throws {
            _ = try P256.Signing.PublicKey(x963Representation: publicKey)
            manifest = Manifest(sessionID: UUID().uuidString, kind: kind, nonce: randomNonce(), publicKey: publicKey)
        }
        public mutating func append(stream: Stream, elapsedNanoseconds: UInt64, encoding: String, bytes: Data) throws -> Record {
            guard manifest.checkpoints.first?.reason == "start" else { throw Failure.unsealed }
            guard manifest.checkpoints.last?.reason != "seal" else { throw Failure.sealed }
            guard !bytes.isEmpty, bytes.count <= maximumBlobBytes, totalBytes <= maximumTotalBytes - bytes.count,
                  manifest.records.count < maximumRecords else { throw Failure.capacity }
            guard !encoding.isEmpty, encoding.utf8.count <= 128,
                  elapsedNanoseconds >= (manifest.records.last?.elapsedNanoseconds ?? 0) else { throw Failure.invalid }
            var record = Record(sequence: manifest.records.count, stream: stream, elapsedNanoseconds: elapsedNanoseconds,
                encoding: encoding, byteLength: bytes.count, contentHash: hash(bytes), previousHead: manifest.head, head: "")
            record.head = try record.digest()
            manifest.records.append(record); totalBytes += bytes.count
            return record
        }
        /// Randomness is independent of the chain head: a predictable head alone is not a nonce source.
        public func probe(modality: String) throws -> Probe {
            guard manifest.checkpoints.first?.reason == "start", manifest.checkpoints.last?.reason != "seal",
                  ["light", "sound", "haptic"].contains(modality) else { throw Failure.invalid }
            return Probe(sessionID: manifest.sessionID, captureHead: manifest.head, nonce: randomNonce(),
                modality: modality, sequence: manifest.records.count)
        }
        public mutating func checkpoint(reason: String, sign: (Data) throws -> Data) throws {
            guard manifest.checkpoints.last?.reason != "seal" else { throw Failure.sealed }
            guard ["start", "probe", "seal"].contains(reason), manifest.checkpoints.count < maximumRecords,
                  (manifest.checkpoints.isEmpty ? reason == "start" : reason != "start"),
                  reason != "seal" || !manifest.records.isEmpty else { throw Failure.invalid }
            var cp = Checkpoint(sequence: manifest.checkpoints.count, recordCount: manifest.records.count,
                head: manifest.head, reason: reason, previousCheckpoint: try manifest.checkpoints.last?.digest(manifest: manifest) ?? "", signature: Data())
            cp.signature = try sign(cp.payload(manifest: manifest))
            let key = try P256.Signing.PublicKey(x963Representation: manifest.publicKey)
            guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: cp.signature),
                  key.isValidSignature(signature, for: try cp.payload(manifest: manifest)) else { throw Failure.invalid }
            manifest.checkpoints.append(cp)
        }
    }

    /// The caller chooses the expected key independently. A file never attests itself.
    /// Blob loading is mandatory: a signed list of hashes alone is not a checked recording.
    public static func inspect(_ manifest: Manifest, expectedKeyHash: String? = nil,
                               loadBlob: (String) throws -> Data) throws -> Inspection {
        guard manifest.format == "huma-media-capture-v1", !manifest.sessionID.isEmpty, manifest.sessionID.utf8.count <= 128,
              manifest.nonce.count == 32, manifest.publicKey.count == 65,
              manifest.records.count <= maximumRecords, !manifest.checkpoints.isEmpty,
              manifest.checkpoints.count <= maximumRecords else { throw Failure.invalid }
        let key = try P256.Signing.PublicKey(x963Representation: manifest.publicKey)
        let keyHash = hash(manifest.publicKey)
        if let expectedKeyHash, expectedKeyHash != keyHash { throw Failure.invalid }
        var previous = manifest.seed, elapsed: UInt64 = 0, total = 0
        var streams = Set<Stream>()
        for (index, record) in manifest.records.enumerated() {
            guard record.sequence == index, record.previousHead == previous, record.elapsedNanoseconds >= elapsed,
                  record.byteLength > 0, record.byteLength <= maximumBlobBytes,
                  total <= maximumTotalBytes - record.byteLength, !record.encoding.isEmpty, record.encoding.utf8.count <= 128,
                  record.contentHash.count == 64, record.contentHash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  record.head == (try record.digest()) else { throw Failure.invalid }
            let blob = try loadBlob(record.contentHash)
            guard blob.count == record.byteLength, hash(blob) == record.contentHash else { throw Failure.missingBlob }
            previous = record.head; elapsed = record.elapsedNanoseconds; total += blob.count; streams.insert(record.stream)
        }
        var prior = "", count = 0
        for (index, cp) in manifest.checkpoints.enumerated() {
            guard cp.sequence == index, cp.recordCount >= count, cp.recordCount <= manifest.records.count,
                  cp.previousCheckpoint == prior, cp.head == (cp.recordCount == 0 ? manifest.seed : manifest.records[cp.recordCount - 1].head),
                  (index == 0 ? cp.reason == "start" && cp.recordCount == 0 : ["probe", "seal"].contains(cp.reason)),
                  cp.reason != "seal" || index == manifest.checkpoints.count - 1,
                  let signature = try? P256.Signing.ECDSASignature(derRepresentation: cp.signature),
                  key.isValidSignature(signature, for: try cp.payload(manifest: manifest)) else { throw Failure.invalid }
            prior = try cp.digest(manifest: manifest); count = cp.recordCount
        }
        let sealed = manifest.checkpoints.last?.reason == "seal" && count == manifest.records.count && !manifest.records.isEmpty
        guard sealed else { throw Failure.unsealed }
        return Inspection(recordCount: manifest.records.count, byteLength: total, streams: streams, captureKeyHash: keyHash, sealed: sealed)
    }
}
