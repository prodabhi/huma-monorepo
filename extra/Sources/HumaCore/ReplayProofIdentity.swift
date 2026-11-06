import Foundation

// A stable identifier for a replay statement, independent of JSON formatting and
// proof compression/randomness. Deriving it does not verify the receipt: callers
// must compare it with the identifier returned by the pinned replay verifier.
public struct ReplayProofIdentity: Sendable, Equatable {
    public static let imageID = "83caafb5987a3c73d37ae9a5a31da1117c021f3818621a9f9911cb9d1fbf8bd4"
    public static let previousImageID = "0968908b3cd5c9b95c692f8786d2d39046de772827fa83992df9495a72c465e9"
    public static let legacyImageID = "dda9a53d84ded1b005a8bf45c193ccbaf52d9d7b62f5d83b54d197803c1a1295"
    public let value: String

    public init(proof: Data) throws {
        struct Envelope: Decodable {
            struct Receipt: Decodable {
                struct Journal: Decodable { var bytes: [UInt8] }
                var journal: Journal
            }
            var version: Int
            var system: String
            var imageId: String
            var receipt: Receipt
        }
        guard proof.count <= 32 * 1024 * 1024 else { throw HumaError.invalidResponse }
        let envelope = try JSONDecoder().decode(Envelope.self, from: proof)
        guard envelope.version == 1, envelope.system == "risc0-3.0.6",
              [Self.imageID, Self.previousImageID, Self.legacyImageID].contains(envelope.imageId), !envelope.receipt.journal.bytes.isEmpty,
              envelope.receipt.journal.bytes.count <= 65536 else { throw HumaError.invalidResponse }
        let journalHash = sha256(Data(envelope.receipt.journal.bytes))
        value = sha256(Data("huma-replay-identity-v1\n\(envelope.imageId)\n\(journalHash)".utf8))
    }
}
