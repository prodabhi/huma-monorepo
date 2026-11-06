import Foundation
import CryptoKit
// Disposable software key. Never reads Keychain, Secure Enclave or a user's draft.
let count = Int(CommandLine.arguments[1])!
let payloadSize = Int(CommandLine.arguments[2])!
let key = P256.Signing.PrivateKey()
let pub = key.publicKey.x963Representation
let order = Array(Data([0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51]))
func normalize(_ signature: Data) -> Data {
    let r = signature.prefix(32), s = Array(signature.suffix(32))
    var negative = [UInt8](repeating: 0, count: 32), borrow = 0
    for i in (0..<32).reversed() {
        let difference = Int(order[i]) - Int(s[i]) - borrow
        negative[i] = UInt8(truncatingIfNeeded: difference); borrow = difference < 0 ? 1 : 0
    }
    return Data(r) + Data(negative.lexicographicallyPrecedes(s) ? negative : s)
}
var signatures = [[UInt8]](), digests = [[UInt8]](), payloads = [[UInt8]]()
for i in 0..<count {
    let bytes = Data((0..<payloadSize).map { UInt8(($0 + i) % 256) })
    let signature = try key.signature(for: bytes)
    signatures.append(Array(normalize(signature.rawRepresentation)))
    digests.append(Array(SHA256.hash(data: bytes)))
    payloads.append(Array(bytes))
}
let result: [String: Any] = ["x": Array(pub[1..<33]), "y": Array(pub[33..<65]),
    "key_hash": Array(SHA256.hash(data: pub)), "digests": digests,
    "signatures": signatures, "payloads": payloads]
FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]))
