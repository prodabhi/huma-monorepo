import Foundation
import CryptoKit

// Disposable fixture signer only. No device key, keychain, biometrics or file key.
let message = FileHandle.standardInput.readDataToEndOfFile()
guard message.count == 32 else { fatalError("Expected a sealed digest") }
let key = P256.Signing.PrivateKey()
let value = ["publicKey": key.publicKey.x963Representation.base64EncodedString(),
             "signature": try key.signature(for: Data("HUMA_MEDIA_SEAL_SIGNATURE_V1\0".utf8) + message).derRepresentation.base64EncodedString()]
FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]))
