import XCTest
import CryptoKit
@testable import HumaCore

final class MediaCaptureTests: XCTestCase {
    func testMediaManifestBindsEveryStreamAndHeaderAcrossSaveReopen() throws {
        let key = P256.Signing.PrivateKey()
        var recorder = try MediaCapture.Recorder(kind: .video, publicKey: key.publicKey.x963Representation)
        try recorder.checkpoint(reason: "start") { try key.signature(for: $0).derRepresentation }
        var blobs = [String: Data]()
        for (i, stream) in [MediaCapture.Stream.camera, .depth, .motion, .microphone].enumerated() {
            let data = Data("synthetic-\(stream.rawValue)".utf8)
            let record = try recorder.append(stream: stream, elapsedNanoseconds: UInt64(i), encoding: "test-bytes-v1", bytes: data)
            blobs[record.contentHash] = data
        }
        try recorder.checkpoint(reason: "seal") { try key.signature(for: $0).derRepresentation }
        let saved = try JSONEncoder().encode(recorder.manifest)
        let manifest = try JSONDecoder().decode(MediaCapture.Manifest.self, from: saved)
        let report = try MediaCapture.inspect(manifest, expectedKeyHash: sha256(key.publicKey.x963Representation)) { blobs[$0]! }
        XCTAssertTrue(report.sealed)
        XCTAssertEqual(report.recordCount, 4)
        XCTAssertEqual(report.streams, [.camera, .depth, .motion, .microphone])
        XCTAssertThrowsError(try MediaCapture.inspect(manifest, expectedKeyHash: String(repeating: "0", count: 64)) { blobs[$0]! })
        var altered = manifest; altered.kind = .audio
        XCTAssertThrowsError(try MediaCapture.inspect(altered) { blobs[$0]! })
        altered = manifest; altered.nonce[0] ^= 1
        XCTAssertThrowsError(try MediaCapture.inspect(altered) { blobs[$0]! })
        altered = manifest; altered.records.remove(at: 1)
        XCTAssertThrowsError(try MediaCapture.inspect(altered) { blobs[$0]! })
        altered = manifest; altered.records[0].elapsedNanoseconds += 1
        XCTAssertThrowsError(try MediaCapture.inspect(altered) { blobs[$0]! })
        XCTAssertThrowsError(try MediaCapture.inspect(manifest) { _ in Data("different bytes".utf8) })
    }
    func testMediaLimitsSealingAndWrongSignersRejectWithoutDiscardingHistory() throws {
        let key = P256.Signing.PrivateKey()
        let other = P256.Signing.PrivateKey()
        var recorder = try MediaCapture.Recorder(kind: .audio, publicKey: key.publicKey.x963Representation)
        XCTAssertThrowsError(try recorder.append(stream: .microphone, elapsedNanoseconds: 0, encoding: "pcm", bytes: Data([1])))
        XCTAssertThrowsError(try recorder.checkpoint(reason: "start") { try other.signature(for: $0).derRepresentation })
        XCTAssertTrue(recorder.manifest.checkpoints.isEmpty)
        try recorder.checkpoint(reason: "start") { try key.signature(for: $0).derRepresentation }
        XCTAssertThrowsError(try recorder.checkpoint(reason: "seal") { try key.signature(for: $0).derRepresentation })
        _ = try recorder.append(stream: .microphone, elapsedNanoseconds: 10, encoding: "pcm", bytes: Data([1]))
        XCTAssertThrowsError(try recorder.append(stream: .microphone, elapsedNanoseconds: 9, encoding: "pcm", bytes: Data([2])))
        XCTAssertThrowsError(try recorder.append(stream: .camera, elapsedNanoseconds: 11, encoding: "raw", bytes: Data(count: MediaCapture.maximumBlobBytes + 1)))
        XCTAssertEqual(recorder.manifest.records.count, 1)
        XCTAssertThrowsError(try MediaCapture.inspect(recorder.manifest) { _ in Data([1]) })
        try recorder.checkpoint(reason: "seal") { try key.signature(for: $0).derRepresentation }
        XCTAssertThrowsError(try recorder.append(stream: .microphone, elapsedNanoseconds: 11, encoding: "pcm", bytes: Data([2])))
        XCTAssertThrowsError(try recorder.checkpoint(reason: "seal") { try key.signature(for: $0).derRepresentation })
    }
    func testMediaProbeNoncesAreFreshAndBoundToTheCaptureScope() throws {
        let key = P256.Signing.PrivateKey()
        var recorder = try MediaCapture.Recorder(kind: .image, publicKey: key.publicKey.x963Representation)
        try recorder.checkpoint(reason: "start") { try key.signature(for: $0).derRepresentation }
        let first = try recorder.probe(modality: "light")
        let second = try recorder.probe(modality: "light")
        XCTAssertEqual(first.nonce.count, 32)
        XCTAssertNotEqual(first.nonce, second.nonce)
        XCTAssertEqual(first.captureHead, recorder.manifest.head)
        XCTAssertEqual(first.sessionID, recorder.manifest.sessionID)
        let bytes = try JSONEncoder().encode(first)
        _ = try recorder.append(stream: .probe, elapsedNanoseconds: 0, encoding: "huma-media-probe-v1", bytes: bytes)
        try recorder.checkpoint(reason: "probe") { try key.signature(for: $0).derRepresentation }
        XCTAssertNotEqual(try recorder.probe(modality: "sound").captureHead, first.captureHead)
        XCTAssertThrowsError(try recorder.probe(modality: "unknown"))
        // A signed stream descriptor alone is not a physical-world consistency proof.
        try recorder.checkpoint(reason: "seal") { try key.signature(for: $0).derRepresentation }
        let report = try MediaCapture.inspect(recorder.manifest) { _ in bytes }
        XCTAssertEqual(report.streams, [.probe])
    }
}
