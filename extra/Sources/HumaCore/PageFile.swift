import Compression
import Foundation

/// How a page is stored on disk. A page is mostly its signed recording, written as hashes in text, which compresses
/// about 4 times, so it's saved compressed: "HUMA" 0x1F 0x01, then the page's JSON as raw DEFLATE (RFC 1951, which
/// browsers read too). Plain JSON pages from Huma 0.1 still open.
public enum PageFile {
    static let magic = Data([0x48, 0x55, 0x4D, 0x41, 0x1F, 0x01])
    /// The most a page may expand to when opened, so a damaged or hostile file can't fill memory.
    public static let limit = 512 * 1024 * 1024

    public static func pack(_ json: Data) throws -> Data {
        var packed = magic
        let filter = try OutputFilter(.compress, using: .zlib) { if let chunk = $0 { packed.append(chunk) } }
        try filter.write(json)
        try filter.finalize()
        return packed
    }

    /// The page's JSON: unpacked when compressed, as it is when it's plain JSON.
    public static func unpack(_ data: Data, limit: Int = limit) throws -> Data {
        guard data.starts(with: magic) else { return data }
        var json = Data()
        let filter = try OutputFilter(.decompress, using: .zlib) { chunk in
            guard let chunk else { return }
            guard json.count + chunk.count <= limit else { throw HumaError.invalidDocument }
            json.append(chunk)
        }
        try filter.write(data.dropFirst(magic.count))
        try filter.finalize()
        return json
    }
}
