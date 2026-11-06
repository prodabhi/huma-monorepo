import AppKit
import UniformTypeIdentifiers
import HumaCore

extension UTType {
    static let humaDocument = UTType(exportedAs: "dev.swayam.huma.document", conformingTo: .data)
}

/// One page as stored on disk: a `.huma` file holding the draft and its signed history, compressed (PageFile).
/// Only Huma pages open in place. Outside text can't come in: every page is typed in Huma.
struct WritingDocument {
    var draft = Draft()

    init() {}
    init(draft: Draft) { self.draft = draft }

    init(data: Data) throws {
        draft = try JSONDecoder().decode(Draft.self, from: PageFile.unpack(data))
        try draft.validate()
        if let richText = draft.richText {
            let formatted = try NSAttributedString(data: richText, options: [.documentType: NSAttributedString.DocumentType.rtf], documentAttributes: nil)
            guard exactTextEqual(formatted.string, draft.text) else { throw HumaError.invalidDocument }
        }
    }

    static func encode(_ draft: Draft) throws -> Data {
        try draft.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try PageFile.pack(encoder.encode(draft))
    }
}
