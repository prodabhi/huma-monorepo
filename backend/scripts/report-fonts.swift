// swiftc -O backend/scripts/report-fonts.swift -o /tmp/report-fonts && /tmp/report-fonts frontend/pages/fonts/inter.woff2 frontend/pages/fonts/inter-report.ttf
// (and the same for geist-mono): the site's fonts as plain TrueType for the shared page's PDF report (report-pdf.mjs),
// whose font library can't read WOFF2 or variable fonts. It keeps the default (Regular) outlines and metrics only.
// With a third argument, "variable", it keeps every table instead, for a fixed weight made with fontTools:
//   /tmp/report-fonts frontend/pages/fonts/inter.woff2 /tmp/inter-var.ttf variable
//   fonttools varLib.instancer /tmp/inter-var.ttf wght=600 -o /tmp/inter-600.ttf
//   pyftsubset /tmp/inter-600.ttf --unicodes='*' --drop-tables+=GSUB,GPOS,GDEF,STAT,gasp,HVAR,MVAR \
//     --output-file=frontend/pages/fonts/inter-semibold-report.ttf
import CoreText
import Foundation
let args = CommandLine.arguments
guard let descriptors = CTFontManagerCreateFontDescriptorsFromURL(URL(fileURLWithPath: args[1]) as CFURL) as? [CTFontDescriptor],
      let descriptor = descriptors.first else { fatalError("no font") }
let font = CTFontCreateWithFontDescriptor(descriptor, 12, nil)
// The array holds the four-byte tags themselves, not CFNumbers.
guard let available = CTFontCopyAvailableTables(font, []) else { fatalError("no tables") }
let tags = (0..<CFArrayGetCount(available)).map { UInt32(UInt(bitPattern: CFArrayGetValueAtIndex(available, $0))) }
var tables: [(UInt32, Data)] = []
// Only the tables a PDF needs: the default (Regular) outlines and metrics; no variations, kerning or layout.
let keep: Set<String> = args.count > 3 && args[3] == "variable" ? [] : ["cmap", "glyf", "head", "hhea", "hmtx", "loca", "maxp", "name", "post", "OS/2"]
for tag in tags.sorted() where keep.isEmpty || keep.contains(String(bytes: withUnsafeBytes(of: tag.bigEndian) { Array($0) }, encoding: .ascii) ?? "") {
    guard let data = CTFontCopyTable(font, CTFontTableTag(tag), []) as Data? else { continue }
    tables.append((tag, data))
}
func be32(_ v: UInt32) -> Data { withUnsafeBytes(of: v.bigEndian) { Data($0) } }
func be16(_ v: UInt16) -> Data { withUnsafeBytes(of: v.bigEndian) { Data($0) } }
func checksum(_ d: Data) -> UInt32 {
    var padded = d; while padded.count % 4 != 0 { padded.append(0) }
    var sum: UInt32 = 0
    padded.withUnsafeBytes { raw in for i in stride(from: 0, to: raw.count, by: 4) { sum &+= raw.loadUnaligned(fromByteOffset: i, as: UInt32.self).bigEndian } }
    return sum
}
let n = UInt16(tables.count)
var entrySelector: UInt16 = 0; while (1 << (entrySelector + 1)) <= n { entrySelector += 1 }
let searchRange = UInt16((1 << entrySelector) * 16)
var out = Data()
out += be32(0x00010000) + be16(n) + be16(searchRange) + be16(entrySelector) + be16(n * 16 - searchRange)
var offset = 12 + 16 * tables.count
var body = Data()
for (tag, data) in tables {
    var table = data
    if tag == 0x68656164 { table.replaceSubrange(8..<12, with: Data(count: 4)) } // head: checkSumAdjustment is worked out below
    out += be32(tag) + be32(checksum(table)) + be32(UInt32(offset)) + be32(UInt32(table.count))
    body += table; while body.count % 4 != 0 { body.append(0) }
    offset = 12 + 16 * tables.count + body.count
}
out += body
// head.checkSumAdjustment = 0xB1B0AFBA - checksum(whole file)
if let index = tables.firstIndex(where: { $0.0 == 0x68656164 }) {
    let headOffset = Int(out[12 + 16 * index + 8..<12 + 16 * index + 12].reduce(0) { $0 << 8 | UInt32($1) })
    out.replaceSubrange(headOffset + 8..<headOffset + 12, with: be32(0xB1B0AFBA &- checksum(out)))
}
try out.write(to: URL(fileURLWithPath: args[2]))
print(args[2], out.count, "bytes,", tables.count, "tables:", tables.map { String(bytes: be32($0.0), encoding: .ascii)! }.joined(separator: " "))
