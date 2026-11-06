import AppKit
import CoreImage.CIFilterBuiltins
import SwiftUI
import HumaCore

/// A finished page's PDF report, the same report a reader downloads from its shared page (frontend/pages/report-pdf.mjs),
/// drawn here with the Mac's own PDF drawing so the app carries no PDF library. In Huma's look: the result and score
/// (with how it adds up), the writing rules, the writing session (when and where it was written), the zero-knowledge
/// proof, how Huma works, how to check it, and numbered references giving the full address of everything cited, each a link; then the text as an appendix, pasted parts
/// shaded. The evidence file readers download is attached inside, so the PDF alone can be checked at huma.social/verify.
@MainActor enum PageReport {
    struct Page {
        var title: String
        var writer: String?
        var text: String
        /// Where each character came from, to shade pasted text.
        var provenance: TextProvenance?
        var summary: PageProofSummary
        /// The score readers see, and the text's make-up they see (nil without the replay).
        var score: HumaScore
        var composition: TextProvenance.Composition?
        var link: URL?
        /// The page proof, and the evidence file readers download (attached).
        var proof: Data
        var evidence: Data
    }
    /// US Letter, in points, as on the web.
    static let size = CGSize(width: 612, height: 792)

    static func make(_ page: Page) throws -> Data {
        let report = Report(page)
        // Drawn twice: once to count the pages for "Page 1 of 4", then for keeps.
        let pages = try draw(report, pages: 0).pages
        return try attach(page.evidence, named: "Huma-evidence.json", to: draw(report, pages: pages).data)
    }
    private static func draw(_ report: Report, pages total: Int) throws -> (data: Data, pages: Int) {
        let data = NSMutableData()
        var box = CGRect(origin: .zero, size: size)
        var info: [CFString: Any] = [kCGPDFContextTitle: report.title + " – Huma writing report", kCGPDFContextCreator: "Huma",
            kCGPDFContextSubject: "Writing report: result, score and how it adds up, writing rules, where it was written and the zero-knowledge proof, with sources. The proof file is attached."]
        if let writer = report.writer { info[kCGPDFContextAuthor] = writer }
        guard let consumer = CGDataConsumer(data: data), let context = CGContext(consumer: consumer, mediaBox: &box, info as CFDictionary) else {
            throw HumaError.configuration("Couldn’t make the report.")
        }
        let sheet = Sheet(context: context, report: report, total: total)
        sheet.render()
        context.closePDF()
        return (data as Data, sheet.pages)
    }

    /// One address the report cites, numbered in the references.
    struct Reference { var key: String, title: String, about: String, url: String, number = 0 }
    nonisolated static let siteURL = "https://huma.social", verifyURL = "https://huma.social/verify", downloadURL = "https://huma.social/download"
    nonisolated static let noirURL = "https://noir-lang.org/docs", barretenbergURL = "https://barretenberg.aztec.network/docs"
    nonisolated static let enclaveURL = "https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web"
    /// The nine writing rules, as met (RULES_MET in report-pdf.mjs).
    nonisolated static let rulesMet = ["Started from a blank page", "All text typed", "Typed for 20 seconds or more", "30 key presses or more", "Usual key presses",
                                       "Usual key holds", "Usual typing rhythm", "A natural pause", "Usual typing speed"]

    /// What the report says, worked out once from the page: the same fields report-pdf.mjs takes.
    struct Report {
        var title: String, writer: String?, started: Date, ended: Date, savedAt = Date(), madeBy: String
        var verified: Bool, headline: String, detail: String, rules: [Bool]
        var score: Int, scoreRows: [(String, String, String)]
        /// How the score adds up, with this page's numbers (score.terms in report-pdf.mjs).
        var typedShare: Double, checks: (met: Int, of: Int), touch: (onTime: Int, asked: Int)
        var session: [(String, String)]
        var fingerprint: String, textHash: String, signingKey: String, parts: Int, fileSize: String
        var link: String?
        /// Paragraphs, each a list of lines (the text's own line breaks), each a list of (text, pasted) runs.
        var paragraphs: [[[(String, Bool)]]]
        var references: [Reference] = []

        init(_ page: Page) {
            title = page.title.isEmpty ? "Untitled" : page.title
            writer = page.writer; started = page.summary.started; ended = page.summary.ended
            madeBy = "Huma for Mac " + (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "")
            // The result, in the words the shared page uses (verify.mjs).
            let names = WritingView.writingRules
            let met = names.indices.map { $0 < page.summary.rules.count ? page.summary.rules[$0] : true }
            rules = met
            let unmet = names.indices.filter { !met[$0] }.map { names[$0] }
            let notAllTyped = unmet.contains(names[0]) || unmet.contains(names[1]), checks = unmet.filter { $0 != names[0] && $0 != names[1] }
            verified = unmet.isEmpty
            headline = verified ? "Verified: typed in Huma" : notAllTyped ? "Written in Huma, not all typed" : "Typed in Huma, not all checks met"
            detail = verified ? "Typed key by key in the Huma app. Unchanged since."
                : !notAllTyped ? "Typed in the Huma app and unchanged since, but not every typing check was met: " + checks.joined(separator: ", ") + "."
                : "Written in the Huma app and unchanged since, but some of it wasn’t typed" + (unmet.contains(names[0]) ? ": it started from imported text" : "") + "."
                    + (checks.isEmpty ? "" : " Also not met: " + checks.joined(separator: ", ") + ".")
            let s = page.score
            score = s.value
            scoreRows = [("Typed by hand", s.handTyped.map { HumaScore.percent($0) + " of the text" + (s.external > 0 ? ", \(HumaScore.percent(s.external)) on another keyboard" : "") }
                            ?? "Replay not shared, so typing counts at 60%", "\(s.points.typed) / 70"),
                         ("Typing checks", "\(s.checksMet) of 7 met", "\(s.points.checks) / 20"),
                         ("Touch ID", s.presenceCount > 0 ? "\(s.presenceOnTime) of \(s.presenceCount) answered within 10 seconds" : "No checks were needed", "\(s.points.touch) / 10")]
            typedShare = s.typedShare; self.checks = (s.checksMet, 7); touch = (s.presenceOnTime, s.presenceCount)
            let summary = page.summary, edits = Double(max(summary.edits, 1)), replay = page.composition != nil
            let seconds = max(1, Int((Double(summary.elapsedMilliseconds) / 1000).rounded())), minutes = seconds / 60
            let pasted = page.composition.map { $0.total == 0 ? 0 : Double($0.pasted) / Double($0.total) } ?? Double(summary.pasteEdits) / edits
            session = [("Writing time", minutes > 0 ? "\(minutes) min" + (seconds % 60 > 0 ? " \(seconds % 60) s" : "") : "\(seconds) s"),
                       ("Key presses", summary.samples.formatted(.number.locale(Locale(identifier: "en_US"))))]
                + (replay ? [] : [("Typing edits", HumaScore.percent(Double(summary.typingEdits) / edits))])
                + [(replay ? "Pasted" : "Pasted edits", HumaScore.percent(pasted)), ("Replay", replay ? "Shared with readers" : "Not shared")]
            let object = (try? JSONSerialization.jsonObject(with: page.proof)) as? [String: Any]
            fingerprint = sha256(page.proof)
            signingKey = sha256((object?["publicKey"] as? String).flatMap { Data(base64Encoded: $0) } ?? Data())
            parts = ((object?["chunks"] as? [Any])?.count ?? 0) + 1
            fileSize = "\(max(1, Int((Double(page.evidence.count) / 1024).rounded()))) KB"
            // The text's SHA-256 as the proof states it.
            let statement = ((try? JSONSerialization.jsonObject(with: page.evidence)) as? [String: Any])?["statement"] as? [String: Any]
            textHash = (statement?["contentHash"] as? String).flatMap { $0.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil ? $0 : nil }
                ?? sha256(Data(page.text.utf8))
            link = page.link?.absoluteString
            paragraphs = Self.blocks(of: page)
            references = Self.cited(link: link)
        }

        /// What the report cites, numbered in the order it's first cited, each with its full address: only those this page has
        /// (references() in report-pdf.mjs).
        static func cited(link: String?) -> [Reference] {
            var list: [Reference] = [.init(key: "download", title: "Huma for Mac", about: "the app the page was written in", url: downloadURL),
                                     .init(key: "noir", title: "Noir", about: "language of Huma’s proof circuits", url: noirURL),
                                     .init(key: "barretenberg", title: "Barretenberg", about: "UltraHonk prover and verifier", url: barretenbergURL),
                                     .init(key: "enclave", title: "The Secure Enclave", about: "Apple Platform Security; where the Mac keeps its signing key", url: enclaveURL)]
            if let link { list.append(.init(key: "page", title: "Shared page", about: "text, proof and replay, checked in your browser", url: link)) }
            list.append(.init(key: "verify", title: "Huma Verify", about: "checks this PDF’s attached proof", url: verifyURL))
            return list.enumerated().map { var item = $1; item.number = $0 + 1; return item }
        }

        /// The text as the shared page shows it: trimmed, split into paragraphs at blank lines, line breaks kept, pasted parts marked.
        private static func blocks(of page: Page) -> [[[(String, Bool)]]] {
            let whole = Array(page.text.utf16), origins = page.provenance.flatMap { $0.string == page.text ? $0.origins : nil }
            let core = page.text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !core.isEmpty else { return [] }
            let span = (page.text as NSString).range(of: core)
            var blocks: [NSRange] = [], at = span.location
            for gap in (try? NSRegularExpression(pattern: "\n{2,}"))?.matches(in: page.text, range: span) ?? [] {
                blocks.append(NSRange(location: at, length: gap.range.location - at)); at = NSMaxRange(gap.range)
            }
            blocks.append(NSRange(location: at, length: NSMaxRange(span) - at))
            return blocks.map { block in
                var lines: [[(String, Bool)]] = [[]], run: [UInt16] = [], runPasted = false
                func flush() { if !run.isEmpty { lines[lines.count - 1].append((String(decoding: run, as: UTF16.self), runPasted)); run = [] } }
                for index in block.location..<NSMaxRange(block) {
                    if whole[index] == 0x0A { flush(); lines.append([]); continue }
                    let pasted = origins.map { index < $0.count && $0[index] == .pasted } ?? false
                    if pasted != runPasted { flush(); runPasted = pasted }
                    run.append(whole[index])
                }
                flush()
                return lines
            }
        }
    }

    /// Lays the report out on US Letter pages from the top down, as report-pdf.mjs does, and draws it into a PDF.
    /// Positions are in points from the top-left corner; PDF counts from the bottom, so drawing turns them around.
    @MainActor private final class Sheet {
        let context: CGContext, report: Report, total: Int
        private(set) var pages = 0
        private var top: CGFloat = 0, section = 0
        private let width: CGFloat = 612, height: CGFloat = 792, margin: CGFloat = 54, foot: CGFloat = 746, labelWidth: CGFloat = 148
        private var content: CGFloat { width - 2 * margin }

        init(context: CGContext, report: Report, total: Int) { self.context = context; self.report = report; self.total = total }

        struct Run {
            var text: String, font: NSFont = Theme.sansFont(9.5), color: NSColor = Ink.text, url: String? = nil, cite = false, shaded = false
        }
        struct Piece { var text: String, run: Run, font: NSFont, width: CGFloat, space: Bool }

        private func sans(_ size: CGFloat) -> NSFont { Theme.sansFont(size) }
        private func bold(_ size: CGFloat) -> NSFont { Theme.sansFont(size, weight: 600) }
        private func mono(_ size: CGFloat) -> NSFont { Theme.monoFont(size) }
        private func line(_ text: String, _ font: NSFont, _ color: NSColor = Ink.text, kern: CGFloat = 0) -> CTLine {
            // No ligatures, as on the web, so a hash like 0x9ff1 reads letter by letter.
            var attributes: [NSAttributedString.Key: Any] = [.font: font, .ligature: 0, NSAttributedString.Key(kCTForegroundColorAttributeName as String): color.cgColor]
            if kern != 0 { attributes[.kern] = kern }
            return CTLineCreateWithAttributedString(NSAttributedString(string: text, attributes: attributes))
        }
        private func measure(_ text: String, _ font: NSFont, kern: CGFloat = 0) -> CGFloat {
            CGFloat(CTLineGetTypographicBounds(line(text, font, kern: kern), nil, nil, nil))
        }
        /// Text with its baseline at `baseline`.
        private func text(_ value: String, _ x: CGFloat, baseline: CGFloat, _ font: NSFont, _ color: NSColor = Ink.text, kern: CGFloat = 0) {
            context.textPosition = CGPoint(x: x, y: height - baseline)
            CTLineDraw(line(value, font, color, kern: kern), context)
        }
        /// Text whose box starts at `y`, as report-pdf.mjs places it (baseline at 0.78 of the size).
        private func text(_ value: String, _ x: CGFloat, _ y: CGFloat, _ font: NSFont, _ color: NSColor = Ink.text) {
            text(value, x, baseline: y + font.pointSize * 0.78, font, color)
        }
        /// A small label in Geist Mono capitals, as on huma.social.
        private func label(_ value: String, _ x: CGFloat, _ y: CGFloat, size: CGFloat = 6.5, color: NSColor = Ink.quiet) {
            text(value.uppercased(), x, baseline: y + size * 0.78, mono(size), color, kern: 0.4)
        }
        private func labelSize(_ value: String, size: CGFloat = 6.5) -> CGFloat { measure(value.uppercased(), mono(size), kern: 0.4) }
        private func fill(_ rect: CGRect, _ color: NSColor) {
            context.setFillColor(color.cgColor); context.fill(CGRect(x: rect.minX, y: height - rect.maxY, width: rect.width, height: rect.height))
        }
        private func rule(_ y: CGFloat, _ color: NSColor = Ink.line, _ thickness: CGFloat = 0.5) {
            context.setStrokeColor(color.cgColor); context.setLineWidth(thickness)
            context.strokeLineSegments(between: [CGPoint(x: margin, y: height - y), CGPoint(x: width - margin, y: height - y)])
        }
        private func link(_ rect: CGRect, _ url: String) {
            guard let url = URL(string: url) else { return }
            context.setURL(url as CFURL, for: CGRect(x: rect.minX, y: height - rect.maxY, width: rect.width, height: rect.height))
        }
        /// A stroked path given in points around (x, y) from the top-left, as report-pdf.mjs's small marks are.
        private func stroke(_ points: [[CGPoint]], at center: CGPoint, _ color: NSColor, width lineWidth: CGFloat = 1.2) {
            context.setStrokeColor(color.cgColor); context.setLineWidth(lineWidth); context.setLineCap(.round)
            for segment in points {
                guard let first = segment.first else { continue }
                context.move(to: CGPoint(x: center.x + first.x, y: height - center.y - first.y))
                for point in segment.dropFirst() { context.addLine(to: CGPoint(x: center.x + point.x, y: height - center.y - point.y)) }
            }
            context.strokePath(); context.setLineCap(.butt)
        }

        // MARK: Pages

        private func newPage() {
            if pages > 0 { finishPage() }
            context.beginPDFPage(nil); pages += 1
            context.setFillColor(NSColor.white.cgColor); context.fill(CGRect(origin: .zero, size: PageReport.size))
            // Huma's mark and name, and what this is.
            let markHeight: CGFloat = 14, markWidth = markHeight * HumaMark.size.width / HumaMark.size.height
            let flip = CGAffineTransform(a: 1, b: 0, c: 0, d: -1, tx: 0, ty: height)
            context.addPath(HumaMark().path(in: CGRect(x: margin, y: 38, width: markWidth, height: markHeight)).applying(flip).cgPath)
            context.setFillColor(Ink.text.cgColor); context.fillPath(using: .evenOdd)
            text("Huma", margin + markWidth + 5, 39.5, bold(11.5))
            label("Writing Report", width - margin - labelSize("Writing Report"), 42.5)
            rule(60, Ink.text, 0.75)
            top = 84
        }
        /// The footer: Huma's site, which proof, when and how this was made, and the page number.
        private func finishPage() {
            rule(foot)
            let made = "Made " + report.savedAt.formatted(.dateTime.month(.wide).day().year().locale(Locale(identifier: "en_US"))) + " by " + report.madeBy
            let site = "huma.social", siteWidth = measure(site, bold(7))
            text(site, margin, foot + 9, bold(7))
            link(CGRect(x: margin, y: foot + 6, width: siteWidth, height: 12), PageReport.siteURL)
            text("  ·  Proof \(report.fingerprint.prefix(8))  ·  " + made, margin + siteWidth, foot + 9, sans(7), Ink.quiet)
            let number = "Page \(pages) of \(max(total, pages))"
            text(number, width - margin - measure(number, sans(7)), foot + 9, sans(7), Ink.quiet)
            context.endPDFPage()
        }
        private func need(_ space: CGFloat) { if top + space > foot - 12 { newPage() } }

        // MARK: Text

        /// Runs broken into lines between words; an address or hash too long for a line breaks anywhere.
        private func lines(_ runs: [Run], _ room: CGFloat) -> [[Piece]] {
            var out: [[Piece]] = [], current: [Piece] = [], used: CGFloat = 0
            func breakLine() {
                while let last = current.last, last.space { used -= last.width; current.removeLast() }
                out.append(current); current = []; used = 0
            }
            for run in runs {
                let font = run.font, extra: CGFloat = run.cite ? 1.2 : 0
                var word = "", parts: [String] = []
                for character in run.text {
                    if let first = word.first, first.isWhitespace != character.isWhitespace { parts.append(word); word = "" }
                    word.append(character)
                }
                if !word.isEmpty { parts.append(word) }
                for part in parts {
                    if part.first?.isWhitespace == true {
                        if !current.isEmpty { let space = measure(" ", font); current.append(Piece(text: " ", run: run, font: font, width: space, space: true)); used += space }
                        continue
                    }
                    var rest = Substring(part)
                    while !rest.isEmpty {
                        let fullWidth = measure(String(rest), font) + extra
                        if used + fullWidth <= room { current.append(Piece(text: String(rest), run: run, font: font, width: fullWidth, space: false)); used += fullWidth; break }
                        if !current.isEmpty { breakLine(); continue }
                        var cut = rest.count
                        while cut > 1 && measure(String(rest.prefix(cut)), font) > room { cut -= 1 }
                        let piece = String(rest.prefix(cut))
                        current.append(Piece(text: piece, run: run, font: font, width: measure(piece, font), space: false))
                        breakLine(); rest = rest.dropFirst(cut)
                    }
                }
            }
            if !current.isEmpty { breakLine() }
            return out
        }
        @discardableResult
        private func draw(_ list: [[Piece]], _ x: CGFloat, _ y: CGFloat, size: CGFloat, leading: CGFloat, color: NSColor = Ink.text) -> CGFloat {
            for (index, pieces) in list.enumerated() {
                let baseline = y + CGFloat(index) * leading + leading / 2 + size * 0.35
                var at = x
                for piece in pieces {
                    if !piece.space {
                        let ink = piece.run.color != Ink.text ? piece.run.color : piece.run.url != nil ? Ink.link : color
                        text(piece.text, at + (piece.run.cite ? 1.2 : 0), baseline: baseline - (piece.run.cite ? size * 0.32 : 0), piece.font, ink)
                        if let url = piece.run.url { link(CGRect(x: at, y: y + CGFloat(index) * leading, width: piece.width, height: leading), url) }
                    }
                    at += piece.width
                }
            }
            return CGFloat(list.count) * leading
        }
        private func paragraph(_ runs: [Run], size: CGFloat = 9.5, leading: CGFloat = 14, color: NSColor = Ink.text) {
            let list = lines(runs, content)
            need(CGFloat(list.count) * leading)
            top += draw(list, margin, top, size: size, leading: leading, color: color)
        }
        private func reference(_ key: String) -> Reference? { report.references.first { $0.key == key } }
        private func cite(_ key: String, size: CGFloat = 9) -> [Run] {
            reference(key).map { [Run(text: "[\($0.number)]", font: sans(size * 0.72), color: Ink.link, url: $0.url, cite: true)] } ?? []
        }
        private func hash(_ value: String, _ key: String? = nil) -> Run { Run(text: value, font: mono(8), url: key.flatMap { reference($0)?.url }) }
        private func aside(_ value: String) -> Run { Run(text: "  " + value, font: sans(8), color: Ink.quiet) }
        private func plain(_ value: String, _ size: CGFloat = 9) -> Run { Run(text: value, font: sans(size)) }

        // MARK: Tables

        /// A section starts on a new page when its table (about `space` points) won't fit on this one.
        private func heading(_ title: String, _ space: CGFloat = 40) {
            need(39 + min(space, 560))
            if top > 84 { top += 20 }
            section += 1
            text("\(section)", margin, top, bold(11), Ink.quiet)
            text(title, margin + 18, top, bold(11))
            top += 19
            rule(top, Ink.text, 0.6)
        }
        /// A row of a table: a label, a value (runs) and, on the right, an optional figure.
        private func row(_ name: String, _ runs: [Run], figure: String? = nil, bold strong: Bool = false) {
            let size: CGFloat = 9, leading: CGFloat = 13, room = content - labelWidth - (figure == nil ? 0 : 72)
            let values = lines(runs, room), names = lines([Run(text: name, font: strong ? bold(size) : sans(size))], labelWidth - 14)
            let rowHeight = CGFloat(max(values.count, names.count)) * leading + 10
            need(rowHeight)
            draw(names, margin, top + 5, size: size, leading: leading, color: strong ? Ink.text : Ink.grey)
            draw(values, margin + labelWidth, top + 5, size: size, leading: leading)
            if let figure {
                let font = strong ? bold(size) : sans(size)
                text(figure, width - margin - measure(figure, font), baseline: top + 5 + leading / 2 + size * 0.35, font)
            }
            top += rowHeight
            rule(top)
        }
        private func columns(_ names: String...) {
            need(40)
            label(names[0], margin, top + 8); label(names[1], margin + labelWidth, top + 8)
            if names.count > 2 { label(names[2], width - margin - labelSize(names[2]), top + 8) }
            top += 20
            rule(top)
        }
        private func note(_ value: String) { top += 7; paragraph([Run(text: value, font: sans(8))], size: 8, leading: 11.5, color: Ink.grey) }

        // MARK: The report

        func render() {
            let r = report, en = Locale(identifier: "en_US")
            let day = { (date: Date) in date.formatted(.dateTime.month(.wide).day().year().locale(en)) }
            let time = { (date: Date, zone: Bool) in
                date.formatted(zone ? .dateTime.hour().minute().timeZone(.specificName(.short)).locale(en) : .dateTime.hour().minute().locale(en)) }
            let written = day(r.started) == day(r.ended) ? "\(day(r.started)), \(time(r.started, false)) – \(time(r.ended, true))"
                : "\(day(r.started)), \(time(r.started, true)) – \(day(r.ended)), \(time(r.ended, true))"

            // ——— The result ———
            newPage()
            var title = lines([Run(text: r.title, font: bold(19))], content)
            if title.count > 3 {
                title = Array(title.prefix(3))
                let ellipsis = Piece(text: "…", run: Run(text: "…", font: bold(19)), font: bold(19), width: measure("…", bold(19)), space: false)
                while let last = title[2].last, title[2].reduce(0, { $0 + $1.width }) + ellipsis.width > content || last.space { title[2].removeLast() }
                title[2].append(ellipsis)
            }
            top += draw(title, margin, top, size: 19, leading: 24) + 2
            paragraph([Run(text: [r.writer.map { "By " + $0 }, "Written " + written].compactMap { $0 }.joined(separator: "  ·  "))], color: Ink.grey)
            top += 14

            // The result in a box, and the score.
            let tone = r.verified ? Ink.green : Ink.amber, pad: CGFloat = 14, scoreRoom: CGFloat = 104
            let detail = lines([Run(text: r.detail)], content - pad * 2 - scoreRoom - 20)
            let boxHeight = max(pad * 2 + 21 + CGFloat(detail.count) * 14, 82)
            let box = CGRect(x: margin, y: top, width: content, height: boxHeight)
            fill(box, Ink.shade)
            context.setStrokeColor(Ink.line.cgColor); context.setLineWidth(0.75)
            context.stroke(CGRect(x: box.minX, y: height - box.maxY, width: box.width, height: box.height))
            fill(CGRect(x: margin, y: top, width: 3, height: boxHeight), tone)
            // A check, or an exclamation mark, in a circle.
            let icon = CGPoint(x: margin + pad + 6, y: top + pad + 6.5)
            context.setStrokeColor(tone.cgColor); context.setLineWidth(1.1)
            context.strokeEllipse(in: CGRect(x: icon.x - 6, y: height - icon.y - 6, width: 12, height: 12))
            if r.verified { stroke([[CGPoint(x: -2.6, y: 0.2), CGPoint(x: -0.8, y: 2), CGPoint(x: 2.7, y: -1.8)]], at: icon, tone) }
            else {
                stroke([[CGPoint(x: 0, y: -3), CGPoint(x: 0, y: 0.6)]], at: icon, tone)
                context.setFillColor(tone.cgColor); context.fillEllipse(in: CGRect(x: icon.x - 0.7, y: height - icon.y - 3.6, width: 1.4, height: 1.4))
            }
            text(r.headline, margin + pad + 18, top + pad + 1, bold(11), tone)
            draw(detail, margin + pad, top + pad + 21, size: 9.5, leading: 14)
            let scoreX = width - margin - pad - scoreRoom
            context.setStrokeColor(Ink.line.cgColor); context.setLineWidth(0.5)
            context.strokeLineSegments(between: [CGPoint(x: scoreX - 14, y: height - top - pad), CGPoint(x: scoreX - 14, y: height - top - boxHeight + pad)])
            label("Huma Score", scoreX, top + pad + 1)
            text("\(r.score)", scoreX, top + pad + 15, bold(28))
            text("/ 100", scoreX + measure("\(r.score)", bold(28)) + 4, top + pad + 30, sans(10), Ink.grey)
            top += boxHeight

            // ——— The score, and the writing rules behind it ———
            heading("Score", 290)
            columns("Part", "Result", "Points")
            for (part, result, points) in r.scoreRows { row(part, [plain(result)], figure: points) }
            row("Huma Score", [], figure: "\(r.score) / 100", bold: true)
            // How it adds up, with this page's numbers.
            top += 10
            need(40)
            label("How it adds up", margin, top)
            top += 12
            paragraph([Run(text: "70 × \(Int((r.typedShare * 100).rounded()))% typed + 20 × \(r.checks.met)/\(r.checks.of) typing checks + 10 × "
                + (r.touch.asked > 0 ? "\(r.touch.onTime)/\(r.touch.asked)" : "1") + " Touch ID = \(r.score)", font: mono(8.5))], size: 8.5, leading: 13)
            note("Typed text counts 1 for each character typed on the Mac’s own keyboard or an Apple keyboard, 0.6 on another keyboard, and 0 when pasted, imported or dictated. "
                + "Typing checks are the proof’s seven typing rules. Touch ID counts the checks answered within 10 seconds" + (r.touch.asked > 0 ? "." : "; none were needed for this page."))
            // The nine rules in two columns, read down: a check for each one met, a cross for each one missed.
            let perColumn = (PageReport.rulesMet.count + 1) / 2
            top += 12
            need(16 + CGFloat(perColumn) * 17)
            label("Writing rules, from the proof", margin, top)
            top += 14
            for (index, name) in PageReport.rulesMet.enumerated() {
                let met = r.rules[index], x = margin + CGFloat(index / perColumn) * content / 2, y = top + CGFloat(index % perColumn) * 17
                let center = CGPoint(x: x + 5, y: y + 6.5)
                if met { stroke([[CGPoint(x: -3, y: 0), CGPoint(x: -1, y: 2.2), CGPoint(x: 3.2, y: -2.4)]], at: center, Ink.green) }
                else { stroke([[CGPoint(x: -2.6, y: -2.6), CGPoint(x: 2.6, y: 2.6)], [CGPoint(x: -2.6, y: 2.6), CGPoint(x: 2.6, y: -2.6)]], at: center, Ink.amber) }
                text(name, x + 16, y + 2.5, sans(9), met ? Ink.text : Ink.amber)
                if !met { text("not met", x + 16 + measure(name, sans(9)) + 6, y + 3.5, sans(7.5), Ink.amber) }
            }
            top += CGFloat(perColumn) * 17 + 4
            rule(top)

            // ——— The writing session: who, when and where ———
            heading("Writing session", 70)
            if let writer = r.writer { row("Writer", [plain(writer), aside("not part of the proof")]) }
            row("When", [plain(written), aside("writer’s Mac clock")])
            row("Where", [Run(text: "Huma for Mac", font: sans(9), url: reference("download")?.url)] + cite("download") + [aside("signing key in the Mac’s Secure Enclave")])
            for (name, figure) in r.session { row(name, [plain(figure)]) }

            // ——— The zero-knowledge proof ———
            heading("Zero-knowledge proof", 200)
            row("Proof system", [Run(text: "Noir", font: sans(9), url: reference("noir")?.url)] + cite("noir") + [plain(", UltraHonk on "),
                Run(text: "Barretenberg", font: sans(9), url: reference("barretenberg")?.url)] + cite("barretenberg"))
            row("Proof file", [plain("Huma-evidence.json  ·  \(r.fileSize)  ·  attached to this PDF")])
            row("Proofs", [plain("\(r.parts)")] + (r.parts > 1 ? [aside("\(r.parts - 1) session parts and the whole page")] : []))
            row("Proof SHA-256", [hash(r.fingerprint)])
            row("Text SHA-256", [hash(r.textHash), aside("Appendix A")])
            row("Signing key SHA-256", [hash(r.signingKey)])

            // ——— How Huma works ———
            heading("How Huma works", 90)
            top += 10
            let workings: [[Run]] = [
                [Run(text: "Records. ", font: bold(9.5)), Run(text: "Huma for Mac records every key press and signs the record with a key that never leaves the Mac’s Secure Enclave")]
                    + cite("enclave", size: 9.5) + [Run(text: ". Touch ID checks for a fingerprint this Mac knows when writing starts and at random times during it.")],
                [Run(text: "Proves. ", font: bold(9.5)), Run(text: "A zero-knowledge proof")] + cite("noir", size: 9.5) + cite("barretenberg", size: 9.5)
                    + [Run(text: " replays the writing and checks the nine rules. It doesn’t reveal the key presses.")],
                [Run(text: "Checks. ", font: bold(9.5)), Run(text: "Your browser checks the proof, the signatures and the text itself. Huma’s server is not trusted for the result.")]]
            for (index, runs) in workings.enumerated() {
                let list = lines(runs, content - 18)
                need(CGFloat(list.count) * 14 + 5)
                text("\(index + 1).", margin, top + 2.5, sans(9.5), Ink.grey)
                top += draw(list, margin + 18, top, size: 9.5, leading: 14) + 5
            }

            // ——— How to check ———
            heading("How to check", 100)
            // The code opens the shared page, where the proof is checked; a page that isn't shared gets no code.
            let qrSize: CGFloat = r.link != nil ? 70 : 0, stepsRoom = content - (qrSize > 0 ? qrSize + 24 : 0)
            var steps: [[Run]] = []
            if r.link != nil {
                steps.append([Run(text: "Open the shared page")] + cite("page", size: 9.5) + [Run(text: " or scan the code.")])
            }
            steps.append([Run(text: "Drop this PDF into Huma Verify")] + cite("verify", size: 9.5) + [Run(text: ".")])
            need(qrSize + 30)
            top += 10
            let stepsTop = top
            for (index, runs) in steps.enumerated() {
                text("\(index + 1).", margin, top + 2.5, sans(9.5), Ink.grey)
                top += draw(lines(runs, stepsRoom - 18), margin + 18, top, size: 9.5, leading: 14) + 5
            }
            if let shared = r.link {
                let qrRect = CGRect(x: width - margin - qrSize, y: stepsTop, width: qrSize, height: qrSize)
                if let code = PageReport.qrCode(shared)?.cgImage(forProposedRect: nil, context: nil, hints: nil) {
                    context.interpolationQuality = .none
                    context.draw(code, in: CGRect(x: qrRect.minX, y: height - qrRect.maxY, width: qrSize, height: qrSize))
                }
                link(qrRect, shared)
                label("Shared page", qrRect.minX + (qrSize - labelSize("Shared page", size: 6)) / 2, qrRect.maxY + 6, size: 6)
                top = max(top, stepsTop + qrSize + 16)
            }

            // ——— References ———
            heading("References", 70)
            top += 6
            for item in r.references {
                let about = lines([Run(text: item.title, font: bold(8.5)), Run(text: " – " + item.about, font: sans(8.5), color: Ink.grey)], content - 26)
                let address = lines([Run(text: item.url, font: mono(7.5), url: item.url)], content - 26)
                need(CGFloat(about.count + address.count) * 12 + 6)
                text("[\(item.number)]", margin, top + 2, sans(8.5), Ink.grey)
                top += draw(about, margin + 26, top, size: 8.5, leading: 12)
                top += draw(address, margin + 26, top, size: 7.5, leading: 11) + 7
            }

            // ——— Appendix: the text ———
            newPage()
            text("A", margin, top, bold(11), Ink.quiet)
            text("The text", margin + 18, top, bold(11))
            top += 19; rule(top, Ink.text, 0.6); top += 8
            if r.paragraphs.contains(where: { $0.contains { $0.contains { $0.1 } } }) {
                fill(CGRect(x: margin, y: top + 1, width: 8, height: 8), Ink.tint)
                label("Pasted", margin + 12, top + 1.5)
                top += 14
            }
            top += 4
            let size: CGFloat = 10.5, leading: CGFloat = 16.5
            for paragraph in r.paragraphs {
                for runs in paragraph {
                    let list = lines(runs.map { Run(text: $0.0, font: sans(size), shaded: $0.1) }, content)
                    if list.isEmpty { top += leading; continue }
                    for pieces in list {
                        need(leading)
                        var x = margin
                        for piece in pieces {
                            if piece.run.shaded { fill(CGRect(x: x - 0.3, y: top + 1.5, width: piece.width + 0.6, height: leading - 2), Ink.tint) }
                            if !piece.space { text(piece.text, x, baseline: top + leading / 2 + size * 0.35, piece.font) }
                            x += piece.width
                        }
                        top += leading
                    }
                }
                top += 8
            }
            finishPage()
        }
    }

    /// Adds `file` to a PDF the Mac drew, as an attached file (as pdf-lib does on the web), by appending an update:
    /// the file, its file entry, a list naming it, and the catalog again pointing at that list.
    static func attach(_ file: Data, named name: String, to pdf: Data) throws -> Data {
        let tail = String(decoding: pdf.suffix(1024), as: UTF8.self)
        func number(_ pattern: String, in text: String) -> Int? {
            (try? NSRegularExpression(pattern: pattern)).flatMap { $0.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) }
                .flatMap { Range($0.range(at: 1), in: text) }.flatMap { Int(text[$0]) }
        }
        guard let size = number("/Size (\\d+)", in: tail), let root = number("/Root (\\d+) 0 R", in: tail),
              let previous = number("startxref\\s+(\\d+)", in: tail),
              let trailer = (try? NSRegularExpression(pattern: "trailer\\s*<<([\\s\\S]*?)>>\\s*startxref"))?.firstMatch(in: tail, range: NSRange(tail.startIndex..., in: tail)),
              let trailerRange = Range(trailer.range(at: 1), in: tail) else { throw HumaError.configuration("Couldn’t attach the proof to the report.") }
        let whole = String(decoding: pdf, as: UTF8.self)
        guard let start = whole.range(of: "\n\(root) 0 obj"), let end = whole.range(of: "endobj", range: start.upperBound..<whole.endIndex) else {
            throw HumaError.configuration("Couldn’t attach the proof to the report.")
        }
        var catalog = whole[start.upperBound..<end.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
        guard catalog.hasSuffix(">>"), !catalog.contains("/Names") else { throw HumaError.configuration("Couldn’t attach the proof to the report.") }
        let fileID = size, specID = size + 1, namesID = size + 2
        catalog = String(catalog.dropLast(2)) + " /Names << /EmbeddedFiles \(namesID) 0 R >> /AF [\(specID) 0 R] >>"
        let packed = try zlib(file)
        let date = { () -> String in
            let format = DateFormatter(); format.locale = Locale(identifier: "en_US_POSIX"); format.timeZone = TimeZone(identifier: "UTC")
            format.dateFormat = "yyyyMMddHHmmss"; return "D:" + format.string(from: Date()) + "Z"
        }()
        var out = pdf, offsets: [Int: Int] = [:]
        func object(_ id: Int, _ body: Data) {
            offsets[id] = out.count
            out.append(Data("\(id) 0 obj\n".utf8)); out.append(body); out.append(Data("\nendobj\n".utf8))
        }
        if out.last != 0x0A { out.append(0x0A) }
        var stream = Data("<< /Type /EmbeddedFile /Subtype /application#2Fjson /Filter /FlateDecode /Length \(packed.count) /Params << /Size \(file.count) /ModDate (\(date)) >> >>\nstream\n".utf8)
        stream.append(packed); stream.append(Data("\nendstream".utf8))
        object(fileID, stream)
        object(specID, Data("<< /Type /Filespec /F (\(name)) /UF (\(name)) /EF << /F \(fileID) 0 R >> /AFRelationship /Data /Desc (The page proof. Drop this PDF or the file into huma.social/verify.) >>".utf8))
        object(namesID, Data("<< /Names [(\(name)) \(specID) 0 R] >>".utf8))
        object(root, Data(catalog.utf8))
        let xref = out.count
        var table = "xref\n\(root) 1\n" + String(format: "%010d 00000 n \n", offsets[root]!) + "\(fileID) 3\n"
        for id in [fileID, specID, namesID] { table += String(format: "%010d 00000 n \n", offsets[id]!) }
        let kept = tail[trailerRange].replacingOccurrences(of: "/Size \(size)", with: "/Size \(namesID + 1)")
        table += "trailer\n<<\(kept) /Prev \(previous) >>\nstartxref\n\(xref)\n%%EOF\n"
        out.append(Data(table.utf8))
        return out
    }
    /// A zlib stream (what PDF's FlateDecode reads): Foundation's raw DEFLATE with zlib's header and Adler-32 check.
    private static func zlib(_ data: Data) throws -> Data {
        let deflated = try (data as NSData).compressed(using: .zlib) as Data
        var a: UInt32 = 1, b: UInt32 = 0
        for byte in data { a = (a + UInt32(byte)) % 65521; b = (b + a) % 65521 }
        var out = Data([0x78, 0x9C]); out.append(deflated)
        out.append(contentsOf: withUnsafeBytes(of: (b << 16 | a).bigEndian) { Array($0) })
        return out
    }

    static func qrCode(_ value: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(value.utf8); filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
              let image = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: image, size: NSSize(width: output.extent.width, height: output.extent.height))
    }


    /// The report's colors, fixed (it's always on white paper), the same as report-pdf.mjs.
    enum Ink {
        static func srgb(_ hex: Int) -> NSColor {
            NSColor(srgbRed: CGFloat(hex >> 16 & 255) / 255, green: CGFloat(hex >> 8 & 255) / 255, blue: CGFloat(hex & 255) / 255, alpha: 1)
        }
        static let text = srgb(0x1C1C1C), grey = srgb(0x5C5C5C), quiet = srgb(0x8A8A8A), line = srgb(0xDCDCDC), link = srgb(0x4F6579)
        static let green = srgb(0x2E6B49), amber = srgb(0x9A6314), shade = srgb(0xF7F6F5), tint = srgb(0xF4E4CA)
    }
}
