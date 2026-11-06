import AppKit
import SwiftUI
import HumaCore

@MainActor
final class EditorCommands: ObservableObject {
    weak var editor: HumaTextView?
    var persist: (() -> Void)?
    var requestLink: (() -> Void)?
    @Published var state = FormatState()
    /// Where the page's text came from (typed, pasted…), kept up to date as it changes.
    @Published var composition = TextProvenance.Composition()
    /// How many spelling and grammar suggestions the page has (GrammarChecker), and how to go to the next one.
    @Published var suggestions = 0
    var nextSuggestion: (() -> Void)?

    func style(_ style: String) {
        if style == "link" { requestLink?(); return }
        if let named = ["body": TextStyle.normal, "h1": .title, "h2": .heading1, "h3": .heading2, "code": .code][style] {
            setStyle(named); return
        }
        guard let editor else { return }
        editor.window?.makeFirstResponder(editor)
        let selection = editor.selectedRange()
        let storage = editor.textStorage!
        let before = editor.attributedString()
        let beforeTyping = editor.typingAttributes
        if ["bold", "italic"].contains(style) {
            let trait: NSFontTraitMask = style == "bold" ? .boldFontMask : .italicFontMask
            if selection.length == 0 {
                let font = editor.typingAttributes[.font] as? NSFont ?? .systemFont(ofSize: 17)
                let manager = NSFontManager.shared
                editor.typingAttributes[.font] = manager.traits(of: font).contains(trait)
                    ? manager.convert(font, toNotHaveTrait: trait) : manager.convert(font, toHaveTrait: trait)
            } else {
                let font = storage.attribute(.font, at: selection.location, effectiveRange: nil) as? NSFont ?? .systemFont(ofSize: 17)
                let remove = NSFontManager.shared.traits(of: font).contains(trait)
                storage.enumerateAttribute(.font, in: selection) { value, subrange, _ in
                    let current = value as? NSFont ?? .systemFont(ofSize: 17)
                    storage.addAttribute(.font, value: remove ? NSFontManager.shared.convert(current, toNotHaveTrait: trait)
                                         : NSFontManager.shared.convert(current, toHaveTrait: trait), range: subrange)
                }
            }
        } else if style == "underline" || style == "strike" {
            let key: NSAttributedString.Key = style == "underline" ? .underlineStyle : .strikethroughStyle
            let old = selection.length > 0 ? storage.attribute(key, at: selection.location, effectiveRange: nil) as? Int
                : editor.typingAttributes[key] as? Int
            let value = old == 1 ? 0 : 1
            if selection.length > 0 { storage.addAttribute(key, value: value, range: selection) }
            else { editor.typingAttributes[key] = value }
        } else if ["bullet", "number", "quote", "check"].contains(style) {
            let prefix = ["bullet": "• ", "number": "1. ", "quote": "> ", "check": "☐ "][style]!
            let start = (editor.string as NSString).paragraphRange(for: selection).location
            editor.pendingSource = "format-insert"
            defer { editor.pendingSource = "other" }
            editor.insertText(prefix, replacementRange: NSRange(location: start, length: 0))
        }
        if !["bullet", "number", "quote", "check"].contains(style) {
            registerFormattingUndo(editor: editor, content: before, typing: beforeTyping)
        }
        persist?()
        refreshSelection()
    }

    func registerFormattingUndo(editor: HumaTextView, content: NSAttributedString, typing: [NSAttributedString.Key: Any]) {
        editor.undoManager?.registerUndo(withTarget: self) { target in
            let current = editor.attributedString()
            let currentTyping = editor.typingAttributes
            target.registerFormattingUndo(editor: editor, content: current, typing: currentTyping)
            editor.textStorage?.setAttributedString(content)
            editor.typingAttributes = typing
            target.persist?()
        }
        editor.undoManager?.setActionName("Format")
    }

    func link(_ raw: String) {
        guard let editor, editor.selectedRange().length > 0,
              let url = URL(string: raw), ["https", "http", "mailto"].contains(url.scheme?.lowercased() ?? "") else { return }
        editor.textStorage?.addAttribute(.link, value: url, range: editor.selectedRange())
        persist?()
    }
}


struct RichTextEditor: NSViewRepresentable {
    @Binding var document: WritingDocument
    @ObservedObject var commands: EditorCommands
    @ObservedObject var captureSigner: CaptureSigner
    /// Called when someone edits a page that is not recording.
    var requestStart: () -> Void = {}
    var pasteRefused: () -> Void = {}
    var untypedRefused: (String) -> Void = { _ in }
    var keyRefused: () -> Void = {}
    var oversizedKeyRefused: () -> Void = {}
    var pausedRefused: () -> Void = {}
    /// Finished pages are view-only: they can be read, selected and copied, not changed.
    var readOnly = false
    var reportError: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        let text = HumaTextView(frame: .zero)
        text.isRichText = true
        text.importsGraphics = false
        text.allowsImageEditing = false
        text.allowsUndo = true
        text.isAutomaticQuoteSubstitutionEnabled = false
        text.isAutomaticDashSubstitutionEnabled = false
        text.isAutomaticTextReplacementEnabled = false
        text.isAutomaticLinkDetectionEnabled = false
        text.isAutomaticSpellingCorrectionEnabled = false
        // Text that arrives without key presses isn't typing: no Writing Tools, predictions or completions.
        text.isAutomaticTextCompletionEnabled = false
        text.inlinePredictionType = .no
        if #available(macOS 15.0, *) { text.writingToolsBehavior = .none }
        // Spelling and grammar are checked as you write: red and green underlines, as in other Mac apps. A suggestion
        // is never put in for you (it wouldn't be typed); choosing one selects the words and says what to type.
        text.isGrammarCheckingEnabled = true
        text.isContinuousSpellCheckingEnabled = true
        text.drawsBackground = false
        text.font = .systemFont(ofSize: 17)
        text.textColor = .labelColor
        text.textContainerInset = .zero
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineHeightMultiple = 1.3; paragraph.paragraphSpacing = 9
        text.defaultParagraphStyle = paragraph
        text.typingAttributes = [.font: NSFont.systemFont(ofSize: 17), .foregroundColor: NSColor.labelColor, .paragraphStyle: paragraph]
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.autoresizingMask = []
        text.textContainer?.widthTracksTextView = true
        text.textContainer?.containerSize = NSSize(width: 600, height: CGFloat.greatestFiniteMagnitude)
        text.setAccessibilityLabel("Writing editor")
        text.delegate = context.coordinator
        scroll.documentView = PaperView(textView: text)
        text.formatHandler = { [weak commands] action in commands?.style(action) }
        text.sampleHandler = { [weak coordinator = context.coordinator] event, kind in coordinator?.sample(event, kind: kind) }
        text.recordingIsActive = { [weak captureSigner] in captureSigner?.recording == true }
        text.isPaused = { [weak captureSigner] in captureSigner?.paused == true || captureSigner?.presencePending == true }
        text.pausedRefused = { [weak coordinator = context.coordinator] in coordinator?.parent.pausedRefused() }
        text.editingLocked = { [weak captureSigner] in captureSigner?.recording != true }
        text.startRequested = { [weak coordinator = context.coordinator] in coordinator?.parent.requestStart() }
        text.pasteRefused = { [weak coordinator = context.coordinator] in coordinator?.parent.pasteRefused() }
        text.untypedRefused = { [weak coordinator = context.coordinator] in coordinator?.parent.untypedRefused($0) }
        text.syntheticKeyRefused = { [weak coordinator = context.coordinator] in coordinator?.parent.keyRefused() }
        text.oversizedKeyRefused = { [weak coordinator = context.coordinator] in coordinator?.parent.oversizedKeyRefused() }
        commands.editor = text
        commands.persist = { [weak coordinator = context.coordinator] in coordinator?.persist() }
        let grammar = GrammarChecker(view: text)
        grammar.onChange = { [weak commands] count in Task { @MainActor in commands?.suggestions = count } }
        context.coordinator.grammar = grammar
        commands.nextSuggestion = { [weak coordinator = context.coordinator] in coordinator?.showNextSuggestion() }
        text.leadingMenuItems = { [weak coordinator = context.coordinator] index in coordinator?.suggestionItems(at: index) ?? [] }
        text.clicked = { [weak coordinator = context.coordinator] index in coordinator?.clicked(at: index) }
        context.coordinator.load(into: text)
        return scroll
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        context.coordinator.parent = self
        context.coordinator.refreshClock()
        // Suggestions are for a page that can still change.
        context.coordinator.grammar?.enabled = !readOnly
        guard let text = nsView.documentView as? HumaTextView else { return }
        text.inputPaused = captureSigner.presencePending || captureSigner.paused
        text.isEditable = !captureSigner.presencePending && !captureSigner.paused && !readOnly
        let placeholder = "Start typing…"
        if text.placeholder != placeholder { text.placeholder = placeholder; text.needsDisplay = true }
        if !exactTextEqual(text.string, document.draft.text) || context.coordinator.loadedRTF != document.draft.richText {
            context.coordinator.load(into: text)
        }
    }

    @MainActor
    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: RichTextEditor
        var loadedRTF: Data?
        var loading = false
        var grammar: GrammarChecker?
        /// The suggestion bubble over the words last clicked.
        let bubble = SuggestionBubbleController()
        /// Where each character came from, rebuilt from the session and then followed edit by edit.
        var provenance: TextProvenance?
        var provenanceSession = ""
        var startedAt = DispatchTime.now().uptimeNanoseconds
        var elapsedOffset: UInt64
        var activeSessionID: String
        init(_ parent: RichTextEditor) {
            self.parent = parent
            activeSessionID = parent.document.draft.session.id
            elapsedOffset = max(parent.document.draft.session.events.last?.elapsedMilliseconds ?? 0, parent.document.draft.session.inputSamples?.last?.elapsedMilliseconds ?? 0)
        }
        func refreshClock() {
            guard activeSessionID != parent.document.draft.session.id else { return }
            activeSessionID = parent.document.draft.session.id
            startedAt = DispatchTime.now().uptimeNanoseconds
            elapsedOffset = max(parent.document.draft.session.events.last?.elapsedMilliseconds ?? 0,
                                parent.document.draft.session.inputSamples?.last?.elapsedMilliseconds ?? 0)
        }
        func load(into text: HumaTextView) {
            loading = true
            defer { loading = false }
            if let data = parent.document.draft.richText,
               let attributed = try? NSAttributedString(data: data, options: [.documentType: NSAttributedString.DocumentType.rtf], documentAttributes: nil) {
                // Default-colored text is saved without a color (see `persist`), so it follows light and dark mode.
                let adapted = NSMutableAttributedString(attributedString: attributed)
                let whole = NSRange(location: 0, length: adapted.length)
                adapted.enumerateAttribute(.foregroundColor, in: whole) { value, range, _ in
                    if value == nil { adapted.addAttribute(.foregroundColor, value: NSColor.labelColor, range: range) }
                }
                // RTF can't name the system font: AppKit writes it as Helvetica Neue. Map it back.
                adapted.enumerateAttribute(.font, in: whole) { value, range, _ in
                    guard let font = value as? NSFont else { adapted.addAttribute(.font, value: EditorCommands.defaultFont, range: range); return }
                    guard font.familyName == "Helvetica Neue" else { return }
                    let traits = font.fontDescriptor.symbolicTraits
                    var system = NSFont.systemFont(ofSize: font.pointSize, weight: traits.contains(.bold) ? .bold : .regular)
                    if traits.contains(.italic) { system = NSFontManager.shared.convert(system, toHaveTrait: .italicFontMask) }
                    adapted.addAttribute(.font, value: system, range: range)
                }
                text.textStorage?.setAttributedString(adapted)
            } else {
                text.string = parent.document.draft.text
                text.textStorage?.addAttributes([.font: NSFont.systemFont(ofSize: 17), .foregroundColor: NSColor.labelColor,
                    .paragraphStyle: text.defaultParagraphStyle ?? NSParagraphStyle.default], range: NSRange(location: 0, length: (text.string as NSString).length))
            }
            loadedRTF = parent.document.draft.richText
            grammar?.textChanged()
            showProvenance(in: text)
        }
        func elapsedMilliseconds() -> UInt64 {
            refreshClock()
            return parent.captureSigner.elapsedMilliseconds(sessionID: activeSessionID)
                ?? (elapsedOffset + (DispatchTime.now().uptimeNanoseconds - startedAt) / 1_000_000)
        }
        func sample(_ event: NSEvent, kind: String) {
            guard !parent.captureSigner.presencePending, !parent.captureSigner.paused else { return }
            let elapsed = elapsedMilliseconds()
            var draft = parent.document.draft
            if (draft.session.inputSamples?.count ?? 0) < 100_000 {
                do {
                    try draft.session.recordSample(InputSample(kind: kind, keyCode: event.keyCode,
                        modifiers: event.modifierFlags.rawValue, elapsedMilliseconds: elapsed,
                        origin: event.cgEvent.map { InputOrigin(
                            sourceUnixProcessID: $0.getIntegerValueField(.eventSourceUnixProcessID),
                            sourceStateID: $0.getIntegerValueField(.eventSourceStateID),
                            keyboardType: $0.getIntegerValueField(.keyboardEventKeyboardType), isRepeat: event.isARepeat) }))
                    do { try parent.captureSigner.checkpoint(draft: &draft) }
                    catch { parent.reportError(error.localizedDescription) }
                    parent.document.draft = draft
                } catch { parent.reportError(error.localizedDescription) }
            }
        }
        func textDidChange(_ notification: Notification) { bubble.close(); persist(); grammar?.textChanged() }
        func textViewDidChangeSelection(_ notification: Notification) {
            parent.commands.refreshSelection(); grammar?.refresh()
            // The bubble stays while the caret or selection is on its words.
            if let shown = bubble.issue, let text = parent.commands.editor {
                let selection = text.selectedRange()
                if selection.location < shown.range.location || NSMaxRange(selection) > NSMaxRange(shown.range) { bubble.close() }
            }
        }
        /// Escape closes the bubble first.
        func textView(_ textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            guard bubble.issue != nil, selector == #selector(NSResponder.cancelOperation(_:)) || selector == #selector(NSTextView.complete(_:)) else { return false }
            bubble.close(); return true
        }
        /// A click in the text: if it landed on underlined words, their suggestion shows right above them.
        func clicked(at index: Int) {
            guard !parent.readOnly, let grammar, let text = parent.commands.editor else { return }
            grammar.caretPlaced()
            guard let issue = grammar.issue(at: index) else { bubble.close(); return }
            bubble.show(issue, typing: false, in: text, choose: { [weak self] in self?.show(issue) },
                        ignore: { [weak self] in self?.bubble.close(); self?.grammar?.ignore(issue) })
        }
        func suggestionItems(at index: Int) -> [NSMenuItem] {
            guard !parent.readOnly, let grammar else { return [] }
            return grammar.menuItems(at: index) { [weak self] issue in self?.show(issue) }
        }
        func showNextSuggestion() {
            guard let text = parent.commands.editor, let issue = grammar?.next(after: NSMaxRange(text.selectedRange())) else { return }
            show(issue)
        }
        /// Selects a suggestion's words and says, right above them, what to type. The fix is never put in for you.
        func show(_ issue: GrammarIssue) {
            guard let text = parent.commands.editor else { return }
            let string = text.string as NSString
            guard NSMaxRange(issue.range) <= string.length, string.substring(with: issue.range) == issue.original else { grammar?.refresh(); return }
            text.window?.makeFirstResponder(text)
            text.scrollRangeToVisible(issue.range)
            text.setSelectedRange(issue.range)
            bubble.show(issue, typing: true, in: text, choose: {}, ignore: { [weak self] in self?.bubble.close(); self?.grammar?.ignore(issue) })
        }
        func persist() {
            guard !loading, !parent.captureSigner.presencePending, let text = parent.commands.editor else { return }
            do {
                var draft = parent.document.draft
                let elapsed = elapsedMilliseconds()
                let before = draft.text
                try draft.updateText(text.string, source: text.pendingSource, elapsed: elapsed)
                // The title follows the first line until someone names the page themselves.
                if autoTitle(draft.title, previousText: before) { draft.title = suggestedTitle(draft.text) }
                let formatted = NSMutableAttributedString(attributedString: text.attributedString())
                let whole = NSRange(location: 0, length: formatted.length)
                formatted.enumerateAttribute(.foregroundColor, in: whole) { value, range, _ in
                    if (value as? NSColor) == NSColor.labelColor { formatted.removeAttribute(.foregroundColor, range: range) }
                }
                let rtf = try formatted.data(from: whole, documentAttributes: [.documentType: NSAttributedString.DocumentType.rtf])
                draft.richText = rtf
                do { try parent.captureSigner.checkpoint(draft: &draft) }
                catch { parent.reportError(error.localizedDescription) }
                loadedRTF = rtf
                parent.document.draft = draft
            } catch { parent.reportError(error.localizedDescription) }
            showProvenance(in: text)
        }
        /// Tints pasted text, so the writer sees what their page will mark as pasted, and keeps the breakdown current.
        func showProvenance(in text: NSTextView) {
            let session = parent.document.draft.session
            if provenance == nil || provenanceSession != session.id || (provenance?.applied ?? 0) > session.events.count {
                provenance = TextProvenance(session: session); provenanceSession = session.id
            } else { provenance?.catchUp(with: session) }
            guard let provenance, let layout = text.textLayoutManager, let content = layout.textContentManager else { return }
            layout.removeRenderingAttribute(.backgroundColor, for: layout.documentRange)
            // Only while the text matches what the session recorded (a page opened from elsewhere may not).
            if provenance.string == text.string {
                for range in provenance.ranges(of: .pasted) {
                    guard let start = content.location(content.documentRange.location, offsetBy: range.location),
                          let end = content.location(start, offsetBy: range.length), let textRange = NSTextRange(location: start, end: end) else { continue }
                    layout.addRenderingAttribute(.backgroundColor, value: NSColor.systemOrange.withAlphaComponent(0.2), for: textRange)
                }
            }
            let parts = provenance.composition
            if parent.commands.composition != parts { Task { @MainActor [commands = parent.commands] in commands.composition = parts } }
        }
    }
}

/// The writing as a sheet of paper on a desk, like Google Docs: a letter-proportioned page
/// centered in the scroll view, with margins, a soft shadow, and height that grows with the text.
final class PaperView: NSView {
    let textView: NSTextView
    private var paperRect = NSRect.zero
    private var tiling = false
    override var isFlipped: Bool { true }

    init(textView: NSTextView) {
        self.textView = textView
        super.init(frame: NSRect(x: 0, y: 0, width: 800, height: 1000))
        addSubview(textView)
        textView.postsFrameChangedNotifications = true
        NotificationCenter.default.addObserver(self, selector: #selector(tile), name: NSView.frameDidChangeNotification, object: textView)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func viewDidMoveToSuperview() {
        super.viewDidMoveToSuperview()
        guard let clip = superview as? NSClipView else { return }
        clip.postsFrameChangedNotifications = true
        NotificationCenter.default.addObserver(self, selector: #selector(tile), name: NSView.frameDidChangeNotification, object: clip)
        tile()
    }
    override func viewDidChangeEffectiveAppearance() { super.viewDidChangeEffectiveAppearance(); needsDisplay = true }

    @objc func tile() {
        guard !tiling, let clip = superview as? NSClipView else { return }
        tiling = true; defer { tiling = false }
        let width = clip.bounds.width, gutter: CGFloat = width < 600 ? 16 : 32
        let paperWidth = min(816, max(280, width - 2 * gutter))
        let margin = max(32, (paperWidth * 96 / 816).rounded())
        let x = ((width - paperWidth) / 2).rounded()
        let textWidth = paperWidth - 2 * margin
        if textView.frame.width != textWidth { textView.setFrameSize(NSSize(width: textWidth, height: textView.frame.height)) }
        textView.setFrameOrigin(NSPoint(x: x + margin, y: gutter + margin))
        let paperHeight = max(textView.frame.height + 2 * margin, (paperWidth * 11 / 8.5).rounded())
        paperRect = NSRect(x: x, y: gutter, width: paperWidth, height: paperHeight)
        let size = NSSize(width: width, height: max(paperHeight + 2 * gutter, clip.bounds.height))
        if frame.size != size { setFrameSize(size) }
        needsDisplay = true
    }

    override func draw(_ dirtyRect: NSRect) {
        Theme.canvasColor.setFill(); dirtyRect.fill()
        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = NSColor.black.withAlphaComponent(effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? 0.5 : 0.12)
        shadow.shadowBlurRadius = 6; shadow.shadowOffset = NSSize(width: 0, height: -1)
        shadow.set()
        Theme.paperColor.setFill(); paperRect.fill()
        NSGraphicsContext.restoreGraphicsState()
        Theme.paperEdge.setStroke()
        let edge = NSBezierPath(rect: paperRect.insetBy(dx: 0.5, dy: 0.5)); edge.lineWidth = 1; edge.stroke()
    }
    /// Clicking the page or the desk puts the cursor in the text, as in Docs.
    override func mouseDown(with event: NSEvent) {
        window?.makeFirstResponder(textView)
        if convert(event.locationInWindow, from: nil).y > textView.frame.maxY {
            textView.setSelectedRange(NSRange(location: (textView.string as NSString).length, length: 0))
        }
    }
}

/// A page title from its first line of text: up to eight words or 60 characters, list markers dropped.
func suggestedTitle(_ text: String) -> String {
    guard let line = text.split(whereSeparator: \.isNewline).map({ $0.trimmingCharacters(in: .whitespaces) }).first(where: { !$0.isEmpty }) else { return "" }
    var words = line.split(whereSeparator: \.isWhitespace).map(String.init)
    if let first = words.first, ["•", "☐", "☑", ">", "-", "*"].contains(first) || first.range(of: "^[0-9]+\\.$", options: .regularExpression) != nil { words.removeFirst() }
    var title = ""
    for word in words.prefix(8) {
        let next = title.isEmpty ? word : title + " " + word
        if next.count > 60 { break }
        title = next
    }
    return title.isEmpty ? String(line.prefix(60)) : title
}
/// True while the title is still automatic: empty, a placeholder ("Untitled 2"), or what the text suggested before.
func autoTitle(_ title: String, previousText: String) -> Bool {
    title.isEmpty || title.range(of: "^Untitled( [0-9]+)?$", options: .regularExpression) != nil || title == suggestedTitle(previousText)
}
