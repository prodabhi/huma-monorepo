import AppKit

public final class HumaTextView: NSTextView {
    /// What caused the next text change: key presses ("typing", or "typing-external" while a non-Apple keyboard is
    /// plugged in), undo, input methods and list buttons, which Huma counts as typing, and "paste". Anything else,
    /// such as Writing Tools, predictions, spelling menus or other apps, stays "other" (and is refused while recording).
    public var pendingSource = "other"
    public var formatHandler: ((String) -> Void)?
    public var sampleHandler: ((NSEvent, String) -> Void)?
    public var inputPaused = false
    /// Evaluated at the input boundary, so a recording-state change takes effect
    /// before SwiftUI has refreshed the represented view.
    public var recordingIsActive: () -> Bool = { false }
    /// Paused (a break, or a Touch ID check in progress), read at the input boundary like recordingIsActive.
    public var isPaused: () -> Bool = { false }
    public var pausedRefused: (() -> Void)?
    /// Outside a recording the text is read-only: the first edit asks to start one instead,
    /// so nothing typed in Huma is ever counted as imported.
    public var editingLocked: () -> Bool = { false }
    public var startRequested: (() -> Void)?
    public var pasteRefused: (() -> Void)?
    /// Text put in by something other than the keyboard while recording: a spelling or grammar suggestion,
    /// Replace, a service. It's refused (it would fail the page's "all typed" rule); the words it would have
    /// changed are selected, and this gets what to type instead.
    public var untypedRefused: ((String) -> Void)?
    /// Items put at the top of the right-click menu for the character clicked (Huma's grammar suggestions).
    public var leadingMenuItems: ((Int) -> [NSMenuItem])?
    /// A single click that leaves a caret (no selection), with where it landed: shows the suggestion for those words.
    public var clicked: ((Int) -> Void)?
    /// Keys sent by software (another app or a script) instead of a keyboard are dropped while recording.
    public var syntheticKeyRefused: (() -> Void)?
    /// Text one key press tried to add beyond `keyPressLimit`, such as an input method writing whole sentences.
    public var oversizedKeyRefused: (() -> Void)?
    /// The most one key press may add, in UTF-16 units. Typing adds one character; accents and Chinese or Japanese
    /// input add fewer characters than keys pressed, and a Japanese prediction adds a few. More is being written for you.
    public static let keyPressLimit = 16
    private var addedThisKey = 0
    public var isFromKeyboard: (NSEvent) -> Bool = HumaTextView.fromKeyboard
    /// The name of a plugged-in non-Apple keyboard (see KeyboardGuard), or nil. Typing is allowed while one is plugged
    /// in and labelled "typing-external", which counts for less in the page's score: Huma can't tell it from a device
    /// that types on its own.
    public var externalKeyboard: () -> String? = { KeyboardGuard.shared.blocked?.name }
    /// A keyboard's own events come from the HID system (state 1) with no sending process (pid 0);
    /// keys posted by another process carry that process's ID.
    public nonisolated static func fromKeyboard(_ event: NSEvent) -> Bool {
        guard let cg = event.cgEvent else { return false }
        return cg.getIntegerValueField(.eventSourceUnixProcessID) == 0 && cg.getIntegerValueField(.eventSourceStateID) == 1
    }
    private func refusedKey(_ event: NSEvent) -> Bool {
        guard recordingIsActive(), !isFromKeyboard(event) else { return false }
        if event.type == .keyDown { syntheticKeyRefused?() }
        return true
    }
    public var placeholder = "Start typing…"
    // Paste goes in, labelled "paste": the page shows what was pasted, and its score counts only typed text.
    private func pasteAllowed() -> Bool { !inputPaused }
    private func pasted<T>(blocked: T, _ operation: () -> T) -> T {
        guard pasteAllowed() else { return blocked }
        pendingSource = "paste"
        defer { pendingSource = "other" }
        return operation()
    }
    public override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        if string.isEmpty {
            (placeholder as NSString).draw(at: NSPoint(x: textContainerInset.width + 5, y: textContainerInset.height),
                withAttributes: [.font: NSFont.systemFont(ofSize: 17), .foregroundColor: NSColor.placeholderTextColor])
        }
    }
    public override func keyDown(with event: NSEvent) {
        if isPaused() { pausedRefused?(); return }
        guard !inputPaused, !refusedKey(event) else { return }
        if !editingLocked() { sampleHandler?(event, "down") }
        // Everything this key press changes, including autocorrect on space, is typing.
        pendingSource = externalKeyboard() == nil ? "typing" : "typing-external"
        addedThisKey = 0
        defer { pendingSource = "other" }
        super.keyDown(with: event)
    }
    /// Undo and redo, from ⌘Z or the Edit menu, only bring back this session's own edits.
    @objc public func undo(_ sender: Any?) { undoOrRedo { $0.undo() } }
    @objc public func redo(_ sender: Any?) { undoOrRedo { $0.redo() } }
    private func undoOrRedo(_ action: (UndoManager) -> Void) {
        guard !inputPaused, let manager = undoManager else { return }
        pendingSource = "undo-redo"
        defer { pendingSource = "other" }
        action(manager)
    }
    public override func keyUp(with event: NSEvent) {
        guard !inputPaused, !isPaused(), !refusedKey(event) else { return }
        if !editingLocked() { sampleHandler?(event, "up") }
        super.keyUp(with: event)
    }
    public override func paste(_ sender: Any?) {
        pasted(blocked: ()) { super.pasteAsPlainText(sender) }
    }
    public override func pasteAsPlainText(_ sender: Any?) {
        pasted(blocked: ()) { super.pasteAsPlainText(sender) }
    }
    public override func pasteAsRichText(_ sender: Any?) {
        pasted(blocked: ()) { super.pasteAsRichText(sender) }
    }
    public override func readSelection(from pboard: NSPasteboard) -> Bool {
        pasted(blocked: false) { super.readSelection(from: pboard) }
    }
    public override func readSelection(from pboard: NSPasteboard, type: NSPasteboard.PasteboardType) -> Bool {
        pasted(blocked: false) { super.readSelection(from: pboard, type: type) }
    }
    public override func performDragOperation(_ sender: any NSDraggingInfo) -> Bool {
        pasted(blocked: false) { super.performDragOperation(sender) }
    }
    public override func validateUserInterfaceItem(_ item: any NSValidatedUserInterfaceItem) -> Bool {
        if item.action == #selector(undo(_:)) { return !inputPaused && undoManager?.canUndo == true }
        if item.action == #selector(redo(_:)) { return !inputPaused && undoManager?.canRedo == true }
        return super.validateUserInterfaceItem(item)
    }
    public override func shouldChangeText(in affectedCharRange: NSRange, replacementString: String?) -> Bool {
        // A nil replacement is an attribute-only change (formatting), which never touches the text.
        // Nothing changes the text while paused: not keys, autocorrect, dictation or other apps.
        if replacementString != nil, isPaused() { return false }
        if replacementString != nil, editingLocked() {
            if pendingSource == "paste" { pasteRefused?() } else { startRequested?() }
            pendingSource = "other"
            return false
        }
        // Deletions (Cut) and input methods finishing a character (accent menu, Chinese or Japanese input) go
        // through as before; only inserted text that didn't come from a key press is refused.
        if let replacement = replacementString, !replacement.isEmpty, pendingSource == "other", !hasMarkedText(), recordingIsActive() {
            DispatchQueue.main.async { [weak self] in
                self?.setSelectedRange(affectedCharRange); self?.scrollRangeToVisible(affectedCharRange)
            }
            untypedRefused?(replacement)
            return false
        }
        // Everything one key press changes counts as typed, so it may add only a character's or a short word's worth.
        if let replacement = replacementString, ["typing", "typing-external", "input-method"].contains(pendingSource), recordingIsActive() {
            let added = max(0, replacement.utf16.count - affectedCharRange.length)
            if addedThisKey + added > Self.keyPressLimit { oversizedKeyRefused?(); return false }
            guard super.shouldChangeText(in: affectedCharRange, replacementString: replacementString) else { return false }
            addedThisKey += added
            return true
        }
        return super.shouldChangeText(in: affectedCharRange, replacementString: replacementString)
    }
    public override func insertText(_ insertString: Any, replacementRange: NSRange) {
        guard !inputPaused, !isPaused() else { return }
        if hasMarkedText() && pendingSource.hasPrefix("typing") { pendingSource = "input-method" }
        super.insertText(insertString, replacementRange: replacementRange)
    }
    public override func mouseDown(with event: NSEvent) {
        super.mouseDown(with: event)   // tracks the click or drag until the button goes up
        if event.clickCount == 1, selectedRange().length == 0 { clicked?(selectedRange().location) }
    }
    public override func menu(for event: NSEvent) -> NSMenu? {
        let menu = super.menu(for: event)
        let index = characterIndexForInsertion(at: convert(event.locationInWindow, from: nil))
        guard let menu, let items = leadingMenuItems?(index), !items.isEmpty else { return menu }
        for (offset, item) in (items + [.separator()]).enumerated() { menu.insertItem(item, at: offset) }
        return menu
    }
    public override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if event.modifierFlags.contains(.command), event.charactersIgnoringModifiers?.lowercased() == "v", recordingIsActive() {
            // The shortcut is handled before keyDown. Keep its down/up pair in the recorded key stream; the paste
            // itself goes through paste(_:), labelled "paste".
            if !inputPaused { sampleHandler?(event, "down") }
        }
        if isEditable, event.modifierFlags.contains(.command), let key = event.charactersIgnoringModifiers,
           let action = ["b": "bold", "i": "italic", "u": "underline", "k": "link"][key] {
            formatHandler?(action); return true
        }
        return super.performKeyEquivalent(with: event)
    }
}

