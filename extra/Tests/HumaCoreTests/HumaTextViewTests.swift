import AppKit
import XCTest
@testable import HumaCore

final class HumaTextViewTests: XCTestCase {
    @MainActor func testPasteGoesInWhileRecordingLabelledPaste() throws {
        let view = HumaTextView(frame: .zero)
        view.string = "Typed text"; view.recordingIsActive = { true }
        var labels: [String] = []
        let watcher = SourceWatcher(view: view) { labels.append($0) }
        view.textStorage?.delegate = watcher
        let board = NSPasteboard(name: .init("huma-paste-test-" + UUID().uuidString))
        defer { board.clearContents() }
        board.setString(" and pasted", forType: .string)
        view.setSelectedRange(NSRange(location: 10, length: 0))
        XCTAssertTrue(view.readSelection(from: board, type: .string))
        XCTAssertEqual(view.string, "Typed text and pasted"); XCTAssertEqual(labels, ["paste"])
        // Between key presses and pastes nothing is labelled typing, so Writing Tools or other apps can't pass as typed.
        XCTAssertEqual(view.pendingSource, "other")
    }
    @MainActor func testCommandVKeepsItsKeyPairWhileThePasteGoesIn() throws {
        let view = HumaTextView(frame: .zero); view.string = "Typed"
        view.recordingIsActive = { true }; view.isFromKeyboard = { _ in true }; view.externalKeyboard = { nil }
        var samples = [String](); view.sampleHandler = { _, kind in samples.append(kind) }
        let down = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command, timestamp: 1,
            windowNumber: 0, context: nil, characters: "v", charactersIgnoringModifiers: "v", isARepeat: false, keyCode: 9))
        let up = try XCTUnwrap(NSEvent.keyEvent(with: .keyUp, location: .zero, modifierFlags: .command, timestamp: 1.1,
            windowNumber: 0, context: nil, characters: "v", charactersIgnoringModifiers: "v", isARepeat: false, keyCode: 9))
        _ = view.performKeyEquivalent(with: down); view.keyUp(with: up)
        XCTAssertEqual(samples, ["down", "up"])
        view.pendingSource = "paste"; view.insertText(" pasted", replacementRange: NSRange(location: 5, length: 0))
        XCTAssertEqual(view.string, "Typed pasted")
    }
    @MainActor func testKeysSentBySoftwareAreDroppedWhileRecording() throws {
        let view = HumaTextView(frame: .zero); view.string = "Typed"
        var recording = true; view.recordingIsActive = { recording }
        var samples = [String](), refused = 0
        view.sampleHandler = { _, kind in samples.append(kind) }; view.syntheticKeyRefused = { refused += 1 }
        view.externalKeyboard = { nil }
        let down = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 1,
            windowNumber: 0, context: nil, characters: "a", charactersIgnoringModifiers: "a", isARepeat: false, keyCode: 0))
        let up = try XCTUnwrap(NSEvent.keyEvent(with: .keyUp, location: .zero, modifierFlags: [], timestamp: 1.1,
            windowNumber: 0, context: nil, characters: "a", charactersIgnoringModifiers: "a", isARepeat: false, keyCode: 0))
        // An event made in code has no keyboard behind it, like keys another app posts.
        XCTAssertFalse(HumaTextView.fromKeyboard(down))
        view.keyDown(with: down); view.keyUp(with: up)
        XCTAssertEqual(samples, []); XCTAssertEqual(refused, 1); XCTAssertEqual(view.string, "Typed")
        view.isFromKeyboard = { _ in true }
        view.keyDown(with: down); view.keyUp(with: up)
        XCTAssertEqual(samples, ["down", "up"])
        // A non-Apple keyboard plugged in doesn't block real keys: they're recorded (labelled "typing-external").
        view.externalKeyboard = { "Pro Micro" }; samples = []
        view.keyDown(with: down); view.keyUp(with: up)
        XCTAssertEqual(samples, ["down", "up"])
        view.externalKeyboard = { nil }
        recording = false; view.isFromKeyboard = HumaTextView.fromKeyboard; samples = []
        view.keyUp(with: up)
        XCTAssertEqual(samples, ["up"])
    }
    /// The evidence behind "keys from other programs are refused": a program can write process ID 0 and the
    /// keyboard's state into an event, but macOS replaces the ID with the sender's own when the event is sent.
    /// Events go only to this test's own process (postToPid), never to the app in front.
    @MainActor func testKeysSentByAProgramAreRefusedEvenWhenTheyClaimToBeTheKeyboard() throws {
        guard CGPreflightPostEventAccess() else { throw XCTSkip("Needs permission to send events (Accessibility).") }
        _ = NSApplication.shared
        let source = CGEventSource(stateID: .hidSystemState)
        for (key, forgeState) in [(CGKeyCode(0), false), (1, true)] {
            let event = try XCTUnwrap(CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: true))
            event.setIntegerValueField(.eventSourceUnixProcessID, value: 0)
            if forgeState { event.setIntegerValueField(.eventSourceStateID, value: 1) }
            XCTAssertTrue(HumaTextView.fromKeyboard(try XCTUnwrap(NSEvent(cgEvent: event)))) // forged in memory
            event.postToPid(getpid())
            var arrived: NSEvent?
            let until = Date(timeIntervalSinceNow: 2)
            while arrived == nil, Date() < until {
                arrived = NSApp.nextEvent(matching: .keyDown, until: Date(timeIntervalSinceNow: 0.05), inMode: .default, dequeue: true)
            }
            let received = try XCTUnwrap(arrived?.cgEvent, "The posted key didn't arrive.")
            XCTAssertEqual(received.getIntegerValueField(.eventSourceUnixProcessID), Int64(getpid()))
            XCTAssertFalse(HumaTextView.fromKeyboard(try XCTUnwrap(arrived)))
        }
    }
    /// One key press counts as typed, so it may add only a character or a short word: an input method that writes
    /// whole sentences on a real key press can't pass its text off as typing.
    @MainActor func testOneKeyPressAddsAtMostAShortWord() throws {
        let view = HumaTextView(frame: .zero); view.string = "Hi"
        var refused = 0
        view.recordingIsActive = { true }; view.isFromKeyboard = { _ in true }; view.externalKeyboard = { nil }
        view.oversizedKeyRefused = { refused += 1 }
        view.pendingSource = "typing"
        // A Japanese prediction swaps a short reading for a longer phrase: allowed.
        XCTAssertTrue(view.shouldChangeText(in: NSRange(location: 0, length: 2), replacementString: "ありがとうございます"))
        // A sentence on one key press is refused, and so is the same sentence in pieces during that key press.
        XCTAssertFalse(view.shouldChangeText(in: NSRange(location: 2, length: 0), replacementString: "The quick brown fox jumps over the lazy dog."))
        XCTAssertFalse(view.shouldChangeText(in: NSRange(location: 2, length: 0), replacementString: "The quick brown"))
        XCTAssertEqual(refused, 2)
        // The next key press starts again.
        let down = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 1,
            windowNumber: 0, context: nil, characters: "a", charactersIgnoringModifiers: "a", isARepeat: false, keyCode: 0))
        view.keyDown(with: down); view.pendingSource = "typing"
        XCTAssertTrue(view.shouldChangeText(in: NSRange(location: 2, length: 0), replacementString: "The quick brown")); XCTAssertEqual(refused, 2)
        // Paste and undo aren't key presses; they're labelled and counted on their own.
        view.pendingSource = "paste"
        XCTAssertTrue(view.shouldChangeText(in: NSRange(location: 0, length: 0), replacementString: "The quick brown fox jumps over the lazy dog."))
    }
    /// Computer-use agents that don't send keys write through Accessibility instead; that text isn't typed and is refused.
    @MainActor func testTextWrittenThroughAccessibilityIsRefused() {
        let view = HumaTextView(frame: .zero); view.string = "Typed"
        var refused: [String] = []
        view.recordingIsActive = { true }; view.untypedRefused = { refused.append($0) }
        view.setSelectedRange(NSRange(location: 5, length: 0))
        view.setAccessibilitySelectedText(" by an agent")
        view.setAccessibilityValue("Replaced by an agent")
        XCTAssertEqual(view.string, "Typed"); XCTAssertEqual(refused.count, 2)
    }
    @MainActor func testNothingIsTypedWhilePaused() throws {
        let view = HumaTextView(frame: .zero); view.string = "Typed"
        view.recordingIsActive = { true }; view.isFromKeyboard = { _ in true }; view.externalKeyboard = { nil }
        var paused = true, refused = 0, samples = 0
        view.isPaused = { paused }; view.pausedRefused = { refused += 1 }; view.sampleHandler = { _, _ in samples += 1 }
        let down = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: 1,
            windowNumber: 0, context: nil, characters: "a", charactersIgnoringModifiers: "a", isARepeat: false, keyCode: 0))
        view.keyDown(with: down)
        view.insertText("x", replacementRange: NSRange(location: 5, length: 0))
        XCTAssertFalse(view.shouldChangeText(in: NSRange(location: 5, length: 0), replacementString: "y"))
        XCTAssertEqual(view.string, "Typed"); XCTAssertEqual(samples, 0); XCTAssertEqual(refused, 1)
        paused = false
        view.pendingSource = "typing" // a key press
        view.insertText("!", replacementRange: NSRange(location: 5, length: 0))
        XCTAssertEqual(view.string, "Typed!")
    }
    @MainActor func testSuggestionsAreNeverPutInWhileRecordingTheWriterTypesThem() {
        let view = HumaTextView(frame: .zero); view.string = "He go home."
        var recording = true, hints: [String] = []
        view.recordingIsActive = { recording }; view.untypedRefused = { hints.append($0) }
        // A grammar or spelling suggestion (or Replace, or a service) arrives without a key press.
        let go = NSRange(location: 3, length: 2)
        XCTAssertFalse(view.shouldChangeText(in: go, replacementString: "goes"))
        XCTAssertEqual(hints, ["goes"]); XCTAssertEqual(view.string, "He go home.")
        // Typing the fix over the same words is a normal typed edit, and cutting text still works as before.
        view.pendingSource = "typing"
        XCTAssertTrue(view.shouldChangeText(in: go, replacementString: "goes"))
        view.pendingSource = "other"
        XCTAssertTrue(view.shouldChangeText(in: go, replacementString: ""))
        // Outside a recording nothing is being proved, so it isn't refused here.
        recording = false
        XCTAssertTrue(view.shouldChangeText(in: go, replacementString: "goes"))
        XCTAssertEqual(hints, ["goes"])
    }
    @MainActor func testOnlyKeyPressesUndoInputMethodsAndListButtonsCountAsTypedInTheProof() {
        for source in ["typing", "typing-external", "undo-redo", "input-method", "format-insert"] {
            XCTAssertEqual(ExperimentalCompactRecorder.provedSource(source), "typing")
        }
        for source in ["other", "paste", "import"] { XCTAssertEqual(ExperimentalCompactRecorder.provedSource(source), source) }
    }
}

/// Records the editor's label for each text change, as the session log would.
@MainActor private final class SourceWatcher: NSObject, NSTextStorageDelegate {
    weak var view: HumaTextView?
    let seen: (String) -> Void
    init(view: HumaTextView, seen: @escaping (String) -> Void) { self.view = view; self.seen = seen }
    nonisolated func textStorage(_ textStorage: NSTextStorage, didProcessEditing editedMask: NSTextStorageEditActions, range: NSRange, changeInLength: Int) {
        guard editedMask.contains(.editedCharacters) else { return }
        MainActor.assumeIsolated { if let view { seen(view.pendingSource) } }
    }
}
