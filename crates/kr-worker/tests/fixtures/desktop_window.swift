// The application a hosted-runner case types into: one window with one text field, standing for a
// program the person is using that no disclosed check has any business with.
//
//   desktop_window <log file> <the text the field starts with>
//
// It writes one line to the log for each thing that reaches it, so what the checks did to it can be
// read back without asking the system anything:
//
//   text <hex>          the field's whole text, once at the start and again after each settled change
//   key <hex> <code>    a key pressed in this application, with the characters it produced
//   mouse <type>        a mouse button pressed in one of its windows
//   scroll              a scroll wheel turned over one of its windows
//   focus <0|1>         whether this application is active and its field is where typing goes
//
// Text is written as the hexadecimal of its UTF-8 bytes. Each line is written whole, so a reader
// takes the lines that end in a line feed and leaves a last one that does not.
//
// Nothing here is shared through a top-level binding: the log and the given text are handed to the
// object that uses them, and the statements at the end only start the program. That is what keeps
// the file valid for every Swift compiler and language mode that can build it.

import AppKit

func hex(_ text: String) -> String {
    text.utf8.map { String(format: "%02x", $0) }.joined()
}

func fail(_ message: String, status: Int32) -> Never {
    FileHandle.standardError.write(Data("desktop_window: \(message)\n".utf8))
    exit(status)
}

/// The log, one line at a time.
///
/// A line that cannot be written ends the program: a log with a line missing would pass for one
/// that says nothing happened.
final class Recorder {
    private let handle: FileHandle

    init(path: String) {
        guard FileManager.default.createFile(atPath: path, contents: nil),
            let handle = FileHandle(forWritingAtPath: path)
        else {
            fail("the log could not be made", status: 2)
        }
        self.handle = handle
    }

    func record(_ line: String) {
        do {
            try handle.write(contentsOf: Data((line + "\n").utf8))
        } catch {
            fail("the log could not be written: \(error)", status: 3)
        }
    }
}

@MainActor
final class Window: NSObject, NSApplicationDelegate, NSTextFieldDelegate {
    private let given: String
    private let recorder: Recorder
    private let window = NSWindow(
        contentRect: NSRect(x: 240, y: 240, width: 420, height: 80),
        styleMask: [.titled],
        backing: .buffered,
        defer: false
    )
    private let field = NSTextField(frame: NSRect(x: 20, y: 24, width: 380, height: 28))
    private var focused: Bool?

    init(given: String, recorder: Recorder) {
        self.given = given
        self.recorder = recorder
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        window.title = "kalareach test window"
        field.stringValue = given
        field.isEditable = true
        field.delegate = self
        window.contentView?.addSubview(field)
        recorder.record("text \(hex(given))")

        let names = [
            NSApplication.didBecomeActiveNotification,
            NSApplication.didResignActiveNotification,
            NSWindow.didBecomeKeyNotification,
            NSWindow.didResignKeyNotification,
        ]
        for name in names {
            NotificationCenter.default.addObserver(
                self, selector: #selector(stateChanged(_:)), name: name, object: nil)
        }
        // Local monitors see what reaches this application and nothing sent to another one.
        let kinds: NSEvent.EventTypeMask = [
            .keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .scrollWheel,
        ]
        _ = NSEvent.addLocalMonitorForEvents(matching: kinds) { [recorder] event in
            switch event.type {
            case .keyDown:
                recorder.record("key \(hex(event.characters ?? "")) \(event.keyCode)")
            case .scrollWheel:
                recorder.record("scroll")
            default:
                recorder.record("mouse \(event.type.rawValue)")
            }
            return event
        }

        window.makeKeyAndOrderFront(nil)
        _ = window.makeFirstResponder(field)
        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
        report()
        // The state is read again as well as on the notifications, because the field starts
        // editing a moment after the window becomes key and nothing announces that.
        Timer.scheduledTimer(
            timeInterval: 0.2, target: self, selector: #selector(tick(_:)), userInfo: nil,
            repeats: true)
    }

    @objc private func stateChanged(_ notification: Notification) {
        report()
    }

    @objc private func tick(_ timer: Timer) {
        report()
    }

    // A text change is written once it is settled: text still being composed is marked text.
    func controlTextDidChange(_ notification: Notification) {
        if let view = field.currentEditor() as? NSTextView, view.hasMarkedText() {
            return
        }
        recorder.record("text \(hex(field.stringValue))")
    }

    // Makes the field editor take what is typed as it is typed. A person's settings can offer
    // inline predictions and rewrite what was typed (corrections, replacements, completions, quotes
    // and dashes), and either would put in the field a character that no key produced.
    private func plain(_ editor: NSText) {
        guard let view = editor as? NSTextView else { return }
        if #available(macOS 14.0, *) {
            view.inlinePredictionType = .no
        }
        view.isAutomaticSpellingCorrectionEnabled = false
        view.isContinuousSpellCheckingEnabled = false
        view.isGrammarCheckingEnabled = false
        view.isAutomaticTextReplacementEnabled = false
        view.isAutomaticTextCompletionEnabled = false
        view.isAutomaticQuoteSubstitutionEnabled = false
        view.isAutomaticDashSubstitutionEnabled = false
        view.isAutomaticLinkDetectionEnabled = false
        view.isAutomaticDataDetectionEnabled = false
    }

    // Says whether typing now would land in the field. A field in a window that was not key when
    // it was made first responder starts editing only once the window is key, so it is asked
    // again here, where the window is. The insertion point is put at the end of the text each time
    // typing begins to land, so that what is typed adds to the given text and does not replace it.
    private func report() {
        if NSApp.isActive && window.isKeyWindow && field.currentEditor() == nil {
            _ = window.makeFirstResponder(field)
        }
        let editor = field.currentEditor()
        let now =
            NSApp.isActive && window.isKeyWindow
            && (window.firstResponder as AnyObject?) === (editor as AnyObject?) && editor != nil
        if now != focused {
            if now, let editor {
                plain(editor)
                editor.selectedRange = NSRange(
                    location: (field.stringValue as NSString).length, length: 0)
            }
            focused = now
            recorder.record("focus \(now ? 1 : 0)")
        }
    }
}

guard CommandLine.arguments.count == 3 else {
    fail("usage: desktop_window <log file> <given text>", status: 2)
}
// The program starts on the main thread, which is the main actor: Swift 6 treats the statements
// of this file that way and Swift 5 does not say so, and this makes both read the same.
MainActor.assumeIsolated {
    let delegate = Window(
        given: CommandLine.arguments[2], recorder: Recorder(path: CommandLine.arguments[1]))
    let application = NSApplication.shared
    application.setActivationPolicy(.regular)
    application.delegate = delegate
    application.run()
}
