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

import AppKit

let arguments = CommandLine.arguments
guard arguments.count == 3 else {
    FileHandle.standardError.write(Data("usage: desktop_window <log file> <given text>\n".utf8))
    exit(2)
}
let given = arguments[2]

guard FileManager.default.createFile(atPath: arguments[1], contents: nil),
    let log = FileHandle(forWritingAtPath: arguments[1])
else {
    FileHandle.standardError.write(Data("desktop_window: the log could not be made\n".utf8))
    exit(2)
}

func hex(_ text: String) -> String {
    text.utf8.map { String(format: "%02x", $0) }.joined()
}

// A line that cannot be written ends the program: a log with a line missing would pass for one
// that says nothing happened.
func record(_ line: String) {
    do {
        try log.write(contentsOf: Data((line + "\n").utf8))
    } catch {
        FileHandle.standardError.write(
            Data("desktop_window: the log could not be written: \(error)\n".utf8))
        exit(3)
    }
}

final class Window: NSObject, NSApplicationDelegate, NSTextFieldDelegate {
    let window = NSWindow(
        contentRect: NSRect(x: 240, y: 240, width: 420, height: 80),
        styleMask: [.titled],
        backing: .buffered,
        defer: false
    )
    let field = NSTextField(frame: NSRect(x: 20, y: 24, width: 380, height: 28))
    var focused: Bool?

    func applicationDidFinishLaunching(_ notification: Notification) {
        window.title = "kalareach test window"
        field.stringValue = given
        field.isEditable = true
        field.delegate = self
        window.contentView?.addSubview(field)
        record("text \(hex(given))")

        let names = [
            NSApplication.didBecomeActiveNotification,
            NSApplication.didResignActiveNotification,
            NSWindow.didBecomeKeyNotification,
            NSWindow.didResignKeyNotification,
        ]
        for name in names {
            NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) {
                [weak self] _ in self?.report()
            }
        }
        // Local monitors see what reaches this application and nothing sent to another one.
        let kinds: NSEvent.EventTypeMask = [
            .keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .scrollWheel,
        ]
        NSEvent.addLocalMonitorForEvents(matching: kinds) { event in
            switch event.type {
            case .keyDown: record("key \(hex(event.characters ?? "")) \(event.keyCode)")
            case .scrollWheel: record("scroll")
            default: record("mouse \(event.type.rawValue)")
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
        Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            self?.report()
        }
    }

    // A text change is written once it is settled: text still being composed is marked text.
    func controlTextDidChange(_ notification: Notification) {
        if let view = field.currentEditor() as? NSTextView, view.hasMarkedText() {
            return
        }
        record("text \(hex(field.stringValue))")
    }

    // Makes the field editor take what is typed as it is typed. A person's settings can offer
    // inline predictions and rewrite what was typed (corrections, replacements, completions, quotes
    // and dashes), and either would put in the field a character that no key produced.
    func plain(_ editor: NSText) {
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
    func report() {
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
                editor.selectedRange = NSRange(location: (field.stringValue as NSString).length, length: 0)
            }
            focused = now
            record("focus \(now ? 1 : 0)")
        }
    }
}

let application = NSApplication.shared
application.setActivationPolicy(.regular)
let delegate = Window()
application.delegate = delegate
application.run()
