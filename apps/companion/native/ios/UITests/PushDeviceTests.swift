//
//  A phone's notifications on the simulator, from the system's side: the permission prompt, the
//  banner of each delivery and the tap on it.
//
//  The host and the gateway are a script's and a suite's (`scripts/e2e-push-device.sh`,
//  `kr-controller`'s `push_device`). The application is started here, after the script has put its
//  request in the application's data directory: it pairs with the host and turns notifications on
//  through the commands the page uses, and asks the system for permission when it gets that far,
//  which this test answers the way a person does. The script then hands the phone each message the
//  gateway sent, with `xcrun simctl push`, and for a delivery asks this test to read the system's
//  banner and, when it says so, to tap it.
//
//  The script and this test talk through files in the directory `KR_PUSH_DIR` names:
//
//  | File | Written by | Holds |
//  | --- | --- | --- |
//  | `go-app` | the script | nothing; the request is in place and the application may start |
//  | `app-running` | this test | nothing; the application is running |
//  | `want` | the script | `foreground` or `background`: where the application is to be |
//  | `is` | this test | where the application is now, once it has gone where `want` says |
//  | `banner-wanted-<n>` | the script | nothing; delivery `n` has been pushed |
//  | `banner-expect-<n>.txt` | the script | the words the banner is to carry |
//  | `banner-<n>.txt` | this test | what the banner said, or `none` |
//  | `tap-<n>` | the script | nothing; the banner is to be tapped |
//  | `tapped-<n>` | this test | what the application showed after the tap |
//  | `act-<k>` | the script | a verb: `choose`, `send` or `observe`; what the person does next |
//  | `acted-<k>` | this test | what the screen showed after the act |
//  | `finish` | the script | nothing; the run is over |
//

import XCTest

final class PushDeviceTests: DeviceTestCase {
    private var directory: String { ProcessInfo.processInfo.environment["KR_PUSH_DIR"] ?? "" }
    private let shots = "/tmp/kr-push-phone"
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")

    override func setUp() {
        super.setUp()
        XCTAssertFalse(directory.isEmpty, "KR_PUSH_DIR names no directory")
        try? FileManager.default.createDirectory(atPath: shots, withIntermediateDirectories: true)
    }

    // MARK: The script's files

    private func path(_ name: String) -> String { directory + "/" + name }

    private func exists(_ name: String) -> Bool { FileManager.default.fileExists(atPath: path(name)) }

    private func touch(_ name: String) {
        FileManager.default.createFile(atPath: path(name), contents: Data("1\n".utf8))
    }

    private func read(_ name: String) -> String {
        (try? String(contentsOfFile: path(name), encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private func write(_ name: String, _ text: String) {
        FileManager.default.createFile(atPath: path(name), contents: Data((text + "\n").utf8))
    }

    private func eventually(_ message: String, timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if condition() { return true }
            Thread.sleep(forTimeInterval: 0.25)
        }
        XCTFail("timed out waiting for: \(message)")
        return false
    }

    /// A line for whoever reads the run, kept beside the files the script reads.
    private func note(_ line: String) {
        let existing = read("test-notes.txt")
        write("test-notes.txt", existing + (existing.isEmpty ? "" : "\n") + line)
    }

    private func screenshot(_ name: String) {
        let picture = XCUIScreen.main.screenshot().pngRepresentation
        try? picture.write(to: URL(fileURLWithPath: "\(shots)/ios-\(name).png"))
    }

    // MARK: The run

    func testNotificationsAreTurnedOnAndEachBannerIsReadAndTapped() {
        guard eventually("the script to say the request is in place", timeout: 600, { exists("go-app") }) else { return }
        launch()
        // The page asks the system once the phone is paired and the steps reach it.
        let answered = answerPrompt(["Allow"], timeout: 240)
        XCTAssertTrue(answered, "the system never asked the person for permission to notify")
        touch("app-running")

        var served = Set<Int>()
        var acted = 0
        let end = Date().addingTimeInterval(1500)
        while !exists("finish") && Date() < end {
            // Where the application is to be is read from the application itself each time, since a
            // person's act brings it to the front without this loop having moved it.
            let wanted = read("want")
            let inFront = app.state == .runningForeground
            if wanted == "background" && inFront {
                // The person goes to another screen before going away, so that a tap on a notification
                // is seen to move the page to Attention and not to find it there already.
                let hosts = app.buttons.matching(NSPredicate(format: "label == 'Hosts'")).firstMatch
                var onHosts = false
                if hosts.waitForExistence(timeout: 10) {
                    hosts.tap()
                    onHosts = app.staticTexts.matching(NSPredicate(format: "label == 'Hosts'")).firstMatch.waitForExistence(timeout: 10)
                }
                note("left the page on Hosts: \(onHosts)")
                XCUIDevice.shared.press(.home)
                // The application may stay a background application with its audio mode and not be
                // suspended: either way it is not in front, and the banner is the system's.
                let gone = leftTheFront()
                note("went to the background: \(gone), state \(app.state.rawValue)")
                write("is", wanted)
            } else if wanted == "foreground" && !inFront {
                app.activate()
                XCTAssertTrue(app.wait(for: .runningForeground, timeout: 30), "the application did not come back")
                write("is", wanted)
            } else if !wanted.isEmpty && !exists("is") {
                write("is", wanted)
            }
            let act = acted + 1
            if exists("act-\(act)") {
                perform(read("act-\(act)"), act)
                acted = act
            }
            // The script numbers a banner by the message it came from, and not every message is a
            // delivery, so each `banner-wanted-<n>` it writes is served once, in whatever order.
            let wantedFiles = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            let numbers = wantedFiles.compactMap { name -> Int? in
                name.hasPrefix("banner-wanted-") ? Int(name.dropFirst("banner-wanted-".count)) : nil
            }
            if let next = numbers.filter({ !served.contains($0) }).min() {
                readBanner(next)
                served.insert(next)
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
    }

    /// Whether the application is out of the front. A `state` read in a loop is not always brought up
    /// to date after the Home button, so this asks XCTest to wait for the state to change, and takes
    /// the home screen showing the application's icon as the same thing.
    private func leftTheFront() -> Bool {
        if app.wait(for: .runningBackground, timeout: 20) || app.wait(for: .runningBackgroundSuspended, timeout: 5) {
            return true
        }
        return springboard.icons["KalaReach"].exists
    }

    // MARK: What the person does

    /// What the screen shows, in one line.
    private func screenText() -> String {
        app.staticTexts.allElementsBoundByIndex.prefix(80).map { $0.label }.joined(separator: " | ")
    }

    private func anyElement(labelled label: String, within root: XCUIApplication) -> XCUIElement {
        root.descendants(matching: .any).matching(NSPredicate(format: "label == %@", label)).firstMatch
    }

    /// Does one thing a person does with the notification and the Attention screen, and says what the
    /// screen showed after it.
    private func perform(_ verb: String, _ act: Int) {
        switch verb {
        case "choose":
            // The sheet of an earlier question may still be open, with this one in it.
            let yes = anyElement(labelled: "Yes", within: app)
            if !yes.exists {
                let item = app.buttons.matching(NSPredicate(format: "label CONTAINS 'A question is waiting for an answer'")).firstMatch
                guard item.waitForExistence(timeout: 30) else {
                    write("acted-\(act)", "no attention item: \(screenText())")
                    return
                }
                item.tap()
            }
            guard yes.waitForExistence(timeout: 30) else {
                write("acted-\(act)", "no Yes choice: \(screenText())")
                return
            }
            yes.tap()
            screenshot("chosen-\(act)")
            write("acted-\(act)", "chosen \(screenText())")
        case "send":
            let send = anyElement(labelled: "Send answer", within: app)
            guard send.waitForExistence(timeout: 30) else {
                write("acted-\(act)", "no Send answer button: \(screenText())")
                return
            }
            send.tap()
            // The answer is decided when the host has answered: the button goes, or the question is
            // said to be no longer waiting.
            let end = Date().addingTimeInterval(45)
            while Date() < end, send.exists,
                !app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'No longer waiting'")).firstMatch.exists
            {
                Thread.sleep(forTimeInterval: 0.25)
            }
            screenshot("sent-\(act)")
            write("acted-\(act)", "sent \(screenText())")
        case "observe":
            // The page says that a question the person had chosen an answer to, and had not sent,
            // was answered by someone else, and offers nothing to send.
            let send = anyElement(labelled: "Send answer", within: app)
            let said = { (words: String) -> Bool in
                app.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] %@", words)).firstMatch.exists
            }
            let end = Date().addingTimeInterval(60)
            while Date() < end, send.exists || !(said("no longer waiting") && said("answered by someone else") && said("You had chosen")) {
                Thread.sleep(forTimeInterval: 0.25)
            }
            screenshot("ended-\(act)")
            write("acted-\(act)", "\(send.exists ? "still offered" : "no longer offered") \(screenText())")
        default:
            write("acted-\(act)", "no such act")
        }
    }

    // MARK: A banner

    /// Reads the system's banner for delivery `n` and, when the script asks, taps it.
    private func readBanner(_ n: Int) {
        let expected = read("banner-expect-\(n).txt")
        let banner = springboard.descendants(matching: .any)
            .matching(NSPredicate(format: "label CONTAINS %@", expected)).firstMatch
        note("reading banner \(n) for \(expected)")
        guard banner.waitForExistence(timeout: 30) else {
            note("no banner \(n)")
            screenshot("no-banner-\(n)")
            write("banner-\(n).txt", "none")
            return
        }
        write("banner-\(n).txt", banner.label)
        screenshot("banner-\(n)")
        guard eventually("the script to say whether to tap", timeout: 30, { exists("tap-\(n)") || exists("no-tap-\(n)") }),
            exists("tap-\(n)")
        else { return }
        banner.tap()
        let opened = app.wait(for: .runningForeground, timeout: 30)
        // What the page shows once the application is in front: the attention screen shows the
        // question, which the banner never did.
        let shown = app.staticTexts.allElementsBoundByIndex.prefix(60).map { $0.label }.joined(separator: " | ")
        screenshot("tapped-\(n)")
        write("tapped-\(n)", "foreground=\(opened) shows=\(shown)")
    }
}
