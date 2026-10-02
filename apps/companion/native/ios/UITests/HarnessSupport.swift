//
//  Driving the application's own screens, in the build whose page is the test harness.
//
//  The harness build is the shipped phone shell on a scripted host, with a small control strip
//  that stands in for what a browser test does through the host's controls: contact lost and
//  regained, sends held and released, and what the page keeps of drafts and sends cleared. The
//  first thing every test asserts is that the strip is there, so a test never runs against the
//  product's own page and finds nothing.
//

import XCTest

class HarnessTestCase: DeviceTestCase {
    // MARK: What the page shows

    var composer: XCUIElement { app.textViews["Message this session"] }
    var send: XCUIElement { app.buttons["Send"] }

    /// What the field holds, without the space the keyboard's own correction adds to a word when the
    /// keyboard goes away. A field with nothing in it reports its placeholder as its value.
    var draftText: String {
        let value = composer.value as? String ?? ""
        return value == (composer.placeholderValue ?? "") ? "" : value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Whether a line of text is on the page, in whole or in part.
    func shows(_ text: String) -> Bool {
        app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch.exists
    }

    /// Whether a line of text is on the page as it is, and nothing more.
    func shows(exactly text: String) -> Bool {
        app.staticTexts.matching(NSPredicate(format: "label == %@", text)).firstMatch.exists
    }

    /// Waits for a condition, which is how the page is waited for: it answers when the host does.
    func eventually(_ message: String, timeout: TimeInterval = 30, _ condition: () -> Bool) {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if condition() { return }
            Thread.sleep(forTimeInterval: 0.25)
        }
        XCTFail("timed out waiting for: \(message)")
    }

    // MARK: Starting

    /// Starts the harness build and waits for its shell and its control strip.
    func launchHarness(_ arguments: [String] = []) {
        launch(arguments)
        XCTAssertTrue(
            app.buttons["Controls"].waitForExistence(timeout: 60),
            "no control strip: this is not the harness build"
        )
        XCTAssertTrue(app.buttons["Sessions"].waitForExistence(timeout: 30), "the shell did not appear")
    }

    /// Opens the first session.
    func openFirstSession() {
        app.buttons["Sessions"].tap()
        let row = app.buttons.matching(NSPredicate(format: "label CONTAINS 'Session 1'")).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 20), "no first session in the list")
        row.tap()
        XCTAssertTrue(composer.waitForExistence(timeout: 20), "the session did not open")
    }

    // MARK: The control strip

    /// Puts the software keyboard away, which the harness does when a finger lifts from text: with
    /// the keyboard up the system moves the page, and the strip with it, out of reach.
    func putTheKeyboardAway() {
        guard app.keyboards.firstMatch.exists else { return }
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.004, dy: 0.4)).tap()
        eventually("the keyboard to go", timeout: 10) { !app.keyboards.firstMatch.exists }
    }

    /// Opens the strip if it is closed. Whether it is open is read from the page, not remembered,
    /// and a tap that the page did not answer is made again, since a tap on a page can land while the
    /// page is busy.
    private func openStrip() {
        putTheKeyboardAway()
        for _ in 0..<3 where !app.buttons["Reset"].exists {
            app.buttons["Controls"].tap()
            _ = app.buttons["Reset"].waitForExistence(timeout: 4)
        }
        XCTAssertTrue(app.buttons["Reset"].exists, "the strip did not open")
    }

    private func closeStrip() {
        if app.buttons["Reset"].exists {
            app.buttons["Controls"].tap()
        }
    }

    /// Presses one of the strip's controls, which closes it again.
    func strip(_ name: String) {
        openStrip()
        let button = app.buttons[name]
        XCTAssertTrue(button.waitForExistence(timeout: 10), "the strip has no \(name)")
        button.tap()
    }

    /// Clears what the page keeps of drafts and sends and starts the page again.
    func resetPage() {
        strip("Reset")
        // The old page goes and the new one comes: its first screen is the one with the sections.
        // Nothing the page or the system says tells when a navigation inside the web view ended,
        // so this waits a fixed time, and the waits for the sections and the strip decide the rest.
        Thread.sleep(forTimeInterval: 2)
        XCTAssertTrue(app.buttons["Sessions"].waitForExistence(timeout: 30), "the page did not come back")
        XCTAssertTrue(app.buttons["Controls"].waitForExistence(timeout: 30))
    }

    /// How many composer sends the scripted host has received. A send is on its way to the host
    /// for a moment after the tap, so this waits a moment before it asks.
    func sendsReceived(settle: TimeInterval = 1.5) -> Int {
        Thread.sleep(forTimeInterval: settle)
        openStrip()
        let count = app.otherElements.matching(NSPredicate(format: "label BEGINSWITH 'Sends received'")).firstMatch
        XCTAssertTrue(count.waitForExistence(timeout: 10), "the strip does not say how many sends the host has")
        let label = count.label
        closeStrip()
        return Int(label.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? "") ?? -1
    }

    // MARK: Typing and sending

    /// Types at the end of what the field holds: a tap just right of the first line puts the cursor
    /// at the end of that line, and every draft these tests type is one line.
    func type(_ text: String) {
        composer.coordinate(withNormalizedOffset: CGVector(dx: 0.97, dy: 0.25)).tap()
        composer.typeText(text)
    }

    /// Sends what the field holds, and waits until the host says it has the send. A tap that the page
    /// did not answer is made again; a send the host already has leaves nothing to send, so a second
    /// tap can never be a second send.
    func sendTheDraft() {
        eventually("Send is enabled", timeout: 15) { send.isEnabled }
        // With the keyboard up Send lies under it, and a tap there is a tap on a key: the keyboard
        // goes first. Whether Send is within reach of a person who is typing is a question for the
        // layout tests, not for the tests that need a draft sent.
        putTheKeyboardAway()
        for _ in 0..<3 {
            send.tap()
            let end = Date().addingTimeInterval(6)
            while Date() < end {
                if sendsReceived(settle: 0.5) >= 1 { return }
            }
        }
        XCTFail("the host did not receive the send")
    }

    // MARK: Going away and coming back

    /// Sends the application to the background and waits until the system has suspended it, then
    /// brings it back to the front.
    func suspendAndReturn() {
        XCUIDevice.shared.press(.home)
        XCTAssertTrue(
            app.wait(for: .runningBackgroundSuspended, timeout: 90),
            "the system did not suspend the application"
        )
        app.activate()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 30))
    }
}
