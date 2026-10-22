//
//  Pairing a phone with a real host, through the application's own screens (10.17, 10.36, 10.37,
//  10.38).
//
//  The host is a daemon on this machine that a script runs (`scripts/e2e-pairing-device.sh`). It
//  issues the invitations as pictures of their QR codes, which the script puts in the simulator's
//  photo library; this test presses the page's own controls, chooses the picture in the system's
//  picker and reads what the screen shows. Nothing here reaches the application except through
//  its screens, and every system prompt is answered by the button the person would press. The
//  cases run in the order their names give: a changed secret, then the pairing, then the other
//  service's code.
//
//  The script and this test talk through files in the directory `KR_PAIRING_DIR` names: the host
//  writes a picture, the script says when the picture is in the library (`<picture>.added`), and
//  the test says each phase it wants with `go-<phase>` and the host answers it with `done-<phase>`.
//
//  The paired phone is an owner device (10.52), and the last two cases are the host asking it to
//  confirm: a request of the host's own, and a second device the host would add. The phone's
//  ceremony is Face ID, which the script enrols on the simulator and matches when the test says
//  the system's prompt is wanted (`faceid-wanted`) and until it says it is done (`faceid-done`).
//

import XCTest

final class PairingTests: DeviceTestCase {
    private var directory: String { ProcessInfo.processInfo.environment["KR_PAIRING_DIR"] ?? "" }
    private let shots = "/tmp/kr-pair-phone"

    override func setUp() {
        super.setUp()
        XCTAssertFalse(directory.isEmpty, "KR_PAIRING_DIR names no directory")
        try? FileManager.default.createDirectory(atPath: shots, withIntermediateDirectories: true)
    }

    // MARK: The host's files

    private func path(_ name: String) -> String { directory + "/" + name }

    /// The port of the host's other service, which `ready.json` names.
    private func servicePort() -> Int {
        let data = Data(read("ready.json").utf8)
        let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        return object?["service_port"] as? Int ?? 0
    }

    private func touch(_ name: String) {
        FileManager.default.createFile(atPath: path(name), contents: Data("1\n".utf8))
    }

    private func read(_ name: String) -> String {
        (try? String(contentsOfFile: path(name), encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    /// Waits until the host has written `name`.
    private func waitFor(_ name: String, timeout: TimeInterval = 60) {
        eventually("the host to write \(name)", timeout: timeout) { FileManager.default.fileExists(atPath: path(name)) }
    }

    /// Asks the host for a phase and waits for its picture to be in the library.
    private func begin(_ phase: String, picture: String) {
        touch("go-\(phase)")
        waitFor("\(picture).png.added")
    }

    private func eventually(_ message: String, timeout: TimeInterval = 30, _ condition: () -> Bool) {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if condition() { return }
            Thread.sleep(forTimeInterval: 0.25)
        }
        // What the screen showed when the wait ended, for whoever reads the failure.
        let labels = app.staticTexts.allElementsBoundByIndex.prefix(40).map { $0.label }.joined(separator: " | ")
        screenshot("timeout")
        XCTFail("timed out waiting for: \(message); the screen shows: \(labels)")
    }

    // MARK: The page

    /// Whether some text of the page contains `text`.
    private func shows(_ text: String) -> Bool {
        app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", text)).firstMatch.exists
    }

    private func waitToShow(_ text: String, timeout: TimeInterval = 60) {
        eventually("the page to show \(text)", timeout: timeout) { shows(text) }
    }

    private func press(_ name: String, timeout: TimeInterval = 30) {
        let button = app.buttons[name].firstMatch
        XCTAssertTrue(button.waitForExistence(timeout: timeout), "no \(name) button on the page")
        button.tap()
    }

    private func screenshot(_ name: String) {
        let picture = XCUIScreen.main.screenshot().pngRepresentation
        try? picture.write(to: URL(fileURLWithPath: "\(shots)/ios-\(name).png"))
    }

    /// Opens the Hosts tab, which is where a phone pairs.
    private func openHosts() {
        launch()
        XCTAssertTrue(app.buttons["Hosts"].waitForExistence(timeout: 60), "the shell did not appear")
        // A tap that lands while the shell is still settling is not answered, so it is made again.
        for _ in 1...3 {
            app.buttons["Hosts"].tap()
            let end = Date().addingTimeInterval(20)
            while Date() < end {
                if shows("Pair with a host") { return }
                Thread.sleep(forTimeInterval: 0.25)
            }
        }
        XCTFail("the page never showed the pairing screen")
    }

    /// Chooses the newest picture in the system's photo picker. The picker is the system's, drawn in
    /// this application's window; its pictures are images that share one identifier, newest first.
    private func chooseTheNewestPicture() {
        press("Choose a photo")
        let newest = app.images.matching(identifier: "PXGGridLayout-Info").firstMatch
        XCTAssertTrue(newest.waitForExistence(timeout: 30), "the photo picker showed no picture")
        // The grid draws its pictures itself and reports none of them as hittable, so the tap goes to
        // the middle of the picture's box.
        newest.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
    }

    // MARK: Confirming

    /// Opens the Attention tab, where the host's requests wait.
    private func openAttention() {
        launch()
        let tab = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Attention'")).firstMatch
        XCTAssertTrue(tab.waitForExistence(timeout: 60), "the shell did not appear")
        for _ in 1...3 {
            tab.tap()
            let end = Date().addingTimeInterval(20)
            while Date() < end {
                if shows("Your hosts need your confirmation") || shows("Reading the inbox") || shows("Filter") { return }
                Thread.sleep(forTimeInterval: 0.25)
            }
        }
    }

    /// Presses the confirm button the host's request has, named for the phone's ceremony.
    private func pressConfirm() {
        press("Confirm with Face ID", timeout: 90)
    }

    /// The alert the phone draws before the system's ceremony, which says what is being confirmed.
    private func confirmAlert() -> XCUIElement {
        let alert = app.alerts.matching(NSPredicate(format: "label CONTAINS 'Confirm on this device'")).firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 30), "no alert asked the person to confirm")
        return alert
    }

    /// Waits until the review that was under way has ended, which is when the button that starts one
    /// can be pressed again.
    private func waitForTheReviewToEnd() {
        eventually("the review to end") { app.buttons["Confirm with Face ID"].firstMatch.isEnabled }
    }

    /// Goes on from the alert to Face ID, which the script sends a face that does not match, and
    /// cancels the system's sheet once it says the face was not recognised: Face ID was asked, did
    /// not know the person, and confirmed nothing. The first use of Face ID by this application asks
    /// the person once, in a prompt of the system that names the application: it is answered as the
    /// person would be.
    private func continueAndFailFaceID() {
        try? FileManager.default.removeItem(atPath: path("faceid-wanted"))
        try? FileManager.default.removeItem(atPath: path("faceid-done"))
        touch("faceid-nomatch")
        confirmAlert().buttons["Continue"].tap()
        touch("faceid-wanted")
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let end = Date().addingTimeInterval(90)
        var cancelled = false
        while Date() < end, !cancelled {
            if shows("Confirmed.") {
                XCTFail("confirmed with a face that did not match")
                break
            }
            let question = springboard.alerts.matching(NSPredicate(format: "label CONTAINS 'KalaReach'")).firstMatch
            if question.exists, question.buttons["OK"].exists {
                question.buttons["OK"].tap()
                say("PROMPT answered OK")
                continue
            }
            // The sheet offers "Try Face ID Again" once it has looked at a face and not known it.
            if springboard.buttons["Try Face ID Again"].firstMatch.exists, springboard.buttons["Cancel"].firstMatch.exists {
                screenshot("faceid-sheet")
                springboard.buttons["Cancel"].firstMatch.tap()
                cancelled = true
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        XCTAssertTrue(cancelled, "the system's Face ID sheet never said the face was not recognised")
        try? FileManager.default.removeItem(atPath: path("faceid-nomatch"))
        touch("faceid-done")
    }

    /// Goes on from the alert to Face ID, which the script then matches. The first use of Face ID
    /// by this application asks the person once, in a prompt of the system that names the
    /// application: it is answered as the person would, and nothing else of the system is touched.
    private func continueToFaceID() {
        try? FileManager.default.removeItem(atPath: path("faceid-wanted"))
        try? FileManager.default.removeItem(atPath: path("faceid-done"))
        confirmAlert().buttons["Continue"].tap()
        touch("faceid-wanted")
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let end = Date().addingTimeInterval(60)
        while Date() < end {
            if shows("Confirmed.") { break }
            let prompt = springboard.alerts.matching(NSPredicate(format: "label CONTAINS 'KalaReach'")).firstMatch
            if prompt.exists, prompt.buttons["OK"].exists {
                prompt.buttons["OK"].tap()
                say("PROMPT answered OK")
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        waitToShow("Confirmed.", timeout: 30)
        touch("faceid-done")
    }

    // MARK: The cases

    /// A direct invitation whose secret has one bit changed opens nothing, and the page says so.
    func test1AnInvitationWithAChangedSecretPairsNothing() {
        openHosts()
        begin("control", picture: "control")
        chooseTheNewestPicture()
        waitToShow("Invitation from a host")
        press("Pair")
        waitToShow("The invitation did not work")
        touch("control-done")
        waitFor("done-control")
        XCTAssertEqual(read("control-result.txt"), "candidate_locked=0", "the host locked a candidate on a changed secret")
        say("PAIRING a changed secret locked nothing")
    }

    /// The phone scans the host's invitation, shows the value the host shows, and is paired once the
    /// host approves it.
    func test2AScannedInvitationPairsAndShowsTheHostsValue() {
        openHosts()
        begin("direct", picture: "direct")
        chooseTheNewestPicture()
        waitToShow("Invitation from a host")
        screenshot("scanned-summary")
        press("Pair")
        waitToShow("Check this value on the host")
        waitFor("host-value.txt")
        let host = read("host-value.txt").replacingOccurrences(of: " ", with: "")
        // The page spells the value out for a screen reader, one character at a time.
        let spelled = host.map { String($0) }.joined(separator: " ")
        let first = String(spelled.prefix(7)), second = String(spelled.suffix(7))
        waitToShow("\(first), \(second)", timeout: 10)
        say("PAIRING the phone shows the host's value \(host)")
        screenshot("value")
        touch("approve")
        waitToShow("Paired with", timeout: 120)
        waitFor("done-direct")
        say("PAIRING the phone is paired")
        screenshot("paired")
    }

    /// A code QR that names another service raises the system's alert with that service's name before
    /// anything is contacted: Cancel contacts nothing, and accepting contacts that service once.
    func test3ACodeForAnotherServiceAsksBeforeAnythingIsContacted() {
        openHosts()
        begin("code", picture: "code")
        chooseTheNewestPicture()
        let alert = app.alerts.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 30), "no alert named the other service")
        XCTAssertTrue(alert.label.contains("Use another pairing service"), "the alert is not the question: \(alert.label)")
        screenshot("origin-alert")
        // The alert names the service the code names: the host's other service, on the port it says.
        let service = "https://127.0.0.1:\(servicePort())"
        let named = alert.staticTexts.matching(
            NSPredicate(format: "label CONTAINS %@", "This code belongs to \(service).")
        ).firstMatch
        XCTAssertTrue(named.exists, "the alert does not name \(service)")
        alert.buttons["Cancel"].tap()
        // Cancelling leaves nothing to pair with, and the host has seen no connection.
        eventually("the page to be back at its start") { !shows("Invitation") && !shows("Code for a host") }
        XCTAssertEqual(read("connections.txt"), "0", "a service was contacted before the person agreed")
        say("PAIRING cancelled: no connection")

        chooseTheNewestPicture()
        XCTAssertTrue(alert.waitForExistence(timeout: 30), "no alert the second time")
        alert.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Use '")).firstMatch.tap()
        waitToShow("Code for a host that uses")
        press("Pair")
        eventually("the service to be contacted once") { read("connections.txt") == "1" }
        say("PAIRING accepted: one connection")
        touch("code-done")
        waitFor("done-code")
    }

    /// The host asks its owner to confirm, and the phone is an owner device. The request is listed on
    /// Attention; the alert the phone draws first is cancelled, and then Face ID is shown a face that
    /// does not match and cancelled at the system's sheet. Neither confirms anything, and both leave
    /// the request listed and the invitation behind it refused; then the same request is confirmed
    /// with a face that matches and the host spends that confirmation on the invitation.
    func test4TheHostsRequestIsConfirmedWithFaceID() {
        openAttention()
        touch("go-confirm")
        waitFor("challenge.txt")
        waitToShow("Your hosts need your confirmation", timeout: 90)
        pressConfirm()
        let alert = confirmAlert()
        screenshot("confirm-alert")
        alert.buttons["Cancel"].tap()
        waitToShow("Not confirmed. Nothing changed.")
        waitForTheReviewToEnd()
        say("PAIRING the host's request is cancelled at the alert")
        // Past the alert, Face ID itself must run: a face that does not match confirms nothing.
        pressConfirm()
        continueAndFailFaceID()
        waitForTheReviewToEnd()
        say("PAIRING Face ID was asked, and a face that did not match confirmed nothing")
        touch("confirm-cancelled")
        waitFor("challenge-open.txt")
        XCTAssertTrue(read("challenge-open.txt").hasPrefix("unanswered=1"), "the cancelled request was answered: \(read("challenge-open.txt"))")
        touch("confirm-go")
        pressConfirm()
        continueToFaceID()
        waitFor("confirm-result.txt", timeout: 90)
        say("PAIRING the host's request is confirmed with Face ID")
        screenshot("confirmed")
    }

    /// A second device redeems an invitation, and the host asks the phone to confirm it against the
    /// value that device shows.
    func test5ANewDeviceIsConfirmedAgainstTheValueItShows() {
        openAttention()
        touch("go-device")
        waitFor("device-value.txt", timeout: 90)
        let value = read("device-value.txt").replacingOccurrences(of: " ", with: "")
        let spelled = value.map { String($0) }.joined(separator: " ")
        let first = String(spelled.prefix(7)), second = String(spelled.suffix(7))
        waitToShow("\(first), \(second)", timeout: 60)
        pressConfirm()
        continueToFaceID()
        waitFor("device-result.txt", timeout: 90)
        say("PAIRING a new device is confirmed against its value")
    }

    /// An invitation on the pasteboard is held through the system's question about pasting it. iOS
    /// asks the person once whether this application may read what another application copied, and
    /// the application is not in front while the question is up: what it was holding must not be
    /// let go of for that. The question is answered as the person would, and the invitation is then
    /// still there to pair with.
    func test6APastedInvitationIsHeldThroughTheSystemsPasteQuestion() {
        openHosts()
        touch("go-paste")
        waitFor("secrets-paste.txt")
        let text = read("secrets-paste.txt").components(separatedBy: "\n").first ?? ""
        XCTAssertFalse(text.isEmpty, "the host wrote no invitation to paste")
        UIPasteboard.general.string = text
        press("Paste invitation")
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        var asked = false
        let end = Date().addingTimeInterval(60)
        while Date() < end, !shows("Invitation from a host") {
            for owner in [springboard, app] {
                let allow = owner.buttons["Allow Paste"].firstMatch
                if allow.exists {
                    allow.tap()
                    asked = true
                }
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        say("PROMPT paste question \(asked ? "answered" : "not asked")")
        waitToShow("Invitation from a host", timeout: 30)
        // Still held once the question is gone: it is pressed, and the attempt starts and ends. The
        // phone is paired with this host already, so the attempt ends before the host is asked; what
        // matters is that "Pair" was there to press.
        press("Pair")
        waitToShow("Pairing did not finish")
        touch("paste-done")
        waitFor("done-paste")
        XCTAssertEqual(read("paste-result.txt"), "candidate_locked=0", "the host locked a candidate on a changed secret")
        say("PAIRING a pasted invitation was held through the system's paste question")
    }
}
