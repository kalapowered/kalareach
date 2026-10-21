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

    private func touch(_ name: String) {
        FileManager.default.createFile(atPath: path(name), contents: Data("1\n".utf8))
    }

    private func read(_ name: String) -> String {
        (try? String(contentsOfFile: path(name), encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    /// Waits until the host has written `name`.
    private func waitFor(_ name: String, timeout: TimeInterval = 180) {
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
        XCTFail("timed out waiting for: \(message)")
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
    /// this application's window, and has no identifier for a picture but its position.
    private func chooseTheNewestPicture() {
        press("Choose a photo")
        let pictures = app.scrollViews.images
        XCTAssertTrue(pictures.firstMatch.waitForExistence(timeout: 30), "the photo picker showed no picture")
        // The library lists the newest picture last.
        pictures.element(boundBy: pictures.count - 1).tap()
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
        let named = alert.staticTexts.matching(NSPredicate(format: "label CONTAINS 'This code belongs to https://'")).firstMatch
        XCTAssertTrue(named.exists, "the alert does not name the service")
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
}
