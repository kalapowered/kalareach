//
//  What every device test shares: starting the application under test, reading what a device
//  check left on the application's own surface, answering the application's own permission
//  prompts, and saying what the test is doing in lines a script can follow.
//
//  The tests drive an installed copy of the application by its identifier and never read another
//  application. The two exceptions are named where they happen: the answer button of a prompt that
//  names this application, and the Cancel button of a system picker.
//

import CoreFoundation
import XCTest

let applicationIdentifier = "to.kala.reach"

/// The base of every device test.
class DeviceTestCase: XCTestCase {
    var app = XCUIApplication(bundleIdentifier: applicationIdentifier)

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        // A system alert that blocks a tap is handled here and nowhere else. The alert's title is
        // read first, and only one that names this application is answered: any other is handled
        // without a tap and the test is failed, so nothing here ever acts on another application's
        // prompt. A banner or anything that is not an alert is left to the system.
        addUIInterruptionMonitor(withDescription: "a prompt of the application under test") { [unowned self] element in
            guard element.elementType == .alert else { return false }
            guard element.label.contains("KalaReach") else {
                self.say("INTERRUPTION an alert that does not name the application was handled without a tap")
                XCTFail("an alert that does not name the application interrupted the test")
                return true
            }
            for name in self.promptAnswers where element.buttons[name].exists {
                element.buttons[name].tap()
                self.say("PROMPT answered \(name)")
                return true
            }
            return false
        }
    }

    #if targetEnvironment(simulator)
    /// On a simulator a failure leaves the application's tree and picture under /tmp, to find out
    /// what was on the screen. A device test never does: nothing of a real phone is kept.
    override func record(_ issue: XCTIssue) {
        let name = name.replacingOccurrences(of: " ", with: "-").filter { $0.isLetter || $0.isNumber || $0 == "-" }
        try? FileManager.default.createDirectory(atPath: "/tmp/kalareach-ui-failures", withIntermediateDirectories: true)
        try? app.debugDescription.write(toFile: "/tmp/kalareach-ui-failures/failure-\(name).txt", atomically: true, encoding: .utf8)
        try? app.screenshot().pngRepresentation.write(to: URL(fileURLWithPath: "/tmp/kalareach-ui-failures/failure-\(name).png"))
        super.record(issue)
    }
    #endif

    /// The buttons to press on a prompt of this application, in order of preference.
    var promptAnswers: [String] = ["Allow", "OK"]

    // MARK: Saying what is going on

    /// A line a script follows. Written as a test activity, which the test runner reports as the
    /// test runs, so a script reading its output sees each line when it happens.
    func say(_ line: String) {
        XCTContext.runActivity(named: "KR-\(line)") { _ in }
    }

    // MARK: Starting the application

    /// Starts the application afresh with these launch arguments.
    func launch(_ arguments: [String] = []) {
        if app.state != .notRunning { app.terminate() }
        app.launchArguments = arguments
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 30), "the application did not come to the front")
    }

    /// Starts the application in one of the debug build's device checks.
    func launch(probe mode: String, extra: [String] = []) {
        launch(["-KRDeviceProbe", mode] + extra)
    }

    // MARK: What a device check left

    /// The element a check shows its result on.
    func probeElement(_ name: String) -> XCUIElement {
        app.descendants(matching: .any).matching(identifier: "kr.probe.\(name)").firstMatch
    }

    /// What a check reported, as its facts, once it has reported.
    ///
    /// A check shows its result as one accessibility value of `key=value` pairs, so a test reads
    /// the whole of it in one go and never half of a result.
    func probeFacts(_ name: String, timeout: TimeInterval = 30) -> [String: String]? {
        let element = probeElement(name)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if element.exists, let value = element.value as? String, !value.isEmpty {
                return Self.facts(from: value)
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        return nil
    }

    static func facts(from value: String) -> [String: String] {
        var facts: [String: String] = [:]
        for pair in value.split(separator: ";") {
            guard let at = pair.firstIndex(of: "=") else { continue }
            facts[String(pair[..<at])] = String(pair[pair.index(after: at)...])
        }
        return facts
    }

    /// States each fact of a check as a line. A token is never a fact, and a nonce is only a digest.
    func sayFacts(_ name: String, _ facts: [String: String]) {
        for key in facts.keys.sorted() { say("FACT \(name) \(key)=\(facts[key] ?? "")") }
    }

    // MARK: The application's own permission prompts

    /// Answers a permission prompt that names this application, if one is showing.
    ///
    /// The prompt belongs to the system, so it is looked for in the system's own application, but
    /// only an alert whose title names this one, and only to press the named button.
    @discardableResult
    func answerPrompt(_ answers: [String], timeout: TimeInterval = 20) -> Bool {
        let system = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let alert = system.alerts.matching(NSPredicate(format: "label CONTAINS %@", "KalaReach")).firstMatch
        guard alert.waitForExistence(timeout: timeout) else { return false }
        for name in answers where alert.buttons[name].exists {
            alert.buttons[name].tap()
            say("PROMPT answered \(name)")
            return true
        }
        say("PROMPT showing, none of \(answers) found")
        return false
    }

    /// Posts a Darwin notification the application's debug build listens for. Nothing travels with it.
    func post(_ name: String) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(name as CFString),
            nil, nil, true
        )
    }

    // MARK: The application's own picture of itself

    /// Has the application render its own windows to a file, which a script copies out afterwards.
    ///
    /// The request is a notification the application listens for, so this test takes no screenshot
    /// of its own, and nothing but the application's own windows can be in the picture. The
    /// application numbers its pictures after those it already holds, so the test waits for the
    /// number to change rather than for a number it counted itself.
    func shot(_ step: String) {
        let element = probeElement("shots")
        let before = element.value as? String
        post("to.kala.reach.probe.shot")
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            if let now = element.value as? String, now != before, !now.isEmpty {
                say("SHOT \(now) \(step)")
                return
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        XCTFail("the application did not render its windows for \(step)")
    }
}
