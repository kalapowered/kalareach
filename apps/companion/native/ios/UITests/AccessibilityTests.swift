//
//  Target sizes, Dynamic Type, contrast and what an accessibility audit finds (13.19).
//
//  Dynamic Type comes from a launch argument and the colour mode from the application's own debug
//  switch, so no setting of the phone is touched, and the audit is Xcode's own, run on the
//  application's screens: VoiceOver is not turned on. A finding is a finding about the product, and
//  a text that does not grow at the largest size is one, so the row stays open until it does.
//
//  The harness's own control strip and the debug build's result elements are not the product and
//  are left out of every audit and every size.
//

import XCTest

final class AccessibilityTests: HarnessTestCase {
    private static let largest = "UICTContentSizeCategoryAccessibilityXXXL"

    /// The screens a phone's person lands on, in the order they are reached from the first one.
    private enum Screen: String, CaseIterable {
        case attention = "the attention inbox"
        case sessions = "the session list"
        case conversation = "a session's conversation"
        case terminal = "a session's terminal"
        case hosts = "the hosts"
        case account = "the account"
    }

    private func go(to screen: Screen) {
        switch screen {
        case .attention:
            app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Attention'")).firstMatch.tap()
        case .sessions:
            app.buttons["Sessions"].tap()
        case .conversation:
            app.buttons["Sessions"].tap()
            app.buttons.matching(NSPredicate(format: "label CONTAINS 'Session 1'")).firstMatch.tap()
            XCTAssertTrue(composer.waitForExistence(timeout: 20))
        case .terminal:
            if !app.buttons["Terminal"].exists { go(to: .conversation) }
            app.buttons["Terminal"].tap()
            XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'cargo'")).firstMatch.waitForExistence(timeout: 20), "the terminal did not show")
        case .hosts:
            app.buttons["Hosts"].tap()
        case .account:
            app.buttons["Account"].tap()
        }
        Thread.sleep(forTimeInterval: 1.5)
    }

    /// A link that sits inside a sentence of the conversation is text, and a size the person sets
    /// for the text is the size of the link: it is not counted as a control that needs its own
    /// forty-four points. Each such link is named here, and is said when it is skipped.
    private static let linksInsideText: Set<String> = ["the reconnect notes"]

    /// Whether an element belongs to the product and not to the harness or the debug build.
    private func isThePage(_ element: XCUIElement?) -> Bool {
        guard let element else { return true }
        if element.identifier.hasPrefix("kr.probe.") { return false }
        let harness: Set<String> = ["Controls", "Lose contact", "Restore contact", "Hold sends", "Release sends", "Reset"]
        if harness.contains(element.label) || element.label.hasPrefix("Sends received") { return false }
        return true
    }

    /// The kinds of element a person touches to do something.
    private static let controls: Set<XCUIElement.ElementType> = [
        .button, .switch, .link, .textView, .textField, .searchField, .menuItem, .segmentedControl, .tab, .tabBar, .slider, .stepper, .toggle, .cell,
    ]

    private func start(size: String?, colour: String) {
        var arguments = ["-KRColourMode", colour]
        if let size { arguments += ["-UIPreferredContentSizeCategoryName", size] }
        launchHarness(arguments)
    }

    /// The three ways to attach something to a draft, each a label over a file input the page keeps
    /// hidden. The label is what a finger meets, so the label is measured.
    private static let attachmentLabels = ["Photo library", "Take a photo", "Files"]

    // MARK: Target sizes

    /// Every control a person is expected to touch is at least 44 by 44 points, at the default size.
    func testEveryControlIsAtLeastFortyFourPointsInBothDirections() {
        continueAfterFailure = true
        start(size: nil, colour: "light")
        for screen in Screen.allCases {
            go(to: screen)
            let controls = app.buttons.allElementsBoundByIndex + app.switches.allElementsBoundByIndex + app.textViews.allElementsBoundByIndex
            for control in controls where control.exists && isThePage(control) {
                let frame = control.frame
                // A one-point button is an input the page hides behind its own label, which a
                // finger cannot reach: the label beside it is the control, and is measured.
                guard frame.width > 4, frame.height > 4 else { continue }
                if Self.linksInsideText.contains(control.label) {
                    say("A11Y \(screen.rawValue): \(control.label) is a link inside a sentence, \(Int(frame.width)) by \(Int(frame.height)), and is not counted")
                    continue
                }
                if frame.width < 44 || frame.height < 44 {
                    say("A11Y \(screen.rawValue): \(control.label) is \(Int(frame.width)) by \(Int(frame.height))")
                    XCTFail("\(control.label) on \(screen.rawValue) is \(Int(frame.width)) by \(Int(frame.height)) points")
                }
            }
            if screen == .conversation {
                for name in Self.attachmentLabels {
                    let label = app.staticTexts[name].firstMatch
                    guard label.exists else {
                        XCTFail("the \(name) control is not on the conversation")
                        continue
                    }
                    let frame = label.frame
                    if frame.width < 44 || frame.height < 44 {
                        say("A11Y \(screen.rawValue): the \(name) control is \(Int(frame.width)) by \(Int(frame.height))")
                        XCTFail("the \(name) control on \(screen.rawValue) is \(Int(frame.width)) by \(Int(frame.height)) points")
                    }
                }
            }
        }
    }

    // MARK: The audit

    /// Xcode's accessibility audit on each screen, at the default size and the largest, in light and
    /// dark.
    func testTheAuditFindsNothingOnAnyScreenAtAnySizeInEitherColour() throws {
        continueAfterFailure = true
        for size in [nil, Self.largest] {
            for colour in ["light", "dark"] {
                start(size: size, colour: colour)
                for screen in Screen.allCases {
                    go(to: screen)
                    let setting = "\(size == nil ? "default" : "largest") size, \(colour)"
                    var notControls = 0
                    try app.performAccessibilityAudit(for: .all) { issue in
                        guard self.isThePage(issue.element) else { return true }
                        // The audit calls a line of text a small hit area. A line of text is not a
                        // control, and every control is measured by the test of sizes above, so a hit
                        // area finding about anything that is not a control is counted, not failed.
                        if issue.auditType == .hitRegion, !Self.controls.contains(issue.element?.elementType ?? .other) {
                            notControls += 1
                            return true
                        }
                        let element = issue.element
                        let frame = element.map { "\(Int($0.frame.width)) by \(Int($0.frame.height))" } ?? "no element"
                        self.say("A11Y \(screen.rawValue), \(setting): \(issue.compactDescription) | \(element?.elementType.rawValue ?? 0) '\(element?.label ?? "")' \(frame)")
                        return false
                    }
                    if notControls > 0 { say("A11Y \(screen.rawValue), \(setting): \(notControls) hit area findings about text, not counted") }
                }
            }
        }
    }

    // MARK: Growth

    /// A line of text is taller at the largest size than at the default one: the page follows the
    /// person's text size.
    func testTextGrowsAtTheLargestSize() throws {
        func measure(size: String?) throws -> (height: CGFloat, category: String) {
            start(size: size, colour: "light")
            go(to: .conversation)
            let line = app.staticTexts["Find why the reconnect test is flaky."]
            XCTAssertTrue(line.waitForExistence(timeout: 20))
            let element = probeElement("textsize")
            XCTAssertTrue(element.waitForExistence(timeout: 10), "the application did not say which text size it has")
            return (line.frame.height, element.value as? String ?? "")
        }
        let normal = try measure(size: nil)
        let large = try measure(size: Self.largest)
        say("A11Y text size asked for: \(large.category)")
        say("A11Y text height default=\(Int(normal.height)) largest=\(Int(large.height))")
        XCTAssertEqual(large.category, Self.largest, "the system did not give the application the size that was asked for")
        XCTAssertGreaterThan(large.height, normal.height * 1.3, "the text does not grow with the person's text size")
    }
}
