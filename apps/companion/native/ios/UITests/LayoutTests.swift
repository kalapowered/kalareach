//
//  Keyboard, rotation and safe areas, on the phone (13.05).
//
//  The software keyboard, the turn of the phone and the sensor housing are what a browser cannot
//  show. These put the composer under a real keyboard, turn the phone both ways, and compare what a
//  person has to touch with the real safe-area insets the application reports. The numbers are said
//  in lines, and the application renders its own picture at each step, which has no keyboard in it:
//  the keyboard is a window of its own, so its place is said in numbers.
//
//  Not covered, because each needs a setting or a device this phone is not to be changed for: input
//  method editors, reduced motion, screen readers and a physical keyboard.
//

import UIKit
import XCTest

final class LayoutTests: HarnessTestCase {
    override func setUp() {
        super.setUp()
        launchHarness(["-KRDeviceProbe", "shots"])
        resetPage()
        openFirstSession()
    }

    override func tearDown() {
        // The next test, and the person's phone, start upright.
        XCUIDevice.shared.orientation = .portrait
        super.tearDown()
    }

    /// The application never gave a reading the test could use.
    private struct NoReading: Error, CustomStringConvertible {
        var description: String { "the application never reported the way up it was turned to" }
    }

    private struct Insets {
        let top: CGFloat, left: CGFloat, bottom: CGFloat, right: CGFloat
        let orientation: String
    }

    /// A fresh reading of the safe-area insets and the way up the interface is, which the application
    /// takes when asked and numbers, so that a reading taken before the phone finished turning is not
    /// taken for the one after. It waits until a new reading names an orientation the caller accepts.
    private func insets(where accept: (String) -> Bool) throws -> Insets {
        var latest = Int(probeFacts("insets", timeout: 2)?["reading"] ?? "0") ?? 0
        let end = Date().addingTimeInterval(20)
        while Date() < end {
            post("to.kala.reach.probe.insets")
            Thread.sleep(forTimeInterval: 0.5)
            guard let facts = probeFacts("insets", timeout: 2), let reading = Int(facts["reading"] ?? ""), reading > latest else { continue }
            latest = reading
            let orientation = facts["orientation"] ?? "unknown"
            guard accept(orientation) else { continue }
            func value(_ key: String) -> CGFloat { CGFloat(Double(facts[key] ?? "") ?? -1) }
            return Insets(top: value("top"), left: value("left"), bottom: value("bottom"), right: value("right"), orientation: orientation)
        }
        throw NoReading()
    }

    /// What a person touches to use a session: the sections, the way back, the composer and Send.
    private func expectedControls() -> [(name: String, element: XCUIElement)] {
        [
            ("Sessions", app.buttons["Sessions"]),
            ("Attention", app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Attention'")).firstMatch),
            ("Hosts", app.buttons["Hosts"]),
            ("Account", app.buttons["Account"]),
            ("Back", app.buttons["Back to sessions"]),
            ("Composer", composer),
            ("Send", send),
        ]
    }

    /// Every control a person touches is there, whole on screen and outside the insets.
    private func checkControls(inset: Insets, name: String) {
        let window = app.windows.firstMatch.frame
        XCTAssertTrue(composer.exists, "no composer in \(name)")
        for (control, element) in expectedControls() {
            guard element.exists else {
                XCTFail("\(control) is missing in \(name)")
                continue
            }
            let frame = element.frame
            guard frame.width > 1, frame.height > 1 else {
                XCTFail("\(control) is \(Int(frame.width)) by \(Int(frame.height)) in \(name)")
                continue
            }
            // A point of slack: the system lays out in fractions of a point and reports frames rounded.
            guard window.insetBy(dx: -1, dy: -1).contains(frame) else {
                XCTFail("\(control) is not whole on the screen in \(name): \(frame) in \(window)")
                continue
            }
            XCTAssertGreaterThanOrEqual(frame.minX, inset.left - 1, "\(control) is in the left inset in \(name)")
            XCTAssertLessThanOrEqual(frame.maxX, window.width - inset.right + 1, "\(control) is in the right inset in \(name)")
            XCTAssertLessThanOrEqual(frame.maxY, window.height - inset.bottom + 1, "\(control) is in the bottom inset in \(name)")
            XCTAssertGreaterThanOrEqual(frame.minY, inset.top - 1, "\(control) is in the top inset in \(name)")
        }
    }

    func testTheComposerStaysAboveTheKeyboardAndSendWithIt() throws {
        shot("before the keyboard")
        composer.tap()
        let keyboard = app.keyboards.firstMatch
        XCTAssertTrue(keyboard.waitForExistence(timeout: 15), "the software keyboard did not come up")
        let screen = app.windows.firstMatch.frame
        // The keyboard slides up and the page moves for it, and both have to end: the keyboard's
        // frame is read until two readings a moment apart agree and it is on the screen.
        var board = keyboard.frame
        let settled = Date().addingTimeInterval(15)
        while Date() < settled {
            Thread.sleep(forTimeInterval: 0.4)
            let now = keyboard.frame
            if now == board, now.minY < screen.maxY { break }
            board = now
        }
        let field = composer.frame
        let sendFrame = send.frame
        say("LAYOUT keyboard minY=\(Int(board.minY)) height=\(Int(board.height))")
        // A keyboard that is not up (a hardware keyboard, or none) would pass every comparison below.
        #if targetEnvironment(simulator)
        if board.minY >= screen.maxY { throw XCTSkip("the simulator takes its keyboard from the Mac, so no software keyboard came up") }
        #endif
        XCTAssertGreaterThan(board.height, 100, "no software keyboard is on screen")
        XCTAssertLessThan(board.minY, screen.maxY - 100, "the keyboard is not on the screen")
        say("LAYOUT composer minY=\(Int(field.minY)) maxY=\(Int(field.maxY))")
        say("LAYOUT send minY=\(Int(sendFrame.minY)) maxY=\(Int(sendFrame.maxY))")
        XCTAssertLessThanOrEqual(field.maxY, board.minY + 1, "the composer is under the keyboard")
        XCTAssertLessThanOrEqual(sendFrame.maxY, board.minY + 1, "Send is under the keyboard")
        XCTAssertGreaterThanOrEqual(field.minY, 0, "the composer is off the top of the screen")
        shot("keyboard up")
    }

    func testTheScreenHoldsInBothLandscapesAndNoControlSitsInASafeAreaInset() throws {
        shot("portrait")
        let portrait = try insets { $0 == "portrait" }
        say("LAYOUT portrait insets top=\(Int(portrait.top)) left=\(Int(portrait.left)) bottom=\(Int(portrait.bottom)) right=\(Int(portrait.right))")
        checkControls(inset: portrait, name: "portrait")
        var seen: [String] = []
        for (name, orientation) in [("landscape left", UIDeviceOrientation.landscapeLeft), ("landscape right", .landscapeRight)] {
            XCUIDevice.shared.orientation = orientation
            eventually("the application to turn to \(name)") { app.frame.width > app.frame.height }
            // The second turn is to the other landscape, which the application says by its own
            // orientation changing, not by a wait that is already over.
            let inset = try insets { $0.hasPrefix("landscape") && !seen.contains($0) }
            seen.append(inset.orientation)
            shot(name)
            say("LAYOUT \(name) is \(inset.orientation), insets top=\(Int(inset.top)) left=\(Int(inset.left)) bottom=\(Int(inset.bottom)) right=\(Int(inset.right))")
            checkControls(inset: inset, name: name)
        }
        XCUIDevice.shared.orientation = .portrait
        eventually("the application to turn upright") { app.frame.height > app.frame.width }
        XCTAssertTrue(composer.waitForExistence(timeout: 10), "no composer once upright")
        shot("portrait again")
    }

    func testADoubleTapSelectsAWordAndOffersToCopyIt() {
        type("alpha beta gamma")
        let field = composer.frame
        // The middle of the second word: the text starts about 13 points inside the field.
        let beta = composer.coordinate(withNormalizedOffset: CGVector(dx: (13 + 82) / field.width, dy: 0.25))
        beta.doubleTap()
        XCTAssertTrue(
            app.menuItems["Copy"].waitForExistence(timeout: 10),
            "a double tap did not select a word and offer Copy"
        )
        say("LAYOUT a double tap offers Copy")
    }
}
