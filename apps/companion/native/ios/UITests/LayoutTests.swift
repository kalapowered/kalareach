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

    /// The safe-area insets the application reports, after a picture was asked for.
    private func insets() throws -> (top: CGFloat, left: CGFloat, bottom: CGFloat, right: CGFloat) {
        let facts = try XCTUnwrap(probeFacts("insets", timeout: 10), "the application did not report its insets")
        func value(_ key: String) -> CGFloat { CGFloat(Double(facts[key] ?? "") ?? -1) }
        return (value("top"), value("left"), value("bottom"), value("right"))
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

    func testTheComposerStaysAboveTheKeyboardAndSendWithIt() throws {
        shot("before the keyboard")
        composer.tap()
        let keyboard = app.keyboards.firstMatch
        XCTAssertTrue(keyboard.waitForExistence(timeout: 15), "the software keyboard did not come up")
        Thread.sleep(forTimeInterval: 1) // the page moves for the keyboard, and its move has to end
        let board = keyboard.frame
        let field = composer.frame
        let sendFrame = send.frame
        say("LAYOUT keyboard minY=\(Int(board.minY)) height=\(Int(board.height))")
        say("LAYOUT composer minY=\(Int(field.minY)) maxY=\(Int(field.maxY))")
        say("LAYOUT send minY=\(Int(sendFrame.minY)) maxY=\(Int(sendFrame.maxY))")
        XCTAssertLessThanOrEqual(field.maxY, board.minY + 1, "the composer is under the keyboard")
        XCTAssertLessThanOrEqual(sendFrame.maxY, board.minY + 1, "Send is under the keyboard")
        XCTAssertGreaterThanOrEqual(field.minY, 0, "the composer is off the top of the screen")
        shot("keyboard up")
    }

    func testTheScreenHoldsInBothLandscapesAndNoControlSitsInASafeAreaInset() throws {
        shot("portrait")
        let portrait = try insets()
        say("LAYOUT portrait insets top=\(Int(portrait.top)) left=\(Int(portrait.left)) bottom=\(Int(portrait.bottom)) right=\(Int(portrait.right))")
        for (name, orientation) in [("landscape left", UIDeviceOrientation.landscapeLeft), ("landscape right", .landscapeRight)] {
            XCUIDevice.shared.orientation = orientation
            eventually("the application to turn to \(name)") { app.frame.width > app.frame.height }
            Thread.sleep(forTimeInterval: 1.5) // the page lays itself out again
            shot(name)
            let inset = try insets()
            say("LAYOUT \(name) insets top=\(Int(inset.top)) left=\(Int(inset.left)) bottom=\(Int(inset.bottom)) right=\(Int(inset.right))")
            let window = app.windows.firstMatch.frame
            XCTAssertTrue(composer.exists, "no composer in \(name)")
            for (control, element) in expectedControls() where element.exists {
                let frame = element.frame
                guard !frame.isEmpty, frame.width > 1, frame.height > 1 else { continue }
                // Only what is on screen: a control the page keeps scrolled out of view is not in an inset.
                guard frame.intersects(window) else { continue }
                XCTAssertGreaterThanOrEqual(frame.minX, inset.left - 1, "\(control) is in the left inset in \(name)")
                XCTAssertLessThanOrEqual(frame.maxX, window.width - inset.right + 1, "\(control) is in the right inset in \(name)")
                XCTAssertLessThanOrEqual(frame.maxY, window.height - inset.bottom + 1, "\(control) is in the bottom inset in \(name)")
            }
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
