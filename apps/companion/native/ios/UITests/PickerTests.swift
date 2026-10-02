//
//  The file pickers, the camera and the terminal's keys, with a person at the phone (13.17).
//
//  Each of Photo library, Take a photo and Files opens the system's own picker or camera, which this
//  test asserts and cancels by its own Cancel button, found by identifier only. Nothing is selected,
//  captured, read or kept, and no picture is taken while one is up. The camera's permission prompt is
//  answered, because it names this application and the test asked for the camera. A system Cancel
//  that has no identifier leaves that leg open and the person at the phone cancels it by hand.
//
//  The accessory row's modifier states are read by their labels. A key press made here is the
//  system's synthetic one; a physical keyboard is a different path and stays open.
//

import XCTest

final class PickerTests: HarnessTestCase {
    override func setUp() {
        super.setUp()
        launchHarness()
        resetPage()
        openFirstSession()
    }

    /// Opens one of the three attachment controls, asserts something came up, and cancels it.
    ///
    /// The control is a label over a file input: a tap on it raises the system's own menu of sources,
    /// which belongs to this application's window, and a tap on its entry raises the picker or the
    /// camera. The Cancel button is looked for by identifier only; a system Cancel that has none leaves
    /// the leg open and the person at the phone cancels it by hand.
    private func openAndCancel(_ control: String, entry: String?) throws {
        let label = app.staticTexts[control].firstMatch
        XCTAssertTrue(label.waitForExistence(timeout: 10), "no \(control) control")
        label.tap()
        // The camera control opens the camera at once on a phone that has one; the others raise the
        // menu of sources first.
        if let entry {
            let item = app.buttons[entry]
            XCTAssertTrue(item.waitForExistence(timeout: 10), "the menu of sources has no \(entry)")
            item.tap()
        }
        // The camera asks first, the first time.
        answerPrompt(["Allow", "OK"], timeout: 5)
        let cancel = app.buttons.matching(NSPredicate(format: "identifier == %@", "Cancel")).firstMatch
        guard cancel.waitForExistence(timeout: 20) else {
            #if targetEnvironment(simulator)
            if entry == nil { throw XCTSkip("the simulator has no camera") }
            #endif
            say("PICKER \(control) opened, and its Cancel has no identifier: the person at the phone cancels it by hand")
            throw XCTSkip("\(control) has no Cancel that can be told by identifier")
        }
        say("PICKER \(control) opened")
        cancel.tap()
        eventually("the application to be back in front", timeout: 20) {
            !app.buttons.matching(NSPredicate(format: "identifier == %@", "Cancel")).firstMatch.exists
        }
        XCTAssertEqual(draftText, "", "nothing was put on the draft")
        XCTAssertFalse(app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Remove '")).firstMatch.exists, "something was attached to the draft")
        say("PICKER \(control) cancelled")
    }

    func testThePhotoLibraryOpensAndIsCancelled() throws { try openAndCancel("Photo library", entry: "Photo Library") }
    func testTheFilePickerOpensAndIsCancelled() throws { try openAndCancel("Files", entry: "Choose Files") }
    func testTheCameraOpensAndIsCancelled() throws { try openAndCancel("Take a photo", entry: nil) }

    /// A modifier on the accessory row says which of its states it is in, and a tap changes it.
    func testAModifierKeySaysWhichStateItIsIn() throws {
        app.buttons["Terminal"].tap()
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'cargo'")).firstMatch.waitForExistence(timeout: 20))
        app.buttons["Take control"].tap()
        let field = app.textViews["Type to the program"]
        XCTAssertTrue(field.waitForExistence(timeout: 10), "control was not taken")
        field.tap()
        // A modifier is a switch on the page: it says which state it is in by its label, and its
        // value is whether it is held at all.
        let off = app.switches["Control, off"]
        XCTAssertTrue(off.waitForExistence(timeout: 10), "the accessory row does not show Control off")
        off.tap()
        let once = app.switches["Control, held for the next key"]
        XCTAssertTrue(once.waitForExistence(timeout: 10), "a tap on Control did not hold it for the next key")
        say("KEYS Control off, then held for the next key")
        once.tap()
        XCTAssertTrue(app.switches["Control, held"].waitForExistence(timeout: 10), "a second tap did not hold Control until released")
        say("KEYS Control held until released")
    }
}
