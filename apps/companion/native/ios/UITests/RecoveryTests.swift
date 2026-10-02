//
//  Recovery after a suspension and a restart, on the phone (KR-ACC-012).
//
//  A phone suspends an application, ends it in the background and starts it cold, and a person's
//  draft has to be there when it comes back, and nothing may look done that is not. The host here is
//  scripted: it can hold a send, as a host does that has the request and has not answered it, and
//  it counts the sends it receives, so the tests can tell a send the host has from one it does not,
//  and a draft that was kept from one that was sent again. Every test starts from the strip's
//  reset, so none starts from another's leftovers.
//
//  What the tests prove is what the page does on a real phone's lifecycle. They prove nothing about
//  a real network or a real host.
//

import XCTest

final class RecoveryTests: HarnessTestCase {
    override func setUp() {
        super.setUp()
        launchHarness()
        resetPage()
        openFirstSession()
    }

    /// A send the host holds, a suspension, and contact lost and regained: the draft is kept and
    /// bound again, nothing looks done, and nothing is sent twice.
    func testASuspensionKeepsTheDraftBindsItAgainAndConfirmsNothing() {
        strip("Hold sends")
        type("draft one")
        sendTheDraft()
        XCTAssertEqual(sendsReceived(), 1, "the host has the send")
        XCTAssertEqual(draftText, "draft one", "the draft stays until the host answers")
        XCTAssertFalse(shows(exactly: "Applied"), "nothing is done yet")

        suspendAndReturn()
        strip("Lose contact")
        strip("Restore contact")

        // The recovery banner counts a draft that is still detached; once the host has said where its
        // conversation stands the draft is bound and only the action is left to report.
        eventually("the draft bound again") {
            shows("with no confirmed outcome") && !shows("kept")
        }
        say("STATE the draft is bound again")
        XCTAssertEqual(draftText, "draft one", "the draft is what it was")
        XCTAssertFalse(shows(exactly: "Applied"), "no success before the receipt")
        XCTAssertEqual(sendsReceived(), 1, "nothing was sent again")
        XCTAssertFalse(send.isEnabled, "sending again could run it twice")
        XCTAssertTrue(shows("One action has no confirmed outcome yet"), "and the page says why")

        strip("Release sends")
        eventually("the receipt applied") { shows(exactly: "Applied") }
        eventually("the composer cleared") { draftText.isEmpty }
        type("draft two")
        XCTAssertTrue(send.isEnabled, "a new draft can be sent, which only a draft bound again can")
        XCTAssertEqual(sendsReceived(), 1, "and nothing was sent")
    }

    /// What is typed while a send is in flight is the person's, and the answer does not take it.
    func testWhatIsTypedWhileASendIsInFlightSurvivesItsAnswer() {
        strip("Hold sends")
        type("first")
        sendTheDraft()
        XCTAssertEqual(sendsReceived(), 1)
        type(" and more")
        XCTAssertEqual(draftText, "first and more")

        strip("Release sends")
        eventually("the receipt applied") { shows(exactly: "Applied") }
        XCTAssertEqual(draftText, "first and more", "the next thing the person typed is not cleared")
    }

    /// The application is ended in the background and started cold: the draft and the action with
    /// no confirmed outcome are there, nothing looks done, and the new host has received nothing.
    func testARestartKeepsTheDraftAndTheActionWithNoConfirmedOutcome() {
        strip("Hold sends")
        type("draft one")
        sendTheDraft()
        XCTAssertEqual(sendsReceived(), 1)

        XCUIDevice.shared.press(.home)
        XCTAssertTrue(app.wait(for: .runningBackgroundSuspended, timeout: 90), "the system did not suspend the application")
        app.terminate()
        // The page's own records are kept, and the scripted host starts empty.
        launchHarness()
        openFirstSession()

        eventually("the action with no confirmed outcome") { shows("1 action with no confirmed outcome") }
        XCTAssertEqual(draftText, "draft one", "the draft came back")
        XCTAssertFalse(shows(exactly: "Applied"), "no success is shown")
        XCTAssertTrue(shows("no confirmed outcome yet"), "the hint is shown")
        // Once the host has said where the conversation stands the draft is bound again, and the guard
        // against a second send holds with nothing in flight: Send stays disabled.
        eventually("the draft bound again") { !shows("kept") }
        XCTAssertFalse(send.isEnabled, "sending again could run the action twice")
        XCTAssertEqual(sendsReceived(), 0, "the new host has received nothing")
    }
}
