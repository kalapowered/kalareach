//
//  What a session has to know about the way these tests run, before it relies on it.
//
//  Four things a script cannot read for itself: that what a test says reaches the script while the
//  test is still running, that pressing Home every ten seconds keeps the phone awake for as long as a
//  push leg needs, that the application's own picture of itself comes out of its container with the
//  page in it, and that a failing test leaves no picture or recording in its result even when every
//  attachment is asked to be kept. The first is what the push legs' wait relies on to send at the
//  right moment; the last is why a test never needs a screenshot of its own.
//

import XCTest

final class ProofTests: DeviceTestCase {
    /// Says a line, waits, and says another: the script notes when each reached it.
    func testWhatATestSaysReachesTheScriptWhileItRuns() {
        say("PROOF first")
        Thread.sleep(forTimeInterval: 15)
        say("PROOF second")
    }

    /// Ninety seconds of Home presses, then the application comes up in front, which it cannot on a
    /// phone that locked.
    func testHomePressesKeepThePhoneAwake() throws {
        launch(probe: "count")
        _ = try XCTUnwrap(probeFacts("count"))
        let end = Date().addingTimeInterval(90)
        while Date() < end {
            XCUIDevice.shared.press(.home)
            Thread.sleep(forTimeInterval: 10)
        }
        launch(probe: "count")
        let facts = try XCTUnwrap(probeFacts("count"), "the application could not be brought to the front")
        XCTAssertEqual(facts["protected"], "1", "the phone locked while the tests ran")
        say("PROOF the phone stayed awake")
    }

    /// The application draws its own windows, page included, into its container, and the script
    /// copies the file out and looks at it: it has the size of the window and is not an empty picture.
    func testTheApplicationDrawsItsOwnWindowsForTheScriptToCopy() {
        launch(probe: "shots")
        _ = probeElement("shots").waitForExistence(timeout: 30)
        shot("proof")
        say("PROOF the application drew its windows")
    }

    /// Fails on purpose, and only when the session's attachment check runs it with every attachment
    /// kept: that check lists what the failure left in its result by kind, and a picture or a
    /// recording among them is the proof that the runner's arguments do not hold. Any other run
    /// skips it.
    func testAFailureLeavesNothingBehind() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["KR_ATTACHMENT_PROOF"] == "1", "run only by the attachment check")
        launch(probe: "count")
        _ = try XCTUnwrap(probeFacts("count"))
        XCTFail("a failure on purpose, to see what a failure leaves in the result")
    }
}
