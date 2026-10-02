//
//  What a session has to know about the way these tests run, before it relies on it.
//
//  Two things a script cannot read for itself: that what a test says reaches the script while the
//  test is still running, and that pressing Home every ten seconds keeps the phone awake for as long
//  as a push leg needs. The first is what the push legs' wait relies on to send at the right moment.
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
}
