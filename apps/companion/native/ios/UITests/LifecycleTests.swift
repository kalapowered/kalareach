//
//  The application's own start of push, through the notification prompt and the lifecycle.
//
//  At launch the application gives its delegate the two methods the system calls with an APNs token,
//  and sets the delegate again so the system takes them in. If the delegate were not kept alive
//  across that, the next message the system sent it, which is the one that tells the application it
//  is about to be deactivated when a permission prompt comes up, would reach an object that is gone
//  and end the process. These bring the prompt up, answer it, and send the application to the
//  background and back, and the application has to be the same running process throughout.
//

import XCTest

final class LifecycleTests: DeviceTestCase {
    func testTheApplicationSurvivesThePromptAndRoundsToTheBackground() throws {
        launch(probe: "push")
        answerPrompt(["Allow", "OK"], timeout: 20)
        let facts = try XCTUnwrap(probeFacts("push", timeout: 90), "the push check did not report")
        sayFacts("push", facts)
        if facts["firebase"] == "skipped" {
            throw XCTSkip("this build starts no Firebase, so there is nothing of the launch hook to survive")
        }
        let methods = try XCTUnwrap(probeElement("tokenmethods").value as? String, "the launch did not say whether it gave the delegate its methods")
        XCTAssertEqual(methods, "added", "the delegate was not given the APNs token methods")

        for round in 1...3 {
            XCUIDevice.shared.press(.home)
            XCTAssertTrue(app.wait(for: .runningBackgroundSuspended, timeout: 90), "round \(round): the system did not suspend the application")
            app.activate()
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 30), "round \(round): the application did not come back")
            XCTAssertTrue(probeElement("push").waitForExistence(timeout: 10), "round \(round): the application's own surface is gone")
            say("LIFECYCLE round \(round) survived")
        }
    }
}
