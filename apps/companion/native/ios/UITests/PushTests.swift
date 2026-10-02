//
//  Push, through Firebase to this phone (26.28, 26.29, 21.03, 13.24).
//
//  Each leg is one notification sent to the one registration token of this install, by a script
//  outside the repository that starts when this test says it is waiting. The notification carries a
//  nonce and the name of the application's private keychain group. The notification extension, in
//  its own process, answers inside the notification it hands the system: why it showed what it
//  showed, whether it could read the item the application filed in the shared group, and what the
//  keychain said when it tried the private group, which it is not entitled to. The application then
//  reads its own delivered notifications and reports what the extension said.
//
//  A leg does not touch the notification. It passes only if the delivered notification carries the
//  extension's own answer; a notification that arrived without it proves delivery and nothing about
//  the extension, and is said so.
//

import XCTest

final class PushTests: DeviceTestCase {
    /// How long a send is given to arrive while the phone is kept awake.
    private let waitSeconds: TimeInterval = 75

    /// Starts the push check: the application asks for the permission, which this test answers, and
    /// reports the registration token it will be sent to. The token itself is never a fact.
    private func startPushCheck() throws -> [String: String] {
        launch(probe: "push")
        answerPrompt(["Allow", "OK"])
        let facts = try XCTUnwrap(probeFacts("push", timeout: 90), "the push check did not report")
        sayFacts("push", facts)
        // A push session's build holds Firebase's configuration: a build that does not start Firebase
        // is not the build under test, whatever its reason.
        XCTAssertNotEqual(facts["firebase"], "skipped", "Firebase was left alone: \(facts["firebase.reason"] ?? "no reason given")")
        if facts["firebase"] == "skipped" { throw XCTSkip("no Firebase in this build") }
        return facts
    }

    /// The first step of every leg, and a session's check that the permission and the token came.
    func testThePushCheckAsksForTheTokenItIsSentTo() throws {
        let facts = try startPushCheck()
        XCTAssertEqual(facts["permission"], "granted", "the person's answer reached the application")
        XCTAssertTrue(["ready", "error"].contains(facts["token"] ?? ""), "the check ended in a token or in an error, not in a timeout")
        XCTAssertEqual(facts["shared.match"], "1", "the shared item the check filed reads back")
        XCTAssertEqual(facts["private.match"], "1", "the private item the check filed reads back")
    }

    /// The notification arrives while the application is not running.
    func testALegWithTheApplicationTerminated() throws {
        let facts = try startPushCheck()
        try requireToken(facts)
        app.terminate()
        say("STEP wait")
        keepAwake(for: waitSeconds)
        try readTheDelivery(of: facts)
    }

    /// The notification arrives while the application is suspended in the background.
    func testALegWithTheApplicationInTheBackground() throws {
        let facts = try startPushCheck()
        try requireToken(facts)
        say("STEP wait")
        keepAwake(for: waitSeconds)
        try readTheDelivery(of: facts)
    }

    // MARK: Steps

    private func requireToken(_ facts: [String: String]) throws {
        XCTAssertEqual(facts["token"], "ready", "a leg needs a registration token to send to")
    }

    /// Presses Home every ten seconds, which is what keeps the phone awake while nobody touches it.
    private func keepAwake(for seconds: TimeInterval) {
        let end = Date().addingTimeInterval(seconds)
        while Date() < end {
            XCUIDevice.shared.press(.home)
            Thread.sleep(forTimeInterval: min(10, max(0, end.timeIntervalSinceNow)))
        }
    }

    /// Reads what the application was delivered, once, and decides the leg.
    private func readTheDelivery(of pushFacts: [String: String]) throws {
        launch(probe: "push-read")
        let facts = try XCTUnwrap(probeFacts("push-read", timeout: 30), "the delivery check did not report")
        sayFacts("push-read", facts)
        XCTAssertEqual(facts["nonce.known"], "1", "the check that filed the nonce did not leave it behind")
        let marked = Int(facts["marked"] ?? "0") ?? 0
        guard marked > 0 else {
            let delivered = Int(facts["delivered"] ?? "0") ?? 0
            let presented = Int(facts["presented_in_front"] ?? "0") ?? 0
            if delivered > 0 {
                say("PUSH delivered, extension unproven")
                XCTFail("a notification was delivered, but none carries the extension's answer")
            } else {
                say("PUSH \(presented > 0 ? "arrived in front" : "not delivered in time")")
                XCTFail("no notification for this send was delivered in time")
            }
            return
        }
        XCTAssertEqual(marked, 1, "one send, one notification")
        XCTAssertNotNil(facts["n1.kr_ext_reason"], "the extension named why it showed what it showed")
        XCTAssertTrue(["1", "true"].contains(facts["n1.kr_ext_shared_match"] ?? ""), "the extension read the shared item the application filed")
        XCTAssertTrue(["0", "false"].contains(facts["n1.kr_ext_private_data"] ?? ""), "the extension got no data from the private group")
        XCTAssertNotEqual(facts["n1.kr_ext_private_status"], "0", "the keychain refused the extension the private group")
        XCTAssertEqual(pushFacts["private.match"], "1", "and the item it was refused is there: the application read it back")
        say("PUSH delivered with the extension's answer")
    }
}
