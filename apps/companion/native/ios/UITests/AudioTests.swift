//
//  The microphone and the audio session, on the phone (15.34, 15.35, 15.36).
//
//  There is no call yet that can open the microphone from the interface, so the application's debug
//  build has an audio check that opens the audio session the way a call does and runs an engine of
//  its own on it. The engine plays silence and drops what it hears: the microphone's state is all
//  that is looked at, and no audio is kept. The permission prompt is answered here, once Don't Allow
//  and once Allow, which are two sessions with the person at the phone.
//
//  What these prove is the session, the state and the route events. A call from a host, the person's
//  mute, a phone call, Bluetooth and the end of the process under a call are not covered and stay open.
//

import XCTest

final class AudioTests: DeviceTestCase {
    override func tearDown() {
        // Whatever ended a test, the check gives the session back and the microphone is not left open.
        post("to.kala.reach.probe.audio-stop")
        super.tearDown()
    }

    /// Waits for the check to report a fact the way a test waits for anything: it answers when it can.
    private func facts(until condition: ([String: String]) -> Bool, timeout: TimeInterval = 30) -> [String: String]? {
        let end = Date().addingTimeInterval(timeout)
        var last: [String: String]?
        while Date() < end {
            if let now = probeFacts("audio", timeout: 2) {
                last = now
                if condition(now) { return now }
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        return last
    }

    /// Each of these is a session of its own, from a fresh install: the system keeps a person's answer
    /// to the microphone prompt for as long as the application is installed, so the test that needs
    /// the prompt to be asked is the first thing run after an install.
    ///
    /// The person says no: the session refuses and says the microphone is not permitted, the
    /// microphone's state is that it is unavailable, and nothing is left held.
    func testARefusedMicrophoneIsSaidAndNothingOpens() throws {
        promptAnswers = ["Don\u{2019}t Allow", "Don't Allow"]
        launch(probe: "audio")
        answerPrompt(["Don\u{2019}t Allow", "Don't Allow"])
        let result = try XCTUnwrap(facts(until: { $0["permission"] != nil }), "the audio check did not report")
        sayFacts("audio", result)
        XCTAssertEqual(result["permission"], "denied")
        XCTAssertEqual(result["activated"], "0", "the session opened without the person's yes")
        XCTAssertTrue(result["error"]?.contains("microphoneNotPermitted") == true, "the refusal was not the product's own")
        XCTAssertEqual(result["capture"], "unavailable", "the microphone's state says it is unavailable")
    }

    /// The person says yes: the session opens, the engine runs, the state is only that, and a change
    /// of route is counted and then the check ends the way a call does.
    func testAnAllowedMicrophoneOpensTheSessionAndAChangeOfRouteIsCounted() throws {
        launch(probe: "audio")
        answerPrompt(["Allow", "OK"])
        let running = try XCTUnwrap(facts(until: { $0["engine"] != nil && (Int($0["ticks"] ?? "0") ?? 0) >= 3 }, timeout: 60))
        sayFacts("audio", running)
        XCTAssertEqual(running["permission"], "granted")
        XCTAssertEqual(running["activated"], "1")
        XCTAssertEqual(running["engine"], "running")
        XCTAssertNotEqual(running["capture"], "unavailable", "the microphone is not available to a session that was allowed it")
        // Input and output both ran, and not merely the timer that watches them.
        XCTAssertGreaterThan(Int(running["callbacks.input"] ?? "0") ?? 0, 0, "the input never ran")
        XCTAssertGreaterThan(Int(running["callbacks.output"] ?? "0") ?? 0, 0, "the output never ran")
        let before = Int(running["route.notifications"] ?? "0") ?? 0

        // The output is moved to the receiver, the speaker and back, and the system reports each move.
        post("to.kala.reach.probe.route")
        let routed = try XCTUnwrap(facts(until: { (Int($0["route.moves"] ?? "0") ?? 0) >= 4 }, timeout: 30))
        sayFacts("audio", routed)
        XCTAssertNil(routed["route.error"], "the check could not move the route: \(routed["route.error"] ?? "")")
        XCTAssertEqual(routed["route.moves"], "4", "all four moves were made")
        // The reports arrive on the main queue a moment after the moves.
        let reported = facts(until: { (Int($0["route.notifications"] ?? "0") ?? 0) >= before + 2 }, timeout: 10) ?? routed
        sayFacts("audio", reported)
        #if targetEnvironment(simulator)
        // A simulator has one output and moves nothing, so the system has nothing to report.
        if (Int(reported["route.notifications"] ?? "0") ?? 0) == before { throw XCTSkip("a simulator reports no change of route") }
        #endif
        XCTAssertGreaterThanOrEqual(Int(reported["route.notifications"] ?? "0") ?? 0, before + 2, "the system reported fewer than two changes of route for four moves")
        XCTAssertGreaterThan(Set((reported["route.trail"] ?? "").split(separator: ",")).count, 1, "the output never changed port")
        XCTAssertGreaterThan(Int(reported["route.product.events"] ?? "0") ?? 0, 0, "the product's own session was told of no change of route")

        post("to.kala.reach.probe.audio-stop")
        let ended = try XCTUnwrap(facts(until: { $0["stopped"] == "1" }, timeout: 30))
        XCTAssertEqual(ended["deactivated"], "1", "the session was given back")
        say("AUDIO ended")
    }

    /// The screen locks and unlocks under the check, with the person at the phone to do it: input
    /// and output go on, a second after a second, while the device's protected data is unavailable.
    func testAudioCarriesOnThroughALockedScreen() throws {
        launch(probe: "audio")
        answerPrompt(["Allow", "OK"])
        _ = try XCTUnwrap(facts(until: { $0["engine"] == "running" && (Int($0["ticks"] ?? "0") ?? 0) >= 5 }, timeout: 60))
        say("STEP lock the phone with the side button, leave it locked for one minute, then unlock it")
        // The person has three minutes. The runner cannot read the application while the phone is
        // locked, so it looks again every five seconds, and decides from what the check reports once
        // the phone is unlocked and the application is in front.
        let end = Date().addingTimeInterval(180)
        var seen: [String: String]?
        while Date() < end {
            Thread.sleep(forTimeInterval: 5)
            if app.state == .runningForeground, let now = probeFacts("audio", timeout: 2) {
                seen = now
                if (Int(now["locked.ticks"] ?? "0") ?? 0) >= 30 { break }
            }
        }
        let result = try XCTUnwrap(seen, "nothing could be read after the phone was unlocked")
        sayFacts("audio", result)
        XCTAssertGreaterThanOrEqual(Int(result["locked.ticks"] ?? "0") ?? 0, 30, "the phone was not locked for thirty seconds")
        XCTAssertLessThanOrEqual(Int(result["gap.input.locked.max"] ?? "99999") ?? 99999, 2000, "input stopped while the phone was locked")
        XCTAssertLessThanOrEqual(Int(result["gap.output.locked.max"] ?? "99999") ?? 99999, 2000, "output stopped while the phone was locked")
        // A stop in the first seconds of the lock falls on ticks that still read the phone as unlocked,
        // and one that suspended the application shows only on the first tick after the unlock; the
        // longest gap of the whole run catches both.
        XCTAssertLessThanOrEqual(Int(result["gap.input.max"] ?? "99999") ?? 99999, 2000, "input stopped at some time in the run")
        XCTAssertLessThanOrEqual(Int(result["gap.output.max"] ?? "99999") ?? 99999, 2000, "output stopped at some time in the run")
        post("to.kala.reach.probe.audio-stop")
    }
}
