//
//  What the microphone's state means for authority.
//
//  KR-REQ-15.36 and KR-ACC-014: muted or unavailable capture is displayed, and a claim that
//  unreceived speech authorised an action is rejected. KR-REQ-15.13: an action that needs a
//  confirmation on the unlocked screen does not proceed without one.
//

import XCTest

final class VoiceCaptureStateTests: XCTestCase {
    /// KR-REQ-15.36: only an open microphone could have heard anything.
    func testOnlyCapturingCouldHaveHeardSpeech() {
        XCTAssertTrue(VoiceCaptureState.capturing.speechCouldHaveBeenHeard)
        for state: VoiceCaptureState in [
            .mutedByPerson, .interrupted, .routeChanging, .suspendedBySystem, .unavailable, .idle,
        ] {
            XCTAssertFalse(
                state.speechCouldHaveBeenHeard,
                "\(state.rawValue) is not a state in which the person was heard"
            )
        }
    }

    /// KR-REQ-15.36: every state a person can be in is displayed, and none of them reads as a code.
    func testEveryStateSaysSomethingAPersonCanRead() {
        for state: VoiceCaptureState in [
            .capturing, .mutedByPerson, .interrupted, .routeChanging, .suspendedBySystem,
            .unavailable, .idle,
        ] {
            let display = state.display
            XCTAssertFalse(display.isEmpty)
            XCTAssertFalse(display.contains("error"), "\(display) reads as a fault, not a state")
            XCTAssertEqual(display, display.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    /// KR-REQ-15.36, KR-ACC-014: unreceived speech authorises nothing, whatever muted the
    /// microphone. The person's own mute is included deliberately.
    func testUnreceivedSpeechAuthorisesNothing() {
        for state: VoiceCaptureState in [
            .mutedByPerson, .interrupted, .routeChanging, .suspendedBySystem, .unavailable, .idle,
        ] {
            let gate = VoiceAuthorityGate(capture: state, holdsUnlockedScreenConfirmation: true)
            XCTAssertEqual(
                gate.refusal(needsConfirmation: false),
                .speechNotHeard(state),
                "\(state.rawValue) must refuse even an action needing no confirmation"
            )
            XCTAssertEqual(
                gate.refusal(needsConfirmation: true),
                .speechNotHeard(state),
                "a held confirmation does not make unheard speech heard"
            )
        }
    }

    /// KR-REQ-15.13: the five unlocked-screen classes need the confirmation, and an open
    /// microphone is not a substitute for it.
    func testAnUnlockedScreenActionNeedsItsConfirmation() {
        let withoutIt = VoiceAuthorityGate(capture: .capturing)
        XCTAssertEqual(
            withoutIt.refusal(needsConfirmation: true),
            .needsUnlockedScreenConfirmation
        )
        XCTAssertNil(withoutIt.refusal(needsConfirmation: false))

        let withIt = VoiceAuthorityGate(capture: .capturing, holdsUnlockedScreenConfirmation: true)
        XCTAssertNil(withIt.refusal(needsConfirmation: true))
    }

    /// The refusal says what is true rather than naming a fault, and names what would change it.
    func testARefusalExplainsItself() {
        let muted = VoiceAuthorityRefusal.speechNotHeard(.mutedByPerson)
        XCTAssertTrue(muted.message.contains("Microphone muted"))
        XCTAssertTrue(muted.message.contains("authorise"))

        let needed = VoiceAuthorityRefusal.needsUnlockedScreenConfirmation
        XCTAssertTrue(needed.message.contains("unlocked screen"))
    }
}

/// Whether the microphone may carry speech, and what the person is told about it.
///
/// KR-REQ-15.34 and KR-REQ-15.36: nothing opens the microphone without a fresh permitted call, and
/// muted or unavailable capture is displayed. KR-REQ-15.35: an interruption, a route change and a
/// stop are each their own state. KR-ACC-014: unheard speech never authorises, answered from the
/// intervals this device kept.
final class VoiceCaptureGateTests: XCTestCase {
    private func permitted(nowMs: UInt64 = 1_000, deadlineMs: UInt64 = 61_000)
        -> (VoiceCaptureGate, VoiceCaptureGate.Permit)
    {
        let gate = VoiceCaptureGate()
        let permit = gate.permit(voiceSessionId: "voice-session-1", deadlineMs: deadlineMs, nowMs: nowMs)
        XCTAssertNotNil(permit, "a current answer permits the call")
        return (gate, permit!)
    }

    /// KR-REQ-15.34: a call with no permit captures nothing, whatever else is true.
    func testNothingIsCapturedWithoutAPermit() {
        let gate = VoiceCaptureGate()
        XCTAssertFalse(gate.captureEnabled(nowMs: 1_000))
        XCTAssertEqual(gate.displayed(nowMs: 1_000), .idle)
        gate.setMutedByPerson(false, nowMs: 1_100)
        gate.taken(.none, nowMs: 1_200)
        gate.route(changing: false, inputAvailable: true, nowMs: 1_300)
        XCTAssertFalse(gate.captureEnabled(nowMs: 1_400), "no event other than a permit opens the microphone")
    }

    /// KR-REQ-15.34: a permit is given once, by an answer that is still current.
    func testAPermitIsRefusedWhenStaleRepeatedOrAfterAStop() {
        XCTAssertNil(VoiceCaptureGate().permit(voiceSessionId: "s", deadlineMs: 1_000, nowMs: 1_000))

        let (gate, _) = permitted()
        XCTAssertNil(gate.permit(voiceSessionId: "s-2", deadlineMs: 90_000, nowMs: 2_000))

        gate.stop(nowMs: 3_000)
        XCTAssertNil(gate.permit(voiceSessionId: "s-3", deadlineMs: 90_000, nowMs: 4_000))
        XCTAssertFalse(gate.captureEnabled(nowMs: 4_000))
    }

    /// KR-REQ-15.34: capture ends at the deadline with no event at all, and the record says so.
    func testCaptureEndsAtTheDeadlineByItself() {
        let (gate, _) = permitted(nowMs: 1_000, deadlineMs: 11_000)
        XCTAssertTrue(gate.captureEnabled(nowMs: 10_999))
        XCTAssertFalse(gate.captureEnabled(nowMs: 11_000))
        XCTAssertEqual(gate.displayed(nowMs: 15_000), .idle)
        XCTAssertTrue(gate.couldHaveHeard(atMs: 10_999))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 12_000))
    }

    /// KR-REQ-15.35: the person's mute and an interruption are kept apart. An interruption that
    /// ends, even one the system says may resume, restores what the person chose.
    func testThePersonsMuteAndTheSystemAreSeparate() {
        let (gate, _) = permitted()
        gate.setMutedByPerson(true, nowMs: 2_000)
        gate.taken(.interrupted, nowMs: 2_100)
        XCTAssertEqual(gate.displayed(nowMs: 2_100), .interrupted)

        gate.taken(.none, nowMs: 2_200)
        XCTAssertFalse(gate.captureEnabled(nowMs: 2_300), "recovery leaves a muted microphone muted")
        XCTAssertEqual(gate.displayed(nowMs: 2_300), .mutedByPerson)

        gate.taken(.interrupted, nowMs: 2_400)
        gate.setMutedByPerson(false, nowMs: 2_500)
        XCTAssertFalse(gate.captureEnabled(nowMs: 2_600), "unmuting during an interruption opens nothing")

        gate.taken(.none, nowMs: 2_700)
        XCTAssertTrue(gate.captureEnabled(nowMs: 2_800))
    }

    /// KR-REQ-15.35 and 15.36: a route in change or without an input keeps capture off and says so.
    func testARouteChangeAndAMissingInputKeepCaptureOff() {
        let (gate, _) = permitted()
        gate.route(changing: true, inputAvailable: true, nowMs: 2_000)
        XCTAssertEqual(gate.displayed(nowMs: 2_000), .routeChanging)
        gate.route(changing: false, inputAvailable: false, nowMs: 3_000)
        XCTAssertEqual(gate.displayed(nowMs: 3_000), .unavailable)
        XCTAssertFalse(gate.captureEnabled(nowMs: 3_000))
        gate.route(changing: false, inputAvailable: true, nowMs: 4_000)
        XCTAssertTrue(gate.captureEnabled(nowMs: 4_000))
    }

    /// KR-REQ-15.35: a revocation names its generation, and a late one for an older call is refused.
    func testOnlyTheCurrentGenerationCanBeRevoked() {
        let (gate, permit) = permitted()
        XCTAssertFalse(gate.revoke(generation: permit.generation - 1, nowMs: 2_000))
        XCTAssertTrue(gate.captureEnabled(nowMs: 2_000))
        XCTAssertTrue(gate.revoke(generation: permit.generation, nowMs: 3_000))
        XCTAssertFalse(gate.captureEnabled(nowMs: 3_000))
        XCTAssertNil(gate.current)
    }

    /// KR-ACC-014: what was said is checked against when the microphone was on, and nothing else.
    func testSpeechIsVouchedForOnlyInsideTheKeptIntervals() {
        let (gate, _) = permitted(nowMs: 1_000, deadlineMs: 100_000)
        gate.setMutedByPerson(true, nowMs: 5_000)
        gate.setMutedByPerson(false, nowMs: 9_000)
        XCTAssertTrue(gate.couldHaveHeard(atMs: 4_999))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 5_000))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 8_999))
        XCTAssertTrue(gate.couldHaveHeard(atMs: 9_000))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 999))

        let bounded = VoiceCaptureGate(keptIntervals: 2)
        bounded.permit(voiceSessionId: "s", deadlineMs: 100_000, nowMs: 0)
        for start: UInt64 in [10_000, 20_000, 30_000] {
            bounded.setMutedByPerson(true, nowMs: start)
            bounded.setMutedByPerson(false, nowMs: start + 5_000)
        }
        XCTAssertFalse(bounded.couldHaveHeard(atMs: 1_000))
        XCTAssertTrue(bounded.couldHaveHeard(atMs: 26_000))
    }

    /// KR-REQ-15.36: what the person is told and whether anything could be heard never disagree.
    func testTheDisplayAndTheMicrophoneAgreeInEveryCombination() {
        for muted in [false, true] {
            for taken in VoiceCaptureGate.Taken.allCases {
                for changing in [false, true] {
                    for input in [false, true] {
                        let (gate, _) = permitted()
                        gate.setMutedByPerson(muted, nowMs: 2_000)
                        gate.taken(taken, nowMs: 2_000)
                        gate.route(changing: changing, inputAvailable: input, nowMs: 2_000)
                        XCTAssertEqual(
                            gate.captureEnabled(nowMs: 3_000),
                            gate.displayed(nowMs: 3_000).speechCouldHaveBeenHeard,
                            "muted=\(muted) taken=\(taken) changing=\(changing) input=\(input)"
                        )
                    }
                }
            }
        }
    }
}
