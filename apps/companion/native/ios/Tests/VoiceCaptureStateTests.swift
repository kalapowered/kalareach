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
