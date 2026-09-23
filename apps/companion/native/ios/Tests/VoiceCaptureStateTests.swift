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
    /// A permitted gate whose recorder reported itself running at the same moment.
    private func permitted(nowMs: UInt64 = 1_000, deadlineMs: UInt64 = 61_000)
        -> (VoiceCaptureGate, VoiceCaptureGate.Permit)
    {
        let gate = VoiceCaptureGate()
        let permit = gate.permit(voiceSessionId: "voice-session-1", deadlineMs: deadlineMs, nowMs: nowMs)
        XCTAssertNotNil(permit, "a current answer permits the call")
        gate.recorder(running: true, nowMs: nowMs)
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
        gate.recorder(running: true, nowMs: 1_350)
        XCTAssertFalse(gate.captureEnabled(nowMs: 1_400), "no event other than a permit opens the microphone")
        XCTAssertFalse(gate.live(nowMs: 1_400))
    }

    /// KR-REQ-15.36: a permitted call captures nothing until the recorder reports itself running,
    /// and says the microphone is unavailable until then and once it fails.
    func testCaptureWaitsForTheRecorderAndEndsWithIt() {
        let gate = VoiceCaptureGate()
        XCTAssertNotNil(gate.permit(voiceSessionId: "voice-session-1", deadlineMs: 61_000, nowMs: 1_000))
        XCTAssertTrue(gate.live(nowMs: 1_000))
        XCTAssertFalse(gate.captureEnabled(nowMs: 1_000), "the recorder has not started")
        XCTAssertEqual(gate.displayed(nowMs: 1_000), .unavailable)
        gate.recorder(running: true, nowMs: 1_200)
        XCTAssertTrue(gate.captureEnabled(nowMs: 1_200))
        XCTAssertEqual(gate.displayed(nowMs: 1_200), .capturing)
        gate.recorder(running: false, nowMs: 5_000)
        XCTAssertFalse(gate.captureEnabled(nowMs: 5_000), "a recorder that failed hears nothing")
        XCTAssertEqual(gate.displayed(nowMs: 5_000), .unavailable)
        XCTAssertFalse(gate.couldHaveHeard(atMs: 1_100, nowMs: 6_000))
        XCTAssertTrue(gate.couldHaveHeard(atMs: 1_200, nowMs: 6_000))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 5_000, nowMs: 6_000))
    }

    /// KR-ACC-014: a running permit vouches for nothing that has not happened yet.
    func testAFutureInstantIsNeverVouchedFor() {
        let (gate, _) = permitted(nowMs: 1_000, deadlineMs: 61_000)
        XCTAssertTrue(gate.captureEnabled(nowMs: 1_000))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 50_000, nowMs: 1_000), "permission to capture is not a record of speech")
        XCTAssertTrue(gate.couldHaveHeard(atMs: 1_000, nowMs: 1_000))
        XCTAssertTrue(gate.couldHaveHeard(atMs: 20_000, nowMs: 30_000))
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
        XCTAssertFalse(gate.live(nowMs: 11_000))
        XCTAssertEqual(gate.displayed(nowMs: 15_000), .idle)
        XCTAssertTrue(gate.couldHaveHeard(atMs: 10_999, nowMs: 15_000))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 12_000, nowMs: 15_000))
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
        XCTAssertTrue(gate.couldHaveHeard(atMs: 4_999, nowMs: 10_000))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 5_000, nowMs: 10_000))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 8_999, nowMs: 10_000))
        XCTAssertTrue(gate.couldHaveHeard(atMs: 9_000, nowMs: 10_000))
        XCTAssertFalse(gate.couldHaveHeard(atMs: 999, nowMs: 10_000))

        let bounded = VoiceCaptureGate(keptIntervals: 2)
        bounded.permit(voiceSessionId: "s", deadlineMs: 100_000, nowMs: 0)
        bounded.recorder(running: true, nowMs: 0)
        for start: UInt64 in [10_000, 20_000, 30_000] {
            bounded.setMutedByPerson(true, nowMs: start)
            bounded.setMutedByPerson(false, nowMs: start + 5_000)
        }
        XCTAssertFalse(bounded.couldHaveHeard(atMs: 1_000, nowMs: 40_000))
        XCTAssertTrue(bounded.couldHaveHeard(atMs: 26_000, nowMs: 40_000))
    }

    /// KR-REQ-15.36: what the person is told and whether anything could be heard never disagree.
    func testTheDisplayAndTheMicrophoneAgreeInEveryCombination() {
        for muted in [false, true] {
            for taken in VoiceCaptureGate.Taken.allCases {
                for changing in [false, true] {
                    for input in [false, true] {
                        for recording in [false, true] {
                            let (gate, _) = permitted()
                            gate.setMutedByPerson(muted, nowMs: 2_000)
                            gate.taken(taken, nowMs: 2_000)
                            gate.route(changing: changing, inputAvailable: input, nowMs: 2_000)
                            gate.recorder(running: recording, nowMs: 2_000)
                            XCTAssertEqual(
                                gate.captureEnabled(nowMs: 3_000),
                                gate.displayed(nowMs: 3_000).speechCouldHaveBeenHeard,
                                "muted=\(muted) taken=\(taken) changing=\(changing) input=\(input) "
                                    + "recording=\(recording)"
                            )
                        }
                    }
                }
            }
        }
    }
}

/// A call's hold on the microphone, driven through the same control the application runs, with the
/// platform replaced by a record of what was asked of it.
///
/// KR-REQ-15.34: nothing records before the host's answer and the recorder both say so, and a
/// refusal undoes the rest. KR-REQ-15.35: interruptions, routes, mute and the end of a call each act
/// on the switches. KR-REQ-15.36 and KR-ACC-014: the microphone carries speech exactly when the
/// screen says it does, and never after the deadline, whatever the timers do.
final class VoiceCallControlTests: XCTestCase {
    /// What the control asked of the media, and whether the recorder or microphone was ever on.
    private final class Switches: VoiceMediaSwitches {
        var deviceOn = false
        var microphoneOn = false
        var playbackOn = false
        var deviceEverOn = false
        var microphoneEverOn = false

        func setAudioDevice(_ on: Bool) {
            deviceOn = on
            deviceEverOn = deviceEverOn || on
        }

        func setMicrophone(_ on: Bool) {
            microphoneOn = on
            microphoneEverOn = microphoneEverOn || on
        }

        func setPlayback(_ on: Bool) { playbackOn = on }
    }

    private struct Refused: Error {}

    /// A platform whose clocks, session and timers the test decides.
    private final class Platform: VoiceCallPlatform {
        var now: UInt64 = 1_000
        let epochAtStart: UInt64 = 1_700_000_000_000
        var opens = true
        var whileOpening: () -> Void = {}
        var sessionOpen = false
        var deactivations = 0
        var ends = 0
        var timers: [(id: Int, atMs: UInt64, task: () -> Void)] = []
        var nextTimer = 0
        var shown: [VoiceCaptureState] = []

        func nowMs() -> UInt64 { now }
        func epochMs() -> UInt64 { epochAtStart + now }

        func activate() throws {
            whileOpening()
            guard opens else { throw Refused() }
            sessionOpen = true
        }

        func deactivate() {
            sessionOpen = false
            deactivations += 1
        }

        func schedule(atMs: UInt64, _ task: @escaping () -> Void) -> () -> Void {
            nextTimer += 1
            let id = nextTimer
            timers.append((id, atMs, task))
            return { [weak self] in self?.timers.removeAll { $0.id == id } }
        }

        func publish(_ state: VoiceCaptureState) { shown.append(state) }
        func ended() { ends += 1 }

        /// Runs every timer that is due. A test that stalls the timers simply does not call this.
        func runDueTimers() {
            let due = timers.filter { $0.atMs <= now }
            timers.removeAll { timer in due.contains { $0.id == timer.id } }
            due.forEach { $0.task() }
        }

        /// The moment the service closes a call `seconds` from now, in epoch milliseconds.
        func closesIn(_ seconds: UInt64) -> UInt64 { epochMs() + seconds * 1_000 }
    }

    private func running(seconds: UInt64 = 60) -> (VoiceCallControl, Platform, Switches) {
        let platform = Platform()
        let switches = Switches()
        let control = VoiceCallControl(platform: platform, switches: switches)
        XCTAssertTrue(control.permit(voiceSessionId: "voice-session-1", closesAtEpochMs: platform.closesIn(seconds)))
        control.recorder(running: true)
        return (control, platform, switches)
    }

    /// KR-REQ-15.34: every switch starts off, and nothing but a permitted call turns one on.
    func testNothingRecordsBeforeTheHostPermitsTheCall() {
        let platform = Platform()
        let switches = Switches()
        let control = VoiceCallControl(platform: platform, switches: switches)
        XCTAssertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)

        control.setMutedByPerson(false)
        control.interruption(began: false, mayResume: true)
        control.route(changing: false, inputAvailable: true)
        control.recorder(running: true)
        control.refresh()
        XCTAssertFalse(switches.deviceEverOn || switches.microphoneEverOn, "nothing before a permit")

        XCTAssertTrue(control.permit(voiceSessionId: "voice-session-1", closesAtEpochMs: platform.closesIn(60)))
        XCTAssertTrue(switches.deviceOn, "the device runs for a permitted call")
        XCTAssertFalse(switches.microphoneOn, "a recorder start from before the device came on does not count")
        XCTAssertEqual(control.displayed(), .unavailable)

        control.recorder(running: true)
        XCTAssertTrue(switches.microphoneOn)
        XCTAssertEqual(control.displayed(), .capturing)
        XCTAssertEqual(platform.shown.last, .capturing)
    }

    /// KR-REQ-15.34: a refused audio session ends the call, and nothing reopens it.
    func testARefusedSessionEndsTheCall() {
        let platform = Platform()
        platform.opens = false
        let switches = Switches()
        let control = VoiceCallControl(platform: platform, switches: switches)
        XCTAssertFalse(control.permit(voiceSessionId: "voice-session-1", closesAtEpochMs: platform.closesIn(60)))
        XCTAssertTrue(control.isStopped)
        XCTAssertEqual(platform.ends, 1)
        control.recorder(running: true)
        control.setMutedByPerson(false)
        XCTAssertFalse(switches.deviceEverOn || switches.microphoneEverOn)
        XCTAssertEqual(platform.shown.last, .idle)
    }

    /// KR-REQ-15.34: time the platform takes counts against the deadline and never extends it.
    func testActivationThatCrossesTheDeadlineRecordsNothing() {
        let platform = Platform()
        platform.whileOpening = { platform.now += 10_000 }
        let switches = Switches()
        let control = VoiceCallControl(platform: platform, switches: switches)
        XCTAssertFalse(control.permit(voiceSessionId: "voice-session-1", closesAtEpochMs: platform.closesIn(5)))
        XCTAssertTrue(control.isStopped)
        XCTAssertFalse(platform.sessionOpen)
        XCTAssertFalse(switches.deviceEverOn || switches.microphoneEverOn)
    }

    /// KR-REQ-15.34: the call's end is scheduled at the deadline itself, and ends everything.
    func testTheCallEndsAtItsDeadline() {
        let (control, platform, switches) = running(seconds: 30)
        XCTAssertEqual(platform.timers.map(\.atMs), [1_000 + 30_000], "scheduled against the deadline")
        platform.now = 1_000 + 29_999
        platform.runDueTimers()
        XCTAssertTrue(switches.microphoneOn)
        platform.now = 1_000 + 30_000
        platform.runDueTimers()
        XCTAssertTrue(control.isStopped)
        XCTAssertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)
        XCTAssertFalse(platform.sessionOpen)
        XCTAssertTrue(platform.timers.isEmpty)
    }

    /// KR-REQ-15.34 and KR-ACC-014: when the timer is late, the first change of any kind after the
    /// deadline ends the call, and the record vouches for nothing from the deadline on. Until the
    /// call's queue runs the timer or delivers such a change, the switches stay as they were: iOS has
    /// no per-frame check.
    func testAChangeAfterTheDeadlineEndsTheCallWhenTheTimerIsLate() {
        let (control, platform, switches) = running(seconds: 30)
        platform.now = 1_000 + 30_000
        XCTAssertFalse(control.couldHaveHeard(atMs: 1_000 + 30_000))
        XCTAssertTrue(control.couldHaveHeard(atMs: 1_000 + 29_999))
        control.setPlaybackMuted(false)
        XCTAssertTrue(control.isStopped)
        XCTAssertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)
    }

    /// KR-REQ-15.36: the switches and the screen agree in every combination of what can happen.
    func testTheSwitchesFollowTheGateInEveryCombination() {
        for muted in [false, true] {
            for interrupted in [false, true] {
                for changing in [false, true] {
                    for input in [false, true] {
                        for recording in [false, true] {
                            for silenced in [false, true] {
                                let (control, platform, switches) = running()
                                control.setMutedByPerson(muted)
                                control.interruption(began: interrupted, mayResume: true)
                                control.route(changing: changing, inputAvailable: input)
                                control.recorder(running: recording)
                                control.setPlaybackMuted(silenced)
                                let shown = platform.shown.last!
                                let label = "muted=\(muted) interrupted=\(interrupted) changing=\(changing) "
                                    + "input=\(input) recording=\(recording) silenced=\(silenced)"
                                XCTAssertEqual(shown.speechCouldHaveBeenHeard, switches.microphoneOn, label)
                                XCTAssertEqual(shown, control.displayed(), label)
                                XCTAssertTrue(switches.deviceOn, label)
                                XCTAssertEqual(switches.playbackOn, !silenced && !interrupted, label)
                            }
                        }
                    }
                }
            }
        }
    }

    /// KR-REQ-15.35: an interruption the system does not invite back from leaves the microphone
    /// closed, and the person's own mute survives one that it does.
    func testAnInterruptionEndsOnTheSystemsWordAndKeepsThePersonsMute() {
        let (control, _, switches) = running()
        control.interruption(began: true, mayResume: false)
        XCTAssertFalse(switches.microphoneOn)
        control.interruption(began: false, mayResume: false)
        XCTAssertFalse(switches.microphoneOn, "without the system's word the microphone stays closed")
        XCTAssertEqual(control.displayed(), .suspendedBySystem)

        let (muted, _, mutedSwitches) = running()
        muted.setMutedByPerson(true)
        muted.interruption(began: true, mayResume: false)
        muted.interruption(began: false, mayResume: true)
        XCTAssertFalse(mutedSwitches.microphoneOn)
        XCTAssertEqual(muted.displayed(), .mutedByPerson)
    }

    /// KR-REQ-15.34: the process's audio belongs to one call. A second call is refused before it can
    /// build anything that sets a switch, and a switch set for a call that does not hold the audio
    /// changes nothing, so the running call keeps its audio.
    func testASecondCallIsRefusedWithoutTouchingTheAudioOfTheFirst() {
        final class SharedDevice { var on = false }
        final class OwnedSwitches: VoiceMediaSwitches {
            let owner: VoiceAudioOwner
            let device: SharedDevice
            let call: AnyObject
            init(owner: VoiceAudioOwner, device: SharedDevice, call: AnyObject) {
                self.owner = owner
                self.device = device
                self.call = call
            }
            func setAudioDevice(_ on: Bool) { if owner.holds(call) { device.on = on } }
            func setMicrophone(_: Bool) {}
            func setPlayback(_: Bool) {}
        }
        let owner = VoiceAudioOwner()
        let device = SharedDevice()
        let first = NSObject()
        XCTAssertTrue(owner.claim(first))
        let platform = Platform()
        let control = VoiceCallControl(
            platform: platform,
            switches: OwnedSwitches(owner: owner, device: device, call: first)
        )
        XCTAssertTrue(control.permit(voiceSessionId: "voice-session-1", closesAtEpochMs: platform.closesIn(60)))
        XCTAssertTrue(device.on)

        let second = NSObject()
        XCTAssertFalse(owner.claim(second), "a second call is refused while the first holds the audio")
        // What building a control for the second call would do: every switch off, which changes
        // nothing it does not hold.
        _ = VoiceCallControl(platform: Platform(), switches: OwnedSwitches(owner: owner, device: device, call: second))
        XCTAssertTrue(device.on, "the running call keeps its audio")

        control.stop()
        XCTAssertFalse(device.on)
        owner.release(second)
        XCTAssertFalse(owner.claim(second), "only the holder gives the audio back")
        owner.release(first)
        XCTAssertTrue(owner.claim(second), "the audio is free once the first call has given it back")
    }

    /// KR-REQ-15.35: the end of a call is final, and the second end does nothing.
    func testAnEndedCallStaysEnded() {
        let (control, platform, switches) = running()
        control.stop()
        control.stop()
        XCTAssertEqual(platform.ends, 1)
        XCTAssertEqual(platform.deactivations, 1)
        control.setMutedByPerson(false)
        control.recorder(running: true)
        XCTAssertFalse(control.permit(voiceSessionId: "voice-session-2", closesAtEpochMs: platform.closesIn(60)))
        XCTAssertFalse(switches.deviceOn || switches.microphoneOn || switches.playbackOn)
    }
}

/// KR-REQ-15.36: on iOS the recorder counts as running while the call's source is taking in audio,
/// and not because WebRTC said playback or recording was asked to begin.
final class VoiceRecorderWatchTests: XCTestCase {
    /// A call that plays and records nothing, or reports no source at all, never counts as recording.
    func testPlaybackAloneIsNotARecorder() {
        var watch = VoiceRecorderWatch()
        let readings: [Double?] = [nil, 0, 0, nil, 0, 0]
        for (index, reading) in readings.enumerated() {
            XCTAssertNil(watch.observe(capturedSeconds: reading, atMs: UInt64(index) * 250))
        }
    }

    /// An input that started and delivers nothing is not recording, whatever was reported about it.
    func testAnInputThatNeverDeliversIsNotARecorder() {
        var watch = VoiceRecorderWatch()
        for index in 0 ..< 8 {
            XCTAssertNil(watch.observe(capturedSeconds: 1.5, atMs: UInt64(index) * 250))
        }
    }

    /// Audio arriving is the start, and the source taking in nothing for the quiet time is the stop.
    func testAudioArrivingStartsItAndNothingArrivingStopsIt() {
        var watch = VoiceRecorderWatch(quietMs: 750)
        XCTAssertNil(watch.observe(capturedSeconds: 0, atMs: 0), "the first reading is where counting starts")
        XCTAssertEqual(watch.observe(capturedSeconds: 0.25, atMs: 250), true)
        XCTAssertNil(watch.observe(capturedSeconds: 0.5, atMs: 500))
        XCTAssertNil(watch.observe(capturedSeconds: 0.5, atMs: 750))
        XCTAssertNil(watch.observe(capturedSeconds: nil, atMs: 1_000))
        XCTAssertEqual(watch.observe(capturedSeconds: 0.5, atMs: 1_250), false)
        XCTAssertNil(watch.observe(capturedSeconds: 0.5, atMs: 1_500))
        XCTAssertEqual(watch.observe(capturedSeconds: 0.75, atMs: 1_750), true)
    }

    /// After a reset, for a device that went off and came on again, counting starts afresh.
    func testAResetStartsCountingAfresh() {
        var watch = VoiceRecorderWatch()
        XCTAssertNil(watch.observe(capturedSeconds: 0, atMs: 0))
        XCTAssertEqual(watch.observe(capturedSeconds: 0.25, atMs: 250), true)
        watch.reset()
        XCTAssertNil(watch.observe(capturedSeconds: 10, atMs: 500), "the first reading after a reset is where counting starts")
        XCTAssertEqual(watch.observe(capturedSeconds: 10.25, atMs: 750), true)
    }
}
