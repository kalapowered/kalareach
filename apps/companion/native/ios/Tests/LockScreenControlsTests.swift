//
//  What the lock screen and the other remote controls can do to a call.
//
//  Most cases replace the system's two centres with a surface the test drives the way the system
//  does: a command reaches its handler only while it is offered. Everything else is the product's:
//  a real `VoiceCallControl`, and a platform that makes the three calls `VoiceCall`'s own platform
//  makes (begin when permitted, follow each publication, end with the call). The cases on
//  `SystemRemoteControls` use the real centres, which a test host can reach, and read them back. A
//  call cannot be permitted in a test host, because opening its audio session needs the
//  microphone, so the simulator run of the device harness reads the real centres of a permitted
//  call.
//

import Foundation
import XCTest

/// Stands in for the system's remote controls and now playing information.
private final class ScriptedSurface: RemoteControlSurface {
    private let lock = NSLock()
    private var current: ((RemoteCommand) -> Void)?
    private var offered = false
    private var showing: NowPlaying?
    private var installed = 0
    private var removed = 0

    var pauseOffered: Bool { locked { offered } }
    var info: NowPlaying? { locked { showing } }
    var installs: Int { locked { installed } }
    var removals: Int { locked { removed } }
    /// The handler the system holds now.
    var handler: ((RemoteCommand) -> Void)? { locked { current } }

    func install(_ handler: @escaping (RemoteCommand) -> Void) {
        locked {
            current = handler
            installed += 1
        }
    }

    func present(pauseOffered: Bool, info: NowPlaying?) {
        locked {
            offered = pauseOffered
            showing = info
        }
    }

    func remove() {
        locked {
            current = nil
            offered = false
            removed += 1
        }
    }

    /// What the system does with a command: it reaches the handler only while it is offered. Pause
    /// is offered when the surface was told so; stop while a handler is held; play and toggle never.
    @discardableResult
    func deliver(_ command: RemoteCommand) -> Bool {
        guard let handler else { return false }
        switch command {
        case .pause: if !pauseOffered { return false }
        case .stop: break
        case .play, .togglePlayPause: return false
        }
        handler(command)
        return true
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

/// A platform that does what the application's call platform does for the lock screen.
private final class ComposedPlatform: VoiceCallPlatform {
    var now: UInt64 = 1_000
    var lockScreen: LockScreenControls!
    weak var control: VoiceCallControl?
    var ends = 0
    var shown: [(VoiceCaptureState, Bool)] = []

    func nowMs() -> UInt64 { now }
    func epochMs() -> UInt64 { 1_700_000_000_000 + now }
    func answerApplied() -> Bool { true }
    func activate() throws {}
    func deactivate() {}
    func schedule(atMs _: UInt64, _: @escaping () -> Void) -> () -> Void { {} }

    func permitted(mutedByPerson: Bool) {
        lockScreen.begin(mutedByPerson: mutedByPerson) { [weak self] in !(self?.control?.isStopped ?? true) }
    }

    func publish(_ state: VoiceCaptureState, mutedByPerson: Bool) {
        shown.append((state, mutedByPerson))
        lockScreen.follow(mutedByPerson: mutedByPerson)
    }

    func ended() {
        ends += 1
        lockScreen.end()
    }

    func closesIn(_ seconds: UInt64) -> UInt64 { epochMs() + seconds * 1_000 }
}

private final class Switches: VoiceMediaSwitches {
    func setAudioDevice(_: Bool) {}
    func setMicrophone(_: Bool) {}
    func setPlayback(_: Bool) {}
}

final class LockScreenControlsTests: XCTestCase {
    private struct Hold {
        let control: VoiceCallControl
        let platform: ComposedPlatform
        let surface: ScriptedSurface
        let queue: DispatchQueue

        /// Waits for everything the call has put on its queue, including what the work on it puts
        /// there in turn: a mute made on the queue publishes, and the publication is queued again.
        func settle() {
            for _ in 0..<3 { queue.sync {} }
        }
    }

    /// A call that is not permitted yet, its controls wired as the application's call wires them.
    private func call() -> Hold {
        let queue = DispatchQueue(label: "to.kala.reach.test-lock-screen")
        let surface = ScriptedSurface()
        let platform = ComposedPlatform()
        let control = VoiceCallControl(platform: platform, switches: Switches())
        platform.control = control
        platform.lockScreen = LockScreenControls(
            surface: surface,
            queue: queue,
            mute: { control.setMutedByPerson(true) },
            stop: { control.stop() }
        )
        return Hold(control: control, platform: platform, surface: surface, queue: queue)
    }

    private func permitted() -> Hold {
        let hold = call()
        XCTAssertTrue(hold.control.permit(
            voiceSessionId: "voice-session-secret-1",
            closesAtEpochMs: hold.platform.closesIn(60)
        ))
        hold.settle()
        return hold
    }

    /// KR-ACC-014: nothing is offered before the host's answer permits the call, and once it does
    /// only pause and stop are, with the fixed title and the microphone's rate.
    func testOnlyAPermittedCallOffersPauseAndStop() {
        let hold = call()
        hold.settle()
        XCTAssertEqual(hold.surface.installs, 0)
        XCTAssertNil(hold.surface.info)
        XCTAssertFalse(hold.surface.deliver(.stop), "nothing is held before the permit")

        XCTAssertTrue(hold.control.permit(voiceSessionId: "voice-session-secret-1", closesAtEpochMs: hold.platform.closesIn(60)))
        hold.settle()
        XCTAssertEqual(hold.surface.installs, 1)
        XCTAssertTrue(hold.surface.pauseOffered)
        XCTAssertEqual(hold.surface.info, NowPlaying(title: LockScreenControls.title, playbackRate: 1))
        XCTAssertFalse(hold.surface.deliver(.play), "play is never offered")
        XCTAssertFalse(hold.surface.deliver(.togglePlayPause), "toggle is never offered")
    }

    /// KR-ACC-014: pause mutes the person's microphone, the lock screen then shows it paused and
    /// offers no pause, and nothing a remote sends opens the microphone again, not even a play
    /// that reaches the handler by another way.
    func testPauseMutesAndNothingARemoteSendsUnmutes() {
        let hold = permitted()
        let handler = hold.surface.handler

        // A play or a toggle that reaches the handler by another way does nothing while the
        // microphone is on.
        handler?(.play)
        handler?(.togglePlayPause)
        hold.settle()
        XCTAssertFalse(hold.control.isMutedByPerson, "play and toggle change nothing")

        XCTAssertTrue(hold.surface.deliver(.pause))
        hold.settle()
        XCTAssertTrue(hold.control.isMutedByPerson)
        XCTAssertEqual(hold.platform.shown.last?.1, true, "the mute is published as a fact of its own")
        XCTAssertFalse(hold.surface.pauseOffered, "a muted microphone offers no pause")
        XCTAssertEqual(hold.surface.info?.playbackRate, 0)

        XCTAssertFalse(hold.surface.deliver(.play))
        XCTAssertFalse(hold.surface.deliver(.togglePlayPause))
        handler?(.play)
        handler?(.togglePlayPause)
        handler?(.pause)
        hold.settle()
        XCTAssertTrue(hold.control.isMutedByPerson, "no remote command unmutes")
    }

    /// KR-ACC-014: a mute or an unmute made by another control, the page, moves the lock screen
    /// with it: pause is offered again once the microphone is on, and works again.
    func testAMuteFromAnotherControlMovesTheLockScreen() {
        let hold = permitted()
        XCTAssertTrue(hold.surface.deliver(.pause))
        hold.settle()
        XCTAssertFalse(hold.surface.pauseOffered)

        hold.control.setMutedByPerson(false)
        hold.settle()
        XCTAssertTrue(hold.surface.pauseOffered, "pause is offered again after the page unmutes")
        XCTAssertEqual(hold.surface.info?.playbackRate, 1)

        hold.control.setMutedByPerson(true)
        hold.settle()
        XCTAssertFalse(hold.surface.pauseOffered, "a mute from the page takes pause away")
        XCTAssertEqual(hold.surface.info?.playbackRate, 0)

        hold.control.setMutedByPerson(false)
        hold.settle()
        XCTAssertTrue(hold.surface.deliver(.pause))
        hold.settle()
        XCTAssertTrue(hold.control.isMutedByPerson)
    }

    /// KR-ACC-014: stop ends the call: the control stops and the platform is told the end, which is
    /// the end the application reports to Rust; the commands are taken away and nothing is shown.
    func testStopEndsTheCallAndTheCommandsGoWithIt() {
        let hold = permitted()

        XCTAssertTrue(hold.surface.deliver(.stop))
        hold.settle()
        XCTAssertTrue(hold.control.isStopped)
        XCTAssertEqual(hold.platform.ends, 1)
        XCTAssertEqual(hold.surface.removals, 1)
        XCTAssertNil(hold.surface.info)
        XCTAssertFalse(hold.surface.pauseOffered)
        XCTAssertFalse(hold.surface.deliver(.stop), "no handler is held after the end")
        XCTAssertFalse(hold.surface.deliver(.pause))
    }

    /// KR-ACC-014: a call that is stopped from inside, whatever stops it, leaves nothing on the lock
    /// screen either.
    func testACallThatIsStoppedLeavesNothingOnTheLockScreen() {
        let hold = permitted()
        hold.control.stop()
        hold.settle()
        XCTAssertNil(hold.surface.info)
        XCTAssertEqual(hold.surface.removals, 1)
        hold.control.stop()
        hold.settle()
        XCTAssertEqual(hold.surface.removals, 1, "the second end takes nothing away twice")
    }

    /// KR-ACC-014: the system's centres are the process's, not a call's. When an earlier call's
    /// controls come to take it away after a later call registered, the later call's commands and
    /// information stay, and its own end takes them away.
    func testAnEarlierCallsLateEndLeavesTheLaterCallsControls() {
        let earlier = SystemRemoteControls()
        let later = SystemRemoteControls()
        earlier.install { _ in }
        earlier.present(pauseOffered: true, info: NowPlaying(title: LockScreenControls.title, playbackRate: 1))
        later.install { _ in }
        later.present(pauseOffered: true, info: NowPlaying(title: LockScreenControls.title, playbackRate: 1))

        // The earlier call's end arrives late.
        earlier.present(pauseOffered: false, info: nil)
        earlier.remove()
        let kept = SystemRemoteControls.reading()
        XCTAssertTrue(kept.pauseOffered, "the later call's pause stays")
        XCTAssertTrue(kept.stopOffered, "the later call's stop stays")
        XCTAssertEqual(kept.title, LockScreenControls.title, "the later call's information stays")

        later.present(pauseOffered: false, info: nil)
        later.remove()
        let gone = SystemRemoteControls.reading()
        XCTAssertFalse(gone.pauseOffered)
        XCTAssertFalse(gone.stopOffered)
        XCTAssertNil(gone.title)
    }

    /// KR-ACC-014: an earlier call whose registration comes late, after a later call registered,
    /// takes nothing from it: the later call's commands and information stay, whatever the earlier
    /// call then shows or removes.
    func testAnEarlierCallsLateInstallTakesNothingFromTheLaterCall() {
        let earlier = SystemRemoteControls()
        let later = SystemRemoteControls()
        later.install { _ in }
        later.present(pauseOffered: true, info: NowPlaying(title: LockScreenControls.title, playbackRate: 1))

        // The earlier call's registration, and then its end, arrive late.
        earlier.install { _ in }
        earlier.present(pauseOffered: false, info: nil)
        earlier.remove()
        let kept = SystemRemoteControls.reading()
        XCTAssertTrue(kept.pauseOffered, "the later call's pause stays")
        XCTAssertTrue(kept.stopOffered, "the later call's stop stays")
        XCTAssertEqual(kept.title, LockScreenControls.title, "the later call's information stays")

        later.present(pauseOffered: false, info: nil)
        later.remove()
        let gone = SystemRemoteControls.reading()
        XCTAssertFalse(gone.pauseOffered)
        XCTAssertFalse(gone.stopOffered)
        XCTAssertNil(gone.title)
    }

    /// KR-ACC-014: a reading of the system's centres, taken while the microphone is muted and
    /// unmuted again and again, never finds pause offered with the muted rate, or withheld with the
    /// rate of an open microphone: the two change as one.
    func testAReadingNeverCatchesPauseAndTheInformationApart() {
        let controls = SystemRemoteControls()
        controls.install { _ in }
        defer {
            controls.present(pauseOffered: false, info: nil)
            controls.remove()
        }
        let writing = DispatchGroup()
        // The writer does not go on past its first change until the reader has read it, so it cannot
        // finish before the reader has made one reading of a call that shows something. The wait's
        // limit only keeps a reader that never reads from holding the suite.
        let firstReading = DispatchSemaphore(value: 0)
        writing.enter()
        DispatchQueue.global().async {
            for turn in 0..<20_000 {
                let muted = turn % 2 == 1
                controls.present(
                    pauseOffered: !muted,
                    info: NowPlaying(title: LockScreenControls.title, playbackRate: muted ? 0 : 1)
                )
                if turn == 0 { _ = firstReading.wait(timeout: .now() + 60) }
            }
            writing.leave()
        }
        var readings = 0
        var apart: LockScreenReading?
        while writing.wait(timeout: .now()) == .timedOut {
            let reading = SystemRemoteControls.reading()
            guard reading.title != nil else { continue }
            readings += 1
            if readings == 1 { firstReading.signal() }
            if reading.pauseOffered != (reading.rate == 1), apart == nil { apart = reading }
        }
        XCTAssertGreaterThan(readings, 0, "the reader read while the writer wrote")
        XCTAssertNil(apart, "pause and the rate were read apart")
    }

    /// KR-ACC-014: the end of a call that holds the real centres leaves nothing on them: no title
    /// and no command, in whatever order the surface takes its own parts away.
    func testTheEndOfACallOnTheRealCentresLeavesNothing() {
        let queue = DispatchQueue(label: "to.kala.reach.test-lock-screen-system")
        let controls = LockScreenControls(surface: SystemRemoteControls(), queue: queue, mute: {}, stop: {})

        controls.begin(mutedByPerson: false) { true }
        queue.sync {}
        let held = SystemRemoteControls.reading()
        XCTAssertTrue(held.pauseOffered)
        XCTAssertTrue(held.stopOffered)
        XCTAssertEqual(held.title, LockScreenControls.title)
        XCTAssertEqual(held.rate, 1)

        controls.end()
        queue.sync {}
        let gone = SystemRemoteControls.reading()
        XCTAssertFalse(gone.pauseOffered)
        XCTAssertFalse(gone.stopOffered)
        XCTAssertFalse(gone.playOffered)
        XCTAssertFalse(gone.toggleOffered)
        XCTAssertNil(gone.title)
        XCTAssertNil(gone.rate)
    }

    /// KR-ACC-014: a registration that was queued when the call ended registers nothing. The queue
    /// is held while the call is permitted and stopped, and let go afterwards.
    func testARegistrationQueuedBeforeTheEndRegistersNothing() {
        let hold = call()
        hold.queue.suspend()
        XCTAssertTrue(hold.control.permit(voiceSessionId: "voice-session-secret-1", closesAtEpochMs: hold.platform.closesIn(60)))
        hold.control.stop()
        hold.queue.resume()
        hold.settle()

        XCTAssertEqual(hold.surface.installs, 0, "the call had ended when its registration came to run")
        XCTAssertNil(hold.surface.info)
        XCTAssertFalse(hold.surface.deliver(.stop))
    }

    /// KR-ACC-014: a handler the system still holds from an earlier hold reaches nothing of a later
    /// one, and a command that was queued behind the end does nothing.
    func testAHandlerFromAnEarlierHoldTouchesNoLaterOne() {
        let queue = DispatchQueue(label: "to.kala.reach.test-lock-screen-generation")
        let surface = ScriptedSurface()
        var stops = 0
        var mutes = 0
        let controls = LockScreenControls(surface: surface, queue: queue, mute: { mutes += 1 }, stop: { stops += 1 })

        controls.begin(mutedByPerson: false) { true }
        queue.sync {}
        let first = surface.handler
        controls.end()
        queue.sync {}
        controls.begin(mutedByPerson: false) { true }
        queue.sync {}
        let second = surface.handler

        first?(.stop)
        first?(.pause)
        queue.sync {}
        XCTAssertEqual(stops, 0)
        XCTAssertEqual(mutes, 0)

        second?(.pause)
        second?(.stop)
        queue.sync {}
        XCTAssertEqual(mutes, 1)
        XCTAssertEqual(stops, 1)

        controls.end()
        queue.sync {}
        second?(.stop)
        queue.sync {}
        XCTAssertEqual(stops, 1, "a handler outlives its hold and does nothing")
    }

    /// KR-ACC-014: what the lock screen is given names no session, host or account.
    func testTheLockScreenNamesNothingOfTheCall() {
        let hold = permitted()
        let info = hold.surface.info
        XCTAssertEqual(info?.title, "Kala Reach voice call")
        XCTAssertFalse(info?.title.contains("secret") ?? true)
        XCTAssertFalse(LockScreenControls.title.contains("voice-session"))
    }
}
