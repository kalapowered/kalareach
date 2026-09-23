//
//  What the microphone is doing, and what that means for authority.
//
//  Section 15 ¶22 asks for two things that are easy to confuse. The first is a display: if capture
//  is muted or unavailable, say so. The second is a refusal, and it is the one that matters: reject
//  any claim that unreceived speech authorised an action. A screen that showed a muted microphone
//  while the application acted on words nobody captured would satisfy the first and fail the second.
//
//  So the state is not a label on a view. It is the thing asked before a spoken instruction is
//  allowed to become anything, and it answers no whenever the microphone was not actually carrying
//  the person's voice. It has no dependency on WebRTC, on the audio session or on UIKit, so the
//  tests run without a device.
//

import Foundation

/// What the microphone is doing right now.
///
/// Ordered from "the person is being heard" to "the person is not", because several of them mean
/// the same thing to authority and differ only in what a person is told.
public enum VoiceCaptureState: String, Equatable, Sendable {
    /// The microphone is open and carrying speech to the call.
    case capturing
    /// The person muted it. Their own choice, and reversible by them.
    case mutedByPerson
    /// The system took the microphone: a phone call, another application, Siri.
    case interrupted
    /// The route changed and capture has not been re-established on the new one yet.
    case routeChanging
    /// The operating system suspended capture. Section 15 ¶22 names this as its own state.
    case suspendedBySystem
    /// There is no microphone, or the person has not granted access to one.
    case unavailable
    /// No call is running, so nothing is being captured.
    case idle

    /// Whether speech could have reached the call in this state.
    ///
    /// This is the whole point of the type. Every state but `capturing` answers false, including
    /// the ones a person caused themselves: a muted microphone heard nothing, whoever muted it.
    public var speechCouldHaveBeenHeard: Bool { self == .capturing }

    /// What a person is told, in their own terms.
    ///
    /// Never "error" and never a code. Each one says what is true and, where the person can change
    /// it, what would change it.
    public var display: String {
        switch self {
        case .capturing: return "Microphone on"
        case .mutedByPerson: return "Microphone muted"
        case .interrupted: return "Microphone taken by another call"
        case .routeChanging: return "Switching audio device"
        case .suspendedBySystem: return "Microphone paused by iOS"
        case .unavailable: return "No microphone available"
        case .idle: return "Not in a call"
        }
    }
}

/// Why a spoken instruction was not allowed to become an action.
public enum VoiceAuthorityRefusal: Equatable, Sendable {
    /// The microphone was not carrying speech when the words were supposed to have been said.
    case speechNotHeard(VoiceCaptureState)
    /// The action needs a confirmation taken on the unlocked screen, and there is none.
    case needsUnlockedScreenConfirmation

    /// What a person is told.
    public var message: String {
        switch self {
        case let .speechNotHeard(state):
            return "\(state.display). Nothing spoken while the microphone was not carrying your "
                + "voice can authorise an action."
        case .needsUnlockedScreenConfirmation:
            return "This needs your confirmation on the unlocked screen of this device."
        }
    }
}

/// The one gate a spoken instruction passes before it can become a host action.
///
/// It is deliberately not a method on a view model. §15 ¶8 says a model statement that the user
/// confirmed an operation is not a native-screen confirmation, and the provider is inside the trust
/// boundary for interpreting speech, so the question "could this person have been heard?" has to be
/// answered from the device's own record of its microphone rather than from anything that arrived
/// over the call.
public struct VoiceAuthorityGate: Sendable {
    /// The microphone's state, as the audio session last reported it.
    public var capture: VoiceCaptureState
    /// Whether the call holds a confirmation signed on this device's unlocked screen.
    public var holdsUnlockedScreenConfirmation: Bool

    public init(capture: VoiceCaptureState, holdsUnlockedScreenConfirmation: Bool = false) {
        self.capture = capture
        self.holdsUnlockedScreenConfirmation = holdsUnlockedScreenConfirmation
    }

    /// Whether a delegation the provider announced may be submitted to the host.
    ///
    /// - Parameter needsConfirmation: true for the five action classes of §15 ¶13.
    /// - Returns: nil when it may, or the refusal when it may not.
    public func refusal(needsConfirmation: Bool) -> VoiceAuthorityRefusal? {
        guard capture.speechCouldHaveBeenHeard else {
            return .speechNotHeard(capture)
        }
        if needsConfirmation && !holdsUnlockedScreenConfirmation {
            return .needsUnlockedScreenConfirmation
        }
        return nil
    }
}

/// Whether the microphone may carry the person's voice, decided in one place.
///
/// Section 15 ¶21 and ¶22 ask for two things at once: a call the person started keeps its
/// microphone through a screen lock, and nothing opens the microphone without a fresh permitted
/// active-call context. This type is the second half. Capture is on only while every one of these
/// holds, and each is kept apart from the others so that none of them can stand in for another:
///
/// - a permit: the host answered a start with a voice session and a deadline, and the call applied
///   that answer. A permit belongs to one generation, and a revocation naming an older generation
///   is refused, so one that arrives late cannot touch the call that replaced the one it was about;
/// - the deadline, on this device's monotonic clock, has not passed;
/// - the person has not muted the microphone;
/// - the system has not taken it: an interruption such as a phone call, or capture suspended;
/// - the audio route is settled on a device that has an input;
/// - the platform's recorder reports itself running. Until it starts, and after it stops or fails,
///   nothing is being recorded, and the display says the microphone is unavailable rather than on;
/// - the call has not been stopped. A stopped gate never opens again.
///
/// It also keeps the intervals in which capture was on, so a claim that something was said when
/// nothing could have been heard is refused from this device's own record. The record answers for
/// the past only: an instant later than the time it is asked at is not one anything was heard in.
///
/// Every method takes the time from its caller, in milliseconds on the monotonic clock, so tests
/// drive time instead of waiting for it. Every method holds one lock: the system reports
/// interruptions and routes on queues of its own, and the one answer to "is the microphone on"
/// cannot be assembled from two halves.
public final class VoiceCaptureGate: @unchecked Sendable {
    /// One permitted call, as the host's answer to a start bound it.
    public struct Permit: Equatable, Sendable {
        public let generation: UInt64
        public let voiceSessionId: String
        public let deadlineMs: UInt64
    }

    /// What the system has done to the microphone, apart from anything the person chose.
    public enum Taken: CaseIterable, Sendable {
        /// Nothing.
        case none
        /// An interruption: a phone call, Siri, another application.
        case interrupted
        /// The system suspended capture, or reset the audio services under it.
        case suspended
    }

    private let lock = NSLock()
    private let keptIntervals: Int
    private var generation: UInt64 = 0
    private var permit: Permit?
    private var mutedByPerson = false
    private var taken = Taken.none
    private var routeChanging = false
    private var inputAvailable = true
    private var recorderRunning = false
    private var stopped = false
    private var openedAtMs: UInt64?
    private var openedUntilMs: UInt64 = .max
    private var heard: [Range<UInt64>] = []
    /// Where the recorder is known only from readings taken now and then, the latest moment audio
    /// was seen arriving. Nil where every moment the recorder runs counts as heard.
    private var confirmedUntilMs: UInt64?

    /// - Parameter hearingConfirmedByReadings: true where the platform tells whether audio is
    ///   arriving only through readings taken now and then. The record then vouches only for time up
    ///   to the last reading that saw audio arrive, whatever the display said in between, and every
    ///   interval, however it closes, ends there at the latest.
    public init(keptIntervals: Int = 64, hearingConfirmedByReadings: Bool = false) {
        self.keptIntervals = keptIntervals
        confirmedUntilMs = hearingConfirmedByReadings ? 0 : nil
    }

    /// The permit capture runs under now, or nil.
    public var current: Permit? { locked { permit } }

    /// Whether the person muted the microphone. Unchanged by anything the system does.
    public var isMutedByPerson: Bool { locked { mutedByPerson } }

    /// Binds the gate to the host's answer, and returns the permit.
    ///
    /// Nil when the gate is stopped, when it already holds a permit, or when the deadline has
    /// already passed: a call is permitted once, by an answer that is still current.
    @discardableResult
    public func permit(voiceSessionId: String, deadlineMs: UInt64, nowMs: UInt64) -> Permit? {
        locked {
            guard !stopped, permit == nil, deadlineMs > nowMs else { return nil }
            generation += 1
            let made = Permit(generation: generation, voiceSessionId: voiceSessionId, deadlineMs: deadlineMs)
            permit = made
            settle(nowMs)
            return made
        }
    }

    /// Withdraws the permit of one generation. False, and nothing changed, for any other.
    @discardableResult
    public func revoke(generation: UInt64, nowMs: UInt64) -> Bool {
        locked {
            guard let held = permit, held.generation == generation else { return false }
            permit = nil
            settle(nowMs)
            return true
        }
    }

    /// The person's own mute. What the system does to the microphone never changes it.
    public func setMutedByPerson(_ muted: Bool, nowMs: UInt64) {
        locked {
            mutedByPerson = muted
            settle(nowMs)
        }
    }

    /// What the system has done to the microphone.
    public func taken(_ by: Taken, nowMs: UInt64) {
        locked {
            taken = by
            settle(nowMs)
        }
    }

    /// The audio route, as the platform reports it.
    public func route(changing: Bool, inputAvailable: Bool, nowMs: UInt64) {
        locked {
            routeChanging = changing
            self.inputAvailable = inputAvailable
            settle(nowMs)
        }
    }

    /// Whether the platform's recorder is running, as the platform reports it.
    ///
    /// Reported by the audio device itself: when it starts, when it stops and when it fails. A
    /// recorder that has not started heard nothing, whatever the call was permitted to do.
    public func recorder(running: Bool, nowMs: UInt64) {
        locked {
            recorderRunning = running
            settle(nowMs)
        }
    }

    /// Audio was seen arriving at `atMs`. Only for a gate whose hearing is confirmed by readings;
    /// elsewhere it changes nothing.
    public func recorderHeard(atMs: UInt64, nowMs: UInt64) {
        locked {
            guard let confirmed = confirmedUntilMs else { return }
            confirmedUntilMs = max(confirmed, min(atMs, nowMs))
            settle(nowMs)
        }
    }

    /// Stops the gate for good.
    public func stop(nowMs: UInt64) {
        locked {
            stopped = true
            permit = nil
            settle(nowMs)
        }
    }

    /// Whether the microphone may carry speech now.
    public func captureEnabled(nowMs: UInt64) -> Bool {
        locked {
            settle(nowMs)
            return enabled(nowMs)
        }
    }

    /// What a person is told about the microphone now.
    ///
    /// `.capturing` exactly when ``captureEnabled(nowMs:)`` is true, so the display and the refusal
    /// of unheard speech can never disagree.
    public func displayed(nowMs: UInt64) -> VoiceCaptureState {
        locked {
            settle(nowMs)
            guard !stopped, let held = permit, nowMs < held.deadlineMs else { return .idle }
            // What the system did is said first: it is why the recorder stopped, when it did.
            switch taken {
            case .interrupted: return .interrupted
            case .suspended: return .suspendedBySystem
            case .none: break
            }
            if routeChanging { return .routeChanging }
            if !inputAvailable || !recorderRunning { return .unavailable }
            return mutedByPerson ? .mutedByPerson : .capturing
        }
    }

    /// Whether the microphone was carrying speech at `atMs`, asked at `nowMs`.
    ///
    /// Answered from the intervals this gate kept. An instant later than `nowMs` answers false: a
    /// permit that is still running is permission to capture, not a record that anything was heard.
    /// An instant older than the oldest kept interval answers false too: a record that no longer
    /// reaches back that far cannot vouch for it.
    public func couldHaveHeard(atMs: UInt64, nowMs: UInt64) -> Bool {
        locked {
            settle(nowMs)
            if atMs > nowMs { return false }
            if let open = openedAtMs, atMs >= open, atMs < heardUntil(openedUntilMs) { return true }
            return heard.contains { $0.contains(atMs) }
        }
    }

    /// Whether a permit is running: given, not withdrawn, not stopped and not past its deadline.
    ///
    /// What the platform's audio device is allowed to run for. Whether the microphone carries
    /// speech is ``captureEnabled(nowMs:)``'s, which asks everything else as well.
    public func live(nowMs: UInt64) -> Bool {
        locked {
            guard !stopped, let held = permit else { return false }
            return nowMs < held.deadlineMs
        }
    }

    private func enabled(_ nowMs: UInt64) -> Bool {
        guard let held = permit else { return false }
        return !stopped && nowMs < held.deadlineMs && !mutedByPerson && taken == .none
            && !routeChanging && inputAvailable && recorderRunning
    }

    /// Opens or closes the interval capture is in, to match what is true now.
    private func settle(_ nowMs: UInt64) {
        let on = enabled(nowMs)
        if on, openedAtMs == nil {
            openedAtMs = nowMs
            openedUntilMs = permit?.deadlineMs ?? nowMs
        } else if !on, let open = openedAtMs {
            // Capture that ran out at the deadline ended there, not whenever somebody next asked;
            // and where hearing is confirmed by readings, it ended at the last one that saw audio.
            let end = heardUntil(min(nowMs, openedUntilMs))
            if end > open {
                heard.append(open ..< end)
                if heard.count > keptIntervals { heard.removeFirst(heard.count - keptIntervals) }
            }
            openedAtMs = nil
            openedUntilMs = .max
        }
    }

    /// `limit`, or the last moment audio was seen arriving if that is earlier and hearing is
    /// confirmed by readings.
    private func heardUntil(_ limit: UInt64) -> UInt64 {
        guard let confirmed = confirmedUntilMs else { return limit }
        return min(limit, confirmed)
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

/// The switches a call's media runs through on the platform.
///
/// ``VoiceCallControl`` sets every one of them, from its gate, in one place, and nothing else sets
/// them. An implementation holds every switch off from the moment its connection exists, before
/// anything is negotiated, so there is no window in which WebRTC could start recording on its own.
public protocol VoiceMediaSwitches: AnyObject {
    /// Whether the platform's audio device runs at all: the recorder, and the player beside it.
    func setAudioDevice(_ on: Bool)
    /// Whether what the recorder hears is carried to the provider.
    func setMicrophone(_ on: Bool)
    /// Whether the provider's voice comes out of this device.
    func setPlayback(_ on: Bool)
}

/// What a call needs from the platform besides its media.
public protocol VoiceCallPlatform: AnyObject {
    /// This device's monotonic clock, in milliseconds.
    func nowMs() -> UInt64
    /// The wall clock, in milliseconds since the epoch.
    func epochMs() -> UInt64
    /// Opens the audio session for the call. Throws when the platform refuses it.
    func activate() throws
    /// Gives the audio session back.
    func deactivate()
    /// Runs `task` once at `atMs` on the monotonic clock, on a queue of the call's own rather than
    /// the main queue. The answer cancels it.
    func schedule(atMs: UInt64, _ task: @escaping () -> Void) -> () -> Void
    /// Tells the screen what the microphone is doing.
    func publish(_ state: VoiceCaptureState)
    /// The call has ended: whatever the platform holds for it, the connection first, goes now.
    func ended()
}

/// A call's hold on the microphone, from the host's answer to the end of the call.
///
/// Every decision about the microphone is made here, and the platform code around it only carries
/// the decisions out, so the tests run the same code the application does. A permitted call goes
/// through two steps, and capture waits for both:
///
/// 1. ``permit(voiceSessionId:closesAtEpochMs:)`` takes the host's answer: the voice session and
///    the moment the service closes the call. It refuses a stopped or already permitted call and
///    an answer whose moment has passed, and opens the audio session; a refusal ends the call. The
///    gate is permitted with the clock read again after the session opened, so time the platform
///    took counts against the deadline instead of extending it, and the call's end is scheduled for
///    that moment on the call's own queue.
/// 2. The platform's recorder reports itself running (``recorder(running:)``). Only then may
///    capture carry speech.
///
/// Every change ends in `apply`, the one place a switch is set. Any change made after the deadline
/// ends the call there and then, so a late timer never leaves the microphone open.
public final class VoiceCallControl: @unchecked Sendable {
    /// The furthest deadline a call is given: a day. No call runs that long.
    public static let longestCallMs: UInt64 = 86_400_000

    private let platform: VoiceCallPlatform
    private let switches: VoiceMediaSwitches
    private let gate: VoiceCaptureGate
    /// Recursive, because the platform can report a route change on the thread that is opening or
    /// closing the audio session, and that report takes this lock too.
    private let lock = NSRecursiveLock()
    private var deviceOn = false
    private var sessionOpen = false
    private var cancelExpiry: (() -> Void)?
    private var playbackMuted = false
    private var interrupted = false
    private var stopped = false

    /// - Parameter hearingConfirmedByReadings: true where the platform tells whether audio is
    ///   arriving only through readings, which ``recorderHeard(atMs:)`` then reports.
    public init(
        platform: VoiceCallPlatform,
        switches: VoiceMediaSwitches,
        keptIntervals: Int = 64,
        hearingConfirmedByReadings: Bool = false
    ) {
        self.platform = platform
        self.switches = switches
        gate = VoiceCaptureGate(keptIntervals: keptIntervals, hearingConfirmedByReadings: hearingConfirmedByReadings)
        switches.setMicrophone(false)
        switches.setPlayback(false)
        switches.setAudioDevice(false)
    }

    /// Whether the person muted their own microphone.
    public var isMutedByPerson: Bool { gate.isMutedByPerson }

    /// Whether the person silenced the provider's voice on this device.
    public var isPlaybackMuted: Bool { locked { playbackMuted } }

    /// Whether the call has ended. It never starts again.
    public var isStopped: Bool { locked { stopped } }

    /// Takes the host's answer to the start: the voice session and the moment the service closes
    /// the call, in milliseconds since the epoch.
    ///
    /// - Returns: true when the gate is permitted; capture then waits for the recorder to start.
    ///   False when the call is stopped or already permitted, and false with the call ended when
    ///   the moment has passed or the platform refused the audio session.
    public func permit(voiceSessionId: String, closesAtEpochMs: UInt64) -> Bool {
        locked {
            guard !stopped, gate.current == nil else { return false }
            let wall = platform.epochMs()
            guard closesAtEpochMs > wall else {
                stopLocked()
                return false
            }
            let deadline = platform.nowMs() + min(closesAtEpochMs - wall, Self.longestCallMs)
            do {
                try platform.activate()
            } catch {
                stopLocked()
                return false
            }
            sessionOpen = true
            let now = platform.nowMs()
            guard gate.permit(voiceSessionId: voiceSessionId, deadlineMs: deadline, nowMs: now) != nil else {
                stopLocked()
                return false
            }
            cancelExpiry = platform.schedule(atMs: deadline) { [weak self] in self?.stop() }
            applyLocked(now)
            return true
        }
    }

    /// The platform's recorder started, stopped or failed. A start counts only while the audio
    /// device is on; one reported while it is off is from before, or from a device this call did
    /// not turn on.
    public func recorder(running: Bool) {
        change { now in gate.recorder(running: running && deviceOn, nowMs: now) }
    }

    /// Audio was seen arriving at `atMs`. What was heard is recorded up to there, and no switch is
    /// set; but like every other change, one that arrives after the deadline ends the call.
    public func recorderHeard(atMs: UInt64) {
        locked {
            guard !stopped else { return }
            let now = platform.nowMs()
            gate.recorderHeard(atMs: atMs, nowMs: now)
            if gate.current != nil, !gate.live(nowMs: now) {
                stopLocked()
            }
        }
    }

    /// The person's own mute. Nothing the system does changes it.
    public func setMutedByPerson(_ muted: Bool) {
        change { now in gate.setMutedByPerson(muted, nowMs: now) }
    }

    /// The person silencing the provider's voice, which changes playback and nothing else.
    public func setPlaybackMuted(_ muted: Bool) {
        change { _ in playbackMuted = muted }
    }

    /// An interruption began or ended; `mayResume` is the system's own word on resuming. Without it
    /// the microphone and the speaker stay closed until a new call.
    public func interruption(began: Bool, mayResume: Bool) {
        change { now in
            interrupted = began || !mayResume
            let taken: VoiceCaptureGate.Taken = began ? .interrupted : (mayResume ? .none : .suspended)
            gate.taken(taken, nowMs: now)
        }
    }

    /// The audio services were reset, and everything the session held is gone.
    public func reset() {
        change { now in
            interrupted = true
            gate.taken(.suspended, nowMs: now)
        }
    }

    /// The audio route, as the platform reports it.
    public func route(changing: Bool, inputAvailable: Bool) {
        change { now in gate.route(changing: changing, inputAvailable: inputAvailable, nowMs: now) }
    }

    /// Something about the media changed, such as a track arriving, and the switches are set again.
    public func refresh() {
        change { _ in }
    }

    /// Whether the microphone was carrying speech at `atMs` on the monotonic clock. Never later
    /// than now.
    public func couldHaveHeard(atMs: UInt64) -> Bool {
        gate.couldHaveHeard(atMs: atMs, nowMs: platform.nowMs())
    }

    /// What the microphone is doing now.
    public func displayed() -> VoiceCaptureState { gate.displayed(nowMs: platform.nowMs()) }

    /// Ends the call. Local and immediate, and the second time does nothing.
    public func stop() {
        locked { stopLocked() }
    }

    private func change(_ body: (UInt64) -> Void) {
        locked {
            guard !stopped else { return }
            let now = platform.nowMs()
            body(now)
            applyLocked(now)
        }
    }

    private func applyLocked(_ now: UInt64) {
        if gate.current != nil, !gate.live(nowMs: now) {
            // The deadline passed. The scheduled end may be late or may never run; this change is
            // the call's end instead.
            stopLocked()
            return
        }
        let live = gate.live(nowMs: now)
        if live != deviceOn {
            // A recorder is heard from afresh each time the device comes on: until the platform
            // reports it started, nothing is being recorded, and a report from before does not count.
            gate.recorder(running: false, nowMs: now)
            deviceOn = live
        }
        let shown = gate.displayed(nowMs: now)
        switches.setAudioDevice(live)
        switches.setMicrophone(gate.captureEnabled(nowMs: now))
        switches.setPlayback(live && !playbackMuted && !interrupted)
        platform.publish(shown)
    }

    private func stopLocked() {
        guard !stopped else { return }
        stopped = true
        gate.stop(nowMs: platform.nowMs())
        cancelExpiry?()
        cancelExpiry = nil
        switches.setMicrophone(false)
        switches.setPlayback(false)
        switches.setAudioDevice(false)
        deviceOn = false
        if sessionOpen {
            platform.deactivate()
            sessionOpen = false
        }
        platform.publish(.idle)
        platform.ended()
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

/// The one call this process's audio belongs to.
///
/// The audio session and the audio unit are the process's, not a call's, so a call that is being
/// built must not touch them while another call holds them: a second call's constructor switching
/// the audio off would silence the call that is running. A call claims the audio before its control
/// can reach it, gives it back when it ends, and every change to the shared audio names the call
/// making it and is ignored when that call is not the holder.
///
/// A claim is a reservation, kept only while the call itself is alive: a call its owner let go of
/// before it opened the audio has nothing open to close, and the next call may have the audio.
/// Opening the audio turns the reservation into a hold, which keeps the call alive until it gives
/// the audio back: a call let go of with the audio session open under it would otherwise leave
/// nothing to close it.
public final class VoiceAudioOwner: @unchecked Sendable {
    private let lock = NSLock()
    private weak var reserved: AnyObject?
    private var held: AnyObject?

    public init() {}

    private var holder: AnyObject? { held ?? reserved }

    /// Reserves the audio for `call`. False, and nothing changed, while another call holds or has
    /// reserved it.
    public func claim(_ call: AnyObject) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let current = holder, current !== call { return false }
        if held == nil { reserved = call }
        return true
    }

    /// Turns `call`'s reservation into a hold, before it opens the audio. False when `call` has
    /// not reserved it.
    public func hold(_ call: AnyObject) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard holder === call else { return false }
        held = call
        reserved = call
        return true
    }

    /// Gives the audio back, when `call` holds or has reserved it.
    public func release(_ call: AnyObject) {
        lock.lock()
        defer { lock.unlock() }
        guard holder === call else { return }
        held = nil
        reserved = nil
    }

    /// Whether `call` holds or has reserved the audio.
    public func holds(_ call: AnyObject) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return holder === call
    }
}

/// Whether the microphone is delivering audio, read from how much audio the call's source has taken
/// in so far.
///
/// WebRTC's audio session says only that playback or recording was asked to start, which a call
/// that plays and records nothing would also report. What the source has taken in is the
/// recorder's own work: while that total grows the microphone is delivering audio, and once it has
/// not grown for `quietMs` it is not. The first reading after the device comes on is where the count
/// starts, not growth.
public struct VoiceRecorderWatch: Sendable {
    private let quietMs: UInt64
    private var last: Double?
    private var grewAtMs: UInt64?
    private var running = false

    public init(quietMs: UInt64 = 750) {
        self.quietMs = quietMs
    }

    /// What a reading showed about the recorder.
    public enum Change: Equatable, Sendable {
        /// Audio started arriving, and was seen arriving at `atMs`.
        case started(atMs: UInt64)
        /// Audio is still arriving, and was seen arriving at `atMs`.
        case heard(atMs: UInt64)
        /// Audio stopped arriving.
        case stopped
    }

    /// Takes one reading of the source's total captured seconds, nil when the report had none, at
    /// `atMs` on the monotonic clock. Answers what it showed, or nil when it showed nothing new.
    public mutating func observe(capturedSeconds: Double?, atMs: UInt64) -> Change? {
        if let total = capturedSeconds {
            defer { last = total }
            if let previous = last, total > previous {
                grewAtMs = atMs
                if !running {
                    running = true
                    return .started(atMs: atMs)
                }
                return .heard(atMs: atMs)
            }
        }
        if running, let grew = grewAtMs, atMs >= grew + quietMs {
            running = false
            return .stopped
        }
        return nil
    }

    /// Starts afresh, for a device that has just come on or gone off.
    public mutating func reset() {
        last = nil
        grewAtMs = nil
        running = false
    }
}

/// Turns what WebRTC reports about a call's audio source into the recorder's state, for one call.
///
/// The call's adapter only carries things here: when its audio device comes on or goes off, each
/// reading of the source's captured total, and WebRTC's own report that the audio unit stopped or
/// failed. Readings are asked for while the device is on and carry the generation they were asked
/// in; a device change or a stop starts a new generation, so a reading asked for before either is
/// dropped rather than taken as news, and a stop starts the count again, so audio that resumes is
/// seen as a start. Not thread-safe: the adapter uses it on the call's own queue only.
public final class VoiceRecorderReader {
    private let control: VoiceCallControl
    private var watch: VoiceRecorderWatch
    private var generation: UInt64 = 0
    private var on = false

    public init(control: VoiceCallControl, quietMs: UInt64 = 750) {
        self.control = control
        watch = VoiceRecorderWatch(quietMs: quietMs)
    }

    /// The audio device came on or went off.
    public func device(on: Bool) {
        guard on != self.on else { return }
        self.on = on
        generation += 1
        watch.reset()
    }

    /// Whether a reading should be asked for now, and the generation to send with it.
    public func request() -> UInt64? { on ? generation : nil }

    /// A reading asked for in `generation`: the source's total captured seconds, nil when the
    /// report had none, at `atMs` on the monotonic clock.
    public func reading(capturedSeconds: Double?, generation: UInt64, atMs: UInt64) {
        guard on, generation == self.generation else { return }
        switch watch.observe(capturedSeconds: capturedSeconds, atMs: atMs) {
        case let .started(at)?:
            control.recorder(running: true)
            control.recorderHeard(atMs: at)
        case let .heard(at)?:
            control.recorderHeard(atMs: at)
        case .stopped?:
            control.recorder(running: false)
        case nil:
            break
        }
    }

    /// WebRTC reported the audio unit stopped, or failed to start.
    public func stopped() {
        generation += 1
        watch.reset()
        control.recorder(running: false)
    }
}
