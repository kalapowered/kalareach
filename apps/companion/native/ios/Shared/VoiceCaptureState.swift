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
/// - the call has not been stopped. A stopped gate never opens again.
///
/// It also keeps the intervals in which capture was on, so a claim that something was said when
/// nothing could have been heard is refused from this device's own record.
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
    private var stopped = false
    private var openedAtMs: UInt64?
    private var openedUntilMs: UInt64 = .max
    private var heard: [Range<UInt64>] = []

    public init(keptIntervals: Int = 64) {
        self.keptIntervals = keptIntervals
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
            if !inputAvailable { return .unavailable }
            if routeChanging { return .routeChanging }
            switch taken {
            case .interrupted: return .interrupted
            case .suspended: return .suspendedBySystem
            case .none: return mutedByPerson ? .mutedByPerson : .capturing
            }
        }
    }

    /// Whether the microphone was carrying speech at `atMs`.
    ///
    /// Answered from the intervals this gate kept. An instant older than the oldest kept interval
    /// answers false: a record that no longer reaches back that far cannot vouch for it.
    public func couldHaveHeard(atMs: UInt64) -> Bool {
        locked {
            if let open = openedAtMs, atMs >= open, atMs < openedUntilMs { return true }
            return heard.contains { $0.contains(atMs) }
        }
    }

    private func enabled(_ nowMs: UInt64) -> Bool {
        guard let held = permit else { return false }
        return !stopped && nowMs < held.deadlineMs && !mutedByPerson && taken == .none
            && !routeChanging && inputAvailable
    }

    /// Opens or closes the interval capture is in, to match what is true now.
    private func settle(_ nowMs: UInt64) {
        let on = enabled(nowMs)
        if on, openedAtMs == nil {
            openedAtMs = nowMs
            openedUntilMs = permit?.deadlineMs ?? nowMs
        } else if !on, let open = openedAtMs {
            // Capture that ran out at the deadline ended there, not whenever somebody next asked.
            let end = min(nowMs, openedUntilMs)
            if end > open {
                heard.append(open ..< end)
                if heard.count > keptIntervals { heard.removeFirst(heard.count - keptIntervals) }
            }
            openedAtMs = nil
            openedUntilMs = .max
        }
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
