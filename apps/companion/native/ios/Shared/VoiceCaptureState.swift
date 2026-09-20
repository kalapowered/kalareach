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
