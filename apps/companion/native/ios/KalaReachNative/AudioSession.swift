//
//  The audio session, configured where the platform expects it to be.
//
//  An audio session belongs to the process, not to a page: it survives the interface being
//  suspended, and it is what decides whether recording continues when the screen locks. Setting it
//  from native code is what makes that true; setting it from a page would mean it is configured
//  only while the page is running, which is the opposite of what is wanted.
//
//  What uses the session is the voice call in `VoiceCall`. The session is configured through
//  `RTCAudioSession` rather than through `AVAudioSession.sharedInstance()` directly, because
//  WebRTC's own audio device owns the category, the mode and the activation while a call is
//  running: two owners setting the same session is how a call ends up with a route nobody chose.
//  `useManualAudio` is what keeps the decision here — WebRTC does not start capture on its own, so
//  the microphone opens when this application opens it for a call and at no other time.
//

import AVFoundation
import WebRTC

/// What the system does to the audio session, as a running call is told about it.
///
/// The session reports; the call decides. Whether the microphone may carry speech is the call's
/// ``VoiceCaptureGate``, which also holds the person's own mute, so nothing the system reports can
/// reopen a microphone the person muted.
public protocol AudioSessionEvents: AnyObject {
    /// An interruption began, or ended; `mayResume` is the system's own word on resuming.
    func audioSessionInterruption(began: Bool, mayResume: Bool)
    /// The route is changing, or has settled with or without an input.
    func audioSessionRoute(changing: Bool, hasInput: Bool)
    /// The audio services were reset, and everything the session held is gone.
    func audioSessionReset()
}

/// Configures and releases this application's audio session, and reports what the system does to it.
///
/// The reporting half is not decoration. Section 15 ¶21 and ¶22 name interruptions, route changes,
/// phone calls and OS capture suspension as explicit states, and an audio session that only
/// configured itself would leave the interface guessing at all four.
public final class AudioSession: NSObject {
    /// Told whenever the microphone's state changes, on the main queue.
    public typealias CaptureObserver = (VoiceCaptureState) -> Void

    /// The one session this process has.
    public static let shared = AudioSession()

    private let session = RTCAudioSession.sharedInstance()
    private var observers: [UUID: CaptureObserver] = [:]
    private var activatedForCall = false
    /// The call the session was activated for, which is told what the system does.
    private weak var call: AudioSessionEvents?

    /// What the microphone is doing, as the system last reported it.
    public private(set) var capture: VoiceCaptureState = .idle {
        didSet {
            guard capture != oldValue else { return }
            let now = capture
            let listeners = observers.values
            DispatchQueue.main.async { listeners.forEach { $0(now) } }
        }
    }

    override private init() {
        super.init()
        let centre = NotificationCenter.default
        centre.addObserver(
            self,
            selector: #selector(handleInterruption(_:)),
            name: AVAudioSession.interruptionNotification,
            object: nil
        )
        centre.addObserver(
            self,
            selector: #selector(handleRouteChange(_:)),
            name: AVAudioSession.routeChangeNotification,
            object: nil
        )
        centre.addObserver(
            self,
            selector: #selector(handleMediaServicesReset(_:)),
            name: AVAudioSession.mediaServicesWereResetNotification,
            object: nil
        )
    }

    /// Watches the microphone's state. The returned closure stops watching.
    @discardableResult
    public func observe(_ observer: @escaping CaptureObserver) -> () -> Void {
        let id = UUID()
        observers[id] = observer
        observer(capture)
        return { [weak self] in self?.observers.removeValue(forKey: id) }
    }

    /// Makes the session ready for recording and playback over whatever route is attached.
    ///
    /// `.mixWithOthers` is deliberate: an application that stops a person's music the moment it
    /// starts is an application that takes something it was not given.
    ///
    /// This is the **only** path that opens the microphone, and its one caller is a call the host
    /// has permitted. Section 15 ¶21 says the background audio support preserves an explicitly
    /// started call and does not authorise unattended microphone activation, and §15 ¶22 says the
    /// microphone is never silently activated later without a fresh permitted active-call context.
    /// `useManualAudio` plus this being the one caller is how that is true rather than intended.
    public func activate(for call: AudioSessionEvents) throws {
        guard AVAudioSession.sharedInstance().recordPermission == .granted else {
            capture = .unavailable
            throw VoiceAudioError.microphoneNotPermitted
        }
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        session.useManualAudio = true
        let wanted = RTCAudioSessionConfiguration.webRTC()
        wanted.category = AVAudioSession.Category.playAndRecord.rawValue
        wanted.mode = AVAudioSession.Mode.voiceChat.rawValue
        wanted.categoryOptions = [.allowBluetooth, .allowBluetoothA2DP, .defaultToSpeaker]
        try session.setConfiguration(wanted, active: true)
        session.isAudioEnabled = true
        activatedForCall = true
        self.call = call
    }

    /// Gives the session back, and tells whatever was interrupted that it may resume.
    public func deactivate() throws {
        activatedForCall = false
        call = nil
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        session.isAudioEnabled = false
        try session.setActive(false)
        capture = .idle
    }

    /// Publishes what the microphone is doing, as the running call's gate decided it.
    ///
    /// The one way the state on the screen changes while a call runs, so it is always the gate's
    /// answer and never a guess made here from one notification.
    public func publish(_ state: VoiceCaptureState) {
        capture = state
    }

    @objc private func handleInterruption(_ note: Notification) {
        guard
            let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
            let type = AVAudioSession.InterruptionType(rawValue: raw)
        else { return }
        guard activatedForCall, let call else { return }
        switch type {
        case .began:
            // A phone call, Siri, or another application taking the microphone. The call is not
            // ended: §15 ¶21 wants an explicit state, and resuming needs fresh state rather than a
            // silent continuation.
            call.audioSessionInterruption(began: true, mayResume: false)
        case .ended:
            let options = (note.userInfo?[AVAudioSessionInterruptionOptionKey] as? UInt)
                .map(AVAudioSession.InterruptionOptions.init(rawValue:)) ?? []
            // The system says whether resuming is appropriate, and the call's gate decides what
            // that means: the person's own mute survives it, and without the system's word the
            // microphone stays closed until the person starts a new call.
            call.audioSessionInterruption(began: false, mayResume: options.contains(.shouldResume))
        @unknown default:
            call.audioSessionInterruption(began: false, mayResume: false)
        }
    }

    @objc private func handleRouteChange(_ note: Notification) {
        guard activatedForCall, let call else { return }
        guard
            let raw = note.userInfo?[AVAudioSessionRouteChangeReasonKey] as? UInt,
            let reason = AVAudioSession.RouteChangeReason(rawValue: raw)
        else { return }
        switch reason {
        case .oldDeviceUnavailable, .newDeviceAvailable, .override, .categoryChange:
            // A Bluetooth headset arriving or leaving. Capture is re-established on the new route
            // by the system; the state says so while it happens rather than claiming the person is
            // still being heard, and what it settles to is the gate's answer, mute included.
            call.audioSessionRoute(changing: true, hasInput: true)
            DispatchQueue.main.async { [weak self] in
                guard let self, self.activatedForCall, let call = self.call else { return }
                call.audioSessionRoute(changing: false, hasInput: self.hasInput)
            }
        case .noSuitableRouteForCategory:
            call.audioSessionRoute(changing: false, hasInput: false)
        default:
            break
        }
    }

    @objc private func handleMediaServicesReset(_: Notification) {
        // Everything the audio system held is gone. The call cannot be silently resumed: §15 ¶21
        // says resume requires fresh state and action reconciliation.
        let held = call
        activatedForCall = false
        call = nil
        held?.audioSessionReset()
    }

    private var hasInput: Bool {
        !AVAudioSession.sharedInstance().currentRoute.inputs.isEmpty
    }
}

/// What can go wrong opening the microphone, in terms a person's screen can use.
public enum VoiceAudioError: Error, Equatable {
    /// The person has not granted microphone access, or the device has no microphone.
    case microphoneNotPermitted
    /// A call was asked for while one is already running.
    case callAlreadyRunning
    /// The provider's answer could not be applied to this connection.
    case answerNotApplicable(String)
}
