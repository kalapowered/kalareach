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
    /// This is the **only** path that opens the microphone. Section 15 ¶21 says the background
    /// audio support preserves an explicitly started call and does not authorise unattended
    /// microphone activation, and §15 ¶22 says the microphone is never silently activated later
    /// without a fresh permitted active-call context. `useManualAudio` plus this being the one
    /// caller is how that is true rather than intended.
    public func activate() throws {
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
        capture = .capturing
    }

    /// Gives the session back, and tells whatever was interrupted that it may resume.
    public func deactivate() throws {
        activatedForCall = false
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        session.isAudioEnabled = false
        try session.setActive(false)
        capture = .idle
    }

    /// Records that the person muted or unmuted their own microphone.
    ///
    /// The track is what actually stops carrying audio; this is the state that goes on the screen
    /// and into the authority gate, and it is set from the same call so the two cannot disagree.
    public func setMutedByPerson(_ muted: Bool) {
        guard activatedForCall else { return }
        capture = muted ? .mutedByPerson : .capturing
    }

    @objc private func handleInterruption(_ note: Notification) {
        guard
            let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
            let type = AVAudioSession.InterruptionType(rawValue: raw)
        else { return }
        switch type {
        case .began:
            // A phone call, Siri, or another application taking the microphone. The call is not
            // ended: §15 ¶21 wants an explicit state, and resuming needs fresh state rather than a
            // silent continuation.
            capture = .interrupted
        case .ended:
            guard activatedForCall else { return }
            let options = (note.userInfo?[AVAudioSessionInterruptionOptionKey] as? UInt)
                .map(AVAudioSession.InterruptionOptions.init(rawValue:)) ?? []
            // The system says whether resuming is appropriate. When it does not, the microphone
            // stays closed and the person restarts it, because reopening a microphone the system
            // did not invite back is the unattended activation §15 ¶21 forbids.
            capture = options.contains(.shouldResume) ? .capturing : .suspendedBySystem
        @unknown default:
            capture = .suspendedBySystem
        }
    }

    @objc private func handleRouteChange(_ note: Notification) {
        guard activatedForCall else { return }
        guard
            let raw = note.userInfo?[AVAudioSessionRouteChangeReasonKey] as? UInt,
            let reason = AVAudioSession.RouteChangeReason(rawValue: raw)
        else { return }
        switch reason {
        case .oldDeviceUnavailable, .newDeviceAvailable, .override, .categoryChange:
            // A Bluetooth headset arriving or leaving. Capture is re-established on the new route
            // by the system; the state says so while it happens rather than claiming the person is
            // still being heard.
            capture = .routeChanging
            DispatchQueue.main.async { [weak self] in
                guard let self, self.activatedForCall else { return }
                self.capture = self.hasInput ? .capturing : .unavailable
            }
        case .noSuitableRouteForCategory:
            capture = .unavailable
        default:
            break
        }
    }

    @objc private func handleMediaServicesReset(_: Notification) {
        // Everything the audio system held is gone. The call cannot be silently resumed: §15 ¶21
        // says resume requires fresh state and action reconciliation.
        activatedForCall = false
        capture = .suspendedBySystem
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
