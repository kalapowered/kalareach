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
//  the microphone opens when this application opens it for a call and at no other time. It is set
//  when this object is made, which a call does before it builds any connection, so there is no
//  moment at which a negotiated connection could start the audio unit by itself.
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
    /// WebRTC's audio unit stopped, or failed to start. A start is not reported here: WebRTC says
    /// only that playback or recording was asked to begin, which says nothing about the microphone.
    func audioSessionRecorderStopped()
}

/// Configures and releases this application's audio session, and reports what the system does to it.
///
/// The reporting half is not decoration. Section 15 ¶21 and ¶22 name interruptions, route changes,
/// phone calls and OS capture suspension as explicit states, and an audio session that only
/// configured itself would leave the interface guessing at all four.
public final class AudioSession: NSObject, RTCAudioSessionDelegate {
    /// Told whenever the microphone's state changes, on the main queue.
    public typealias CaptureObserver = (VoiceCaptureState) -> Void

    /// The one session this process has.
    public static let shared = AudioSession()

    private let session = RTCAudioSession.sharedInstance()
    private var observers: [UUID: CaptureObserver] = [:]
    private var activatedForCall = false
    /// The one call the process's audio belongs to. Every change below names its call and is
    /// ignored for any other, so a call being built cannot touch the audio of a call that is running.
    private let owner = VoiceAudioOwner()
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
        // Before any connection exists: WebRTC starts no audio unit until a call turns audio on.
        session.lockForConfiguration()
        session.useManualAudio = true
        session.isAudioEnabled = false
        session.unlockForConfiguration()
        session.add(self)
    }

    /// Reserves the process's audio for `call`, for as long as the call is alive. False, and nothing
    /// changed, while another call holds or has reserved it.
    public func claim(_ call: AudioSessionEvents) -> Bool { owner.claim(call) }

    /// Gives the audio back, when `call` holds it.
    public func release(_ call: AudioSessionEvents) { owner.release(call) }

    /// Holds WebRTC's audio unit off until a call turns it on. A call calls this before it builds
    /// its connection; the first use of ``shared`` has already done it, and this says so where the
    /// order matters.
    public func holdAudioUntilACallTurnsItOn() {
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        session.useManualAudio = true
        if !activatedForCall { session.isAudioEnabled = false }
    }

    /// Watches the microphone's state. The returned closure stops watching.
    @discardableResult
    public func observe(_ observer: @escaping CaptureObserver) -> () -> Void {
        let id = UUID()
        observers[id] = observer
        observer(capture)
        return { [weak self] in self?.observers.removeValue(forKey: id) }
    }

    /// Makes the session ready for recording and playback over whatever route is attached: play and
    /// record in the voice chat mode, Bluetooth headsets allowed, and the speaker by default.
    ///
    /// This opens the session and nothing more. The audio unit, and with it the recorder, runs only
    /// once the call turns audio on through ``setAudioEnabled(_:)``, and its one caller is a call the
    /// host has permitted. Section 15 ¶21 says the background audio support preserves an explicitly
    /// started call and does not authorise unattended microphone activation, and §15 ¶22 says the
    /// microphone is never silently activated later without a fresh permitted active-call context.
    public func activate(for call: AudioSessionEvents) throws {
        // From here the call is kept until it gives the audio back: it is about to open something
        // only its own end can close.
        guard owner.hold(call) else { throw VoiceAudioError.callAlreadyRunning }
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
        activatedForCall = true
        self.call = call
    }

    /// Lets WebRTC run its audio unit, recorder and player, or stops it. The call's one switch for
    /// the audio device; nothing else turns it on, and a call that does not hold the audio changes
    /// nothing.
    public func setAudioEnabled(_ on: Bool, for call: AudioSessionEvents) {
        guard owner.holds(call) else { return }
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        session.isAudioEnabled = on && activatedForCall
    }

    /// Gives the session back, and tells whatever was interrupted that it may resume. Only the call
    /// that holds the audio can.
    public func deactivate(for call: AudioSessionEvents) throws {
        guard owner.holds(call) else { return }
        activatedForCall = false
        self.call = nil
        session.lockForConfiguration()
        defer { session.unlockForConfiguration() }
        session.isAudioEnabled = false
        try session.setActive(false)
        capture = .idle
    }

    /// Publishes what the microphone is doing, as the running call's gate decided it.
    ///
    /// The one way the state on the screen changes while a call runs, so it is always the gate's
    /// answer and never a guess made here from one notification. Only the call that holds the audio
    /// publishes.
    public func publish(_ state: VoiceCaptureState, for call: AudioSessionEvents) {
        guard owner.holds(call) else { return }
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

    // What WebRTC's audio unit reports, on WebRTC's own threads. The call moves each report onto
    // its own queue before acting on it. Only a stop or a failure is taken from here: a start is read
    // from the audio the call's source has taken in.

    public func audioSessionDidStopPlayOrRecord(_: RTCAudioSession) {
        call?.audioSessionRecorderStopped()
    }

    public func audioSession(_: RTCAudioSession, audioUnitStartFailedWithError _: Error) {
        call?.audioSessionRecorderStopped()
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
