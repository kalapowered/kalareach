//
//  The native voice call: WebRTC's own peer connection, and the microphone the platform owns.
//
//  Section 15 ¶2 is the constraint this file exists to satisfy, and it admits no exception: native
//  WebRTC and native platform audio own capture and playback, not a background WebView
//  `getUserMedia` path. Nothing here goes near the WebView. The offer is made by this process, the
//  answer is applied by this process, and the audio flows between this device and the provider
//  without passing through the interface or through KalaReach.
//
//  Section 15 ¶6 is the other constraint: the provider's data channel is read-only. This
//  connection creates the one channel the provider's protocol names, `oai-events`, before it makes
//  the offer, because the offer has to describe it and the provider writes to it, and it writes
//  nothing to that channel or to any other. What arrives is handed to the caller as bytes with a
//  type, and an event the caller does not recognise is dropped rather than reflected into
//  anything.
//

import Foundation
import WebRTC

/// What a running call tells the application about.
///
/// Everything is reported on the call's own queue, never on WebRTC's thread: a call that ended itself
/// from a report would otherwise close the connection that is reporting to it.
public protocol VoiceCallObserver: AnyObject {
    /// The connection's own state changed.
    func voiceCall(_ call: VoiceCall, connectionChanged state: RTCPeerConnectionState)
    /// The provider sent something on its read-only channel.
    func voiceCall(_ call: VoiceCall, receivedProviderEvent data: Data)
    /// The first remote audio track arrived. It reports a track, not audible playback.
    func voiceCallReceivedFirstAudio(_ call: VoiceCall)
}

/// One native voice call.
///
/// It owns exactly four things: the peer connection, the local microphone track, the remote audio
/// track the provider sends, and the one channel the provider writes its events to. Everything about
/// *who* is on the other end — the broker, the
/// account, the control socket — is outside it, which is what keeps the provider interface modular
/// in §15 ¶1's sense: a different provider replaces the signalling around this object and replaces
/// nothing inside it.
///
/// Every decision about the microphone is ``VoiceCallControl``'s; this class carries them out.
/// WebRTC's audio unit is held off before the connection exists, so negotiating starts nothing on
/// its own. ``permit(voiceSessionId:closesAtEpochMs:)`` is given the host's answer to the start;
/// the control opens the audio session, turns the audio unit on, and lets the microphone carry
/// speech once the recorder reports itself running. Timers and the platform's reports run on this
/// call's own queue, never the main one.
public final class VoiceCall: NSObject {
    /// The label the provider's protocol gives the channel its events arrive on.
    static let eventsLabel = "oai-events"

    /// The longest the offer waits for candidate gathering to report itself done, in seconds.
    ///
    /// Gathering is continual, and WebRTC does not report continual gathering done, so in practice
    /// every offer waits the whole bound and then offers the candidates it has.
    static let gatheringBound: TimeInterval = 3

    /// Shared across calls, because building one is expensive and it holds the audio device.
    private static let factory: RTCPeerConnectionFactory = {
        RTCInitializeSSL()
        return RTCPeerConnectionFactory(
            encoderFactory: RTCDefaultVideoEncoderFactory(),
            decoderFactory: RTCDefaultVideoDecoderFactory()
        )
    }()

    private let connection: RTCPeerConnection
    private let microphone: RTCAudioTrack
    private weak var observer: VoiceCallObserver?
    private var announcedFirstAudio = false
    /// The call's own queue: its timer, and every report from the audio session and WebRTC.
    private let queue: DispatchQueue
    /// The provider's events channel, which this end creates before the offer and only reads.
    private var events: RTCDataChannel?
    /// The first round of candidate gathering, which the offer waits for.
    private let gathering: GatheringWait
    /// What the provider's answer was read to say, once it was applied; guarded by ``negotiation``.
    private let negotiation = NSLock()
    private var answer: (applied: Bool, usesDtx: Bool) = (false, false)
    /// Every decision about the microphone, the speaker and the end of this call.
    private var control: VoiceCallControl!
    /// Asks, while the audio device is on, how much audio the call's source has taken in, and hands
    /// each answer to the reader, which decides what it means. Both touched only on ``queue``.
    private var recorderTimer: DispatchSourceTimer?
    private var recorderReader: VoiceRecorderReader!

    /// Whether the person has muted their own microphone.
    public var isMutedByPerson: Bool { control.isMutedByPerson }

    /// Whether the remote voice is silenced on this device.
    public var isPlaybackMuted: Bool { control.isPlaybackMuted }

    /// Whether the provider's answer to the offer has been applied to the connection.
    public var answerIsApplied: Bool {
        negotiation.lock()
        defer { negotiation.unlock() }
        return answer.applied
    }

    /// Whether the provider's answer turns Opus discontinuous transmission on (`usedtx=1`), which
    /// stops the stream during silence. `nil` until the answer is applied.
    public var answerUsesDtx: Bool? {
        negotiation.lock()
        defer { negotiation.unlock() }
        return answer.applied ? answer.usesDtx : nil
    }

    /// Builds a call for its offer and its answer, with the audio unit and the microphone off.
    ///
    /// No audio session is opened here: that waits for ``permit(voiceSessionId:closesAtEpochMs:)``,
    /// so nothing but a call the host permitted can open the microphone. The call claims the
    /// process's audio before anything it does can reach it, and a second call, while one holds it,
    /// is refused without touching the first.
    ///
    /// - Throws: ``VoiceAudioError/callAlreadyRunning`` while another call holds the audio, and
    ///   ``VoiceAudioError/eventChannelNotOpened`` when the provider's channel cannot be made.
    public convenience init(observer: VoiceCallObserver) throws {
        try self.init(observer: observer, gathering: IceGatheringWait())
    }

    /// The same, with the wait for candidate gathering supplied: a test holds it open to end the
    /// call inside it.
    init(observer: VoiceCallObserver, gathering: GatheringWait) throws {
        self.gathering = gathering
        // Before the factory or any connection exists, so the audio unit cannot start by itself.
        AudioSession.shared.holdAudioUntilACallTurnsItOn()

        let configuration = RTCConfiguration()
        // The provider's answer names its own candidates. No KalaReach STUN or TURN server is
        // configured here: media travels between this device and the provider, and a relay of
        // KalaReach's would be a third party in a path §15 ¶3 says has two.
        configuration.sdpSemantics = .unifiedPlan
        configuration.continualGatheringPolicy = .gatherContinually

        let constraints = RTCMediaConstraints(
            mandatoryConstraints: nil,
            // No constraint asks for a data channel of its own: §15 ¶6 makes the provider's channel
            // read-only, and the one channel this end makes is the provider's, made below.
            optionalConstraints: nil
        )
        guard
            let made = VoiceCall.factory.peerConnection(
                with: configuration,
                constraints: constraints,
                delegate: nil
            )
        else {
            throw VoiceAudioError.answerNotApplicable("this device could not open a connection")
        }
        connection = made

        // Audio processing is the platform's. On iOS libwebrtc's audio device runs through Apple's
        // Voice-Processing I/O unit, which is where echo cancellation, gain control and noise
        // suppression happen; asking for them again in software would be two cancellers fighting.
        let source = VoiceCall.factory.audioSource(with: RTCMediaConstraints(
            mandatoryConstraints: nil,
            optionalConstraints: nil
        ))
        microphone = VoiceCall.factory.audioTrack(with: source, trackId: "kr-voice-microphone")
        // Off until the control turns it on. The offer describes a track, and a described track
        // carries nothing until the control lets it.
        microphone.isEnabled = false
        queue = DispatchQueue(label: "to.kala.reach.voice-call")
        self.observer = observer
        super.init()
        // Before the control exists: building it sets every switch off, and a call that does not
        // hold the audio must not switch off the audio of the call that does.
        guard AudioSession.shared.claim(self) else {
            connection.close()
            throw VoiceAudioError.callAlreadyRunning
        }
        // The recorder is known here only from readings, so what was heard is vouched for only up
        // to the last reading that saw audio arrive.
        control = VoiceCallControl(
            platform: Platform(call: self),
            switches: Switches(call: self),
            hearingConfirmedByReadings: true
        )
        recorderReader = VoiceRecorderReader(control: control)
        connection.delegate = self
        connection.add(microphone, streamIds: ["kr-voice"])
        // Before any offer exists: an offer made first would not describe the channel, and the
        // provider writes its events to this one.
        guard let channel = connection.dataChannel(
            forLabel: VoiceCall.eventsLabel,
            configuration: RTCDataChannelConfiguration()
        ) else {
            stop()
            throw VoiceAudioError.eventChannelNotOpened
        }
        channel.delegate = self
        events = channel
    }

    /// Tells the reader the device came on or went off, and asks for readings while it is on. The
    /// switch is set on every change; only a change of state starts or stops the asking.
    private func watchRecorder(_ on: Bool) {
        queue.async { [weak self] in
            guard let self, let reader = self.recorderReader else { return }
            reader.device(on: on)
            guard on != (self.recorderTimer != nil) else { return }
            self.recorderTimer?.cancel()
            self.recorderTimer = nil
            guard on else { return }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
            timer.setEventHandler { [weak self] in self?.readCapturedAudio() }
            timer.resume()
            self.recorderTimer = timer
        }
    }

    /// Asks for one reading of the local source's `totalSamplesDuration`, the seconds of audio it
    /// has taken in, and hands the answer to the reader on this call's queue with the generation it
    /// was asked in.
    private func readCapturedAudio() {
        guard let generation = recorderReader.request() else { return }
        connection.statistics { [weak self] report in
            let source = report.statistics.values.first {
                $0.type == "media-source" && ($0.values["kind"] as? String) == "audio"
            }
            let seconds = (source?.values["totalSamplesDuration"] as? NSNumber)?.doubleValue
            self?.queue.async { [weak self] in
                self?.recorderReader.reading(capturedSeconds: seconds, generation: generation, atMs: VoiceCall.nowMs())
            }
        }
    }

    /// Opens the microphone for a call the host started.
    ///
    /// Takes the host's answer: the voice session and the moment the service closes the call, in
    /// UTC milliseconds. The audio session is opened here and nowhere else, the microphone waits
    /// for the recorder to report itself running, and the call ends itself at that moment whether
    /// or not anything else happened.
    ///
    /// - Returns: false, and the call ended, when the moment has passed or the audio session was
    ///   refused; false and nothing changed when this call is stopped or already permitted, or when
    ///   the provider's answer to the offer is not applied yet: the owner asks again once
    ///   ``accept(answerSdp:)`` has returned, or stops the call.
    public func permit(voiceSessionId: String, closesAtEpochMs: UInt64) -> Bool {
        control.permit(voiceSessionId: voiceSessionId, closesAtEpochMs: closesAtEpochMs)
    }

    /// Whether the microphone was carrying speech at `atMs` on this device's monotonic clock.
    public func couldHaveHeard(atMs: UInt64) -> Bool { control.couldHaveHeard(atMs: atMs) }

    /// Makes this call's SDP offer.
    ///
    /// Section 15 ¶3: the client creates the offer. The host forwards it and never generates one.
    /// The offer is returned after the first round of candidate gathering, or after
    /// ``gatheringBound``, so that it names the addresses this device can be reached at: the
    /// provider is answered once, and a candidate found later is not sent. A call that ends before
    /// the offer is complete makes none: this throws ``VoiceAudioError/callEnded``.
    public func offer() async throws -> String {
        let constraints = RTCMediaConstraints(
            mandatoryConstraints: [
                kRTCMediaConstraintsOfferToReceiveAudio: kRTCMediaConstraintsValueTrue,
                kRTCMediaConstraintsOfferToReceiveVideo: kRTCMediaConstraintsValueFalse,
            ],
            optionalConstraints: nil
        )
        do {
            let description = try await connection.offer(for: constraints)
            try await connection.setLocalDescription(description)
            await gathering.wait(upTo: VoiceCall.gatheringBound)
            // The wait ends with the call, and an offer for a call that ended would be sent on.
            guard !control.isStopped else { throw VoiceAudioError.callEnded }
            return connection.localDescription?.sdp ?? description.sdp
        } catch {
            // A call that cannot make its offer has nothing to wait for, and gives the audio back.
            stop()
            throw error
        }
    }

    /// Applies the provider's SDP answer. It starts nothing: the audio unit stays off until the
    /// call is permitted, and a permit before this has applied the answer is refused.
    public func accept(answerSdp: String) async throws {
        let description = RTCSessionDescription(type: .answer, sdp: answerSdp)
        do {
            try await connection.setRemoteDescription(description)
            negotiation.lock()
            answer = (true, VoiceAnswer.usesDtx(answerSdp))
            negotiation.unlock()
        } catch {
            // The same: a call whose answer does not apply ends, and gives the audio back.
            stop()
            throw VoiceAudioError.answerNotApplicable(error.localizedDescription)
        }
    }

    /// Stops the person's voice reaching the model, without ending the call.
    ///
    /// Local and immediate. Section 15 ¶10 requires local microphone and speaker mute to remain
    /// available if the broker fails, so this touches the track and nothing that could be waiting on
    /// a network answer.
    public func setMutedByPerson(_ muted: Bool) { control.setMutedByPerson(muted) }

    /// Stops the model's voice coming out of this device, without ending the call.
    ///
    /// This is **playback**, and §15 ¶13 is explicit that speech interruption stops playback and
    /// not a coding task. Nothing here cancels anything on a host.
    public func setPlaybackMuted(_ muted: Bool) { control.setPlaybackMuted(muted) }

    /// Ends the call and gives the microphone back.
    ///
    /// Local and immediate, for the same reason mute is.
    public func stop() { control.stop() }

    /// This device's monotonic clock, in milliseconds. The gate's deadlines are on it.
    fileprivate static func nowMs() -> UInt64 { DispatchTime.now().uptimeNanoseconds / 1_000_000 }

    /// The platform, as the control sees it.
    private final class Platform: VoiceCallPlatform {
        private unowned let call: VoiceCall

        init(call: VoiceCall) { self.call = call }

        func nowMs() -> UInt64 { VoiceCall.nowMs() }

        func epochMs() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1_000) }

        func answerApplied() -> Bool { call.answerIsApplied }

        func activate() throws { try AudioSession.shared.activate(for: call) }

        func deactivate() { try? AudioSession.shared.deactivate(for: call) }

        func schedule(atMs: UInt64, _ task: @escaping () -> Void) -> () -> Void {
            let work = DispatchWorkItem(block: task)
            // On the call's own queue, at the deadline on the same clock the gate uses.
            call.queue.asyncAfter(deadline: DispatchTime(uptimeNanoseconds: atMs * 1_000_000), execute: work)
            return { work.cancel() }
        }

        func publish(_ state: VoiceCaptureState) { AudioSession.shared.publish(state, for: call) }

        func ended() {
            // An offer still waiting for candidates has nothing left to wait for.
            call.gathering.finish()
            call.watchRecorder(false)
            call.connection.close()
            call.events?.delegate = nil
            call.events = nil
            AudioSession.shared.release(call)
        }
    }

    /// The media, as the control sets it.
    private final class Switches: VoiceMediaSwitches {
        private unowned let call: VoiceCall

        init(call: VoiceCall) { self.call = call }

        func setAudioDevice(_ on: Bool) {
            AudioSession.shared.setAudioEnabled(on, for: call)
            call.watchRecorder(on)
        }

        func setMicrophone(_ on: Bool) { call.microphone.isEnabled = on }

        func setPlayback(_ on: Bool) {
            for receiver in call.connection.receivers {
                (receiver.track as? RTCAudioTrack)?.isEnabled = on
            }
        }
    }
}

extension VoiceCall: AudioSessionEvents {
    // Reported on the system's and WebRTC's own threads, and acted on on the call's queue.

    public func audioSessionInterruption(began: Bool, mayResume: Bool) {
        queue.async { [weak self] in self?.control.interruption(began: began, mayResume: mayResume) }
    }

    public func audioSessionRoute(changing: Bool, hasInput: Bool) {
        queue.async { [weak self] in self?.control.route(changing: changing, inputAvailable: hasInput) }
    }

    public func audioSessionReset() {
        queue.async { [weak self] in self?.control.reset() }
    }

    public func audioSessionRecorderStopped() {
        queue.async { [weak self] in self?.recorderReader.stopped() }
    }
}

extension VoiceCall: RTCPeerConnectionDelegate {
    public func peerConnection(
        _: RTCPeerConnection,
        didChange state: RTCPeerConnectionState
    ) {
        queue.async { [weak self] in
            guard let self else { return }
            self.observer?.voiceCall(self, connectionChanged: state)
        }
    }

    public func peerConnection(_: RTCPeerConnection, didAdd receiver: RTCRtpReceiver, streams _: [RTCMediaStream]) {
        guard receiver.track is RTCAudioTrack else { return }
        // A track arrives playing; the control decides whether it may.
        queue.async { [weak self] in self?.control.refresh() }
        guard !announcedFirstAudio else { return }
        announcedFirstAudio = true
        queue.async { [weak self] in
            guard let self else { return }
            self.observer?.voiceCallReceivedFirstAudio(self)
        }
    }

    public func peerConnection(_: RTCPeerConnection, didOpen channel: RTCDataChannel) {
        // A channel the provider opened. This end reads it and never writes to it.
        channel.delegate = self
    }

    public func peerConnectionShouldNegotiate(_: RTCPeerConnection) {}
    public func peerConnection(_: RTCPeerConnection, didChange _: RTCSignalingState) {}
    public func peerConnection(_: RTCPeerConnection, didAdd _: RTCMediaStream) {}
    public func peerConnection(_: RTCPeerConnection, didRemove _: RTCMediaStream) {}
    public func peerConnection(_: RTCPeerConnection, didChange _: RTCIceConnectionState) {}
    public func peerConnection(_: RTCPeerConnection, didChange state: RTCIceGatheringState) {
        if state == .complete { gathering.finish() }
    }
    public func peerConnection(_: RTCPeerConnection, didGenerate _: RTCIceCandidate) {}
    public func peerConnection(_: RTCPeerConnection, didRemove _: [RTCIceCandidate]) {}
}

extension VoiceCall: RTCDataChannelDelegate {
    public func dataChannelDidChangeState(_: RTCDataChannel) {}

    public func dataChannel(_: RTCDataChannel, didReceiveMessageWith buffer: RTCDataBuffer) {
        // Handed up as bytes. What is a known event and what is not is decided by the frozen
        // provider profile, one level above this file, and an unknown one is dropped there.
        let data = buffer.data
        queue.async { [weak self] in
            guard let self else { return }
            self.observer?.voiceCall(self, receivedProviderEvent: data)
        }
    }
}

/// How the offer waits for the first round of candidate gathering.
protocol GatheringWait: AnyObject {
    /// Returns when gathering is done or the wait was ended, and at the latest after `seconds`.
    func wait(upTo seconds: TimeInterval) async

    /// Gathering is done: whoever waits, and whoever waits later, is released.
    func finish()
}

/// Waits for the first round of candidate gathering to finish, or for a bound.
final class IceGatheringWait: GatheringWait {
    private let lock = NSLock()
    private var done = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    /// Gathering reported itself done, the bound passed or the call ended. Any number of times;
    /// each waiter is resumed once.
    func finish() {
        lock.lock()
        done = true
        let waiters = waiting
        waiting = []
        lock.unlock()
        waiters.forEach { $0.resume() }
    }

    /// Returns when gathering is done, which may be before this is called, and at the latest after
    /// `seconds`.
    func wait(upTo seconds: TimeInterval) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if done {
                lock.unlock()
                continuation.resume()
                return
            }
            waiting.append(continuation)
            lock.unlock()
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in
                self?.finish()
            }
        }
    }
}
