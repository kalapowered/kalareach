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
//  connection creates no data channel of its own and sends **zero** bytes on the one the provider
//  opens. What arrives is handed to the caller as bytes with a type, and an event the caller does
//  not recognise is dropped rather than reflected into anything.
//

import Foundation
import WebRTC

/// What a running call tells the application about.
public protocol VoiceCallObserver: AnyObject {
    /// The connection's own state changed.
    func voiceCall(_ call: VoiceCall, connectionChanged state: RTCPeerConnectionState)
    /// The provider sent something on its read-only channel.
    func voiceCall(_ call: VoiceCall, receivedProviderEvent data: Data)
    /// The first remote audio arrived. Section 27's KR-PERF-010 first-audio figure is taken here.
    func voiceCallReceivedFirstAudio(_ call: VoiceCall)
}

/// One native voice call.
///
/// It owns exactly three things: the peer connection, the local microphone track, and the remote
/// audio track the provider sends. Everything about *who* is on the other end — the broker, the
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
    /// Every decision about the microphone, the speaker and the end of this call.
    private var control: VoiceCallControl!

    /// Whether the person has muted their own microphone.
    public var isMutedByPerson: Bool { control.isMutedByPerson }

    /// Whether the remote voice is silenced on this device.
    public var isPlaybackMuted: Bool { control.isPlaybackMuted }

    /// Builds a call for its offer and its answer, with the audio unit and the microphone off.
    ///
    /// No audio session is opened here: that waits for ``permit(voiceSessionId:closesAtEpochMs:)``,
    /// so nothing but a call the host permitted can open the microphone.
    public init(observer: VoiceCallObserver) throws {
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
            // The one place the caller could have asked for a data channel of its own. It does
            // not: §15 ¶6 makes the provider's channel read-only and this end creates none.
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
        queue = DispatchQueue(label: "to.kala.reach.companion.voice-call")
        self.observer = observer
        super.init()
        control = VoiceCallControl(platform: Platform(call: self), switches: Switches(call: self))
        connection.delegate = self
        connection.add(microphone, streamIds: ["kr-voice"])
    }

    /// Opens the microphone for a call the host started.
    ///
    /// Takes the host's answer: the voice session and the moment the service closes the call, in
    /// UTC milliseconds. The audio session is opened here and nowhere else, the microphone waits
    /// for the recorder to report itself running, and the call ends itself at that moment whether
    /// or not anything else happened.
    ///
    /// - Returns: false, and the call ended, when the moment has passed or the audio session was
    ///   refused; false and nothing changed when this call is stopped or already permitted.
    public func permit(voiceSessionId: String, closesAtEpochMs: UInt64) -> Bool {
        control.permit(voiceSessionId: voiceSessionId, closesAtEpochMs: closesAtEpochMs)
    }

    /// Whether the microphone was carrying speech at `atMs` on this device's monotonic clock.
    public func couldHaveHeard(atMs: UInt64) -> Bool { control.couldHaveHeard(atMs: atMs) }

    /// Makes this call's SDP offer.
    ///
    /// Section 15 ¶3: the client creates the offer. The host forwards it and never generates one.
    public func offer() async throws -> String {
        let constraints = RTCMediaConstraints(
            mandatoryConstraints: [
                kRTCMediaConstraintsOfferToReceiveAudio: kRTCMediaConstraintsValueTrue,
                kRTCMediaConstraintsOfferToReceiveVideo: kRTCMediaConstraintsValueFalse,
            ],
            optionalConstraints: nil
        )
        let description = try await connection.offer(for: constraints)
        try await connection.setLocalDescription(description)
        return description.sdp
    }

    /// Applies the provider's SDP answer. It starts nothing: the audio unit stays off until the
    /// call is permitted.
    public func accept(answerSdp: String) async throws {
        let answer = RTCSessionDescription(type: .answer, sdp: answerSdp)
        do {
            try await connection.setRemoteDescription(answer)
        } catch {
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

        func activate() throws { try AudioSession.shared.activate(for: call) }

        func deactivate() { try? AudioSession.shared.deactivate() }

        func schedule(atMs: UInt64, _ task: @escaping () -> Void) -> () -> Void {
            let work = DispatchWorkItem(block: task)
            // On the call's own queue, at the deadline on the same clock the gate uses.
            call.queue.asyncAfter(deadline: DispatchTime(uptimeNanoseconds: atMs * 1_000_000), execute: work)
            return { work.cancel() }
        }

        func publish(_ state: VoiceCaptureState) { AudioSession.shared.publish(state) }

        func ended() { call.connection.close() }
    }

    /// The media, as the control sets it.
    private final class Switches: VoiceMediaSwitches {
        private unowned let call: VoiceCall

        init(call: VoiceCall) { self.call = call }

        func setAudioDevice(_ on: Bool) { AudioSession.shared.setAudioEnabled(on) }

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

    public func audioSessionRecorder(running: Bool) {
        queue.async { [weak self] in self?.control.recorder(running: running) }
    }
}

extension VoiceCall: RTCPeerConnectionDelegate {
    public func peerConnection(
        _: RTCPeerConnection,
        didChange state: RTCPeerConnectionState
    ) {
        observer?.voiceCall(self, connectionChanged: state)
    }

    public func peerConnection(_: RTCPeerConnection, didAdd receiver: RTCRtpReceiver, streams _: [RTCMediaStream]) {
        guard receiver.track is RTCAudioTrack else { return }
        // A track arrives playing; the control decides whether it may.
        queue.async { [weak self] in self?.control.refresh() }
        guard !announcedFirstAudio else { return }
        announcedFirstAudio = true
        observer?.voiceCallReceivedFirstAudio(self)
    }

    public func peerConnection(_: RTCPeerConnection, didOpen channel: RTCDataChannel) {
        // The provider opened its channel. This end reads it and never writes to it.
        channel.delegate = self
    }

    public func peerConnectionShouldNegotiate(_: RTCPeerConnection) {}
    public func peerConnection(_: RTCPeerConnection, didChange _: RTCSignalingState) {}
    public func peerConnection(_: RTCPeerConnection, didAdd _: RTCMediaStream) {}
    public func peerConnection(_: RTCPeerConnection, didRemove _: RTCMediaStream) {}
    public func peerConnection(_: RTCPeerConnection, didChange _: RTCIceConnectionState) {}
    public func peerConnection(_: RTCPeerConnection, didChange _: RTCIceGatheringState) {}
    public func peerConnection(_: RTCPeerConnection, didGenerate _: RTCIceCandidate) {}
    public func peerConnection(_: RTCPeerConnection, didRemove _: [RTCIceCandidate]) {}
}

extension VoiceCall: RTCDataChannelDelegate {
    public func dataChannelDidChangeState(_: RTCDataChannel) {}

    public func dataChannel(_: RTCDataChannel, didReceiveMessageWith buffer: RTCDataBuffer) {
        // Handed up as bytes. What is a known event and what is not is decided by the frozen
        // provider profile, one level above this file, and an unknown one is dropped there.
        observer?.voiceCall(self, receivedProviderEvent: buffer.data)
    }
}
