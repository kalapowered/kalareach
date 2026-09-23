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
/// A call has two stages, and the microphone belongs only to the second. Building it makes the
/// connection and a microphone track that is off, for the offer and the answer; no audio session
/// is opened and nothing is captured. ``permit(voiceSessionId:closesAtEpochMs:)`` is given the
/// host's answer to the start, and only then is the session opened and capture allowed. Whether
/// the microphone is on is decided by one ``VoiceCaptureGate`` from the permit, the person's mute,
/// what the system did and the route, and the call stops itself when its deadline comes.
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

    /// Held by every change to what the microphone and the speaker are allowed to do.
    ///
    /// Recursive, because opening or closing the audio session can report a route change on the
    /// thread that is doing it, and that report takes this lock too.
    private let lock = NSRecursiveLock()
    private let gate = VoiceCaptureGate()
    private var stopped = false
    private var expiry: DispatchWorkItem?

    /// Whether the person has muted their own microphone.
    public var isMutedByPerson: Bool { gate.isMutedByPerson }

    /// Whether the remote voice is being played out of this device.
    public private(set) var isPlaybackMuted = false

    /// Builds a call for its offer and its answer, with the microphone off.
    ///
    /// No audio session is opened here: that waits for ``permit(voiceSessionId:closesAtEpochMs:)``,
    /// so nothing but a call the host permitted can open the microphone.
    public init(observer: VoiceCallObserver) throws {
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
        // Off until the call is permitted. The offer describes a track, and a described track
        // carries nothing until the gate lets it.
        microphone.isEnabled = false
        self.observer = observer
        super.init()
        connection.delegate = self
        connection.add(microphone, streamIds: ["kr-voice"])
    }

    /// This device's monotonic clock, in milliseconds. The gate's deadlines are on it.
    private static func nowMs() -> UInt64 { DispatchTime.now().uptimeNanoseconds / 1_000_000 }

    /// The furthest deadline a call is given, in milliseconds: a day.
    private static let longestCallMs: UInt64 = 86_400_000

    /// Opens the microphone for a call the host started.
    ///
    /// Takes the host's answer: the voice session and the moment the service closes the call, in
    /// UTC milliseconds. The audio session is opened here and nowhere else, and the call stops
    /// itself when that moment comes, whether or not anything else happened.
    ///
    /// - Returns: false, and nothing opened, when this call is stopped, already permitted or past
    ///   its deadline.
    /// - Throws: ``VoiceAudioError/microphoneNotPermitted`` when the microphone is not available.
    public func permit(voiceSessionId: String, closesAtEpochMs: UInt64) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped, gate.current == nil else { return false }
        let wall = UInt64(Date().timeIntervalSince1970 * 1_000)
        guard closesAtEpochMs > wall else { return false }
        let now = VoiceCall.nowMs()
        // No call runs for a day. A deadline further away than that closes the call at a day, never
        // later, and keeps the arithmetic below inside its type whatever the answer said.
        let deadline = now + min(closesAtEpochMs - wall, VoiceCall.longestCallMs)
        try AudioSession.shared.activate(for: self)
        guard gate.permit(voiceSessionId: voiceSessionId, deadlineMs: deadline, nowMs: now) != nil else {
            try? AudioSession.shared.deactivate()
            return false
        }
        let ends = DispatchWorkItem { [weak self] in self?.stop() }
        expiry = ends
        DispatchQueue.main.asyncAfter(
            deadline: .now() + .milliseconds(Int(deadline - now)),
            execute: ends
        )
        apply(now)
        return true
    }

    /// Whether the microphone was carrying speech at `atMs` on this device's monotonic clock.
    public func couldHaveHeard(atMs: UInt64) -> Bool { gate.couldHaveHeard(atMs: atMs) }

    /// Makes the microphone and the speaker what the gate says, and publishes the one state.
    /// Called with ``lock`` held after every change.
    private func apply(_ now: UInt64) {
        microphone.isEnabled = gate.captureEnabled(nowMs: now)
        let shown = gate.displayed(nowMs: now)
        let speaker = !isPlaybackMuted && shown != .interrupted
        for receiver in connection.receivers {
            (receiver.track as? RTCAudioTrack)?.isEnabled = speaker
        }
        AudioSession.shared.publish(shown)
    }

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

    /// Applies the provider's SDP answer.
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
    /// available if the broker fails, so this touches the track and the audio session and nothing
    /// that could be waiting on a network answer.
    public func setMutedByPerson(_ muted: Bool) {
        lock.lock()
        defer { lock.unlock() }
        let now = VoiceCall.nowMs()
        gate.setMutedByPerson(muted, nowMs: now)
        apply(now)
    }

    /// Stops the model's voice coming out of this device, without ending the call.
    ///
    /// This is **playback**, and §15 ¶13 is explicit that speech interruption stops playback and
    /// not a coding task. Nothing here cancels anything on a host.
    public func setPlaybackMuted(_ muted: Bool) {
        lock.lock()
        defer { lock.unlock() }
        isPlaybackMuted = muted
        apply(VoiceCall.nowMs())
    }

    /// Ends the call and gives the microphone back.
    ///
    /// Local and immediate, for the same reason mute is.
    public func stop() {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        stopped = true
        gate.stop(nowMs: VoiceCall.nowMs())
        expiry?.cancel()
        expiry = nil
        microphone.isEnabled = false
        connection.close()
        try? AudioSession.shared.deactivate()
    }
}

extension VoiceCall: AudioSessionEvents {
    public func audioSessionInterruption(began: Bool, mayResume: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        let now = VoiceCall.nowMs()
        // Began, or ended without the system's word to resume: the microphone stays closed. What
        // the person chose, their own mute, is untouched either way and applies when it reopens.
        let taken: VoiceCaptureGate.Taken = began ? .interrupted : (mayResume ? .none : .suspended)
        gate.taken(taken, nowMs: now)
        apply(now)
    }

    public func audioSessionRoute(changing: Bool, hasInput: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        let now = VoiceCall.nowMs()
        gate.route(changing: changing, inputAvailable: hasInput, nowMs: now)
        apply(now)
    }

    public func audioSessionReset() {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        let now = VoiceCall.nowMs()
        gate.taken(.suspended, nowMs: now)
        apply(now)
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
        guard receiver.track is RTCAudioTrack, !announcedFirstAudio else { return }
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
