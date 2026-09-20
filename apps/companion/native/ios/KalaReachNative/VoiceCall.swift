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

    /// Whether the person has muted their own microphone.
    public private(set) var isMutedByPerson = false

    /// Whether the remote voice is being played out of this device.
    public private(set) var isPlaybackMuted = false

    /// Builds a call and opens the microphone.
    ///
    /// The audio session is activated first and on the same path, so there is no window in which a
    /// track exists and the session that governs it does not.
    ///
    /// - Throws: ``VoiceAudioError/microphoneNotPermitted`` when the microphone is not available.
    public init(observer: VoiceCallObserver) throws {
        try AudioSession.shared.activate()

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
        self.observer = observer
        super.init()
        connection.delegate = self
        connection.add(microphone, streamIds: ["kr-voice"])
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
        isMutedByPerson = muted
        microphone.isEnabled = !muted
        AudioSession.shared.setMutedByPerson(muted)
    }

    /// Stops the model's voice coming out of this device, without ending the call.
    ///
    /// This is **playback**, and §15 ¶13 is explicit that speech interruption stops playback and
    /// not a coding task. Nothing here cancels anything on a host.
    public func setPlaybackMuted(_ muted: Bool) {
        isPlaybackMuted = muted
        for receiver in connection.receivers {
            (receiver.track as? RTCAudioTrack)?.isEnabled = !muted
        }
    }

    /// Ends the call and gives the microphone back.
    ///
    /// Local and immediate, for the same reason mute is.
    public func stop() {
        microphone.isEnabled = false
        connection.close()
        try? AudioSession.shared.deactivate()
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
