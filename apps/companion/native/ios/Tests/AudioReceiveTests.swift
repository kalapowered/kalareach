//
//  What a call receives from a peer that makes audio, counted from the connection's statistics.
//
//  The peer is the device run's: a second factory whose audio device makes a tone for its
//  microphone and takes what it is played, on a thread of its own, and opens neither the audio
//  session nor the microphone. The call is never permitted, so its own audio unit never starts and
//  the test needs neither the microphone nor the speaker. What the call receives is read the way the
//  application reads it, from the connection's statistics, and judged on a counter crossing a
//  floor.
//

#if DEBUG
import Foundation
import WebRTC
import XCTest

private final class Silent: VoiceCallObserver {
    func voiceCall(_: VoiceCall, connectionChanged _: RTCPeerConnectionState) {}
    func voiceCall(_: VoiceCall, receivedProviderEvent _: Data) {}
    func voiceCallPlayedAudio(_: VoiceCall) {}
    func voiceCall(_: VoiceCall, barrier _: UInt64) {}
}

final class AudioReceiveTests: XCTestCase {
    /// The audio packets a direction must have carried, about a second of them.
    private static let floor: Int64 = 50

    /// How long the two ends are given to connect and carry the floor. It bounds a wait that ends
    /// as soon as the counter crosses.
    private static let within: TimeInterval = 90

    /// KR-REQ-15.03: the audio of a peer that makes a tone reaches the call as RTP packets, counted
    /// by the call's own statistics, with no part of the call ever permitted.
    func testTheCallReceivesRtpPacketsFromAPeerThatMakesAudio() async throws {
        let call = try VoiceCall(observer: Silent())
        defer { call.stop() }
        let peer = AudioPeer(token: "test")
        let offer = try await call.offer()
        let answer = try await peer.answer(offer)
        try await call.accept(answerSdp: answer)

        var received: Int64?
        let end = Date().addingTimeInterval(Self.within)
        while Date() < end {
            received = await call.mediaCounters()?.packetsReceived
            if let received, received >= Self.floor { break }
            try await Task.sleep(nanoseconds: 250_000_000)
        }

        let figures = await peer.figures()
        XCTAssertGreaterThanOrEqual(
            received ?? 0, Self.floor,
            "the call received \(received.map(String.init) ?? "no count") packets; the peer's figures were \(figures)"
        )
        XCTAssertEqual(figures["recorderStarted"] as? Bool, true, "the peer's audio device made the tone")
    }
}
#endif
