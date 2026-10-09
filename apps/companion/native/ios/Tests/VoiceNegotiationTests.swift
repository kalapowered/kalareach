//
//  What a call offers the provider, and what it hears back, against a peer in this process.
//
//  The peer answers an offer the way the provider's side does: it applies the offer, answers with
//  its own candidates, and reads the channel the offer names. Nothing here goes near a network
//  beyond this machine's own interfaces, a broker, or the microphone.
//

import Foundation
import WebRTC
import XCTest

/// What a call told the application, kept for the test to read.
private final class Told: VoiceCallObserver {
    private let lock = NSLock()
    private var kept: [Data] = []
    let event = XCTestExpectation(description: "the provider's event reached the application")

    var events: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return kept
    }

    func voiceCall(_: VoiceCall, connectionChanged _: RTCPeerConnectionState) {}

    func voiceCall(_: VoiceCall, receivedProviderEvent data: Data) {
        lock.lock()
        kept.append(data)
        lock.unlock()
        event.fulfill()
    }

    func voiceCallReceivedFirstAudio(_: VoiceCall) {}
}

/// A wait for candidate gathering that the test holds open until the call, or the test, ends it.
private final class HeldGatheringWait: GatheringWait {
    private let lock = NSLock()
    private var released = false
    private var waiting: CheckedContinuation<Void, Never>?

    /// Fulfilled when the offer has reached the wait.
    let reached = XCTestExpectation(description: "the offer is waiting for candidate gathering")

    func wait(upTo _: TimeInterval) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if released {
                lock.unlock()
                continuation.resume()
                return
            }
            waiting = continuation
            lock.unlock()
            reached.fulfill()
        }
    }

    func finish() {
        lock.lock()
        released = true
        let waiter = waiting
        waiting = nil
        lock.unlock()
        waiter?.resume()
    }
}

/// How an offer ended, kept for the test to read.
private final class Outcome: @unchecked Sendable {
    private let lock = NSLock()
    private var kept: Result<String, Error>?

    /// Fulfilled when the offer has ended, one way or the other.
    let ended = XCTestExpectation(description: "the offer ended")

    var result: Result<String, Error>? {
        lock.lock()
        defer { lock.unlock() }
        return kept
    }

    func keep(_ result: Result<String, Error>) {
        lock.lock()
        kept = result
        lock.unlock()
        ended.fulfill()
    }
}

/// A peer in this process that answers an offer and reads the channel the offer names.
private final class AnsweringPeer: NSObject, RTCPeerConnectionDelegate, RTCDataChannelDelegate {
    /// How long the peer is given to gather, in seconds.
    private static let gatherWithin: TimeInterval = 30

    private let factory = RTCPeerConnectionFactory()
    private let connection: RTCPeerConnection
    private let lock = NSLock()
    private var gatheringDone: CheckedContinuation<Void, Never>?
    private var gathered = false
    private var channel: RTCDataChannel?

    /// Fulfilled when the channel the offer names is open at this end.
    let channelOpen = XCTestExpectation(description: "the channel the offer names opened at the peer")

    /// The label of that channel, once it has arrived.
    var channelLabel: String? {
        lock.lock()
        defer { lock.unlock() }
        return channel?.label
    }

    override init() {
        let configuration = RTCConfiguration()
        configuration.sdpSemantics = .unifiedPlan
        // Once, so that the gathering reports itself done and the answer carries every candidate.
        configuration.continualGatheringPolicy = .gatherOnce
        connection = factory.peerConnection(
            with: configuration,
            constraints: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil),
            delegate: nil
        )!
        super.init()
        connection.delegate = self
    }

    deinit { connection.close() }

    /// Applies `offer` and answers it, with the candidates this peer gathered.
    func answer(_ offer: String) async throws -> String {
        try await connection.setRemoteDescription(RTCSessionDescription(type: .offer, sdp: offer))
        let answer = try await connection.answer(for: RTCMediaConstraints(
            mandatoryConstraints: [kRTCMediaConstraintsOfferToReceiveAudio: kRTCMediaConstraintsValueTrue],
            optionalConstraints: nil
        ))
        try await connection.setLocalDescription(answer)
        await withCheckedContinuation { (done: CheckedContinuation<Void, Never>) in
            lock.lock()
            if gathered {
                lock.unlock()
                done.resume()
            } else {
                gatheringDone = done
                lock.unlock()
                // A peer that never reports gathering done answers with what it has after this
                // long, instead of holding the test forever.
                DispatchQueue.global().asyncAfter(deadline: .now() + AnsweringPeer.gatherWithin) { [weak self] in
                    self?.gatheringEnded()
                }
            }
        }
        return AnsweringPeer.asIceLite(connection.localDescription?.sdp ?? answer.sdp)
    }

    /// The answer as the provider's reads: it says it is an ICE-lite agent, which only answers the
    /// checks it is sent. Given an offer with no candidate this peer has none to check either, so
    /// the call's own checks to the candidates in the answer are all that can connect the two.
    private static func asIceLite(_ sdp: String) -> String {
        guard !sdp.contains("a=ice-lite"), let media = sdp.range(of: "m=") else { return sdp }
        return sdp.replacingCharacters(in: media.lowerBound..<media.lowerBound, with: "a=ice-lite\r\n")
    }

    /// Sends `text` on the channel the offer named.
    func send(_ text: String) {
        lock.lock()
        let open = channel
        lock.unlock()
        _ = open?.sendData(RTCDataBuffer(data: Data(text.utf8), isBinary: false))
    }

    func peerConnection(_: RTCPeerConnection, didChange state: RTCIceGatheringState) {
        guard state == .complete else { return }
        gatheringEnded()
    }

    private func gatheringEnded() {
        lock.lock()
        gathered = true
        let waiting = gatheringDone
        gatheringDone = nil
        lock.unlock()
        waiting?.resume()
    }

    func peerConnection(_: RTCPeerConnection, didOpen opened: RTCDataChannel) {
        lock.lock()
        channel = opened
        lock.unlock()
        opened.delegate = self
        if opened.readyState == .open { channelOpen.fulfill() }
    }

    func dataChannelDidChangeState(_ changed: RTCDataChannel) {
        if changed.readyState == .open { channelOpen.fulfill() }
    }

    func dataChannel(_: RTCDataChannel, didReceiveMessageWith _: RTCDataBuffer) {}

    func peerConnectionShouldNegotiate(_: RTCPeerConnection) {}
    func peerConnection(_: RTCPeerConnection, didChange _: RTCSignalingState) {}
    func peerConnection(_: RTCPeerConnection, didAdd _: RTCMediaStream) {}
    func peerConnection(_: RTCPeerConnection, didRemove _: RTCMediaStream) {}
    func peerConnection(_: RTCPeerConnection, didChange _: RTCIceConnectionState) {}
    func peerConnection(_: RTCPeerConnection, didGenerate _: RTCIceCandidate) {}
    func peerConnection(_: RTCPeerConnection, didRemove _: [RTCIceCandidate]) {}
}

final class VoiceNegotiationTests: XCTestCase {
    /// How long the two ends are given to connect before the test calls it a failure. It bounds a
    /// wait that ends as soon as the connection does.
    private static let connectWithin: TimeInterval = 120

    /// How long a call that ended is given to release what waits on it.
    private static let endWithin: TimeInterval = 20

    /// A call and a peer that have exchanged an offer and an answer.
    private func negotiated(
        observer: VoiceCallObserver
    ) async throws -> (VoiceCall, AnsweringPeer, String) {
        let call = try VoiceCall(observer: observer)
        let offer = try await call.offer()
        let peer = AnsweringPeer()
        let answer = try await peer.answer(offer)
        try await call.accept(answerSdp: answer)
        return (call, peer, offer)
    }

    /// KR-REQ-15.10: the call creates the provider's events channel before it makes the offer, so
    /// the offer names it and the provider has one to write to.
    func testTheOfferNamesTheProvidersEventChannel() async throws {
        let told = Told()
        let (call, peer, offer) = try await negotiated(observer: told)
        defer { call.stop() }

        XCTAssertTrue(offer.contains("m=application"), "the offer holds a data channel section")
        await fulfillment(of: [peer.channelOpen], timeout: Self.connectWithin)
        XCTAssertEqual(peer.channelLabel, "oai-events")
    }

    /// KR-REQ-15.03: the offer is sent with no candidate in it, and still connects to an answerer
    /// that is ICE-lite, as the provider is: that answerer learns where the call is from the call's
    /// own checks to the candidates in the answer, so the candidates the call finds after the
    /// offer is made are not needed and nothing waits for them.
    func testAnOfferWithNoCandidateConnectsToAnIceLiteAnswerer() async throws {
        let (call, peer, offer) = try await negotiated(observer: Told())
        defer { call.stop() }

        XCTAssertFalse(offer.contains("a=candidate:"), "the offer was made before any candidate was found")
        await fulfillment(of: [peer.channelOpen], timeout: Self.connectWithin)
        XCTAssertEqual(peer.channelLabel, "oai-events")
    }

    /// KR-REQ-15.10: what the provider writes on that channel reaches the application as bytes.
    func testAnEventTheProviderWritesReachesTheApplication() async throws {
        let told = Told()
        let (call, peer, _) = try await negotiated(observer: told)
        defer { call.stop() }

        await fulfillment(of: [peer.channelOpen], timeout: Self.connectWithin)
        peer.send("{\"type\":\"session.created\"}")
        await fulfillment(of: [told.event], timeout: Self.connectWithin)
        XCTAssertEqual(told.events, [Data("{\"type\":\"session.created\"}".utf8)])
    }

    /// KR-REQ-15.03: the offer carries the candidates this device had gathered by the time it was
    /// made, because the provider is answered once and the candidates that come later are not sent.
    func testTheOfferCarriesTheCandidatesGatheredSoFar() async throws {
        let call = try VoiceCall(observer: Told())
        defer { call.stop() }
        let offer = try await call.offer()
        XCTAssertTrue(offer.contains("a=candidate:"), "the offer names at least one address to reach")
    }

    /// KR-REQ-15.34: the call knows whether the provider's answer has been applied, and what it
    /// says of discontinuous transmission, only once it has been. A host's answer is taken only
    /// after that, which ``VoiceCallControl`` decides.
    func testTheCallKnowsTheAnswerOnlyOnceItIsApplied() async throws {
        let call = try VoiceCall(observer: Told())
        defer { call.stop() }
        let offer = try await call.offer()
        XCTAssertFalse(call.answerIsApplied)
        XCTAssertNil(call.answerUsesDtx)

        // The host's answer comes first: nothing opens, and the call is still there to be answered.
        let closes = UInt64(Date().timeIntervalSince1970 * 1_000) + 60_000
        XCTAssertFalse(call.permit(voiceSessionId: "voice-session-1", closesAtEpochMs: closes))

        let answer = try await AnsweringPeer().answer(offer)
        try await call.accept(answerSdp: answer)
        XCTAssertTrue(call.answerIsApplied)
        XCTAssertEqual(call.answerUsesDtx, false)
    }

    /// KR-REQ-15.34: a call that ends while its offer waits for candidates makes no offer. The
    /// owner would send it on, and the broker would reserve a provider session for a dead call.
    func testACallEndedWhileItsOfferWaitsOffersNothing() async throws {
        let held = HeldGatheringWait()
        let call = try VoiceCall(observer: Told(), gathering: held)
        defer { held.finish() }
        let outcome = Outcome()
        Task {
            do { outcome.keep(.success(try await call.offer())) } catch { outcome.keep(.failure(error)) }
        }

        await fulfillment(of: [held.reached], timeout: Self.connectWithin)
        call.stop()
        await fulfillment(of: [outcome.ended], timeout: Self.endWithin)

        guard let result = outcome.result else { return XCTFail("ending the call releases its offer") }
        if case .success = result { XCTFail("an offer was handed on for a call that ended") }
    }
}
