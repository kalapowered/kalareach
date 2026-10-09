//
//  What the call reads of the provider's SDP answer.
//
//  The answer is a recording of the real provider's, so the reader is held to what the provider
//  sends and not to what a test imagines it sends.
//

import Foundation
import XCTest

final class VoiceAnswerTests: XCTestCase {
    /// The answer the provider gave to an offer in its qualification run, byte for byte.
    private func recorded() throws -> String {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let answer = url.appendingPathComponent("fixtures/voice/provider-answer.sdp")
        return try String(contentsOf: answer, encoding: .utf8)
    }

    /// KR-REQ-15.35: the provider's real answer does not turn discontinuous transmission on, so a
    /// gap in what it receives is read as a closed microphone.
    func testTheProvidersAnswerDoesNotUseDtx() throws {
        let sdp = try recorded()
        XCTAssertTrue(sdp.contains("a=rtpmap:111 opus/48000/2"), "the recording is an answer with Opus")
        XCTAssertFalse(VoiceAnswer.usesDtx(sdp))
    }

    /// KR-REQ-15.35: an answer that does turn it on is read as doing so, wherever among the
    /// parameters it stands, and an answer that turns it off is not.
    func testAnAnswerThatTurnsDtxOnIsRead() throws {
        let sdp = try recorded()
        let plain = "a=fmtp:111 minptime=10;useinbandfec=1"
        XCTAssertTrue(sdp.contains(plain))
        for on in [
            "a=fmtp:111 minptime=10;useinbandfec=1;usedtx=1",
            "a=fmtp:111 usedtx=1;minptime=10;useinbandfec=1",
            "a=fmtp:111 minptime=10; usedtx=1; useinbandfec=1",
        ] {
            XCTAssertTrue(VoiceAnswer.usesDtx(sdp.replacingOccurrences(of: plain, with: on)), on)
        }
        XCTAssertFalse(VoiceAnswer.usesDtx(
            sdp.replacingOccurrences(of: plain, with: "a=fmtp:111 minptime=10;useinbandfec=1;usedtx=0")
        ))
    }

    /// KR-REQ-15.35: the setting counts for the codec that carries the call. The same word on a
    /// payload that is not Opus says nothing about it.
    func testDtxOnAnotherPayloadIsNotTheCalls() throws {
        let sdp = try recorded()
        let other = sdp + "a=fmtp:96 usedtx=1\r\n"
        XCTAssertFalse(VoiceAnswer.usesDtx(other))
    }
}
