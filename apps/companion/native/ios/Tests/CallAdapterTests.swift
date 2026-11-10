//
//  The adapter the plugin reaches the voice call by: what it answers to each command and what it
//  tells of a call, against the fixtures the Rust and Kotlin halves are tested against, with a call
//  and a device that answer as the test says.
//

import Foundation
import XCTest

/// The cases of the fixtures, which this half, the Rust half and the Kotlin half share.
private enum Fixtures {
    static let directory: URL = {
        // .../native/ios/Tests/CallAdapterTests.swift
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("platform/fixtures/call")
    }()

    static func json(_ name: String) throws -> Any {
        try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent(name)))
    }

    /// The nth case of a command.
    static func command(_ name: String, _ nth: Int = 0) throws -> (request: String, response: NSDictionary) {
        let cases = (try json("commands.json") as! [[String: Any]]).filter { $0["command"] as? String == name }
        let found = cases[nth]
        return (text(found["request"]!), found["response"] as! NSDictionary)
    }

    static func text(_ object: Any) -> String {
        String(decoding: try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]), as: UTF8.self)
    }
}

/// A call that does what the test tells it and remembers what it was asked.
private final class FakeEngine: CallEngine {
    /// What the call was asked, in order. A stop is asked from the adapter's engine queue while a
    /// test reads this, so it is kept under a lock.
    private let lock = NSLock()
    private var log: [String] = []
    var asked: [String] {
        get { lock.lock(); defer { lock.unlock() }; return log }
        set { lock.lock(); defer { lock.unlock() }; log = newValue }
    }
    var offered = "v=0\r\ns=-\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
    var usesDtx: Bool? = true
    var permitted = true
    var isPlaybackMuted = false
    var isMutedByPerson = false
    /// What the call's statistics say the media carried, when a test gives it.
    var counters: MediaCounters?
    /// What the call's record of capture shows, and the number its next marker has.
    var proof = VoiceCaptureGate.Proof(
        state: .capturing, opened: true, openings: 1, breaks: 0, progressAgeMs: 120)
    var nextMarker: UInt64 = 3
    /// Where a real call reports its end, which a stop is followed by.
    var reporting: CallReporting?

    func record(_ what: String) {
        lock.lock()
        log.append(what)
        lock.unlock()
    }

    func offer() async throws -> String {
        record("offer")
        return offered
    }

    func accept(answerSdp: String) async throws { record("accept \(answerSdp.count)") }
    func media() async -> MediaCounters? { counters }

    /// A real call reads the record and tells the marker in one step on its own queue; this one does
    /// both before it answers.
    func captureProof(barrier: Bool) async -> (proof: VoiceCaptureGate.Proof, barrier: UInt64?)? {
        record("captureProof \(barrier)")
        guard !asked.contains("stop") else { return nil }
        guard barrier else { return (proof, nil) }
        reporting?.barrier(nextMarker)
        return (proof, nextMarker)
    }
    var answerUsesDtx: Bool? { usesDtx }

    func permit(voiceSessionId: String, closesAtEpochMs: UInt64) -> Bool {
        record("permit \(voiceSessionId) \(closesAtEpochMs)")
        return permitted
    }

    func setMutedByPerson(_ muted: Bool) {
        record("microphone \(muted)")
        isMutedByPerson = muted
    }
    func setPlaybackMuted(_ muted: Bool) {
        record("playback \(muted)")
        isPlaybackMuted = muted
    }

    /// A stop ends the call, and the call says so, as a real one does. The end is reported before
    /// the stop is recorded, so a test that has seen the stop has the end already queued.
    func stop() {
        reporting?.ended()
        record("stop")
    }
}

/// Makes the fake call, keeping the reporter the adapter gave it.
private final class FakeMaker: CallEngineMaker {
    let engine = FakeEngine()
    var reporting: CallReporting?
    var made = 0

    func make(reporting: CallReporting) throws -> CallEngine {
        made += 1
        self.reporting = reporting
        engine.reporting = reporting
        return engine
    }
}

private struct FakeDevice: CallDevice {
    var microphone = true
    var notifications = true

    func requestMicrophone(_ answered: @escaping (Bool) -> Void) { answered(microphone) }
    func notificationsAllowed(_ answered: @escaping (Bool) -> Void) { answered(notifications) }
}

/// What the adapter answered, and the news it was given to send.
private final class Told {
    private let lock = NSLock()
    private var frames: [NSDictionary] = []
    private var waiting: [(Int, XCTestExpectation)] = []

    var news: [NSDictionary] {
        lock.lock()
        defer { lock.unlock() }
        return frames
    }

    func take(_ text: String) {
        let frame = try! JSONSerialization.jsonObject(with: Data(text.utf8)) as! NSDictionary
        lock.lock()
        frames.append(frame)
        let count = frames.count
        let ready = waiting.filter { $0.0 <= count }
        waiting.removeAll { $0.0 <= count }
        lock.unlock()
        ready.forEach { $0.1.fulfill() }
    }

    func expectation(frames count: Int) -> XCTestExpectation {
        let expectation = XCTestExpectation(description: "\(count) items of news")
        lock.lock()
        if frames.count >= count { expectation.fulfill() } else { waiting.append((count, expectation)) }
        lock.unlock()
        return expectation
    }
}

final class CallAdapterTests: XCTestCase {
    private func ask(
        _ adapter: CallAdapter, _ command: String, _ arguments: String, told: Told? = nil
    ) async -> (result: NSDictionary?, code: String?, message: String?) {
        await withCheckedContinuation { continuation in
            let reply: @convention(block) (NSString?, NSString?, NSString?) -> Void = { result, code, message in
                let object = (result as String?).flatMap {
                    try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? NSDictionary
                }
                continuation.resume(returning: (object, code as String?, message as String?))
            }
            var request: [String: Any] = [
                "command": command as NSString,
                "arguments": arguments as NSString,
                "reply": reply as AnyObject,
            ]
            if let told = told {
                let news: @convention(block) (NSString) -> Void = { told.take($0 as String) }
                request["news"] = news as AnyObject
            }
            adapter.krCall(request as NSDictionary)
        }
    }

    func testTheNamesThePluginReachesTheAdapterByAreTheFixtures() throws {
        let link = try Fixtures.json("link.json") as! [String: Any]
        XCTAssertEqual(NSStringFromClass(CallAdapter.self), link["class"] as? String)
        XCTAssertNotNil(NSClassFromString(link["class"] as! String))
        let adapterType = CallAdapter.self as AnyClass
        XCTAssertTrue(adapterType.responds(to: NSSelectorFromString(link["shared"] as! String)))
        XCTAssertTrue(CallAdapter.krShared().responds(to: NSSelectorFromString(link["call"] as! String)))
        let keys = link["keys"] as! [String: String]
        XCTAssertEqual(CallAdapter.Link.command, keys["command"])
        XCTAssertEqual(CallAdapter.Link.arguments, keys["arguments"])
        XCTAssertEqual(CallAdapter.Link.news, keys["news"])
        XCTAssertEqual(CallAdapter.Link.reply, keys["reply"])
    }

    func testEachCommandAnswersWhatTheFixtureHolds() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice())
        let told = Told()

        let open = try Fixtures.command("callOpen")
        let opened = await ask(adapter, "callOpen", open.request, told: told)
        XCTAssertEqual(opened.result, open.response, "\(String(describing: opened))")

        let offer = try Fixtures.command("callOffer")
        maker.engine.offered = (offer.response["sdp"] as! String)
        let offered = await ask(adapter, "callOffer", offer.request)
        XCTAssertEqual(offered.result, offer.response)

        let accept = try Fixtures.command("callAccept")
        let accepted = await ask(adapter, "callAccept", accept.request)
        XCTAssertEqual(accepted.result, accept.response)

        let permit = try Fixtures.command("callPermit")
        let permitted = await ask(adapter, "callPermit", permit.request)
        XCTAssertEqual(permitted.result, permit.response)
        XCTAssertTrue(maker.engine.asked.contains("permit 5b2f0a3c-8a56-4c53-bb7e-6a4a4a1c9e01 1760300000000"))

        for nth in 0..<2 {
            let mute = try Fixtures.command("callMute", nth)
            let muted = await ask(adapter, "callMute", mute.request)
            XCTAssertEqual(muted.result, mute.response)
        }
        XCTAssertTrue(maker.engine.asked.contains("microphone true"))
        XCTAssertTrue(maker.engine.asked.contains("playback false"))

        // The gate shows the microphone muted, as it reports to the call.
        maker.reporting?.capture(.mutedByPerson)
        maker.engine.counters = MediaCounters(packetsReceived: 1200, packetsSent: 1180, playedSamples: 960_000)
        let state = try Fixtures.command("callState", 0)
        let held = await ask(adapter, "callState", state.request)
        XCTAssertEqual(held.result, state.response)

        let stop = try Fixtures.command("callStop")
        let stopped = await ask(adapter, "callStop", stop.request)
        XCTAssertEqual(stopped.result, stop.response)
        XCTAssertTrue(maker.engine.asked.contains("stop"))

        let idle = try Fixtures.command("callState", 1)
        let after = await ask(adapter, "callState", idle.request)
        XCTAssertEqual(after.result, idle.response, "a call that has ended is not held")
    }

    /// A figure the statistics did not hold is absent from the call's state, never a zero, a sign of
    /// life carries no reading of the media, and a call that measured nothing says nothing of it.
    func testTheStateOfAHeldCallCarriesTheMediaOnlyWhereItWasMeasured() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice(), watches: false)
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())
        maker.reporting?.capture(.capturing)

        maker.engine.counters = MediaCounters(packetsReceived: 40)
        let partial = try Fixtures.command("callState", 2)
        let some = await ask(adapter, "callState", partial.request)
        XCTAssertEqual(some.result, partial.response)

        let alive = await ask(adapter, "callAlive", #"{"call":"c1"}"#)
        XCTAssertNil(alive.result?["media"], "a sign of life reads no statistics")

        maker.engine.counters = MediaCounters()
        let none = await ask(adapter, "callState", "{}")
        XCTAssertNil(none.result?["media"], "nothing measured is nothing said")
        maker.engine.counters = nil
        let unread = await ask(adapter, "callState", "{}")
        XCTAssertNil(unread.result?["media"], "statistics that did not come back are nothing said")
    }

    /// The capture proof answers what the fixtures hold, with the marker's number when one was asked
    /// for, a figure that was not seen as `null`, and nothing at all for a call that has ended.
    func testTheCaptureProofAnswersWhatTheFixtureHolds() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice(), watches: false)
        let told = Told()
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: told)

        let first = try Fixtures.command("callCaptureProof", 0)
        let marked = await ask(adapter, "callCaptureProof", first.request)
        XCTAssertEqual(marked.result, first.response, "\(String(describing: marked))")
        XCTAssertTrue(maker.engine.asked.contains("captureProof true"))
        await fulfillment(of: [told.expectation(frames: 1)], timeout: 10)
        XCTAssertEqual(told.news.first?["kind"] as? String, "barrier", "the marker is in the news")
        XCTAssertEqual(told.news.first?["token"] as? Int, 3)

        maker.engine.proof = VoiceCaptureGate.Proof(
            state: .mutedByPerson, opened: true, openings: 2, breaks: 3, progressAgeMs: nil)
        let second = try Fixtures.command("callCaptureProof", 1)
        let plain = await ask(adapter, "callCaptureProof", second.request)
        XCTAssertEqual(plain.result, second.response, "no marker was asked for, and none is told")
        XCTAssertEqual(told.news.count, 1)

        // A call whose capture never opened answers with nothing seen, and a marker of its own.
        let third = try Fixtures.command("callCaptureProof", 2)
        let otherMaker = FakeMaker()
        otherMaker.engine.proof = VoiceCaptureGate.Proof(
            state: .unavailable, opened: false, openings: 0, breaks: 0, progressAgeMs: nil)
        otherMaker.engine.nextMarker = 1
        let other = CallAdapter(maker: otherMaker, device: FakeDevice(), watches: false)
        _ = await ask(other, "callOpen", #"{"call":"c2","events":"__CHANNEL__:8"}"#, told: Told())
        let unopened = await ask(other, "callCaptureProof", third.request)
        XCTAssertEqual(unopened.result, third.response, "\(String(describing: unopened))")

        _ = await ask(adapter, "callStop", #"{"call":"c1"}"#)
        let ended = await ask(adapter, "callCaptureProof", first.request)
        XCTAssertEqual(ended.code, "ended")
        let named = await ask(adapter, "callCaptureProof", #"{"call":"c9","barrier":false}"#)
        XCTAssertEqual(named.code, "no_such_call")
    }

    /// A call's report of the marker takes the adapter's queue as every other report does, so the
    /// news waiting there is sent ahead of it, and what is reported after it is sent after it.
    func testTheMarkerIsSentBehindTheNewsWaitingInTheAdaptersQueue() async throws {
        let maker = FakeMaker()
        let queue = DispatchQueue(label: "test.call-adapter")
        let adapter = CallAdapter(maker: maker, device: FakeDevice(), watches: false, queue: queue)
        let told = Told()
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: told)
        let reporting = try XCTUnwrap(maker.reporting)

        let held = DispatchSemaphore(value: 0)
        queue.async { held.wait() }
        reporting.providerEvent(Data([1]))
        reporting.capture(.interrupted)
        reporting.barrier(5)
        reporting.providerEvent(Data([2]))
        held.signal()

        await fulfillment(of: [told.expectation(frames: 4)], timeout: 10)
        XCTAssertEqual(
            told.news.map { $0["kind"] as? String }, ["provider_event", "capture", "barrier", "provider_event"])
        XCTAssertEqual(told.news[2]["token"] as? Int, 5)
    }

    func testASignOfLifeNamesACallAndIsAnsweredWithWhatTheCallIsDoing() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice(), watches: false)
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())
        maker.reporting?.capture(.capturing)
        let alive = try Fixtures.command("callAlive")

        let answered = await ask(adapter, "callAlive", alive.request)

        XCTAssertEqual(answered.result, alive.response)

        let other = await ask(adapter, "callAlive", #"{"call":"c9"}"#)
        XCTAssertEqual(other.code, "no_such_call")
        _ = await ask(adapter, "callStop", #"{"call":"c1"}"#)
        let ended = await ask(adapter, "callAlive", alive.request)
        XCTAssertEqual(ended.code, "ended", "a sign for a call that has ended says so")
    }

    /// KR-REQ-13.24: a call whose owner gives no sign ends itself in native code at the bound, so the
    /// microphone is never left open under an application nothing is running for; a sign starts the
    /// wait again.
    func testACallWhoseOwnerGivesNoSignEndsAtTheBoundAndASignStartsTheWaitAgain() async throws {
        var now: TimeInterval = 0
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice(), clock: { now }, watches: false)
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())

        now = CallWatch.beforePermit - 1
        adapter.endIfOwnerIsGone()
        _ = await ask(adapter, "callAlive", #"{"call":"c1"}"#)
        now += CallWatch.beforePermit - 1
        adapter.endIfOwnerIsGone()
        XCTAssertFalse(maker.engine.asked.contains("stop"), "a sign started the wait again")

        now += 1
        adapter.endIfOwnerIsGone()

        try await waitUntil { maker.engine.asked.contains("stop") }
        XCTAssertEqual(maker.engine.asked.filter { $0 == "stop" }.count, 1)
        adapter.endIfOwnerIsGone()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(maker.engine.asked.filter { $0 == "stop" }.count, 1, "it ends once")
    }

    // A call the watch ended reports its end like any other, and is let go of: the next open is not
    // met by a call that is gone.
    func testACallTheWatchEndedIsLetGoOfSoTheNextOpenIsNotRefused() async throws {
        var now: TimeInterval = 0
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice(), clock: { now }, watches: false)
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())
        now = CallWatch.beforePermit
        adapter.endIfOwnerIsGone()
        try await waitUntil { maker.engine.asked.contains("stop") }

        let again = await ask(adapter, "callOpen", #"{"call":"c2","events":"__CHANNEL__:8"}"#, told: Told())

        XCTAssertNil(again.code, "the call the watch ended is not held")
        XCTAssertEqual(maker.made, 2)
        let old = await ask(adapter, "callAlive", #"{"call":"c1"}"#)
        XCTAssertEqual(old.code, "ended", "a sign for the call that ended says so")
    }

    func testAPermittedCallWaitsTheShorterBound() async throws {
        var now: TimeInterval = 0
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice(), clock: { now }, watches: false)
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())
        let permit = try Fixtures.command("callPermit")
        _ = await ask(adapter, "callPermit", permit.request)

        now = CallWatch.afterPermit - 1
        adapter.endIfOwnerIsGone()
        XCTAssertFalse(maker.engine.asked.contains("stop"))
        now = CallWatch.afterPermit

        adapter.endIfOwnerIsGone()

        try await waitUntil { maker.engine.asked.contains("stop") }
    }

    func testAConnectionThatHasFailedForGoodEndsTheCall() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice(), watches: false)
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())

        maker.reporting?.connection("disconnected")
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertFalse(maker.engine.asked.contains("stop"), "a connection that may come back is left")
        maker.reporting?.connection("failed")

        try await waitUntil { maker.engine.asked.contains("stop") }
    }

    func testTheWatchWaitsTheLongerBoundBeforeThePermitAndTheShorterAfterIt() {
        var now: TimeInterval = 0
        var opened = CallWatch(clock: { now }, beforePermit: 100, afterPermit: 10)
        now = 99
        XCTAssertFalse(opened.expired())
        now = 100
        XCTAssertTrue(opened.expired())
        now = 500
        XCTAssertFalse(opened.expired(), "a call is found gone once")

        now = 0
        var permitted = CallWatch(clock: { now }, beforePermit: 100, afterPermit: 10)
        now = 50
        permitted.permit()
        now = 59
        XCTAssertFalse(permitted.expired())
        permitted.sign()
        now = 68
        XCTAssertFalse(permitted.expired(), "a sign starts the wait again")
        now = 69
        XCTAssertTrue(permitted.expired())
    }

    /// Waits for `condition` to hold, which something on another queue makes so, for up to ten seconds.
    private func waitUntil(_ condition: @escaping () -> Bool) async throws {
        let end = Date().addingTimeInterval(10)
        while !condition() {
            if Date() > end { return XCTFail("it did not come about") }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    func testNotificationsRefusedIsReportedAndDoesNotRefuseTheCall() async throws {
        let adapter = CallAdapter(maker: FakeMaker(), device: FakeDevice(notifications: false))
        let open = try Fixtures.command("callOpen", 1)

        let opened = await ask(adapter, "callOpen", open.request, told: Told())

        XCTAssertEqual(opened.result, open.response)
    }

    func testAMicrophoneTheApplicationMayNotUseRefusesTheCall() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice(microphone: false))

        let opened = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())

        XCTAssertNil(opened.result)
        XCTAssertEqual(opened.code, "microphone_refused")
        XCTAssertEqual(maker.made, 0, "no call was made")
    }

    func testASecondCallWhileOneIsHeldIsRefusedAndTheFirstIsLeftAlone() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice())
        let first = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())
        XCTAssertNotNil(first.result)

        let second = await ask(adapter, "callOpen", #"{"call":"c2","events":"__CHANNEL__:8"}"#, told: Told())

        XCTAssertEqual(second.code, "already_running")
        XCTAssertEqual(maker.made, 1)
        let held = await ask(adapter, "callState", "{}")
        XCTAssertEqual(held.result?["call"] as? String, "c1")
    }

    func testACommandThatNamesAnotherCallOrAnEndedOneIsTold() async throws {
        let adapter = CallAdapter(maker: FakeMaker(), device: FakeDevice())
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())

        let other = await ask(adapter, "callOffer", #"{"call":"c9"}"#)
        XCTAssertEqual(other.code, "no_such_call")

        _ = await ask(adapter, "callStop", #"{"call":"c1"}"#)
        let ended = await ask(adapter, "callOffer", #"{"call":"c1"}"#)
        XCTAssertEqual(ended.code, "ended")
    }

    func testEachItemOfNewsIsTheFixturesFrame() throws {
        let items: [CallItem] = [
            .connection("new"), .connection("connecting"), .connection("connected"),
            .connection("disconnected"), .connection("failed"), .connection("closed"),
            .providerEvent(Data(#"{"type":"session.created"}"#.utf8)), .playout,
            .capture(.capturing), .capture(.mutedByPerson), .capture(.interrupted),
            .capture(.routeChanging), .capture(.suspendedBySystem), .capture(.unavailable),
            .capture(.idle), .lost, .ended, .barrier(3),
        ]
        let frames = (try Fixtures.json("events.json") as! [[String: Any]]).map { $0["frame"] as! NSDictionary }
        XCTAssertEqual(frames.count, items.count)
        for (index, item) in items.enumerated() {
            let text = CallWire.frame(call: "c1", seq: UInt64(index + 1), item: item)
            let made = try JSONSerialization.jsonObject(with: Data(text.utf8)) as! NSDictionary
            XCTAssertEqual(made, frames[index], "item \(index + 1)")
        }
    }

    func testTheCallsNewsIsSentInTheOrderItWasReportedAndNumberedAsItIsSent() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice())
        let told = Told()
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: told)
        let reporting = try XCTUnwrap(maker.reporting)

        reporting.connection("connecting")
        reporting.connection("connected")
        reporting.providerEvent(Data(#"{"type":"session.created"}"#.utf8))
        reporting.playout()
        reporting.capture(.routeChanging)
        reporting.ended()

        await fulfillment(of: [told.expectation(frames: 6)], timeout: 10)
        XCTAssertEqual(
            told.news.map { $0["kind"] as? String },
            ["connection", "connection", "provider_event", "playout", "capture", "ended"])
        XCTAssertEqual(told.news.map { $0["seq"] as? Int }, [1, 2, 3, 4, 5, 6])
    }

    func testTheBufferKeepsTheOrderAndTellsALossWhereItHappened() throws {
        let cases = try Fixtures.json("queue.json") as! [[String: Any]]
        XCTAssertGreaterThanOrEqual(cases.count, 10)
        func item(_ kind: String) -> CallItem {
            switch kind {
            case "provider": return .providerEvent(Data([1]))
            case "connection": return .connection("connected")
            case "capture": return .capture(.capturing)
            case "playout": return .playout
            case "ended": return .ended
            case "barrier": return .barrier(1)
            default: preconditionFailure("the fixture names news of a kind \(kind)")
            }
        }
        func kind(_ entry: CallNewsBuffer.Entry?) -> String {
            switch entry {
            case nil: return "none"
            case .lost?: return "lost"
            case .news(let news)?:
                switch news {
                case .providerEvent: return "provider"
                case .connection: return "connection"
                case .capture: return "capture"
                case .playout: return "playout"
                case .ended: return "ended"
                case .barrier: return "barrier"
                case .lost: preconditionFailure("a loss is never queued as news")
                }
            }
        }
        for found in cases {
            var buffer = CallNewsBuffer(limit: found["limit"] as! Int)
            var popped: [String] = []
            for op in found["ops"] as! [String] {
                if op.hasPrefix("push ") {
                    buffer.push(item(String(op.dropFirst(5))))
                } else {
                    popped.append(kind(buffer.pop()))
                }
            }
            XCTAssertEqual(popped, found["results"] as! [String], found["name"] as! String)
        }
    }

    func testARequestTheOtherHalvesRefuseIsRefusedHereToo() async throws {
        let refusals = try Fixtures.json("refusals.json") as! [[String: Any]]
        XCTAssertGreaterThanOrEqual(refusals.count, 15)
        for found in refusals {
            let arguments = Fixtures.text(found["request"]!)
            let adapter = CallAdapter(maker: FakeMaker(), device: FakeDevice())
            _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())

            let answered = await ask(adapter, found["command"] as! String, arguments)

            XCTAssertNil(answered.result, found["name"] as! String)
            XCTAssertEqual(answered.code, "engine", found["name"] as! String)
        }
    }

    func testNewsOfACallThatHasEndedIsNotNewsOfTheNextOne() async throws {
        let maker = FakeMaker()
        let adapter = CallAdapter(maker: maker, device: FakeDevice())
        _ = await ask(adapter, "callOpen", #"{"call":"c1","events":"__CHANNEL__:7"}"#, told: Told())
        let early = try XCTUnwrap(maker.reporting)
        _ = await ask(adapter, "callStop", #"{"call":"c1"}"#)
        let told = Told()
        _ = await ask(adapter, "callOpen", #"{"call":"c2","events":"__CHANNEL__:8"}"#, told: told)

        early.ended()
        early.connection("failed")
        maker.reporting?.playout()

        await fulfillment(of: [told.expectation(frames: 1)], timeout: 10)
        XCTAssertEqual(told.news.map { $0["kind"] as? String }, ["playout"])
        XCTAssertEqual(told.news.first?["call"] as? String, "c2")
        XCTAssertEqual(told.news.first?["seq"] as? Int, 1, "the new call's news is counted from one")
    }

    func testAProviderEventDroppedAsTheLastNewsIsStillToldAsLost() async throws {
        let sent = Told()
        let taken = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let queue = CallNewsQueue(call: "c1", limit: 1) { text in
            taken.signal()
            release.wait()
            sent.take(text)
        }

        queue.offer(.providerEvent(Data([1])))  // taken by the sender, which waits
        taken.wait()
        queue.offer(.providerEvent(Data([2])))  // waits in the buffer
        queue.offer(.providerEvent(Data([3])))  // finds the buffer full, and nothing follows
        for _ in 0..<3 { release.signal() }

        await fulfillment(of: [sent.expectation(frames: 3)], timeout: 10)
        XCTAssertEqual(sent.news.map { $0["kind"] as? String }, ["provider_event", "provider_event", "lost"])
        XCTAssertEqual(sent.news.map { $0["seq"] as? Int }, [1, 2, 3])
    }

    func testTheEndIsSentWhenTheBufferIsFullAndNothingFollowsIt() async throws {
        let sent = Told()
        let taken = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let queue = CallNewsQueue(call: "c1", limit: 1) { text in
            taken.signal()
            release.wait()
            sent.take(text)
        }

        queue.offer(.playout)  // taken by the sender, which waits
        taken.wait()
        queue.offer(.providerEvent(Data([1])))  // waits in the buffer
        queue.offer(.ended)  // takes the place of the provider event
        queue.offer(.capture(.idle))  // after the end: not queued
        for _ in 0..<3 { release.signal() }

        await fulfillment(of: [sent.expectation(frames: 3)], timeout: 10)
        XCTAssertEqual(sent.news.map { $0["kind"] as? String }, ["playout", "lost", "ended"])
    }
}
