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
    var asked: [String] = []
    var offered = "v=0\r\ns=-\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
    var usesDtx: Bool? = true
    var permitted = true
    var isPlaybackMuted = false
    var isMutedByPerson = false

    func offer() async throws -> String {
        asked.append("offer")
        return offered
    }

    func accept(answerSdp: String) async throws { asked.append("accept \(answerSdp.count)") }
    var answerUsesDtx: Bool? { usesDtx }

    func permit(voiceSessionId: String, closesAtEpochMs: UInt64) -> Bool {
        asked.append("permit \(voiceSessionId) \(closesAtEpochMs)")
        return permitted
    }

    func setMutedByPerson(_ muted: Bool) {
        asked.append("microphone \(muted)")
        isMutedByPerson = muted
    }
    func setPlaybackMuted(_ muted: Bool) {
        asked.append("playback \(muted)")
        isPlaybackMuted = muted
    }

    func stop() { asked.append("stop") }
}

/// Makes the fake call, keeping the reporter the adapter gave it.
private final class FakeMaker: CallEngineMaker {
    let engine = FakeEngine()
    var reporting: CallReporting?
    var made = 0

    func make(reporting: CallReporting) throws -> CallEngine {
        made += 1
        self.reporting = reporting
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
            .providerEvent(Data(#"{"type":"session.created"}"#.utf8)), .firstAudio,
            .capture(.capturing), .capture(.mutedByPerson), .capture(.interrupted),
            .capture(.routeChanging), .capture(.suspendedBySystem), .capture(.unavailable),
            .capture(.idle), .lost, .ended,
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
        reporting.firstAudio()
        reporting.capture(.routeChanging)
        reporting.ended()

        await fulfillment(of: [told.expectation(frames: 6)], timeout: 10)
        XCTAssertEqual(
            told.news.map { $0["kind"] as? String },
            ["connection", "connection", "provider_event", "first_audio", "capture", "ended"])
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
            case "first_audio": return .firstAudio
            case "ended": return .ended
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
                case .firstAudio: return "first_audio"
                case .ended: return "ended"
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
        maker.reporting?.firstAudio()

        await fulfillment(of: [told.expectation(frames: 1)], timeout: 10)
        XCTAssertEqual(told.news.map { $0["kind"] as? String }, ["first_audio"])
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

        queue.offer(.firstAudio)  // taken by the sender, which waits
        taken.wait()
        queue.offer(.providerEvent(Data([1])))  // waits in the buffer
        queue.offer(.ended)  // takes the place of the provider event
        queue.offer(.capture(.idle))  // after the end: not queued
        for _ in 0..<3 { release.signal() }

        await fulfillment(of: [sent.expectation(frames: 3)], timeout: 10)
        XCTAssertEqual(sent.news.map { $0["kind"] as? String }, ["first_audio", "lost", "ended"])
    }
}
