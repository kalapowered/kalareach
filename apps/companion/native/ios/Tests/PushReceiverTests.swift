//
//  What the push receiver does with a message, from the message to the record and the gateway.
//
//  The decision and the signature are the Rust half's and are tested there against the protocol's
//  vectors; here the rest of the receiver is held: the order (decide, then sign, then post), what each
//  outcome does to the record, that the record's deadline is a fact of the clock, and that the
//  adapter the plugin reaches answers each command from what it holds.
//

import XCTest

final class PendingFileTests: XCTestCase {
    private static let registration = "2e749a03-c158-4d62-a019-6f3bd784215c"
    private let now: UInt64 = 1_763_000_000_000
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func file() -> PendingFile { PendingFile(url: directory.appendingPathComponent("pending.json")) }

    private func record(deadline: UInt64, state: String = "pending") -> String {
        let object: [String: Any] = [
            "registration_id": Self.registration,
            "token_digest": "vluKsRhhTV5NI9BuJZCyN2OsL1hi2yQbHXhFhtHMqmQ",
            "gateway_origin": "https://reach.kala.to",
            "platform": "ios",
            "deadline_ms": deadline,
            "state": state,
        ]
        let data = try! JSONSerialization.data(withJSONObject: object)
        return String(data: data, encoding: .utf8)!
    }

    private func state(_ file: PendingFile, at time: UInt64? = nil) -> String? {
        file.read(nowMilliseconds: time ?? now)
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            .flatMap { $0["state"] as? String }
    }

    func testARecordPastItsDeadlineReadsAsExpiredEvenToAReaderThatStartedAfterTheWriter() throws {
        try file().write(record(deadline: now + 10))
        XCTAssertEqual(state(file(), at: now), "pending")
        XCTAssertEqual(state(file(), at: now + 10), "expired")
        XCTAssertEqual(state(file(), at: now), "expired", "and it stays so for every later reader")
    }

    func testATryThatOutlivedItsRegistrationCannotMoveItsReplacement() throws {
        let kept = file()
        try kept.write(record(deadline: now + 60_000))
        let other = "9a0f4c2e-6b1d-4c53-8e8a-7d1f2b3c4d5e"
        let replacement = record(deadline: now + 60_000).replacingOccurrences(of: Self.registration, with: other)
        // The later registration replaces the record while the earlier one's post is in flight.
        try file().write(replacement)
        XCTAssertFalse(kept.mark(registrationId: Self.registration, state: PendingFile.refused, reason: "gateway_403", nowMilliseconds: now))
        XCTAssertEqual(state(kept), "pending")
        XCTAssertTrue(kept.mark(registrationId: other, state: PendingFile.answered, reason: nil, nowMilliseconds: now))
        XCTAssertEqual(state(kept), "answered")
    }

    func testOnlyAPendingRecordMovesAndAReplacedOrExpiredOneIsLeftAlone() throws {
        let kept = file()
        try kept.write(record(deadline: now + 60_000))
        XCTAssertTrue(kept.mark(registrationId: Self.registration, state: PendingFile.answered, reason: nil, nowMilliseconds: now))
        XCTAssertEqual(state(kept), "answered")
        XCTAssertFalse(kept.mark(registrationId: Self.registration, state: PendingFile.refused, reason: "late", nowMilliseconds: now))
        XCTAssertEqual(state(kept), "answered")

        try kept.write(record(deadline: now + 1))
        XCTAssertFalse(kept.mark(registrationId: Self.registration, state: PendingFile.answered, reason: nil, nowMilliseconds: now + 1))
        XCTAssertEqual(state(kept, at: now + 1), "expired")

        try kept.clear()
        XCTAssertNil(kept.read(nowMilliseconds: now))
        XCTAssertFalse(kept.mark(registrationId: Self.registration, state: PendingFile.answered, reason: nil, nowMilliseconds: now))
    }

    func testANewRegistrationReplacesTheOldOneWhole() throws {
        let kept = file()
        try kept.write(record(deadline: now + 60_000))
        kept.mark(registrationId: Self.registration, state: PendingFile.refused, reason: "gateway_403", nowMilliseconds: now)
        try kept.write(record(deadline: now + 120_000))
        let text = try XCTUnwrap(kept.read(nowMilliseconds: now))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
        XCTAssertEqual(object["state"] as? String, "pending")
        XCTAssertNil(object["reason"], "nothing of the earlier reason is kept")
    }
}

final class ChallengeAnswererTests: XCTestCase {
    private let now: UInt64 = 1_763_000_000_000
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private final class Crypto: ChallengeCrypto {
        let verdict: String
        let signed: String
        var signCalls = 0

        init(verdict: String, signed: String = #"{"ok":true,"url":"https://reach.kala.to/api/push/installation/register","body":"{}"}"#) {
            self.verdict = verdict
            self.signed = signed
        }

        func classify(_ input: String) -> String { verdict }

        func sign(_ input: String) -> String {
            signCalls += 1
            return signed
        }
    }

    private final class Gateway: GatewayPost {
        let result: PostResult
        var posted: [(String, String)] = []

        init(_ result: PostResult) { self.result = result }

        func post(url: String, body: Data, then: @escaping (PostResult) -> Void) {
            posted.append((url, String(data: body, encoding: .utf8) ?? ""))
            then(result)
        }
    }

    private let goOn = #"{"verdict":"answer","url":"https://reach.kala.to/api/push/installation/register","seed_item":"x"}"#

    private func pending(deadline: UInt64? = nil) throws -> PendingFile {
        let file = PendingFile(url: directory.appendingPathComponent("pending.json"))
        let object: [String: Any] = [
            "registration_id": "2e749a03-c158-4d62-a019-6f3bd784215c",
            "token_digest": "vluKsRhhTV5NI9BuJZCyN2OsL1hi2yQbHXhFhtHMqmQ",
            "gateway_origin": "https://reach.kala.to",
            "platform": "ios",
            "deadline_ms": deadline ?? now + 60_000,
            "state": "pending",
        ]
        try file.write(String(data: JSONSerialization.data(withJSONObject: object), encoding: .utf8)!)
        return file
    }

    private func state(_ file: PendingFile) -> String? {
        file.read(nowMilliseconds: now)
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            .flatMap { $0["state"] as? String }
    }

    private func outcome(_ crypto: Crypto, _ gateway: Gateway, _ record: PendingFile) -> ChallengeOutcome {
        var result: ChallengeOutcome?
        ChallengeAnswerer(record: record, crypto: crypto, gateway: gateway, clock: { self.now })
            .answer(["kr_challenge": "x", "kr_registration_id": "r"]) { result = $0 }
        return result!
    }

    func testAMessageTheDecisionLeavesAloneSignsNothingAndPostsNothing() throws {
        let crypto = Crypto(verdict: #"{"verdict":"not_a_challenge"}"#)
        let gateway = Gateway(.status(200))
        XCTAssertEqual(outcome(crypto, gateway, try pending()), .notAChallenge)
        XCTAssertEqual(crypto.signCalls, 0)
        XCTAssertTrue(gateway.posted.isEmpty)
    }

    func testAChallengeTheDecisionRefusesSignsNothingPostsNothingAndLeavesTheRecordPending() throws {
        let record = try pending()
        let crypto = Crypto(verdict: #"{"verdict":"refused","reason":"registration"}"#)
        let gateway = Gateway(.status(200))
        XCTAssertEqual(outcome(crypto, gateway, record), .ignored("registration"))
        XCTAssertEqual(crypto.signCalls, 0, "the key is read only after the decision says to go on")
        XCTAssertTrue(gateway.posted.isEmpty)
        XCTAssertEqual(state(record), "pending")
    }

    func testTheAnswerIsPostedToTheAddressTheDecisionGaveAndTheRecordSaysItWasTaken() throws {
        let record = try pending()
        let gateway = Gateway(.status(200))
        XCTAssertEqual(outcome(Crypto(verdict: goOn), gateway, record), .answered)
        XCTAssertEqual(gateway.posted.count, 1)
        XCTAssertEqual(gateway.posted.first?.0, "https://reach.kala.to/api/push/installation/register")
        XCTAssertEqual(gateway.posted.first?.1, "{}")
        XCTAssertEqual(state(record), "answered")
    }

    func testASignatureTheRustHalfWillNotMakeIsNotPosted() throws {
        let crypto = Crypto(verdict: goOn, signed: #"{"ok":false,"reason":"clock"}"#)
        let gateway = Gateway(.status(200))
        XCTAssertEqual(outcome(crypto, gateway, try pending()), .ignored("clock"))
        XCTAssertTrue(gateway.posted.isEmpty)
    }

    func testAGatewayThatCouldNotBeReachedOrCannotTakeItNowIsAskedAgainAndTheRecordWaits() throws {
        for result in [PostResult.unreachable, .status(503), .status(429)] {
            let record = try pending()
            let done = outcome(Crypto(verdict: goOn), Gateway(result), record)
            guard case .retry = done else { return XCTFail("\(result): \(done)") }
            XCTAssertEqual(state(record), "pending")
        }
    }

    func testAGatewayThatRefusesTheAnswerEndsTheRegistrationWithItsStatus() throws {
        let record = try pending()
        XCTAssertEqual(outcome(Crypto(verdict: goOn), Gateway(.status(403)), record), .gatewayRefused(403))
        let text = try XCTUnwrap(record.read(nowMilliseconds: now))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
        XCTAssertEqual(object["state"] as? String, "refused")
        XCTAssertEqual(object["reason"] as? String, "gateway_403")
    }
}

final class PushAdapterTests: XCTestCase {
    private let now: UInt64 = 1_763_000_000_000
    private var directory: URL!
    private var defaults: UserDefaults!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defaults = UserDefaults(suiteName: UUID().uuidString)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private struct Permissions: NotificationPermissions {
        let current: PushPermission
        let afterAsking: PushPermission

        func current(then: @escaping (PushPermission) -> Void) { then(current) }
        func ask(then: @escaping (PushPermission) -> Void) { then(current == .unknown ? afterAsking : current) }
    }

    private final class Keys: LimitedKeyWriting {
        var filed: [(String, Data)] = []

        func write(recipientKeyID: String, seed: Data) -> Bool {
            filed.append((recipientKeyID, seed))
            return true
        }
    }

    private func adapter(
        _ permissions: Permissions = Permissions(current: .unknown, afterAsking: .granted),
        keys: Keys = Keys(),
        route: NotificationRoute = NotificationRoute()
    ) -> PushAdapter {
        PushAdapter(
            permissions: permissions,
            tokens: PushTokenStore(defaults: defaults),
            record: PendingFile(url: directory.appendingPathComponent("pending.json")),
            keys: keys,
            route: route,
            clock: { self.now }
        )
    }

    private func answer(_ adapter: PushAdapter, _ command: String, _ arguments: String = "{}") -> [String: Any]? {
        var result: String?
        adapter.run(command, arguments) { text, _, _ in result = text }
        return result.flatMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any] }
    }

    func testTheNamesThePluginReachesTheAdapterByAreTheFixturesAndEveryCommandIsTaken() throws {
        let here = URL(fileURLWithPath: #filePath)
        // .../native/ios/Tests/PushReceiverTests.swift
        let fixture = here.deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("platform/fixtures/push/link.json")
        let link = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: fixture)) as? [String: Any])
        XCTAssertEqual(link["class"] as? String, "KRPushAdapter")
        XCTAssertNotNil(NSClassFromString("KRPushAdapter"))
        XCTAssertEqual(PushAdapter.Link.command, (link["keys"] as? [String: String])?["command"])
        XCTAssertEqual(PushAdapter.Link.arguments, (link["keys"] as? [String: String])?["arguments"])
        XCTAssertEqual(PushAdapter.Link.reply, (link["keys"] as? [String: String])?["reply"])
        for command in try XCTUnwrap(link["commands"] as? [String]) {
            var code: String?
            adapter().run(command, "{}") { _, answered, _ in code = answered }
            XCTAssertNotEqual(code, "unavailable", "\(command) is a command the adapter takes")
        }
    }

    func testEveryPermissionTheSystemIsReadForIsToldToTheRegistrationAsItIs() {
        var told: [PushPermission] = []
        func adapter(_ permissions: Permissions) -> PushAdapter {
            PushAdapter(
                permissions: permissions,
                tokens: PushTokenStore(defaults: defaults),
                record: PendingFile(url: directory.appendingPathComponent("pending.json")),
                keys: Keys(),
                route: NotificationRoute(),
                clock: { self.now },
                permissionRead: { told.append($0) }
            )
        }
        // A person who refused and then agreed in the system's settings is read as agreed, so the
        // registration goes on without asking again.
        XCTAssertEqual(answer(adapter(Permissions(current: .refused, afterAsking: .refused)), "pushPermission")?["state"] as? String, "denied")
        XCTAssertEqual(answer(adapter(Permissions(current: .granted, afterAsking: .granted)), "pushPermission")?["state"] as? String, "granted")
        XCTAssertEqual(answer(adapter(Permissions(current: .unknown, afterAsking: .granted)), "pushAskPermission")?["state"] as? String, "granted")
        XCTAssertEqual(told, [.refused, .granted, .granted])
    }

    func testThePermissionIsReadWithoutAskingAndAskedOnlyWhenTheCommandSaysSo() {
        let unanswered = adapter()
        XCTAssertEqual(answer(unanswered, "pushPermission")?["state"] as? String, "unknown")
        XCTAssertEqual(answer(unanswered, "pushAskPermission")?["state"] as? String, "granted")
        let refused = adapter(Permissions(current: .refused, afterAsking: .granted))
        XCTAssertEqual(answer(refused, "pushAskPermission")?["state"] as? String, "denied")
    }

    func testATokenIsKeptAndReplacedByTheOneTheProviderGivesNext() {
        let held = adapter()
        XCTAssertTrue(answer(held, "pushToken")?["token"] is NSNull)
        PushTokenStore(defaults: defaults).given("t-1")
        XCTAssertEqual(answer(held, "pushToken")?["token"] as? String, "t-1")
        PushTokenStore(defaults: defaults).given("t-2")
        XCTAssertEqual(answer(held, "pushToken")?["token"] as? String, "t-2")
    }

    func testThePendingRecordIsKeptReadAsItStandsAndRemoved() {
        let held = adapter()
        let record: [String: Any] = [
            "registration_id": "r", "token_digest": "d", "gateway_origin": "https://reach.kala.to",
            "platform": "ios", "deadline_ms": now + 1, "state": "pending",
        ]
        let arguments = String(
            data: try! JSONSerialization.data(withJSONObject: ["record": record]), encoding: .utf8)!
        XCTAssertNotNil(answer(held, "pushPendingSet", arguments))
        XCTAssertEqual((answer(held, "pushPendingGet")?["record"] as? [String: Any])?["state"] as? String, "pending")
        XCTAssertNotNil(answer(held, "pushPendingClear"))
        XCTAssertTrue(answer(held, "pushPendingGet")?["record"] is NSNull)
    }

    /// KR-REQ-10.48: what the adapter files in the store the extension reads is the preview key, by
    /// the identifier of its public half, and nothing else.
    func testOnlyThePreviewKeyIsFiledInTheStoreTheExtensionReads() {
        let keys = Keys()
        let held = adapter(keys: keys)
        let seed = Data(repeating: 3, count: 32)
        let arguments = String(
            data: try! JSONSerialization.data(withJSONObject: [
                "recipient_key_id": Data(repeating: 0x91, count: 32).base64EncodedString(),
                "seed": seed.base64EncodedString(),
            ]),
            encoding: .utf8)!
        XCTAssertNotNil(answer(held, "pushLimitedKey", arguments))
        XCTAssertEqual(keys.filed.count, 1)
        XCTAssertEqual(keys.filed.first?.0, Data(repeating: 0x91, count: 32).base64EncodedString())
        XCTAssertEqual(keys.filed.first?.1, seed)
        XCTAssertNil(answer(held, "pushLimitedKey", "{}"), "a request that names no key files none")
        XCTAssertEqual(keys.filed.count, 1)
    }

    func testATapOnANotificationOpensAttentionOnceAndOnlyWhenTheDefaultActionWasTaken() {
        let route = NotificationRoute()
        let held = adapter(route: route)
        XCTAssertTrue(answer(held, "pushRoute")?["route"] is NSNull)
        route.opened(on: NotificationRoute.attention)
        XCTAssertEqual(answer(held, "pushRoute")?["route"] as? String, "attention")
        XCTAssertTrue(answer(held, "pushRoute")?["route"] is NSNull, "the route is given once")
    }
}
