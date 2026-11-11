//
//  What the push receiver does with a message, from the message to the record and the gateway.
//
//  The decision and the signature are the Rust half's and are tested there against the protocol's
//  vectors; here the rest of the receiver is held: the order (decide, then sign, then post), what each
//  outcome does to the record, that the record's deadline is a fact of the clock, and that the
//  adapter the plugin reaches answers each command from what it holds.
//

import UIKit
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

    /// KR-REQ-16.06, the receiver's side of answering only its own pending registration: an answer
    /// that outlived its registration cannot move the record of the registration that replaced it,
    /// and the replacement is moved only by its own identifier.
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

    /// KR-REQ-16.06, the receiver's side of answering only its own pending registration: a challenge
    /// the decision refuses is not answered. Nothing is signed or posted, and the registration stays
    /// pending. Not shown here: which challenges the decision refuses, which is the Rust half's cases.
    func testAChallengeTheDecisionRefusesSignsNothingPostsNothingAndLeavesTheRecordPending() throws {
        let record = try pending()
        let crypto = Crypto(verdict: #"{"verdict":"refused","reason":"registration"}"#)
        let gateway = Gateway(.status(200))
        XCTAssertEqual(outcome(crypto, gateway, record), .ignored("registration"))
        XCTAssertEqual(crypto.signCalls, 0, "the key is read only after the decision says to go on")
        XCTAssertTrue(gateway.posted.isEmpty)
        XCTAssertEqual(state(record), "pending")
    }

    /// KR-REQ-16.06, the receiver's side of returning a signed challenge: the answer the signer
    /// returns is posted to the gateway with the body the signer gave, and the pending registration
    /// it answers moves to answered. Not shown here: what the signature binds (token hash,
    /// registration, gateway origin and expiry), which is the Rust half's cases, or that the
    /// address posted to is the signer's and not the decision's (the fixture gives both the same).
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
        var filed: [PreviewKeySet] = []

        func replace(with keys: PreviewKeySet) -> Bool {
            filed.append(keys)
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

    /// KR-REQ-10.48: what the adapter files in the store the extension reads is the set of preview
    /// keys the application hands over, whole, and nothing else: the seed by the identifier of its
    /// public half, and the public key of each host that may seal a preview to it.
    func testOnlyThePreviewKeysAreFiledInTheStoreTheExtensionReads() {
        let keys = Keys()
        let held = adapter(keys: keys)
        let recipient = Data(repeating: 0x91, count: 32)
        let seed = Data(repeating: 3, count: 32)
        let host = Data(repeating: 0x21, count: 32)
        let hostKey = Data(repeating: 5, count: 32)
        func set(_ recipients: [[String: String]], _ senders: [[String: String]]) -> String {
            String(
                data: try! JSONSerialization.data(withJSONObject: ["recipients": recipients, "senders": senders]),
                encoding: .utf8)!
        }
        let one = set(
            [["id": recipient.base64EncodedString(), "seed": seed.base64EncodedString()]],
            [["id": host.base64EncodedString(), "key": hostKey.base64EncodedString()]])
        XCTAssertNotNil(answer(held, "pushPreviewKeys", one))
        XCTAssertEqual(keys.filed.count, 1)
        XCTAssertEqual(keys.filed.first?.recipients, [recipient: seed])
        XCTAssertEqual(keys.filed.first?.senders, [host: hostKey])

        // An empty set is a set: every host is off, and the store is made empty.
        XCTAssertNotNil(answer(held, "pushPreviewKeys", set([], [])))
        XCTAssertEqual(keys.filed.last, PreviewKeySet(recipients: [:], senders: [:]))

        // What is not made of keys files nothing: the store is never handed half of a set.
        XCTAssertNil(answer(held, "pushPreviewKeys", "{}"), "a request that names no keys files none")
        XCTAssertNil(
            answer(
                held, "pushPreviewKeys",
                set([["id": recipient.base64EncodedString(), "seed": Data(count: 31).base64EncodedString()]], [])),
            "a seed of another length")
        XCTAssertNil(
            answer(
                held, "pushPreviewKeys",
                set([], [
                    ["id": host.base64EncodedString(), "key": hostKey.base64EncodedString()],
                    ["id": host.base64EncodedString(), "key": hostKey.base64EncodedString()],
                ])),
            "one host twice")
        XCTAssertEqual(keys.filed.count, 2)
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

/// The delegate class of the case below, which the methods are added to for the life of the process.
private final class RestartedDelegate: NSObject {}

final class RegistrationRecoveryTests: XCTestCase {
    private static let registration = "2e749a03-c158-4d62-a019-6f3bd784215c"
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

    private var file: URL { directory.appendingPathComponent("pending.json") }

    private struct NoPermissions: NotificationPermissions {
        func current(then: @escaping (PushPermission) -> Void) { then(.unknown) }
        func ask(then: @escaping (PushPermission) -> Void) { then(.unknown) }
    }

    private struct NoKeys: LimitedKeyWriting {
        func replace(with keys: PreviewKeySet) -> Bool { true }
    }

    /// The Rust half's decision for this case, made from the record it is given and from nothing
    /// else: with no record, a record that is no longer pending, or a challenge for another
    /// registration, it refuses.
    private struct RecordDecidingCrypto: ChallengeCrypto {
        func classify(_ input: String) -> String {
            let read = (try? JSONSerialization.jsonObject(with: Data(input.utf8))) as? [String: Any] ?? [:]
            guard let record = read["pending"] as? [String: Any] else {
                return #"{"verdict":"refused","reason":"no_pending"}"#
            }
            if record["state"] as? String != PendingFile.pending {
                return #"{"verdict":"refused","reason":"state"}"#
            }
            let named = (read["data"] as? [String: String])?["kr_registration_id"]
            if record["registration_id"] as? String != named {
                return #"{"verdict":"refused","reason":"registration"}"#
            }
            return #"{"verdict":"answer","url":"https://reach.kala.to/api/push/installation/register","seed_item":"x"}"#
        }

        func sign(_ input: String) -> String {
            #"{"ok":true,"url":"https://reach.kala.to/api/push/installation/register","body":"{}"}"#
        }
    }

    /// A gateway that takes the post and answers it when the test says so, as the network does.
    private final class Gateway: GatewayPost {
        var posted: [(String, String)] = []
        private var waiting: ((PostResult) -> Void)?

        func post(url: String, body: Data, then: @escaping (PostResult) -> Void) {
            posted.append((url, String(data: body, encoding: .utf8) ?? ""))
            waiting = then
        }

        /// The gateway answers the post that is waiting.
        func answers(_ result: PostResult) {
            let then = waiting
            waiting = nil
            then?(result)
        }
    }

    /// The application in one process: its adapter over the record in the application's directory.
    private func application() -> PushAdapter {
        PushAdapter(
            permissions: NoPermissions(),
            tokens: PushTokenStore(defaults: defaults),
            record: PendingFile(url: file),
            keys: NoKeys(),
            route: NotificationRoute(),
            clock: { self.now },
            permissionRead: { _ in })
    }

    private func ask(_ adapter: PushAdapter, _ command: String, _ arguments: String = "{}") -> [String: Any]? {
        var result: String?
        adapter.run(command, arguments) { text, _, _ in result = text }
        return result.flatMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any] }
    }

    /// The state the record file holds, read from the file itself and not through the record.
    private func stateOnDisk() -> String {
        let object = (try? Data(contentsOf: file))
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        return (object?["state"] as? String) ?? "no record"
    }

    /// The system's call of the delegate's wake method, made as it makes it: the application, the
    /// payload and a block that takes the result.
    private func wake(_ delegate: NSObject, with payload: [String: String], told: @escaping (UInt) -> Void) {
        let selector = Selector(("application:didReceiveRemoteNotification:fetchCompletionHandler:"))
        typealias Call = @convention(c) (AnyObject, Selector, AnyObject, NSDictionary, @escaping @convention(block) (UInt) -> Void) -> Void
        let call = unsafeBitCast(delegate.method(for: selector), to: Call.self)
        call(delegate, selector, NSObject(), payload as NSDictionary, told)
    }

    /// KR-REQ-13.24: lifecycle recovery with no page running. The application is ended after it
    /// wrote the record of the registration it waits for. The system starts it again for the
    /// challenge's push alone, and native code answers from the stored record: the delegate's wake
    /// method reaches an answerer built afresh over the file, the answer is posted, the record moves
    /// to answered, and only then is the system told the data was new. The application's next start
    /// reads that the answer was taken, and the same push delivered again is not answered twice. No
    /// page exists in any of these processes. Not shown here: the application's own hand-off from the
    /// delegate to the answerer, which links the Rust library and is not built into this bundle.
    func testAPushThatWakesAnEndedApplicationIsAnsweredFromTheRecordItLeftAndTheNextStartReadsTheResult() throws {
        // The application's earlier run writes the record before it proposes a token, and is ended.
        let record: [String: Any] = [
            "registration_id": Self.registration, "token_digest": "d", "gateway_origin": "https://reach.kala.to",
            "platform": "ios", "deadline_ms": now + 60_000, "state": "pending",
        ]
        let arguments = String(data: try JSONSerialization.data(withJSONObject: ["record": record]), encoding: .utf8)!
        do {
            let earlier = application()
            XCTAssertNotNil(ask(earlier, "pushPendingSet", arguments))
        }
        XCTAssertEqual(stateOnDisk(), "pending", "the record is in the file and not in a process")

        // The system starts the application again for the push, through the delegate's wake method.
        let gateway = Gateway()
        let outcomes = Box<[ChallengeOutcome]>([])
        let stateWhenTold = Box<[String]>([])
        let results = Box<[UInt]>([])
        let added = DelegateMethods.install(
            on: RestartedDelegate.self, received: { _ in }, refused: { _ in },
            remote: { userInfo, finished in
                var data: [String: String] = [:]
                for (key, value) in userInfo {
                    if let key = key as? String, let value = value as? String { data[key] = value }
                }
                // An answerer built afresh over the file: nothing of the earlier process is in it.
                ChallengeAnswerer(
                    record: PendingFile(url: self.file), crypto: RecordDecidingCrypto(), gateway: gateway,
                    clock: { self.now }
                ).answer(data) { outcome in
                    outcomes.value.append(outcome)
                    finished()
                }
            })
        XCTAssertEqual(added, .added)
        let delegate = RestartedDelegate()
        let message = ["kr_challenge": "x", "kr_registration_id": Self.registration]
        wake(delegate, with: message) {
            results.value.append($0)
            stateWhenTold.value.append(self.stateOnDisk())
        }

        XCTAssertEqual(gateway.posted.map(\.0), ["https://reach.kala.to/api/push/installation/register"])
        XCTAssertEqual(gateway.posted.map(\.1), ["{}"])
        XCTAssertEqual(results.value, [], "the system is not told while the answer is on its way")
        XCTAssertEqual(stateOnDisk(), "pending")
        gateway.answers(.status(200))
        XCTAssertEqual(outcomes.value, [.answered])
        XCTAssertEqual(stateOnDisk(), "answered")
        XCTAssertEqual(results.value, [UIBackgroundFetchResult.newData.rawValue])
        XCTAssertEqual(stateWhenTold.value, ["answered"], "the system is told only once the record says so")

        // The application's next start reads what became of the registration.
        let next = application()
        let read = ask(next, "pushPendingGet")?["record"] as? [String: Any]
        XCTAssertEqual(read?["state"] as? String, "answered")

        // The same push delivered again finds the registration settled and answers nothing.
        wake(delegate, with: message) { results.value.append($0) }
        XCTAssertEqual(outcomes.value, [.answered, .ignored("state")])
        XCTAssertEqual(gateway.posted.count, 1, "nothing is posted a second time")
        XCTAssertEqual(results.value.count, 2, "and the system is told this push is done too")
    }
}
