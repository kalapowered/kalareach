//
//  The notification extension opening a preview the host's own code sealed.
//
//  The golden is one such preview (the file the Rust opener's tests and the Android receiver read
//  too), sealed under fixed test keys with an expiry far ahead. These cases run the real library:
//  the opener on the golden, and the extension's own `didReceive` over a notification that carries
//  it, with the keys the golden names and the clock the golden was made at.
//

import UserNotifications
import XCTest

final class SealedPreviewTests: XCTestCase {
    private struct Golden {
        let alert: String
        let preview: String
        let summary: String
        let nowMilliseconds: UInt64
        let recipientKeyID: Data
        let recipientSeed: Data
        let senderKeyID: Data
        let senderKey: Data
    }

    private func golden() throws -> Golden {
        let here = URL(fileURLWithPath: #filePath)
        // .../native/ios/Tests/SealedPreviewTests.swift
        let fixture = here.deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("platform/fixtures/push/recorded-preview.json")
        let file = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: fixture)) as? [String: Any])
        func text(_ name: String) throws -> String { try XCTUnwrap(file[name] as? String) }
        func standard(_ name: String) throws -> Data { try XCTUnwrap(Data(base64Encoded: try text(name))) }
        func url(_ name: String) throws -> Data {
            let padded = try text(name).replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            return try XCTUnwrap(Data(base64Encoded: padded + String(repeating: "=", count: (4 - padded.count % 4) % 4)))
        }
        return Golden(
            alert: try text("alert"), preview: try text("preview"), summary: try text("summary"),
            nowMilliseconds: UInt64(try XCTUnwrap(file["now_ms"] as? Int)),
            recipientKeyID: try url("recipient_key_id"), recipientSeed: try standard("recipient_seed"),
            senderKeyID: try url("sender_key_id"), senderKey: try standard("sender_key"))
    }

    /// The keys the golden names, as the extension would find them in the keychain.
    private struct GoldenKeys: PreviewKeyReading {
        let golden: Golden
        let holdsTheSender: Bool

        func recipientSeed(forRecipient recipientKeyID: Data) throws -> Data {
            guard recipientKeyID == golden.recipientKeyID else { throw PreviewKeyUnavailable.notProvisioned }
            return golden.recipientSeed
        }

        func senderKey(forSender senderKeyID: Data) throws -> Data {
            guard holdsTheSender, senderKeyID == golden.senderKeyID else {
                throw PreviewKeyUnavailable.notProvisioned
            }
            return golden.senderKey
        }
    }

    func testTheLibraryOpensWhatTheHostSealed() throws {
        let sealed = try golden()
        let opened = RustPreviewOpener().open(
            preview: sealed.preview, alert: sealed.alert, seed: sealed.recipientSeed,
            senderKey: sealed.senderKey, nowMilliseconds: sealed.nowMilliseconds)
        XCTAssertEqual(opened, .text(sealed.summary))
    }

    func testTheLibraryRefusesAnAlertTheSealedPreviewDoesNotRepeat() throws {
        let sealed = try golden()
        let opened = RustPreviewOpener().open(
            preview: sealed.preview, alert: "Something else needs you.", seed: sealed.recipientSeed,
            senderKey: sealed.senderKey, nowMilliseconds: sealed.nowMilliseconds)
        XCTAssertEqual(opened, .refused("alert_mismatch"))
    }

    /// Runs the extension's own `didReceive` over a notification that carries the golden, with the
    /// extension's parts replaced by the golden's keys, the real opener and the golden's clock. The
    /// body the system is handed back is the answer.
    private func shown(holdingTheSender: Bool) throws -> String {
        let sealed = try golden()
        let earlier = NotificationService.parts
        defer { NotificationService.parts = earlier }
        NotificationService.parts = ExtensionParts(
            keys: GoldenKeys(golden: sealed, holdsTheSender: holdingTheSender),
            opener: RustPreviewOpener(),
            nowMilliseconds: { sealed.nowMilliseconds })

        let content = UNMutableNotificationContent()
        content.body = sealed.alert
        content.userInfo = ["preview": sealed.preview]
        let request = UNNotificationRequest(identifier: "n-1", content: content, trigger: nil)
        var handedBack: String?
        NotificationService().didReceive(request) { handedBack = $0.body }
        return try XCTUnwrap(handedBack)
    }

    /// Keys that hold the first read of the host's key until the test lets it go, so that the system's
    /// call that the time is up can be made while the extension is still opening the preview. Later
    /// reads (the extension reads the key again after the preview has opened) are not held.
    private final class HeldKeys: PreviewKeyReading {
        let inner: GoldenKeys
        let reading = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var held = false

        init(_ inner: GoldenKeys) { self.inner = inner }

        func recipientSeed(forRecipient recipientKeyID: Data) throws -> Data {
            try inner.recipientSeed(forRecipient: recipientKeyID)
        }

        func senderKey(forSender senderKeyID: Data) throws -> Data {
            lock.lock()
            let first = !held
            held = true
            lock.unlock()
            if first {
                reading.signal()
                _ = release.wait(timeout: .now() + 30)
            }
            return try inner.senderKey(forSender: senderKeyID)
        }
    }

    /// The keys the golden names, until the host's key is taken away, as turning previews off does.
    private final class SwitchableKeys: PreviewKeyReading {
        private let lock = NSLock()
        private let golden: Golden
        private var holdsTheSender = true

        init(_ golden: Golden) { self.golden = golden }

        func turnPreviewsOff() {
            lock.lock()
            holdsTheSender = false
            lock.unlock()
        }

        func recipientSeed(forRecipient recipientKeyID: Data) throws -> Data {
            guard recipientKeyID == golden.recipientKeyID else { throw PreviewKeyUnavailable.notProvisioned }
            return golden.recipientSeed
        }

        func senderKey(forSender senderKeyID: Data) throws -> Data {
            lock.lock()
            let holds = holdsTheSender
            lock.unlock()
            guard holds, senderKeyID == golden.senderKeyID else { throw PreviewKeyUnavailable.notProvisioned }
            return golden.senderKey
        }
    }

    /// The real opener, held at the start of its work until the test lets it go.
    private final class HeldOpener: PreviewOpening {
        let opening = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)

        func open(preview: String, alert: String, seed: Data, senderKey: Data, nowMilliseconds: UInt64)
            -> PreviewOpened
        {
            opening.signal()
            _ = release.wait(timeout: .now() + 30)
            return RustPreviewOpener().open(
                preview: preview, alert: alert, seed: seed, senderKey: senderKey,
                nowMilliseconds: nowMilliseconds)
        }
    }

    /// The bodies the system was handed, from whichever thread handed them.
    private final class HandedBack {
        private let lock = NSLock()
        private var all: [String] = []

        func add(_ body: String) {
            lock.lock()
            all.append(body)
            lock.unlock()
        }

        var bodies: [String] {
            lock.lock()
            defer { lock.unlock() }
            return all
        }
    }

    private func request(for sealed: Golden) -> UNNotificationRequest {
        let content = UNMutableNotificationContent()
        content.body = sealed.alert
        content.userInfo = ["preview": sealed.preview]
        return UNNotificationRequest(identifier: "n-2", content: content, trigger: nil)
    }

    func testAnExpiryWhileThePreviewIsBeingOpenedHandsTheSystemTheGenericAlertOnce() throws {
        let sealed = try golden()
        let earlier = NotificationService.parts
        defer { NotificationService.parts = earlier }
        let keys = HeldKeys(GoldenKeys(golden: sealed, holdsTheSender: true))
        NotificationService.parts = ExtensionParts(
            keys: keys,
            opener: RustPreviewOpener(),
            nowMilliseconds: { sealed.nowMilliseconds })
        let handedBack = HandedBack()
        let returned = expectation(description: "didReceive returned")
        let service = NotificationService()
        let incoming = request(for: sealed)
        DispatchQueue.global().async {
            service.didReceive(incoming) { handedBack.add($0.body) }
            returned.fulfill()
        }

        XCTAssertEqual(keys.reading.wait(timeout: .now() + 30), .success, "the extension reached the keys")
        // The system's deadline comes while the preview is still being opened.
        service.serviceExtensionTimeWillExpire()
        keys.release.signal()
        wait(for: [returned], timeout: 30)

        XCTAssertEqual(handedBack.bodies, [sealed.alert], "the generic alert, once, and nothing after it")
    }

    func testPreviewsTurnedOffWhileThePreviewIsBeingOpenedLeaveTheGenericAlert() throws {
        let sealed = try golden()
        let earlier = NotificationService.parts
        defer { NotificationService.parts = earlier }
        let keys = SwitchableKeys(sealed)
        let opener = HeldOpener()
        NotificationService.parts = ExtensionParts(
            keys: keys,
            opener: opener,
            nowMilliseconds: { sealed.nowMilliseconds })
        let handedBack = HandedBack()
        let returned = expectation(description: "didReceive returned")
        let service = NotificationService()
        let incoming = request(for: sealed)
        DispatchQueue.global().async {
            service.didReceive(incoming) { handedBack.add($0.body) }
            returned.fulfill()
        }

        // The extension has read the host's key and is opening the preview with it.
        XCTAssertEqual(opener.opening.wait(timeout: .now() + 30), .success, "the extension reached the opener")
        // The person turns previews off, and the host's key goes, while the preview is still open.
        keys.turnPreviewsOff()
        opener.release.signal()
        wait(for: [returned], timeout: 30)

        XCTAssertEqual(handedBack.bodies, [sealed.alert], "the generic alert, since previews are off now")
    }

    func testANotificationServedWhileAnotherIsBeingOpenedIsCompletedWithItsOwnHandler() throws {
        let sealed = try golden()
        let earlier = NotificationService.parts
        defer { NotificationService.parts = earlier }
        let keys = HeldKeys(GoldenKeys(golden: sealed, holdsTheSender: true))
        NotificationService.parts = ExtensionParts(
            keys: keys,
            opener: RustPreviewOpener(),
            nowMilliseconds: { sealed.nowMilliseconds })
        let first = HandedBack()
        let second = HandedBack()
        let returned = expectation(description: "the first didReceive returned")
        let service = NotificationService()
        let opening = request(for: sealed)
        DispatchQueue.global().async {
            service.didReceive(opening) { first.add($0.body) }
            returned.fulfill()
        }
        XCTAssertEqual(keys.reading.wait(timeout: .now() + 30), .success, "the extension reached the keys")

        // The same instance is given another notification while the first is still being opened.
        let other = UNMutableNotificationContent()
        other.body = "Another alert."
        service.didReceive(UNNotificationRequest(identifier: "n-3", content: other, trigger: nil)) {
            second.add($0.body)
        }
        keys.release.signal()
        wait(for: [returned], timeout: 30)

        XCTAssertEqual(second.bodies, ["Another alert."])
        XCTAssertEqual(first.bodies, [sealed.summary], "each was completed with the handler it came with")
    }

    func testAnExpiryAfterThePreviewWasShownHandsTheSystemNothingMore() throws {
        let sealed = try golden()
        let earlier = NotificationService.parts
        defer { NotificationService.parts = earlier }
        NotificationService.parts = ExtensionParts(
            keys: GoldenKeys(golden: sealed, holdsTheSender: true),
            opener: RustPreviewOpener(),
            nowMilliseconds: { sealed.nowMilliseconds })
        let handedBack = HandedBack()
        let service = NotificationService()

        service.didReceive(request(for: sealed)) { handedBack.add($0.body) }
        service.serviceExtensionTimeWillExpire()

        XCTAssertEqual(handedBack.bodies, [sealed.summary], "the preview, once, and nothing after it")
    }

    func testTheExtensionShowsWhatTheHostSealed() throws {
        XCTAssertEqual(try shown(holdingTheSender: true), try golden().summary)
    }

    func testTheExtensionLeavesTheGenericAlertForAHostItHoldsNoKeyFor() throws {
        XCTAssertEqual(try shown(holdingTheSender: false), try golden().alert)
    }
}
