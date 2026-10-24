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

    func testTheExtensionShowsWhatTheHostSealed() throws {
        XCTAssertEqual(try shown(holdingTheSender: true), try golden().summary)
    }

    func testTheExtensionLeavesTheGenericAlertForAHostItHoldsNoKeyFor() throws {
        XCTAssertEqual(try shown(holdingTheSender: false), try golden().alert)
    }
}
