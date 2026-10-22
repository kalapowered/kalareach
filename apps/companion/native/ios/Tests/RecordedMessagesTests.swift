//
//  The messages a real gateway sent a phone, recorded from a device run, read the way the phone's
//  receiver reads them. The Rust and Kotlin halves read the same files, so a change to what the
//  gateway sends has to be made in all three at once.
//

import XCTest

final class RecordedMessagesTests: XCTestCase {
    /// What the system hands the application's delegate for a recorded message: the message's data at
    /// the top level, beside the `aps` the push carries.
    private func recorded(_ name: String) throws -> [AnyHashable: Any] {
        let here = URL(fileURLWithPath: #filePath)
        // .../native/ios/Tests/RecordedMessagesTests.swift
        let fixture = here.deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("platform/fixtures/push/\(name)")
        let file = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: fixture)) as? [String: Any])
        let message = try XCTUnwrap(file["message"] as? [String: Any])
        let data = try XCTUnwrap(message["data"] as? [String: String])
        var userInfo = Dictionary(uniqueKeysWithValues: data.map { (AnyHashable($0.key), $0.value as Any) })
        let payload = (message["apns"] as? [String: Any])?["payload"] as? [String: Any] ?? [:]
        for (key, value) in payload { userInfo[key] = value }
        return userInfo
    }

    func testTheChallengeTheGatewaySentIsAChallengeAndCarriesNoPreview() throws {
        let data = try recorded("recorded-challenge.json")
        XCTAssertNotNil(data["kr_challenge"])
        XCTAssertThrowsError(try PreviewEnvelope.parse(userInfo: data)) { error in
            XCTAssertEqual(error as? PreviewParseFailure, .absent)
        }
    }

    func testTheDeliveryTheGatewaySentCarriesItsSealedPreviewInTheShapeTheReceiverReads() throws {
        let data = try recorded("recorded-delivery-android.json")
        XCTAssertNil(data["kr_challenge"])
        XCTAssertEqual(data["alert"] as? String, "A KalaReach session is waiting for an answer.")
        let preview = try PreviewEnvelope.parse(userInfo: data)
        XCTAssertEqual(preview.nonce.count, previewNonceLength)
        XCTAssertEqual(preview.routing.recipientKeyID.count, previewKeyIDLength)
        XCTAssertEqual(preview.routing.senderKeyID.count, previewKeyIDLength)
        XCTAssertEqual(preview.routing.sizeBucketBytes, 1024)
        XCTAssertEqual(preview.routing.expiresAtMilliseconds, UInt64(try XCTUnwrap(data["expires_at_ms"] as? String)))
        XCTAssertGreaterThan(preview.ciphertext.count, 1024)
    }

    func testTheDeliveryTheGatewaySentAnIPhoneCarriesTheGenericAlertForTheSystemAndTheSameSealedPreview() throws {
        let info = try recorded("recorded-delivery-ios.json")
        let aps = try XCTUnwrap(info["aps"] as? [String: Any])
        XCTAssertEqual((aps["alert"] as? [String: Any])?["body"] as? String, "A KalaReach session is waiting for an answer.")
        XCTAssertEqual(aps["mutable-content"] as? Int, 1, "the extension is let run")
        let preview = try PreviewEnvelope.parse(userInfo: info)
        XCTAssertEqual(preview.nonce.count, previewNonceLength)
        XCTAssertEqual(preview.routing.sizeBucketBytes, 1024)
        XCTAssertEqual(preview.routing.expiresAtMilliseconds, UInt64(try XCTUnwrap(info["expires_at_ms"] as? String)))
    }
}
