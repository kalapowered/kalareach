//
//  What the notification extension reports back about itself when a device check asks it to.
//
//  A check sends a notification carrying a nonce and the name of the application's private group.
//  The extension answers inside the notification it hands the system: why it showed what it
//  showed, whether it could read the item the check filed in the shared group, and what the
//  keychain said when it tried the private one, which it is not entitled to.
//

#if DEBUG
import Security
import XCTest

final class ExtensionProbeTests: XCTestCase {
    private let nonce = "nonce-1"
    private let group = "TEAM.to.kala.reach"

    private func userInfo(_ extra: [String: Any] = [:]) -> [AnyHashable: Any] {
        var base: [AnyHashable: Any] = ["aps": ["alert": ["body": "A KalaReach session needs attention."]]]
        base["kr_probe_nonce"] = nonce
        base["kr_probe_group"] = group
        for (key, value) in extra { base[key] = value }
        return base
    }

    func testANotificationWithNoNonceIsLeftAlone() {
        let probe = ExtensionProbe(keys: SharedKeyReading.found(ProbeFixture.value(nonce: nonce)), private: PrivateRead(status: errSecItemNotFound, data: nil))
        XCTAssertNil(probe.additions(for: ["aps": ["alert": "x"]], reason: "no_preview"))
    }

    func testTheSharedItemTheCheckFiledIsFoundAndMatches() throws {
        let probe = ExtensionProbe(keys: SharedKeyReading.found(ProbeFixture.value(nonce: nonce)), private: PrivateRead(status: errSecMissingEntitlement, data: nil))
        let added = try XCTUnwrap(probe.additions(for: userInfo(), reason: "no_preview"))
        XCTAssertEqual(added["kr_ext_reason"] as? String, "no_preview")
        XCTAssertEqual(added["kr_ext_shared_match"] as? Bool, true)
        XCTAssertEqual(added["kr_ext_private_data"] as? Bool, false)
        XCTAssertEqual(added["kr_ext_private_status"] as? Int, Int(errSecMissingEntitlement))
    }

    func testAnotherValueUnderTheAccountIsNotAMatch() throws {
        let probe = ExtensionProbe(keys: SharedKeyReading.found(Data([1, 2, 3])), private: PrivateRead(status: errSecItemNotFound, data: nil))
        let added = try XCTUnwrap(probe.additions(for: userInfo(), reason: "no_preview"))
        XCTAssertEqual(added["kr_ext_shared_match"] as? Bool, false)
    }

    func testAnUnreadableSharedItemSaysWhyAndIsNotAMatch() throws {
        let probe = ExtensionProbe(keys: SharedKeyReading.failing(.lockedBeforeFirstUnlock), private: PrivateRead(status: errSecItemNotFound, data: nil))
        let added = try XCTUnwrap(probe.additions(for: userInfo(), reason: "locked_before_first_unlock"))
        XCTAssertEqual(added["kr_ext_shared_match"] as? Bool, false)
        XCTAssertEqual(added["kr_ext_shared_unavailable"] as? String, "lockedBeforeFirstUnlock")
    }

    func testAPrivateItemTheExtensionCouldReadIsReportedAsData() throws {
        // This is the failure the check exists to find: the extension reading what it must not.
        let probe = ExtensionProbe(keys: SharedKeyReading.found(ProbeFixture.value(nonce: nonce)), private: PrivateRead(status: errSecSuccess, data: Data([9])))
        let added = try XCTUnwrap(probe.additions(for: userInfo(), reason: "no_preview"))
        XCTAssertEqual(added["kr_ext_private_data"] as? Bool, true)
    }

    func testTheRecipientAndTheGroupCameFromThePayload() throws {
        let recorder = RecordingPrivateReader()
        let probe = ExtensionProbe(keys: SharedKeyReading.found(ProbeFixture.value(nonce: nonce)), private: recorder)
        _ = probe.additions(for: userInfo(), reason: "no_preview")
        XCTAssertEqual(recorder.asked.count, 1)
        XCTAssertEqual(recorder.asked.first?.group, group)
        XCTAssertEqual(recorder.asked.first?.service, ProbeFixture.privateService)
        XCTAssertEqual(recorder.asked.first?.account, ProbeFixture.account(nonce: nonce))
    }

    func testTheNamesTheExtensionReadsByAreTheOnesTheApplicationWritesUnder() {
        // The extension does not compile the application's key writer, so the names it reads the
        // two fixtures by are written out beside the fixture; these hold them equal to the writer's.
        XCTAssertEqual(ProbeFixture.privateService, StoredKeyPurpose.deviceAuthorisation.rawValue)
        XCTAssertEqual(PreviewKeyLocation.shared.service, StoredKeyPurpose.notificationPreview.rawValue)
    }

    func testANonceWithNoGroupNamedStillAnswersWithoutReadingAGroup() throws {
        let recorder = RecordingPrivateReader()
        let probe = ExtensionProbe(keys: SharedKeyReading.found(ProbeFixture.value(nonce: nonce)), private: recorder)
        var info = userInfo()
        info["kr_probe_group"] = nil
        let added = try XCTUnwrap(probe.additions(for: info, reason: "no_preview"))
        XCTAssertTrue(recorder.asked.isEmpty)
        XCTAssertEqual(added["kr_ext_private_status"] as? Int, Int(errSecParam))
    }
}

/* ---- Doubles --------------------------------------------------------------------------------- */

private enum SharedKeyReading {
    static func found(_ value: Data) -> PreviewKeyReading { Found(value: value) }
    static func failing(_ failure: PreviewKeyUnavailable) -> PreviewKeyReading { Failing(failure: failure) }

    private struct Found: PreviewKeyReading {
        let value: Data
        func key(forRecipient recipientKeyID: Data) throws -> Data { value }
    }

    private struct Failing: PreviewKeyReading {
        let failure: PreviewKeyUnavailable
        func key(forRecipient recipientKeyID: Data) throws -> Data { throw failure }
    }
}

private struct PrivateRead: ProbeKeychainReading {
    let status: OSStatus
    let data: Data?
    func read(group: String, service: String, account: String) -> (status: OSStatus, data: Data?) { (status, data) }
}

private final class RecordingPrivateReader: ProbeKeychainReading {
    private(set) var asked: [(group: String, service: String, account: String)] = []
    func read(group: String, service: String, account: String) -> (status: OSStatus, data: Data?) {
        asked.append((group, service, account))
        return (errSecMissingEntitlement, nil)
    }
}
#endif
