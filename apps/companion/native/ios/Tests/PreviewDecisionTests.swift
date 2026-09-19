//
//  What the notification extension shows, driven through every case the specification names.
//
//  Section 16 states four conditions under which the generic alert stands. Each one has a test
//  here, and so does the case where a preview is shown, because a rule about when not to reveal
//  something is only meaningful beside the case where revealing is right.
//

import XCTest

final class PreviewDecisionTests: XCTestCase {
    private let now: UInt64 = 1_763_000_000_000
    private let recipient = Data(repeating: 0x91, count: previewKeyIDLength)
    private let sender = Data(repeating: 0x76, count: previewKeyIDLength)

    private func payload(
        expiresAtMilliseconds: UInt64? = nil,
        recipientKeyID: Data? = nil,
        nonceLength: Int = previewNonceLength
    ) -> [AnyHashable: Any] {
        [
            "preview": [
                "nonce": base64URL(Data(repeating: 0x01, count: nonceLength)),
                "ciphertext": base64URL(Data(repeating: 0x02, count: 64)),
                "routing": [
                    "envelope_id": "e-1",
                    "recipient_key_id": base64URL(recipientKeyID ?? recipient),
                    "sender_key_id": base64URL(sender),
                    "expires_at_ms": String(expiresAtMilliseconds ?? (now + 60_000)),
                    "size_bucket_bytes": "1024",
                ],
            ]
        ]
    }

    private func decider(
        keys: PreviewKeyReading,
        opener: PreviewOpening = RefusingOpener(),
        deviceKeyIDs: Set<Data> = []
    ) -> PreviewDecider {
        PreviewDecider(keys: keys, opener: opener, deviceKeyIDs: deviceKeyIDs)
    }

    func testARevealedPreviewReplacesTheAlert() {
        let decision = decider(keys: ProvidingKeys(), opener: OpeningTo("Allow scripts/release.sh?"))
            .decide(userInfo: payload(), nowMilliseconds: now)
        XCTAssertEqual(decision, .reveal("Allow scripts/release.sh?"))
    }

    func testTheGenericAlertStandsWhenNoKeyHasBeenProvisioned() {
        let decision = decider(keys: FailingKeys(.notProvisioned))
            .decide(userInfo: payload(), nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.keyUnavailable))
    }

    func testTheGenericAlertStandsBeforeTheFirstUnlock() {
        let decision = decider(keys: FailingKeys(.lockedBeforeFirstUnlock))
            .decide(userInfo: payload(), nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.lockedBeforeFirstUnlock))
    }

    func testTheGenericAlertStandsWhenDecryptionFails() {
        let decision = decider(keys: ProvidingKeys(), opener: RefusingOpener())
            .decide(userInfo: payload(), nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.decryptionFailed))
    }

    func testTheGenericAlertStandsWhenThisBuildCarriesNoOpener() {
        let decision = decider(keys: ProvidingKeys(), opener: SharedClientPreviewOpener())
            .decide(userInfo: payload(), nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.decryptionFailed))
    }

    func testAPayloadWithNoPreviewIsTheOrdinaryGenericAlert() {
        let decision = decider(keys: ProvidingKeys())
            .decide(userInfo: ["aps": ["alert": "Something needs you"]], nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.noPreview))
    }

    func testAMalformedPreviewIsNeverInterpreted() {
        let decision = decider(keys: ProvidingKeys())
            .decide(userInfo: payload(nonceLength: 12), nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.malformedPreview))
    }

    func testAnExpiredPreviewIsNotOpened() {
        let keys = ProvidingKeys()
        let decision = decider(keys: keys, opener: OpeningTo("secret"))
            .decide(userInfo: payload(expiresAtMilliseconds: now - 1), nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.expired))
        XCTAssertEqual(keys.reads, 0, "an expired preview never reaches the keychain")
    }

    func testAPreviewForAnotherDeviceIsNotOpened() {
        let keys = ProvidingKeys()
        let decision = decider(
            keys: keys,
            opener: OpeningTo("secret"),
            deviceKeyIDs: [recipient]
        ).decide(
            userInfo: payload(recipientKeyID: Data(repeating: 0x33, count: previewKeyIDLength)),
            nowMilliseconds: now
        )
        XCTAssertEqual(decision, .generic(.notForThisDevice))
        XCTAssertEqual(keys.reads, 0)
    }

    func testAnEmptyPlaintextIsNotShownAsAPreview() {
        let decision = decider(keys: ProvidingKeys(), opener: OpeningTo("   "))
            .decide(userInfo: payload(), nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.decryptionFailed))
    }

    func testABuildThatStatesNoSharedGroupHasNoKeyToFind() throws {
        // The group carries a team prefix only the build knows. A build that did not state one
        // must not search its own default group and report the device as having no key.
        let unstated = Bundle(for: PreviewDecisionTests.self)
        XCTAssertNil(PreviewKeyLocation.resolvedGroup(bundle: unstated))

        let decision = decider(keys: FailingKeys(.groupNotConfigured))
            .decide(userInfo: payload(), nowMilliseconds: now)
        XCTAssertEqual(decision, .generic(.keyUnavailable))
    }

    func testTheRoutingIsReadExactlyAsTheProtocolDeclaresIt() throws {
        let envelope = try PreviewEnvelope.parse(userInfo: payload())
        XCTAssertEqual(envelope.routing.envelopeID, "e-1")
        XCTAssertEqual(envelope.routing.recipientKeyID, recipient)
        XCTAssertEqual(envelope.routing.senderKeyID, sender)
        XCTAssertEqual(envelope.routing.sizeBucketBytes, 1024)
        XCTAssertEqual(envelope.nonce.count, previewNonceLength)
    }
}

/// The signing rule, which is the application's half of section 16.
final class SigningGateTests: XCTestCase {
    private let now: UInt64 = 1_763_000_000_000

    private func refusal(_ gate: SigningGate, at moment: UInt64) -> SigningRefusal? {
        do {
            try gate.admit(nowMilliseconds: moment)
            return nil
        } catch let refusal as SigningRefusal {
            return refusal
        } catch {
            return nil
        }
    }

    func testAnUnauthenticatedApplicationSignsNothing() {
        let gate = SigningGate(isMainApplication: true, state: .none)
        XCTAssertEqual(refusal(gate, at: now), .notAuthenticated)
    }

    func testAnAuthenticatedApplicationSigns() {
        let gate = SigningGate(isMainApplication: true, state: .verified(atMilliseconds: now))
        XCTAssertNil(refusal(gate, at: now + 1000))
    }

    func testAnOldAuthenticationIsNotAnAuthentication() {
        let gate = SigningGate(isMainApplication: true, state: .verified(atMilliseconds: now))
        XCTAssertEqual(
            refusal(gate, at: now + authenticationLifetimeMilliseconds + 1),
            .authenticationExpired
        )
    }

    func testAnExtensionNeverSigns() {
        let gate = SigningGate(isMainApplication: false, state: .verified(atMilliseconds: now))
        XCTAssertEqual(refusal(gate, at: now), .notTheApplication)
    }
}

/* ---- Doubles --------------------------------------------------------------------------------- */

private final class ProvidingKeys: PreviewKeyReading {
    private(set) var reads = 0
    func key(forRecipient recipientKeyID: Data) throws -> Data {
        reads += 1
        return Data(repeating: 0x44, count: 32)
    }
}

private struct FailingKeys: PreviewKeyReading {
    let failure: PreviewKeyUnavailable
    init(_ failure: PreviewKeyUnavailable) { self.failure = failure }
    func key(forRecipient recipientKeyID: Data) throws -> Data { throw failure }
}

private struct RefusingOpener: PreviewOpening {
    func open(envelope: PreviewEnvelope, key: Data) throws -> String {
        throw PreviewOpenFailure.authentication
    }
}

private struct OpeningTo: PreviewOpening {
    let text: String
    init(_ text: String) { self.text = text }
    func open(envelope: PreviewEnvelope, key: Data) throws -> String { text }
}

private func base64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
