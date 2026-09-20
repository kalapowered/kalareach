//
//  Tests for the unlocked-screen ceremony on iOS.
//
//  KR-REQ-15.13: an action that needs a confirmation on the unlocked screen does not proceed without one.
//  The signature must cover the action hash, a confirmation for one action must not authorise another,
//  and no provider text or model statement can produce one.
//

import CryptoKit
import XCTest

private struct MockPresenceEvaluator: OwnerPresenceEvaluating {
    let shouldVerify: Bool

    func evaluatePresence(reason: String) async -> Bool {
        shouldVerify
    }
}

final class VoiceCeremonyTests: XCTestCase {
    private let confirmationId = Data(repeating: 0x11, count: 16)
    private let voiceSessionId = Data(repeating: 0x12, count: 16)
    private let actionId = Data(repeating: 0x22, count: 16)
    private let hostDeviceId = Data(repeating: 0x33, count: 16)
    private let clientDeviceId = Data(repeating: 0x44, count: 16)
    private let nonce = Data(repeating: 0x55, count: 32)
    private let actionDigest = Data(repeating: 0xaa, count: 32)
    private let nowMs: UInt64 = 1_000_000

    private func sampleChallenge(
        action: String = "apply_diff",
        digest: Data? = nil,
        expiresAt: UInt64? = nil
    ) -> VoiceConfirmationChallenge {
        VoiceConfirmationChallenge(
            confirmationId: confirmationId,
            voiceSessionId: voiceSessionId,
            action: action,
            actionDigest: digest ?? actionDigest,
            actionId: actionId,
            hostDeviceId: hostDeviceId,
            clientDeviceId: clientDeviceId,
            nonce: nonce,
            expiresAtMilliseconds: expiresAt ?? (nowMs + 120_000)
        )
    }

    /// Tests that the ceremony verifies owner presence and produces a valid signature over the action digest.
    func testSignatureCoversActionHashAndVerifies() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let challenge = sampleChallenge()
        let ceremony = VoiceCeremony(presenceEvaluator: MockPresenceEvaluator(shouldVerify: true))

        let proof = try await ceremony.confirm(
            challenge: challenge,
            signingKey: key,
            nowMilliseconds: nowMs
        )

        let result = VoiceCeremony.verify(
            proof: proof,
            expectedAction: "apply_diff",
            expectedActionDigest: actionDigest,
            expectedClientDeviceId: clientDeviceId,
            expectedSignerPublicKey: key.publicKey,
            nowMilliseconds: nowMs + 1000
        )
        switch result {
        case .success: break
        case .failure(let err): XCTFail("Expected success, got \(err)")
        }
    }

    /// Tampering with the action digest causes verification failure.
    func testTamperedActionDigestIsRefused() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let challenge = sampleChallenge()
        let ceremony = VoiceCeremony(presenceEvaluator: MockPresenceEvaluator(shouldVerify: true))

        let proof = try await ceremony.confirm(
            challenge: challenge,
            signingKey: key,
            nowMilliseconds: nowMs
        )

        var badDigest = actionDigest
        badDigest[0] ^= 0xff

        let result = VoiceCeremony.verify(
            proof: proof,
            expectedAction: "apply_diff",
            expectedActionDigest: badDigest,
            expectedClientDeviceId: clientDeviceId,
            expectedSignerPublicKey: key.publicKey,
            nowMilliseconds: nowMs + 1000
        )
        switch result {
        case .success: XCTFail("Expected failure")
        case .failure(let err): XCTAssertEqual(err, .confirmationMismatch)
        }
    }

    /// Confirmation for one action cannot authorize another action.
    func testConfirmationForOneActionDoesNotAuthorizeAnother() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let challenge = sampleChallenge(action: "apply_diff")
        let ceremony = VoiceCeremony(presenceEvaluator: MockPresenceEvaluator(shouldVerify: true))

        let proof = try await ceremony.confirm(
            challenge: challenge,
            signingKey: key,
            nowMilliseconds: nowMs
        )

        let result = VoiceCeremony.verify(
            proof: proof,
            expectedAction: "shell_input",
            expectedActionDigest: actionDigest,
            expectedClientDeviceId: clientDeviceId,
            expectedSignerPublicKey: key.publicKey,
            nowMilliseconds: nowMs + 1000
        )
        switch result {
        case .success: XCTFail("Expected failure")
        case .failure(let err): XCTAssertEqual(err, .confirmationMismatch)
        }
    }

    /// Model speech or provider text cannot produce a valid confirmation proof without the paired key.
    func testProviderTextCannotProduceConfirmationProof() async throws {
        let pairedKey = Curve25519.Signing.PrivateKey()
        let imposterKey = Curve25519.Signing.PrivateKey()
        let challenge = sampleChallenge()
        let ceremony = VoiceCeremony(presenceEvaluator: MockPresenceEvaluator(shouldVerify: true))

        // An imposter attempting to sign a confirmation challenge
        let imposterProof = try await ceremony.confirm(
            challenge: challenge,
            signingKey: imposterKey,
            nowMilliseconds: nowMs
        )

        // Verifying against the paired device's key fails
        let result = VoiceCeremony.verify(
            proof: imposterProof,
            expectedAction: "apply_diff",
            expectedActionDigest: actionDigest,
            expectedClientDeviceId: clientDeviceId,
            expectedSignerPublicKey: pairedKey.publicKey,
            nowMilliseconds: nowMs + 1000
        )
        switch result {
        case .success: XCTFail("Expected failure")
        case .failure(let err): XCTAssertEqual(err, .confirmationMismatch)
        }
    }

    /// When user presence verification fails (e.g. user cancels Face ID / passcode), ceremony refuses.
    func testUnverifiedPresenceRefusesSigning() async {
        let key = Curve25519.Signing.PrivateKey()
        let challenge = sampleChallenge()
        let ceremony = VoiceCeremony(presenceEvaluator: MockPresenceEvaluator(shouldVerify: false))

        do {
            _ = try await ceremony.confirm(
                challenge: challenge,
                signingKey: key,
                nowMilliseconds: nowMs
            )
            XCTFail("Should have thrown presenceVerificationFailed")
        } catch let refusal as VoiceCeremonyRefusal {
            XCTAssertEqual(refusal, .presenceVerificationFailed)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    /// Expired challenge is refused.
    func testExpiredChallengeIsRefused() async {
        let key = Curve25519.Signing.PrivateKey()
        let challenge = sampleChallenge(expiresAt: nowMs - 1)
        let ceremony = VoiceCeremony(presenceEvaluator: MockPresenceEvaluator(shouldVerify: true))

        do {
            _ = try await ceremony.confirm(
                challenge: challenge,
                signingKey: key,
                nowMilliseconds: nowMs
            )
            XCTFail("Should have thrown confirmationExpired")
        } catch let refusal as VoiceCeremonyRefusal {
            XCTAssertEqual(refusal, .confirmationExpired)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    // MARK: - The cross-language vector

    /// The exact bytes the host signs, for one fixed challenge.
    ///
    /// The same two constants are asserted by the desktop ceremony tests, against the shared
    /// protocol's own encoder, and by the Android ceremony tests. A client that signs anything else
    /// produces proofs the host rejects, and no test of this client alone would notice.
    func testSigningInputMatchesTheCrossLanguageVector() {
        let challenge = VoiceConfirmationChallenge(
            confirmationId: Data(repeating: 0x11, count: 16),
            voiceSessionId: Data(repeating: 0x22, count: 16),
            action: "apply_diff",
            actionDigest: Data(repeating: 0x33, count: 32),
            actionId: Data(repeating: 0x44, count: 16),
            hostDeviceId: Data(repeating: 0x55, count: 16),
            clientDeviceId: Data(repeating: 0x66, count: 16),
            nonce: Data(repeating: 0x77, count: 32),
            expiresAtMilliseconds: 1_700_000_000_000
        )

        XCTAssertEqual(hexadecimal(challenge.signingInput()), Self.signingInputVector)
    }

    /// The identifier the host derives for the key that signs a proof.
    func testSignerKeyIdentifierMatchesTheCrossLanguageVector() {
        let identifier = authorisationKeyId(rawPublicKey: Data(repeating: 0x88, count: 32))
        XCTAssertEqual(hexadecimal(identifier), Self.signerKeyIdVector)
    }

    private func hexadecimal(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static let signingInputVector = "82726b722d766f6963652f636f6e6669726d2f31a9656e6f6e6365582077777777777777777777777777777777777777"
        + "7777777777777777777777777766616374696f6e6a6170706c795f6469666669616374696f6e5f696450444444444444"
        + "44444444444444444444696465766963655f696450666666666666666666666666666666666d616374696f6e5f646967"
        + "657374582033333333333333333333333333333333333333333333333333333333333333336d657870697265735f6174"
        + "5f6d731b0000018bcfe568006e686f73745f6465766963655f696450555555555555555555555555555555556f636f6e"
        + "6669726d6174696f6e5f6964501111111111111111111111111111111170766f6963655f73657373696f6e5f69645022"
        + "222222222222222222222222222222"
    private static let signerKeyIdVector = "a1e1283a5a7d9396772f55cfbd0867b9836c583a4381dd3f70a7a78afd9dec7f"
}
