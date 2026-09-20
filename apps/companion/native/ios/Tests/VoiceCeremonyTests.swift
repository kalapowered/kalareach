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
    private let actionId = Data(repeating: 0x22, count: 16)
    private let hostDeviceId = Data(repeating: 0x33, count: 16)
    private let clientDeviceId = Data(repeating: 0x44, count: 16)
    private let actionDigest = Data(repeating: 0xaa, count: 32)
    private let nowMs: UInt64 = 1_000_000

    private func sampleChallenge(
        action: String = "apply_diff",
        digest: Data? = nil,
        expiresAt: UInt64? = nil
    ) -> VoiceConfirmationChallenge {
        VoiceConfirmationChallenge(
            confirmationId: confirmationId,
            action: action,
            actionDigest: digest ?? actionDigest,
            actionId: actionId,
            hostDeviceId: hostDeviceId,
            clientDeviceId: clientDeviceId,
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
}
