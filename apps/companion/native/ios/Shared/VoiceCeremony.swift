//
//  The unlocked-screen ceremony on iOS.
//
//  Section 15 paragraph 8 and section 10 require that sensitive action classes
//  (running commands, applying diffs, answering approvals, closing sessions, and external delivery)
//  cannot be authorized by provider speech alone. A statement from the model that the user
//  confirmed something is content, never authority.
//
//  The ceremony requires user-presence verification on the unlocked screen of the paired device
//  through Apple's LocalAuthentication (`LAContext`). Once presence is verified, the client signs
//  the confirmation over `kr-voice/confirm/1` using the paired device's `authorisation` key.
//

import CryptoKit
import Foundation
import LocalAuthentication

/// A request from the host to confirm a sensitive voice action on an unlocked screen.
public struct VoiceConfirmationChallenge: Equatable, Sendable {
    public let confirmationId: Data
    public let action: String
    public let actionDigest: Data
    public let actionId: Data
    public let hostDeviceId: Data
    public let clientDeviceId: Data
    public let expiresAtMilliseconds: UInt64

    public init(
        confirmationId: Data,
        action: String,
        actionDigest: Data,
        actionId: Data,
        hostDeviceId: Data,
        clientDeviceId: Data,
        expiresAtMilliseconds: UInt64
    ) {
        self.confirmationId = confirmationId
        self.action = action
        self.actionDigest = actionDigest
        self.actionId = actionId
        self.hostDeviceId = hostDeviceId
        self.clientDeviceId = clientDeviceId
        self.expiresAtMilliseconds = expiresAtMilliseconds
    }

    /// The canonical signing input for this challenge under domain `kr-voice/confirm/1`.
    public func signingInput() -> Data {
        var data = Data("kr-voice/confirm/1".utf8)
        data.append(confirmationId)
        data.append(Data(action.utf8))
        data.append(actionDigest)
        data.append(actionId)
        data.append(hostDeviceId)
        data.append(clientDeviceId)
        var expires = expiresAtMilliseconds.bigEndian
        data.append(Data(bytes: &expires, count: MemoryLayout<UInt64>.size))
        return data
    }
}

/// The signed proof produced by the unlocked-screen ceremony.
public struct VoiceConfirmationProof: Equatable, Sendable {
    public let challenge: VoiceConfirmationChallenge
    public let signature: Data
    public let signerKeyId: Data

    public init(
        challenge: VoiceConfirmationChallenge,
        signature: Data,
        signerKeyId: Data
    ) {
        self.challenge = challenge
        self.signature = signature
        self.signerKeyId = signerKeyId
    }
}

/// Why a voice confirmation ceremony failed or was refused.
public enum VoiceCeremonyRefusal: Error, Equatable, Sendable {
    case presenceVerificationFailed
    case confirmationExpired
    case confirmationMismatch
    case signingFailed
}

/// Evaluator protocol for device owner presence (LocalAuthentication).
public protocol OwnerPresenceEvaluating: Sendable {
    func evaluatePresence(reason: String) async -> Bool
}

/// Production implementation using LocalAuthentication `LAContext`.
public struct LocalAuthenticationPresenceEvaluator: OwnerPresenceEvaluating {
    public init() {}

    public func evaluatePresence(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return false
        }
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
        } catch {
            return false
        }
    }
}

/// Executes the unlocked-screen ceremony and signs the confirmation proof upon owner approval.
public struct VoiceCeremony: Sendable {
    public let presenceEvaluator: any OwnerPresenceEvaluating

    public init(presenceEvaluator: any OwnerPresenceEvaluating = LocalAuthenticationPresenceEvaluator()) {
        self.presenceEvaluator = presenceEvaluator
    }

    /// Performs the ceremony: prompts for device owner presence, and signs the challenge if verified.
    public func confirm(
        challenge: VoiceConfirmationChallenge,
        signingKey: Curve25519.Signing.PrivateKey,
        nowMilliseconds: UInt64
    ) async throws -> VoiceConfirmationProof {
        if nowMilliseconds >= challenge.expiresAtMilliseconds {
            throw VoiceCeremonyRefusal.confirmationExpired
        }

        let reason = "Authorise voice action: \(challenge.action)"
        let verified = await presenceEvaluator.evaluatePresence(reason: reason)
        guard verified else {
            throw VoiceCeremonyRefusal.presenceVerificationFailed
        }

        return try sign(challenge: challenge, signingKey: signingKey)
    }

    /// Signs the confirmation without presence prompt (used when presence has already been established).
    public func sign(
        challenge: VoiceConfirmationChallenge,
        signingKey: Curve25519.Signing.PrivateKey
    ) throws -> VoiceConfirmationProof {
        let input = challenge.signingInput()
        guard let signature = try? signingKey.signature(for: input) else {
            throw VoiceCeremonyRefusal.signingFailed
        }

        let signerKeyId = SHA256.hash(data: signingKey.publicKey.rawRepresentation)
        return VoiceConfirmationProof(
            challenge: challenge,
            signature: Data(signature),
            signerKeyId: Data(signerKeyId)
        )
    }

    /// Verifies that a signed proof matches the expected plan and signer.
    public static func verify(
        proof: VoiceConfirmationProof,
        expectedAction: String,
        expectedActionDigest: Data,
        expectedClientDeviceId: Data,
        expectedSignerPublicKey: Curve25519.Signing.PublicKey,
        nowMilliseconds: UInt64
    ) -> Result<Void, VoiceCeremonyRefusal> {
        let challenge = proof.challenge

        if nowMilliseconds >= challenge.expiresAtMilliseconds {
            return .failure(.confirmationExpired)
        }
        if challenge.action != expectedAction || challenge.actionDigest != expectedActionDigest {
            return .failure(.confirmationMismatch)
        }
        if challenge.clientDeviceId != expectedClientDeviceId {
            return .failure(.confirmationMismatch)
        }

        let expectedKeyId = Data(SHA256.hash(data: expectedSignerPublicKey.rawRepresentation))
        if proof.signerKeyId != expectedKeyId {
            return .failure(.confirmationMismatch)
        }

        let input = challenge.signingInput()
        guard expectedSignerPublicKey.isValidSignature(proof.signature, for: input) else {
            return .failure(.confirmationMismatch)
        }

        return .success(())
    }
}
