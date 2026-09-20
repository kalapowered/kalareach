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

/// The deterministic encoding the host signs and verifies.
///
/// The host builds its signing input from canonical CBOR, so a client that concatenates fields in
/// its own order produces a signature over different bytes and every proof it makes is rejected.
/// This is that encoding, restricted to the four shapes a confirmation uses: an unsigned integer, a
/// byte string, a text string and a map whose keys are ordered shortest first and then by their
/// bytes.
enum CanonicalCbor {
    case unsigned(UInt64)
    case bytes(Data)
    case text(String)
    indirect case array([CanonicalCbor])
    indirect case map([(String, CanonicalCbor)])

    /// The canonical bytes of this value.
    func encoded() -> Data {
        switch self {
        case let .unsigned(value):
            return Self.head(major: 0, argument: value)
        case let .bytes(value):
            return Self.head(major: 2, argument: UInt64(value.count)) + value
        case let .text(value):
            let utf8 = Data(value.utf8)
            return Self.head(major: 3, argument: UInt64(utf8.count)) + utf8
        case let .array(items):
            return items.reduce(into: Self.head(major: 4, argument: UInt64(items.count))) {
                $0 += $1.encoded()
            }
        case let .map(entries):
            // Shortest key first, then by the key's own bytes. The host orders its maps this way,
            // and a map in any other order is a different document.
            let ordered = entries.sorted { left, right in
                let a = Array(left.0.utf8)
                let b = Array(right.0.utf8)
                if a.count != b.count { return a.count < b.count }
                return a.lexicographicallyPrecedes(b)
            }
            var out = Self.head(major: 5, argument: UInt64(ordered.count))
            for (key, value) in ordered {
                out += CanonicalCbor.text(key).encoded()
                out += value.encoded()
            }
            return out
        }
    }

    /// The major type and its argument, in the shortest form that holds the argument.
    private static func head(major: UInt8, argument: UInt64) -> Data {
        let prefix = major << 5
        switch argument {
        case ..<24:
            return Data([prefix | UInt8(argument)])
        case ..<0x100:
            return Data([prefix | 24, UInt8(argument)])
        case ..<0x1_0000:
            return Data([prefix | 25]) + be(argument, bytes: 2)
        case ..<0x1_0000_0000:
            return Data([prefix | 26]) + be(argument, bytes: 4)
        default:
            return Data([prefix | 27]) + be(argument, bytes: 8)
        }
    }

    private static func be(_ value: UInt64, bytes count: Int) -> Data {
        var out = Data(capacity: count)
        for shift in stride(from: (count - 1) * 8, through: 0, by: -8) {
            out.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
        return out
    }
}

/// The domain the confirmation signature is bound to.
let voiceConfirmDomain = "kr-voice/confirm/1"

/// The domain a key identifier is derived under, and the purpose of the key that signs a proof.
let keyIdDomain = "kr-key-id/1"
let authorisationKeyPurpose = "authorisation"

/// `SHA256(CBOR(["kr-key-id/1", purpose, key]))` over the raw 32-byte public key.
///
/// The host derives the identifier from the key a caller presents rather than believing a claimed
/// one, so the same bytes under two purposes name two different keys. A digest of the key on its
/// own would name neither.
func authorisationKeyId(rawPublicKey: Data) -> Data {
    let value = CanonicalCbor.array([
        .text(keyIdDomain),
        .text(authorisationKeyPurpose),
        .bytes(rawPublicKey)
    ])
    return Data(SHA256.hash(data: value.encoded()))
}

/// A request from the host to confirm a sensitive voice action on an unlocked screen.
public struct VoiceConfirmationChallenge: Equatable, Sendable {
    public let confirmationId: Data
    public let voiceSessionId: Data
    public let action: String
    public let actionDigest: Data
    public let actionId: Data
    public let hostDeviceId: Data
    public let clientDeviceId: Data
    public let nonce: Data
    public let expiresAtMilliseconds: UInt64

    public init(
        confirmationId: Data,
        voiceSessionId: Data,
        action: String,
        actionDigest: Data,
        actionId: Data,
        hostDeviceId: Data,
        clientDeviceId: Data,
        nonce: Data,
        expiresAtMilliseconds: UInt64
    ) {
        self.confirmationId = confirmationId
        self.voiceSessionId = voiceSessionId
        self.action = action
        self.actionDigest = actionDigest
        self.actionId = actionId
        self.hostDeviceId = hostDeviceId
        self.clientDeviceId = clientDeviceId
        self.nonce = nonce
        self.expiresAtMilliseconds = expiresAtMilliseconds
    }

    /// The exact bytes the host signs and verifies: `CBOR(["kr-voice/confirm/1", request])`.
    ///
    /// The field names are the host's own, because the host's map is what is hashed. A cross
    /// language vector in `VoiceCeremonyTests` holds these bytes to the ones the shared protocol
    /// produces for the same challenge.
    public func signingInput() -> Data {
        CanonicalCbor.array([
            .text(voiceConfirmDomain),
            .map([
                ("confirmation_id", .bytes(confirmationId)),
                ("voice_session_id", .bytes(voiceSessionId)),
                ("action", .text(action)),
                ("action_digest", .bytes(actionDigest)),
                ("action_id", .bytes(actionId)),
                ("host_device_id", .bytes(hostDeviceId)),
                ("device_id", .bytes(clientDeviceId)),
                ("nonce", .bytes(nonce)),
                ("expires_at_ms", .unsigned(expiresAtMilliseconds))
            ])
        ]).encoded()
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

        return VoiceConfirmationProof(
            challenge: challenge,
            signature: Data(signature),
            signerKeyId: authorisationKeyId(rawPublicKey: signingKey.publicKey.rawRepresentation)
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

        let expectedKeyId = authorisationKeyId(rawPublicKey: expectedSignerPublicKey.rawRepresentation)
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
