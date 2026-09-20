package to.kala.reach.companion.mobile

import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature

/**
 * A challenge from the host to confirm a sensitive voice action on an unlocked screen.
 */
data class VoiceConfirmationChallenge(
    val confirmationId: ByteArray,
    val action: String,
    val actionDigest: ByteArray,
    val actionId: ByteArray,
    val hostDeviceId: ByteArray,
    val clientDeviceId: ByteArray,
    val expiresAtMillis: Long
) {
    /**
     * The canonical signing input for this challenge under domain `kr-voice/confirm/1`.
     */
    fun signingInput(): ByteArray {
        val domain = "kr-voice/confirm/1".toByteArray(Charsets.UTF_8)
        val actionBytes = action.toByteArray(Charsets.UTF_8)
        val expiresBuf = ByteBuffer.allocate(8).putLong(expiresAtMillis).array()

        val totalLen = domain.size + confirmationId.size + actionBytes.size +
            actionDigest.size + actionId.size + hostDeviceId.size + clientDeviceId.size + expiresBuf.size
        val buf = ByteBuffer.allocate(totalLen)
        buf.put(domain)
        buf.put(confirmationId)
        buf.put(actionBytes)
        buf.put(actionDigest)
        buf.put(actionId)
        buf.put(hostDeviceId)
        buf.put(clientDeviceId)
        buf.put(expiresBuf)
        return buf.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VoiceConfirmationChallenge) return false
        return confirmationId.contentEquals(other.confirmationId) &&
            action == other.action &&
            actionDigest.contentEquals(other.actionDigest) &&
            actionId.contentEquals(other.actionId) &&
            hostDeviceId.contentEquals(other.hostDeviceId) &&
            clientDeviceId.contentEquals(other.clientDeviceId) &&
            expiresAtMillis == other.expiresAtMillis
    }

    override fun hashCode(): Int {
        var result = confirmationId.contentHashCode()
        result = 31 * result + action.hashCode()
        result = 31 * result + actionDigest.contentHashCode()
        result = 31 * result + actionId.contentHashCode()
        result = 31 * result + hostDeviceId.contentHashCode()
        result = 31 * result + clientDeviceId.contentHashCode()
        result = 31 * result + expiresAtMillis.hashCode()
        return result
    }
}

/**
 * The signed proof produced by the unlocked-screen ceremony.
 */
data class VoiceConfirmationProof(
    val challenge: VoiceConfirmationChallenge,
    val signature: ByteArray,
    val signerKeyId: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VoiceConfirmationProof) return false
        return challenge == other.challenge &&
            signature.contentEquals(other.signature) &&
            signerKeyId.contentEquals(other.signerKeyId)
    }

    override fun hashCode(): Int {
        var result = challenge.hashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + signerKeyId.contentHashCode()
        return result
    }
}

/**
 * Why a voice confirmation ceremony failed or was refused.
 */
sealed class VoiceCeremonyRefusal(override val message: String) : Exception(message) {
    object PresenceVerificationFailed :
        VoiceCeremonyRefusal("Owner presence verification on unlocked screen failed or was cancelled")

    object ConfirmationExpired :
        VoiceCeremonyRefusal("Confirmation challenge has expired")

    object ConfirmationMismatch :
        VoiceCeremonyRefusal("Confirmation proof does not match the expected challenge or signer")

    object SigningFailed :
        VoiceCeremonyRefusal("Cryptographic signing of confirmation challenge failed")
}

/**
 * Evaluator for device owner presence (BiometricPrompt with device-credential fallback).
 */
fun interface OwnerPresenceEvaluator {
    fun evaluatePresence(reason: String): Boolean
}

/**
 * Executes the unlocked-screen ceremony and signs the confirmation proof upon owner approval.
 */
class VoiceCeremony(
    private val presenceEvaluator: OwnerPresenceEvaluator
) {
    /**
     * Performs the ceremony: prompts for device owner presence, and signs the challenge if verified.
     */
    fun confirm(
        challenge: VoiceConfirmationChallenge,
        keyPair: KeyPair,
        nowMillis: Long
    ): VoiceConfirmationProof {
        if (nowMillis >= challenge.expiresAtMillis) {
            throw VoiceCeremonyRefusal.ConfirmationExpired
        }

        val reason = "Authorise voice action: ${challenge.action}"
        val verified = presenceEvaluator.evaluatePresence(reason)
        if (!verified) {
            throw VoiceCeremonyRefusal.PresenceVerificationFailed
        }

        return sign(challenge, keyPair)
    }

    /**
     * Signs the confirmation request using the device's authorization key.
     */
    fun sign(
        challenge: VoiceConfirmationChallenge,
        keyPair: KeyPair
    ): VoiceConfirmationProof {
        try {
            val signer = Signature.getInstance("Ed25519")
            signer.initSign(keyPair.private)
            signer.update(challenge.signingInput())
            val signature = signer.sign()

            val md = MessageDigest.getInstance("SHA-256")
            val keyId = md.digest(keyPair.public.encoded)

            return VoiceConfirmationProof(
                challenge = challenge,
                signature = signature,
                signerKeyId = keyId
            )
        } catch (e: Exception) {
            throw VoiceCeremonyRefusal.SigningFailed
        }
    }

    companion object {
        /**
         * Verifies that a signed proof matches the expected plan, action digest, and signer.
         */
        fun verify(
            proof: VoiceConfirmationProof,
            expectedAction: String,
            expectedActionDigest: ByteArray,
            expectedClientDeviceId: ByteArray,
            expectedSignerPublicKey: ByteArray,
            nowMillis: Long
        ): Result<Unit> {
            val challenge = proof.challenge

            if (nowMillis >= challenge.expiresAtMillis) {
                return Result.failure(VoiceCeremonyRefusal.ConfirmationExpired)
            }
            if (challenge.action != expectedAction || !challenge.actionDigest.contentEquals(expectedActionDigest)) {
                return Result.failure(VoiceCeremonyRefusal.ConfirmationMismatch)
            }
            if (!challenge.clientDeviceId.contentEquals(expectedClientDeviceId)) {
                return Result.failure(VoiceCeremonyRefusal.ConfirmationMismatch)
            }

            val md = MessageDigest.getInstance("SHA-256")
            val expectedKeyId = md.digest(expectedSignerPublicKey)
            if (!proof.signerKeyId.contentEquals(expectedKeyId)) {
                return Result.failure(VoiceCeremonyRefusal.ConfirmationMismatch)
            }

            return try {
                val kf = java.security.KeyFactory.getInstance("Ed25519")
                val pubKey = kf.generatePublic(java.security.spec.X509EncodedKeySpec(expectedSignerPublicKey))
                val verifier = Signature.getInstance("Ed25519")
                verifier.initVerify(pubKey)
                verifier.update(challenge.signingInput())
                if (verifier.verify(proof.signature)) {
                    Result.success(Unit)
                } else {
                    Result.failure(VoiceCeremonyRefusal.ConfirmationMismatch)
                }
            } catch (e: Exception) {
                Result.failure(VoiceCeremonyRefusal.ConfirmationMismatch)
            }
        }

        /**
         * Generates an Ed25519 keypair for testing or pairing.
         */
        fun generateKeyPair(): KeyPair {
            val kpg = KeyPairGenerator.getInstance("Ed25519")
            return kpg.generateKeyPair()
        }
    }
}
