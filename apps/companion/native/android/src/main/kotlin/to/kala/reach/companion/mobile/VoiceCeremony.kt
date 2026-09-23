package to.kala.reach.companion.mobile

import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature

/**
 * The deterministic encoding the host signs and verifies.
 *
 * The host builds its signing input from canonical CBOR, so a client that concatenates fields in
 * its own order signs different bytes and every proof it makes is rejected. This is that encoding,
 * restricted to the four shapes a confirmation uses: an unsigned integer, a byte string, a text
 * string, and a map whose keys are ordered shortest first and then by their own bytes.
 */
sealed class CanonicalCbor {
    /**
     * An unsigned integer, over the whole range CBOR's major type 0 carries. Unsigned by its type,
     * so a negative value cannot be written as one.
     */
    data class Unsigned(val value: ULong) : CanonicalCbor()

    data class Bytes(val value: ByteArray) : CanonicalCbor() {
        override fun equals(other: Any?): Boolean =
            this === other || (other is Bytes && value.contentEquals(other.value))

        override fun hashCode(): Int = value.contentHashCode()
    }

    data class Text(val value: String) : CanonicalCbor()

    data class Arr(val items: List<CanonicalCbor>) : CanonicalCbor()

    data class Map(val entries: List<Pair<String, CanonicalCbor>>) : CanonicalCbor()

    /** The canonical bytes of this value. */
    fun encoded(): ByteArray {
        val out = ByteArrayOutputStream()
        write(out)
        return out.toByteArray()
    }

    internal fun write(out: ByteArrayOutputStream) {
        when (this) {
            is Unsigned -> out.write(head(0, value))
            is Bytes -> {
                out.write(head(2, value.size.toULong()))
                out.write(value)
            }
            is Text -> {
                val utf8 = value.toByteArray(Charsets.UTF_8)
                out.write(head(3, utf8.size.toULong()))
                out.write(utf8)
            }
            is Arr -> {
                out.write(head(4, items.size.toULong()))
                items.forEach { it.write(out) }
            }
            is Map -> {
                // Shortest key first, then by the key's own bytes: the host's map order, and a map
                // in any other order is a different document.
                val ordered = entries.sortedWith(
                    compareBy<Pair<String, CanonicalCbor>> { it.first.toByteArray(Charsets.UTF_8).size }
                        .thenComparator { left, right ->
                            val a = left.first.toByteArray(Charsets.UTF_8)
                            val b = right.first.toByteArray(Charsets.UTF_8)
                            var index = 0
                            while (index < a.size && index < b.size) {
                                val difference = (a[index].toInt() and 0xff) - (b[index].toInt() and 0xff)
                                if (difference != 0) return@thenComparator difference
                                index += 1
                            }
                            a.size - b.size
                        }
                )
                out.write(head(5, ordered.size.toULong()))
                for ((key, value) in ordered) {
                    Text(key).write(out)
                    value.write(out)
                }
            }
        }
    }

    private fun head(major: Int, argument: ULong): ByteArray {
        val prefix = (major shl 5)
        return when {
            argument < 24uL -> byteArrayOf((prefix or argument.toInt()).toByte())
            argument < 0x100uL -> byteArrayOf((prefix or 24).toByte(), argument.toByte())
            argument < 0x10000uL -> byteArrayOf((prefix or 25).toByte()) + bigEndian(argument, 2)
            argument < 0x100000000uL -> byteArrayOf((prefix or 26).toByte()) + bigEndian(argument, 4)
            else -> byteArrayOf((prefix or 27).toByte()) + bigEndian(argument, 8)
        }
    }

    private fun bigEndian(value: ULong, count: Int): ByteArray =
        ByteArray(count) { index -> (value shr ((count - 1 - index) * 8)).toByte() }
}

/** The domain a voice confirmation signature is bound to. */
const val VOICE_CONFIRM_DOMAIN = "kr-voice/confirm/1"

/** The domain a key identifier is derived under, and the purpose of the key that signs a proof. */
const val KEY_ID_DOMAIN = "kr-key-id/1"
const val AUTHORISATION_KEY_PURPOSE = "authorisation"

/**
 * `SHA256(CBOR(["kr-key-id/1", purpose, key]))` over the raw 32-byte public key.
 *
 * The host derives the identifier from the key a caller presents rather than believing a claimed
 * one, and the purpose is inside the hash, so the same bytes under two purposes name two different
 * keys. A digest of the key's X.509 encoding names neither.
 */
fun authorisationKeyId(rawPublicKey: ByteArray): ByteArray {
    val value = CanonicalCbor.Arr(
        listOf(
            CanonicalCbor.Text(KEY_ID_DOMAIN),
            CanonicalCbor.Text(AUTHORISATION_KEY_PURPOSE),
            CanonicalCbor.Bytes(rawPublicKey)
        )
    )
    return MessageDigest.getInstance("SHA-256").digest(value.encoded())
}

/**
 * The raw 32 bytes of an Ed25519 public key, taken out of its X.509 `SubjectPublicKeyInfo`.
 *
 * Java hands back the encoded form; the host names the key by its raw bytes.
 */
fun rawEd25519PublicKey(encoded: ByteArray): ByteArray =
    if (encoded.size >= 32) encoded.copyOfRange(encoded.size - 32, encoded.size) else encoded

/**
 * A challenge from the host to confirm a sensitive voice action on an unlocked screen.
 */
data class VoiceConfirmationChallenge(
    val confirmationId: ByteArray,
    val voiceSessionId: ByteArray,
    val action: String,
    val actionDigest: ByteArray,
    val actionId: ByteArray,
    val hostDeviceId: ByteArray,
    val clientDeviceId: ByteArray,
    val nonce: ByteArray,
    val expiresAtMillis: Long
) {
    init {
        // The host writes this as an unsigned count of milliseconds since the epoch.
        require(expiresAtMillis >= 0) { "a challenge expires at a moment after the epoch" }
    }

    /**
     * The exact bytes the host signs and verifies: `CBOR(["kr-voice/confirm/1", request])`.
     *
     * The field names are the host's own, because the host's map is what is hashed. A cross
     * language vector in `VoiceCeremonyTest` holds these bytes to the ones the shared protocol
     * produces for the same challenge.
     */
    fun signingInput(): ByteArray =
        CanonicalCbor.Arr(
            listOf(
                CanonicalCbor.Text(VOICE_CONFIRM_DOMAIN),
                CanonicalCbor.Map(
                    listOf(
                        "confirmation_id" to CanonicalCbor.Bytes(confirmationId),
                        "voice_session_id" to CanonicalCbor.Bytes(voiceSessionId),
                        "action" to CanonicalCbor.Text(action),
                        "action_digest" to CanonicalCbor.Bytes(actionDigest),
                        "action_id" to CanonicalCbor.Bytes(actionId),
                        "host_device_id" to CanonicalCbor.Bytes(hostDeviceId),
                        "device_id" to CanonicalCbor.Bytes(clientDeviceId),
                        "nonce" to CanonicalCbor.Bytes(nonce),
                        "expires_at_ms" to CanonicalCbor.Unsigned(expiresAtMillis.toULong())
                    )
                )
            )
        ).encoded()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VoiceConfirmationChallenge) return false
        return confirmationId.contentEquals(other.confirmationId) &&
            voiceSessionId.contentEquals(other.voiceSessionId) &&
            action == other.action &&
            actionDigest.contentEquals(other.actionDigest) &&
            actionId.contentEquals(other.actionId) &&
            hostDeviceId.contentEquals(other.hostDeviceId) &&
            clientDeviceId.contentEquals(other.clientDeviceId) &&
            nonce.contentEquals(other.nonce) &&
            expiresAtMillis == other.expiresAtMillis
    }

    override fun hashCode(): Int {
        var result = confirmationId.contentHashCode()
        result = 31 * result + voiceSessionId.contentHashCode()
        result = 31 * result + action.hashCode()
        result = 31 * result + actionDigest.contentHashCode()
        result = 31 * result + actionId.contentHashCode()
        result = 31 * result + hostDeviceId.contentHashCode()
        result = 31 * result + clientDeviceId.contentHashCode()
        result = 31 * result + nonce.contentHashCode()
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

            return VoiceConfirmationProof(
                challenge = challenge,
                signature = signature,
                signerKeyId = authorisationKeyId(rawEd25519PublicKey(keyPair.public.encoded))
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

            val expectedKeyId = authorisationKeyId(rawEd25519PublicKey(expectedSignerPublicKey))
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
