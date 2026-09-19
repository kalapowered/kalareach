package to.kala.reach.companion.mobile

/**
 * What a notification shows, and why.
 *
 * The same decision the iOS extension makes, in the same order and for the same reasons.
 * Everything that can be decided without the key is decided first, so a device that has not been
 * unlocked does not go looking in a keystore it cannot read, and a preview addressed to another
 * device is never opened against a key it was not sealed to.
 *
 * The generic alert is never replaced by anything this decision is unsure of.
 */

/** What was decided. */
sealed interface PreviewDecision {
    /** The decrypted text, which replaces the alert body. */
    data class Reveal(val text: String) : PreviewDecision

    /** The generic alert the message already carried, with the reason it stands. */
    data class Generic(val reason: GenericReason) : PreviewDecision
}

/** Why the generic alert stands. */
enum class GenericReason(val wireName: String) {
    NO_PREVIEW("no_preview"),
    MALFORMED_PREVIEW("malformed_preview"),
    KEY_UNAVAILABLE("key_unavailable"),
    LOCKED_BEFORE_FIRST_UNLOCK("locked_before_first_unlock"),
    NOT_FOR_THIS_DEVICE("not_for_this_device"),
    EXPIRED("expired"),
    DECRYPTION_FAILED("decryption_failed"),
    TIMED_OUT("timed_out")
}

/** Why the preview key is not available. */
sealed interface PreviewKeyUnavailable {
    object NotProvisioned : PreviewKeyUnavailable

    /** The device has not been unlocked since it started, so protected material is unreadable. */
    object LockedBeforeFirstUnlock : PreviewKeyUnavailable

    data class Refused(val detail: String) : PreviewKeyUnavailable
}

/** The key was not available, carried as a failure. */
class PreviewKeyUnavailableException(val unavailable: PreviewKeyUnavailable) :
    Exception(unavailable.toString())

/** Reads the limited preview key. */
fun interface PreviewKeyReading {
    /** The key for one recipient, or the reason there is none. */
    fun key(recipientKeyId: ByteArray): Result<ByteArray>
}

/** Opens a sealed preview. */
fun interface PreviewOpening {
    /** The plaintext, or a failure when the ciphertext does not authenticate. */
    fun open(envelope: PreviewEnvelope, key: ByteArray): Result<String>
}

/** The whole decision, from the message's data to what is shown. */
class PreviewDecider(
    private val keys: PreviewKeyReading,
    private val opener: PreviewOpening,
    /** The key identifiers this device holds. Empty means the device has not been told. */
    private val deviceKeyIds: Set<String> = emptySet()
) {
    /** Decides what one message shows. */
    fun decide(data: Map<String, String>, nowMillis: Long): PreviewDecision {
        val envelope =
            when (val parsed = PreviewEnvelope.parse(data)) {
                is ParsedPreview.Absent -> return PreviewDecision.Generic(GenericReason.NO_PREVIEW)
                is ParsedPreview.Malformed ->
                    return PreviewDecision.Generic(GenericReason.MALFORMED_PREVIEW)
                is ParsedPreview.Sealed -> parsed.envelope
            }

        if (!envelope.isLive(nowMillis)) {
            return PreviewDecision.Generic(GenericReason.EXPIRED)
        }
        val recipient = envelope.routing.recipientKeyId.joinToString("") { "%02x".format(it) }
        if (deviceKeyIds.isNotEmpty() && recipient !in deviceKeyIds) {
            return PreviewDecision.Generic(GenericReason.NOT_FOR_THIS_DEVICE)
        }

        val key =
            keys.key(envelope.routing.recipientKeyId).getOrElse { failure ->
                val unavailable = (failure as? PreviewKeyUnavailableException)?.unavailable
                return PreviewDecision.Generic(
                    if (unavailable is PreviewKeyUnavailable.LockedBeforeFirstUnlock) {
                        GenericReason.LOCKED_BEFORE_FIRST_UNLOCK
                    } else {
                        GenericReason.KEY_UNAVAILABLE
                    }
                )
            }

        val text =
            opener.open(envelope, key).getOrElse {
                return PreviewDecision.Generic(GenericReason.DECRYPTION_FAILED)
            }
        val trimmed = text.trim()
        // An envelope that opens to nothing is not a preview. The alert the host chose stands.
        return if (trimmed.isEmpty()) {
            PreviewDecision.Generic(GenericReason.DECRYPTION_FAILED)
        } else {
            PreviewDecision.Reveal(trimmed)
        }
    }
}

/**
 * Opening a sealed preview.
 *
 * The construction is the shared client's, and its implementation lives in the native client
 * library. Until this process links that primitive there is nothing here that can open an
 * envelope, and the honest answer is to say so: the decision then shows the generic alert, which
 * is exactly what the specification asks for when a preview cannot be opened. A second
 * implementation of one sealing construction is how two implementations come to disagree.
 */
object SharedClientPreviewOpener : PreviewOpening {
    override fun open(envelope: PreviewEnvelope, key: ByteArray): Result<String> =
        Result.failure(UnsupportedOperationException("this build carries no preview opener"))
}
