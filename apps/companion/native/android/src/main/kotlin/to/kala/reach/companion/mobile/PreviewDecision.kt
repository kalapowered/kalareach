package to.kala.reach.companion.mobile

import org.json.JSONException
import org.json.JSONObject

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
    TIMED_OUT("timed_out"),

    /** No key is filed for the host the preview says it came from: previews are off for it. */
    SENDER_UNKNOWN("sender_unknown"),

    /** The preview opened, authenticated, and had nothing to show. */
    EMPTY_PREVIEW("empty_preview")
}

/** Why a preview key is not available. */
sealed interface PreviewKeyUnavailable {
    object NotProvisioned : PreviewKeyUnavailable

    /** The device has not been unlocked since it started, so protected material is unreadable. */
    object LockedBeforeFirstUnlock : PreviewKeyUnavailable

    data class Refused(val detail: String) : PreviewKeyUnavailable
}

/** The key was not available, carried as a failure. */
class PreviewKeyUnavailableException(val unavailable: PreviewKeyUnavailable) :
    Exception(unavailable.toString())

/**
 * Reads the keys a receiver may open a preview with: this device's own preview seed, and the public
 * key of each host that may seal one to it. A read of either fails the same way before the first
 * unlock.
 */
interface PreviewKeyReading {
    /**
     * The seed for one recipient key identifier, or the reason there is none. The array is the
     * caller's own copy, which it clears when it has used it.
     */
    fun recipientSeed(recipientKeyId: ByteArray): Result<ByteArray>

    /** The public key for one sender key identifier, or the reason there is none. */
    fun senderKey(senderKeyId: ByteArray): Result<ByteArray>
}

/** What opening a sealed preview came to. */
sealed interface PreviewOpened {
    /** The text the host sealed to show. */
    data class Text(val text: String) : PreviewOpened

    /** The preview was refused, for the reason the opener names (never for any of its content). */
    data class Refused(val reason: String) : PreviewOpened
}

/** Opens a sealed preview. */
fun interface PreviewOpening {
    /**
     * Opens `preview`, the text of the sealed envelope as the gateway sent it, with this device's
     * seed and the sender's public key. `alert` is the generic alert the message is shown with,
     * which the sealed preview repeats and which has to match.
     */
    fun open(
        preview: String,
        alert: String,
        seed: ByteArray,
        senderKey: ByteArray,
        nowMillis: Long
    ): PreviewOpened
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

        // A host this device holds no key for is one whose previews are off here, or one it never
        // asked for them: nothing it sealed is opened. It is asked first, since a phone whose every
        // host has previews off holds no seed either, and the reason is then this one.
        val senderKey =
            keys.senderKey(envelope.routing.senderKeyId).getOrElse { failure ->
                return PreviewDecision.Generic(unavailable(failure, GenericReason.SENDER_UNKNOWN))
            }
        val seed =
            keys.recipientSeed(envelope.routing.recipientKeyId).getOrElse { failure ->
                return PreviewDecision.Generic(unavailable(failure, GenericReason.KEY_UNAVAILABLE))
            }

        // The opener is the Rust library, reached through JNI. A library that does not load, or one
        // that fails or panics, leaves the generic alert and not a message that is lost. The copy of
        // the seed this call was handed is cleared when the call ends; the keys it was read from
        // are held for the one message only.
        val opened =
            try {
                opener.open(
                    preview = data.getValue("preview"),
                    alert = data["alert"].orEmpty(),
                    seed = seed,
                    senderKey = senderKey,
                    nowMillis = nowMillis
                )
            } catch (failure: LinkageError) {
                PreviewOpened.Refused("library")
            } catch (failure: RuntimeException) {
                PreviewOpened.Refused("library")
            } finally {
                seed.fill(0)
            }
        return when (opened) {
            is PreviewOpened.Refused -> PreviewDecision.Generic(refusal(opened.reason))
            is PreviewOpened.Text -> {
                val trimmed = opened.text.trim()
                // An envelope that opens to nothing is not a preview. The alert the host chose stands.
                if (trimmed.isEmpty()) {
                    PreviewDecision.Generic(GenericReason.EMPTY_PREVIEW)
                } else {
                    PreviewDecision.Reveal(trimmed)
                }
            }
        }
    }

    /** Why a key could not be had: the lock is its own reason; anything else is `otherwise`. */
    private fun unavailable(failure: Throwable, otherwise: GenericReason): GenericReason {
        val unavailable = (failure as? PreviewKeyUnavailableException)?.unavailable
        return when (unavailable) {
            is PreviewKeyUnavailable.LockedBeforeFirstUnlock ->
                GenericReason.LOCKED_BEFORE_FIRST_UNLOCK
            is PreviewKeyUnavailable.NotProvisioned -> otherwise
            else -> GenericReason.KEY_UNAVAILABLE
        }
    }

    /** The reason the generic alert stands for a refusal the opener named. */
    private fun refusal(reason: String): GenericReason =
        when (reason) {
            "expired" -> GenericReason.EXPIRED
            "empty_preview" -> GenericReason.EMPTY_PREVIEW
            else -> GenericReason.DECRYPTION_FAILED
        }
}

/**
 * The input the opener reads and the answer it gives, as JSON text, so that the Rust function is
 * the only place a sealed preview is read.
 */
object PreviewOpenerJson {
    /** The input for one preview: the members the Rust opener reads, and no others. */
    fun input(preview: String, senderKey: ByteArray, alert: String, nowMillis: Long): String =
        JSONObject()
            .put("preview", preview)
            .put("sender_key", java.util.Base64.getEncoder().encodeToString(senderKey))
            .put("alert", alert)
            .put("now_ms", nowMillis)
            .toString()

    /** What the opener's answer says. An answer that is not one of the two shapes is a refusal. */
    fun answer(text: String): PreviewOpened =
        try {
            val answer = JSONObject(text)
            if (answer.optBoolean("ok", false) && answer.opt("text") is String) {
                PreviewOpened.Text(answer.getString("text"))
            } else {
                PreviewOpened.Refused(answer.optString("reason", "answer"))
            }
        } catch (failure: JSONException) {
            PreviewOpened.Refused("answer")
        }
}
