package to.kala.reach.companion.mobile

/**
 * The sealed preview a push message carries, and what can be decided about it before it is opened.
 *
 * A data message from the gateway carries a generic alert and, when previews are on, a sealed
 * envelope: a 24-byte nonce, the routing that names the two keys and the expiry, and the padded
 * ciphertext. Everything in this file is parsing and checking, and none of it decrypts, because
 * what can be decided without the key decides whether the key is fetched at all.
 *
 * It is plain Kotlin on purpose. It runs in a receiver, in a background worker and in a unit test
 * on a developer's machine, and none of those should need a device.
 */

/** What the message says about the sealed preview, before anything is opened. */
class PreviewRouting(
    val envelopeId: String,
    val recipientKeyId: ByteArray,
    val senderKeyId: ByteArray,
    val expiresAtMillis: Long,
    val sizeBucketBytes: Long
)

/** One sealed preview, as it arrives. */
class PreviewEnvelope(
    val routing: PreviewRouting,
    val nonce: ByteArray,
    val ciphertext: ByteArray
) {
    /** Whether this preview is still within the life the host gave it. */
    fun isLive(nowMillis: Long): Boolean = nowMillis < routing.expiresAtMillis

    companion object {
        /** The nonce length of the sealing construction, in bytes. */
        const val NONCE_LENGTH = 24

        /** The length of a key identifier, in bytes. */
        const val KEY_ID_LENGTH = 32

        /**
         * Reads a sealed preview out of a message's data.
         *
         * A push message's data is a flat map of strings, so the routing arrives as its own fields
         * rather than as a nested object. Every failure is a reason to show the generic alert, so
         * the parse is strict rather than forgiving.
         */
        fun parse(data: Map<String, String>): ParsedPreview {
            if (!data.containsKey("preview_ciphertext")) return ParsedPreview.Absent
            val nonce = decode(data["preview_nonce"]) ?: return ParsedPreview.Malformed("nonce")
            if (nonce.size != NONCE_LENGTH) return ParsedPreview.Malformed("nonce")
            val ciphertext =
                decode(data["preview_ciphertext"]) ?: return ParsedPreview.Malformed("ciphertext")
            if (ciphertext.isEmpty()) return ParsedPreview.Malformed("ciphertext")
            val envelopeId = data["envelope_id"]
            if (envelopeId.isNullOrEmpty()) return ParsedPreview.Malformed("envelope_id")
            val recipient =
                decode(data["recipient_key_id"])
                    ?: return ParsedPreview.Malformed("recipient_key_id")
            if (recipient.size != KEY_ID_LENGTH) return ParsedPreview.Malformed("recipient_key_id")
            val sender =
                decode(data["sender_key_id"]) ?: return ParsedPreview.Malformed("sender_key_id")
            if (sender.size != KEY_ID_LENGTH) return ParsedPreview.Malformed("sender_key_id")
            val expires =
                data["expires_at_ms"]?.toLongOrNull()
                    ?: return ParsedPreview.Malformed("expires_at_ms")
            val bucket =
                data["size_bucket_bytes"]?.toLongOrNull()
                    ?: return ParsedPreview.Malformed("size_bucket_bytes")
            return ParsedPreview.Sealed(
                PreviewEnvelope(
                    PreviewRouting(envelopeId, recipient, sender, expires, bucket),
                    nonce,
                    ciphertext
                )
            )
        }

        /**
         * Decodes one base64url field.
         *
         * Written out rather than taken from the platform: the library decoder arrived in a later
         * Android than this application's minimum, and this same code runs in a receiver, in a
         * worker and in a test on a developer's machine.
         */
        private fun decode(value: String?): ByteArray? {
            if (value.isNullOrEmpty()) return null
            val text = value.trimEnd('=')
            val bits = StringBuilder()
            for (character in text) {
                val index = ALPHABET.indexOf(character)
                if (index < 0) return null
                bits.append(index.toString(2).padStart(6, '0'))
            }
            val whole = bits.length / 8
            val bytes = ByteArray(whole)
            for (position in 0 until whole) {
                bytes[position] =
                    bits.substring(position * 8, position * 8 + 8).toInt(2).toByte()
            }
            // Whatever is left is the padding the encoder dropped, and it must be zero: anything
            // else is a field that was not produced by a base64url encoder.
            val remainder = bits.substring(whole * 8)
            if (remainder.any { it != '0' }) return null
            return bytes
        }

        private const val ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    }
}

/** What a parse found. */
sealed interface ParsedPreview {
    /** The message carries no preview, which is what a host with previews off sends. */
    object Absent : ParsedPreview

    /** A field is missing or is not the shape the protocol declares. */
    data class Malformed(val field: String) : ParsedPreview

    /** A sealed preview, ready to be decided about. */
    data class Sealed(val envelope: PreviewEnvelope) : ParsedPreview
}
