package to.kala.reach.companion.mobile

import java.io.File
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

/**
 * Where the push receiver and the application keep what they share, by name.
 *
 * The receiver runs in a process the system may start for one message, and the application's
 * plugin runs inside the application, so neither can ask the other where a thing is: both name it
 * the same way, from here.
 */
object PushStores {
    /** The preferences file the registration token is kept in. */
    const val TOKEN_STORE = "to.kala.reach.push"

    /** The current registration token. */
    const val TOKEN_KEY = "registration_token"

    /** When the token was given, in milliseconds. */
    const val TOKEN_AT_KEY = "registration_token_at_ms"

    /** The file the pending registration is kept in, in the application's no-backup directory. */
    const val PENDING_FILE = "push-pending.json"

    /** The directory the application's secure store keeps its items in, in the no-backup directory. */
    const val SECRETS_DIRECTORY = "secrets"

    /** The directory the limited preview keys are kept in, in the no-backup directory. */
    const val LIMITED_DIRECTORY = "limited-keys"

    fun pending(noBackup: File): PendingFile = PendingFile(File(noBackup, PENDING_FILE))

    fun secrets(noBackup: File, sealer: Sealer): SecretFiles =
        SecretFiles(File(noBackup, SECRETS_DIRECTORY), sealer)

    fun limited(noBackup: File, sealer: Sealer): LimitedKeys =
        LimitedKeys(File(noBackup, LIMITED_DIRECTORY), sealer)
}

/**
 * The keys a receiver may open a notification preview with, and nothing else: this device's preview
 * seeds, each under the identifier of its public half (which is what a sealed preview names its
 * recipient by), and the public key of each host that may seal a preview to it, under the
 * identifier a sealed preview names its sender by.
 *
 * The application hands over the whole set each time it changes, so the set a receiver reads is
 * always one the application meant as a whole: a host turned off is not in it, and a seed is in it
 * only while some host that may use it is.
 */
class PreviewKeySet private constructor(
    private val recipients: Map<String, ByteArray>,
    private val senders: Map<String, ByteArray>
) {
    /** The seed for one recipient key identifier, when the set holds it. */
    fun recipientSeed(recipientKeyId: ByteArray): ByteArray? = recipients[hex(recipientKeyId)]

    /** The public key for one sender key identifier, when the set holds it. */
    fun senderKey(senderKeyId: ByteArray): ByteArray? = senders[hex(senderKeyId)]

    /** The set as the application sends it: members of base64 text. */
    fun toJson(): String {
        val encoder = java.util.Base64.getEncoder()
        val recipientItems = JSONArray()
        for ((id, seed) in recipients) {
            recipientItems.put(
                JSONObject().put("id", encoder.encodeToString(unhex(id))).put("seed", encoder.encodeToString(seed))
            )
        }
        val senderItems = JSONArray()
        for ((id, key) in senders) {
            senderItems.put(
                JSONObject().put("id", encoder.encodeToString(unhex(id))).put("key", encoder.encodeToString(key))
            )
        }
        return JSONObject().put("recipients", recipientItems).put("senders", senderItems).toString()
    }

    companion object {
        /** The length of a key identifier, a seed and a public key, in bytes. */
        private const val LENGTH = 32

        /** A set of these seeds, each with the identifier of its public half, and these senders. */
        fun of(
            recipients: List<Pair<ByteArray, ByteArray>>,
            senders: List<Pair<ByteArray, ByteArray>>
        ): PreviewKeySet =
            PreviewKeySet(
                recipients.associate { (id, seed) -> hex(id) to seed },
                senders.associate { (id, key) -> hex(id) to key }
            )

        /**
         * Reads a set from the application's text. A set with a member that is not what a key is,
         * or that names one identifier twice, is not read: a receiver is never handed half of one.
         */
        fun parse(text: String): PreviewKeySet? {
            return try {
                val decoder = java.util.Base64.getDecoder()
                val root = JSONObject(text)
                val recipients = mutableMapOf<String, ByteArray>()
                val recipientItems = root.getJSONArray("recipients")
                for (position in 0 until recipientItems.length()) {
                    val item = recipientItems.getJSONObject(position)
                    val id = decoder.decode(item.getString("id"))
                    val seed = decoder.decode(item.getString("seed"))
                    if (id.size != LENGTH || seed.size != LENGTH) return null
                    if (recipients.put(hex(id), seed) != null) return null
                }
                val senders = mutableMapOf<String, ByteArray>()
                val senderItems = root.getJSONArray("senders")
                for (position in 0 until senderItems.length()) {
                    val item = senderItems.getJSONObject(position)
                    val id = decoder.decode(item.getString("id"))
                    val key = decoder.decode(item.getString("key"))
                    if (id.size != LENGTH || key.size != LENGTH) return null
                    if (senders.put(hex(id), key) != null) return null
                }
                PreviewKeySet(recipients, senders)
            } catch (failure: JSONException) {
                null
            } catch (failure: IllegalArgumentException) {
                null
            }
        }

        private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        private fun unhex(text: String): ByteArray =
            ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}

/**
 * The store of [PreviewKeySet]: one sealed item in a directory of its own, apart from the
 * application's secure store, replaced whole by each set the application hands over. On Android a
 * receiver and the application are one process with one Keystore key, so this is a boundary of
 * files and not of processes, and nothing here claims more.
 */
class LimitedKeys(directory: File, sealer: Sealer) {
    private val files = SecretFiles(directory, sealer)

    /** Makes the store hold exactly `keys`. */
    fun replace(keys: PreviewKeySet) {
        files.write(ITEM, keys.toJson().toByteArray(Charsets.UTF_8))
    }

    /** The set the store holds, or null when none was ever handed over. */
    fun read(): PreviewKeySet? {
        val stored = files.read(ITEM) ?: return null
        return PreviewKeySet.parse(String(stored, Charsets.UTF_8))
            ?: throw SecretUnreadable("the stored keys are not a set of keys")
    }

    private companion object {
        const val ITEM = "preview-keys"
    }
}
