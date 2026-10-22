package to.kala.reach.companion.mobile

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.SecureRandom
import org.json.JSONException
import org.json.JSONObject

/**
 * The record of the one registration this phone is waiting for the challenge of.
 *
 * The application writes it before it proposes a token, and the receiver reads it when a challenge
 * arrives, possibly in a process the system started for that message alone. It holds nothing
 * secret: the identifiers a challenge has to repeat, the gateway to answer to and the phone's own
 * deadline. The Rust half owns what the fields mean; this class keeps the text, tells the
 * receiver's decision what is there, and moves one field, `state`, as the registration moves.
 *
 * A write replaces the file whole through a staging file and a rename, so a reader sees the old
 * record or the new one. A record whose deadline has passed reads as `expired` on every read,
 * whether or not the process that wrote it still runs: expiry is a fact of the clock and not of a
 * timer, because nothing guarantees a timer in a stopped process.
 */
class PendingFile(private val file: File) {
    /** The record as text, with the state it is in now, or null when there is none. */
    @Synchronized
    fun read(nowMillis: Long): String? {
        val record = load() ?: return null
        if (record.optString("state") == PENDING && nowMillis >= record.optLong("deadline_ms", 0L)) {
            record.put("state", EXPIRED)
            store(record)
        }
        return record.toString()
    }

    /** Replaces the record, which supersedes whatever was there. */
    @Synchronized
    fun write(text: String) {
        store(JSONObject(text))
    }

    /** Removes the record. */
    @Synchronized
    fun clear() {
        if (file.exists() && !file.delete()) throw IOException("the pending record could not be removed")
    }

    /**
     * Moves a record that is still `pending` to `state`, with the reason when there is one.
     * Returns false when there is no such record, which is the case for one that has since been
     * replaced or has expired: it is then left alone.
     */
    @Synchronized
    fun mark(state: String, reason: String? = null, nowMillis: Long): Boolean {
        val record = load() ?: return false
        if (record.optString("state") != PENDING) return false
        if (nowMillis >= record.optLong("deadline_ms", 0L)) {
            record.put("state", EXPIRED)
            store(record)
            return false
        }
        record.put("state", state)
        if (reason != null) record.put("reason", reason)
        store(record)
        return true
    }

    private fun load(): JSONObject? {
        if (!file.exists()) return null
        return try {
            JSONObject(file.readText(Charsets.UTF_8))
        } catch (failure: JSONException) {
            null
        }
    }

    private fun store(record: JSONObject) {
        val directory = file.parentFile
        if (directory != null && !directory.isDirectory && !directory.mkdirs()) {
            throw IOException("the directory of the pending record could not be made")
        }
        val staging = File(directory, "${file.name}.staging-${suffix()}")
        try {
            FileOutputStream(staging).use { stream ->
                stream.write(record.toString().toByteArray(Charsets.UTF_8))
                stream.fd.sync()
            }
            if (!staging.renameTo(file)) throw IOException("the pending record could not be replaced")
        } finally {
            if (staging.exists()) staging.delete()
        }
    }

    private fun suffix(): String {
        val bytes = ByteArray(6)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    companion object {
        /** A registration waiting for its challenge. */
        const val PENDING = "pending"

        /** A registration whose challenge was answered and taken by the gateway. */
        const val ANSWERED = "answered"

        /** A registration the receiver or the gateway refused. */
        const val REFUSED = "refused"

        /** A registration whose deadline passed. */
        const val EXPIRED = "expired"
    }
}
