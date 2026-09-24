package to.kala.reach.companion.mobile

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom

/** Seals and opens one item's bytes, bound to the item's name. */
interface Sealer {
    fun seal(plain: ByteArray, associated: ByteArray): ByteArray

    fun open(sealed: ByteArray, associated: ByteArray): ByteArray
}

/** An item that is there and does not open, which is a failure and never "missing". */
class SecretUnreadable(message: String) : IOException(message)

/**
 * The phone's secret store on disk: one file per item.
 *
 * Each file is named by the SHA-256 of the item's name and holds the item sealed with the item's
 * name as the associated data, so a file moved under another item's name does not open. A write
 * seals into a staging file in the same directory, syncs it and renames it over the item: a reader
 * sees the whole old item or the whole new one, and a write that fails leaves the old one. An item
 * that does not open is an error; only an absent file is "missing".
 */
open class SecretFiles(private val directory: File, private val sealer: Sealer) {
    fun read(name: String): ByteArray? {
        val file = fileFor(name)
        if (!file.exists()) return null
        val sealed = file.readBytes()
        return try {
            sealer.open(sealed, associated(name))
        } catch (failure: Exception) {
            throw SecretUnreadable("the stored item does not open")
        }
    }

    fun write(name: String, value: ByteArray) {
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw IOException("the secret directory could not be made")
        }
        val sealed = sealer.seal(value, associated(name))
        val target = fileFor(name)
        val staging = File(directory, "${target.name}.staging-${suffix()}")
        try {
            FileOutputStream(staging).use { stream ->
                stream.write(sealed)
                stream.fd.sync()
            }
            commit(staging, target)
        } finally {
            if (staging.exists()) staging.delete()
        }
    }

    fun delete(name: String) {
        val file = fileFor(name)
        if (file.exists() && !file.delete()) {
            throw IOException("the stored item could not be removed")
        }
    }

    fun fileFor(name: String): File = File(directory, hex(sha256(name.toByteArray(Charsets.UTF_8))))

    /** Puts the staged file in the item's place: a rename, which replaces all of it or none. */
    protected open fun commit(staging: File, target: File) {
        if (!staging.renameTo(target)) {
            throw IOException("the stored item could not be replaced")
        }
    }

    private fun associated(name: String): ByteArray = name.toByteArray(Charsets.UTF_8)

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun suffix(): String {
        val bytes = ByteArray(8)
        SecureRandom().nextBytes(bytes)
        return hex(bytes)
    }
}
