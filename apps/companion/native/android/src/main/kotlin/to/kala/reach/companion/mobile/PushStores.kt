package to.kala.reach.companion.mobile

import java.io.File

/**
 * Where the push receiver and the application keep what they share, by name.
 *
 * The receiver runs in a process the system may start for one message, and the application's
 * plugin runs inside the application, so neither can ask the other where a thing is: both name it
 * the same way, from here.
 */
object PushStores {
    /** The preferences file the registration token and its flags are kept in. */
    const val TOKEN_STORE = "to.kala.reach.push"

    /** The current registration token. */
    const val TOKEN_KEY = "registration_token"

    /** When the token was given, in milliseconds. */
    const val TOKEN_AT_KEY = "registration_token_at_ms"

    /** Whether the token changed since the application last looked. */
    const val TOKEN_CHANGED_KEY = "registration_token_changed"

    /** The file the pending registration is kept in, in the application's no-backup directory. */
    const val PENDING_FILE = "push-pending.json"

    /** The directory the application's secure store keeps its items in, in the no-backup directory. */
    const val SECRETS_DIRECTORY = "secrets"

    /** The directory the limited preview key is kept in, in the no-backup directory. */
    const val LIMITED_DIRECTORY = "limited-keys"

    fun pending(noBackup: File): PendingFile = PendingFile(File(noBackup, PENDING_FILE))

    fun secrets(noBackup: File, sealer: Sealer): SecretFiles =
        SecretFiles(File(noBackup, SECRETS_DIRECTORY), sealer)

    fun limited(noBackup: File, sealer: Sealer): LimitedKeys =
        LimitedKeys(File(noBackup, LIMITED_DIRECTORY), sealer)
}

/**
 * The limited preview key: the one private key a receiver may open a notification preview with,
 * and nothing else.
 *
 * It is kept in a store of its own, apart from the application's secure store, under the identifier
 * of the key's public half, which is what a sealed preview names its recipient by. Each item is the
 * seed the application's secure store keeps for the device's notification-preview key. This
 * separates what is filed where; on Android a receiver and the application are one process with one
 * Keystore key, so it is a boundary of files and not of processes, and nothing here claims more.
 */
class LimitedKeys(directory: File, sealer: Sealer) {
    private val files = SecretFiles(directory, sealer)

    /** Files the key for one recipient, replacing any earlier one under that identifier. */
    fun write(recipientKeyId: ByteArray, seed: ByteArray) {
        files.write(name(recipientKeyId), seed)
    }

    /** The key for one recipient, or null when none is filed. */
    fun read(recipientKeyId: ByteArray): ByteArray? = files.read(name(recipientKeyId))

    /** Removes the key for one recipient. */
    fun delete(recipientKeyId: ByteArray) {
        files.delete(name(recipientKeyId))
    }

    private fun name(recipientKeyId: ByteArray): String =
        recipientKeyId.joinToString("") { "%02x".format(it) }
}
