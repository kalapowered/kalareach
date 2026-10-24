package to.kala.reach.companion.push

import android.content.Context
import android.os.UserManager
import to.kala.reach.companion.mobile.PreviewKeyReading
import to.kala.reach.companion.mobile.PreviewKeySet
import to.kala.reach.companion.mobile.PreviewKeyUnavailable
import to.kala.reach.companion.mobile.PreviewKeyUnavailableException
import to.kala.reach.companion.mobile.PushStores
import to.kala.reach.platform.KeystoreSealer

/**
 * The preview keys, where the platform keeps keys.
 *
 * The keys are sealed under a key in the hardware-backed keystore and filed in the limited store,
 * apart from the application's secure store, which the receiver and the worker can read and
 * nothing outside the application can. They open a notification preview and can do nothing else:
 * the seed is not this device's authorisation key and cannot sign, and the senders' keys are
 * public.
 *
 * A device that has not been unlocked since it started reports exactly that, rather than a
 * failure, because the two mean different things and the specification distinguishes them. Both
 * lookups are one read of the store, so both fail the same way before the first unlock.
 */
class KeystorePreviewKeys(private val context: Context) : PreviewKeyReading {
    private var loaded: Result<PreviewKeySet>? = null

    override fun recipientSeed(recipientKeyId: ByteArray): Result<ByteArray> =
        load().fold(
            { keys ->
                keys.recipientSeed(recipientKeyId)?.let { Result.success(it.copyOf()) }
                    ?: notProvisioned()
            },
            { Result.failure(it) }
        )

    override fun senderKey(senderKeyId: ByteArray): Result<ByteArray> =
        load().fold(
            { keys -> keys.senderKey(senderKeyId)?.let { Result.success(it) } ?: notProvisioned() },
            { Result.failure(it) }
        )

    private fun load(): Result<PreviewKeySet> = loaded ?: read().also { loaded = it }

    private fun read(): Result<PreviewKeySet> {
        if (!isUnlockedSinceBoot()) {
            return unavailable(PreviewKeyUnavailable.LockedBeforeFirstUnlock)
        }
        return try {
            val stored =
                PushStores.limited(context.noBackupFilesDir, KeystoreSealer()).read()
                    ?: return unavailable(PreviewKeyUnavailable.NotProvisioned)
            Result.success(stored)
        } catch (failure: Exception) {
            unavailable(PreviewKeyUnavailable.Refused(failure.message.orEmpty()))
        }
    }

    private fun <T> unavailable(reason: PreviewKeyUnavailable): Result<T> =
        Result.failure(PreviewKeyUnavailableException(reason))

    private fun <T> notProvisioned(): Result<T> = unavailable(PreviewKeyUnavailable.NotProvisioned)

    private fun isUnlockedSinceBoot(): Boolean {
        val users = context.getSystemService(UserManager::class.java) ?: return true
        return users.isUserUnlocked
    }
}
