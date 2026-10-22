package to.kala.reach.companion.push

import android.content.Context
import android.os.UserManager
import to.kala.reach.companion.mobile.PreviewKeyReading
import to.kala.reach.companion.mobile.PreviewKeyUnavailable
import to.kala.reach.companion.mobile.PreviewKeyUnavailableException
import to.kala.reach.companion.mobile.PushStores
import to.kala.reach.platform.KeystoreSealer

/**
 * The limited preview key, where the platform keeps keys.
 *
 * The key is sealed under a key in the hardware-backed keystore and filed in the limited store,
 * apart from the application's secure store, which the receiver and the worker can read and
 * nothing outside the application can. It opens a notification preview and can do nothing else: it
 * is not this device's authorisation key and it cannot sign.
 *
 * A device that has not been unlocked since it started reports exactly that, rather than a
 * failure, because the two mean different things and the specification distinguishes them.
 */
class KeystorePreviewKeys(private val context: Context) : PreviewKeyReading {
    override fun key(recipientKeyId: ByteArray): Result<ByteArray> {
        if (!isUnlockedSinceBoot()) {
            return Result.failure(
                PreviewKeyUnavailableException(PreviewKeyUnavailable.LockedBeforeFirstUnlock)
            )
        }
        return try {
            val stored =
                PushStores.limited(context.noBackupFilesDir, KeystoreSealer()).read(recipientKeyId)
                    ?: return Result.failure(
                        PreviewKeyUnavailableException(PreviewKeyUnavailable.NotProvisioned)
                    )
            Result.success(stored)
        } catch (failure: Exception) {
            Result.failure(
                PreviewKeyUnavailableException(
                    PreviewKeyUnavailable.Refused(failure.message.orEmpty())
                )
            )
        }
    }

    private fun isUnlockedSinceBoot(): Boolean {
        val users = context.getSystemService(UserManager::class.java) ?: return true
        return users.isUserUnlocked
    }
}
