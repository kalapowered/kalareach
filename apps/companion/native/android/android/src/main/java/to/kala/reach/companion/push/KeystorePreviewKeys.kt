package to.kala.reach.companion.push

import android.content.Context
import android.os.Build
import android.os.UserManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import to.kala.reach.companion.mobile.PreviewKeyReading
import to.kala.reach.companion.mobile.PreviewKeyUnavailable
import to.kala.reach.companion.mobile.PreviewKeyUnavailableException
import android.util.Base64

/**
 * The limited preview key, where the platform keeps keys.
 *
 * The key is wrapped by a key in the hardware-backed keystore and stored in the application's own
 * encrypted preferences, which the receiver and the worker can read and nothing outside the
 * application can. It opens a notification preview and can do nothing else: it is not this
 * device's authorisation key and it cannot sign.
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
            val preferences =
                EncryptedSharedPreferences.create(
                    context,
                    STORE,
                    MasterKey.Builder(context)
                        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                        .build(),
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
            val stored =
                preferences.getString(Base64.encodeToString(recipientKeyId, Base64.NO_WRAP), null)
                    ?: return Result.failure(
                        PreviewKeyUnavailableException(PreviewKeyUnavailable.NotProvisioned)
                    )
            Result.success(Base64.decode(stored, Base64.NO_WRAP))
        } catch (failure: Exception) {
            Result.failure(
                PreviewKeyUnavailableException(
                    PreviewKeyUnavailable.Refused(failure.message.orEmpty())
                )
            )
        }
    }

    private fun isUnlockedSinceBoot(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return true
        val users = context.getSystemService(UserManager::class.java) ?: return true
        return users.isUserUnlocked
    }

    private companion object {
        const val STORE = "to.kala.reach.companion.preview-keys"
    }
}
