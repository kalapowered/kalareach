package to.kala.reach.companion.voice

import android.app.KeyguardManager
import android.os.Build
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import to.kala.reach.companion.mobile.OwnerPresenceEvaluator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The unlocked-screen ceremony on Android: the device owner, on this device, right now.
 *
 * Section 15 paragraph 8 draws the line this class exists to hold. A model statement that the
 * person confirmed an operation is content; an action that needs an unlocked-screen confirmation
 * needs the owner to answer a prompt the operating system drew. Biometric authentication is asked
 * for first, and a device credential (PIN, pattern or password) is the fallback, so a device with
 * no enrolled fingerprint or face still has a ceremony.
 *
 * A device with neither is refused. Answering "verified" without a ceremony would make exactly the
 * claim the specification forbids, and that is why every path below returns false rather than
 * assuming an absent prompt means consent. So is a ceremony weaker than the one asked for: the
 * authenticators are strong biometrics or the device credential, never a weak biometric, on every
 * version of Android this application runs on.
 */
class BiometricOwnerPresence(
    private val activity: FragmentActivity,
    private val executor: Executor = ContextCompat.getMainExecutor(activity),
    private val timeoutSeconds: Long = PROMPT_TIMEOUT_SECONDS,
) : OwnerPresenceEvaluator {

    /**
     * Asks the owner, and answers only what the system said.
     *
     * This blocks until the person answers, so the main thread is refused rather than deadlocked:
     * the prompt is drawn on the main thread, and a main thread waiting here could never draw it.
     * The callbacks only record the answer, so they run on the main thread, which is never the one
     * waiting, and there is no thread of this object's own to leave running afterwards.
     */
    override fun evaluatePresence(reason: String): Boolean {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "the unlocked-screen ceremony waits for the person and cannot run on the main thread"
        }

        val information = promptInformation(reason) ?: return false

        val answered = CountDownLatch(1)
        val verified = AtomicBoolean(false)

        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    verified.set(true)
                    answered.countDown()
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    answered.countDown()
                }

                override fun onAuthenticationFailed() {
                    // One rejected finger is not an answer: the prompt stays up until the person
                    // succeeds, cancels, or the system gives up and calls onAuthenticationError.
                }
            },
        )

        activity.runOnUiThread { prompt.authenticate(information) }

        if (!answered.await(timeoutSeconds, TimeUnit.SECONDS)) {
            activity.runOnUiThread { prompt.cancelAuthentication() }
            return false
        }
        return verified.get()
    }

    /**
     * What this device can actually ask, or null when it can ask nothing strong enough.
     *
     * From Android 11 the authenticator set is a value: strong biometrics with the device credential
     * as the fallback, or the credential alone. Before it, the only way to name the credential is a
     * flag that also admits weak biometrics, so that flag is not used: those versions ask for strong
     * biometrics alone, and a device without them is refused rather than asked something weaker.
     */
    private fun promptInformation(reason: String): BiometricPrompt.PromptInfo? {
        val manager = BiometricManager.from(activity)
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm on this device")
            .setSubtitle(reason)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            for (candidate in listOf(AUTHENTICATORS, BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
                if (manager.canAuthenticate(candidate) == BiometricManager.BIOMETRIC_SUCCESS) {
                    return builder.setAllowedAuthenticators(candidate).build()
                }
            }
            return null
        }

        val strong = BiometricManager.Authenticators.BIOMETRIC_STRONG
        if (manager.canAuthenticate(strong) != BiometricManager.BIOMETRIC_SUCCESS) return null
        // The device is locked by something, or a biometric would not be enrolled at all; a strong
        // biometric on a device with no lock screen is not an unlocked-screen confirmation.
        if (activity.getSystemService(KeyguardManager::class.java)?.isDeviceSecure != true) return null
        return builder
            .setAllowedAuthenticators(strong)
            .setNegativeButtonText("Cancel")
            .build()
    }

    companion object {
        /** Biometric first, device credential as the fallback. */
        const val AUTHENTICATORS: Int =
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL

        /** How long an unanswered prompt is waited for before it is withdrawn. */
        const val PROMPT_TIMEOUT_SECONDS: Long = 120
    }
}
