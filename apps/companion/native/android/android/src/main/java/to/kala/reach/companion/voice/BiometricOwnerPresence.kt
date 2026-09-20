package to.kala.reach.companion.voice

import android.app.KeyguardManager
import android.os.Build
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import to.kala.reach.companion.mobile.OwnerPresenceEvaluator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
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
 * assuming an absent prompt means consent.
 */
class BiometricOwnerPresence(
    private val activity: FragmentActivity,
    private val executor: Executor = Executors.newSingleThreadExecutor(),
    private val timeoutSeconds: Long = PROMPT_TIMEOUT_SECONDS,
) : OwnerPresenceEvaluator {

    /**
     * Asks the owner, and answers only what the system said.
     *
     * This blocks until the person answers, so the main thread is refused rather than deadlocked:
     * the prompt is drawn on the main thread, and a main thread waiting here could never draw it.
     * The callbacks arrive on this object's own executor, which is never the main thread either.
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
     * What this device can actually ask, or null when it can ask nothing.
     *
     * Android 11 took the authenticator set as a value; before it, a device credential is allowed
     * through its own flag and the two cannot be named together. Both routes end at the same place:
     * the owner authenticating on an unlocked screen. A device that can do neither is refused.
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

        val hasBiometric =
            manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) ==
                BiometricManager.BIOMETRIC_SUCCESS
        val hasCredential =
            activity.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true
        if (!hasBiometric && !hasCredential) return null

        @Suppress("DEPRECATION")
        return builder.setDeviceCredentialAllowed(true).build()
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
