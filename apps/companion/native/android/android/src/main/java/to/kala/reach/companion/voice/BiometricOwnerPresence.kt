package to.kala.reach.companion.voice

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import to.kala.reach.companion.mobile.OwnerPresenceEvaluator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

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
 * claim the specification forbids, and that is why the check below returns false rather than
 * assuming an absent prompt means consent.
 */
class BiometricOwnerPresence(
    private val activity: FragmentActivity,
    private val executor: Executor = ContextCompat.getMainExecutor(activity),
    private val timeoutSeconds: Long = PROMPT_TIMEOUT_SECONDS,
) : OwnerPresenceEvaluator {

    /**
     * Asks the owner, and answers only what the system said.
     *
     * This blocks until the person answers, so it is called from the ceremony's own thread and
     * never from the main thread: the prompt it waits for is drawn on the main thread.
     */
    override fun evaluatePresence(reason: String): Boolean {
        val authenticators = usableAuthenticators() ?: return false

        val information = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm on this device")
            .setSubtitle(reason)
            .setAllowedAuthenticators(authenticators)
            .build()

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
     * Biometric with a device-credential fallback is the first choice. Some platform versions do
     * not support that combination, and there the credential alone is still a ceremony the owner
     * performs on an unlocked screen. A device that can do neither is refused.
     */
    private fun usableAuthenticators(): Int? {
        val manager = BiometricManager.from(activity)
        for (candidate in listOf(AUTHENTICATORS, BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
            if (manager.canAuthenticate(candidate) == BiometricManager.BIOMETRIC_SUCCESS) {
                return candidate
            }
        }
        return null
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
