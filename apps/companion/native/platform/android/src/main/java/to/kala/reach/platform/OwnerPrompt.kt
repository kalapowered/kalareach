package to.kala.reach.platform

import android.app.KeyguardManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import to.kala.reach.companion.mobile.OwnerAsk
import to.kala.reach.companion.mobile.OwnerAuthenticators

/**
 * The prompt that confirms the person who owns this phone is in front of it now, which the system
 * draws: a strong biometric, with the screen lock as its fallback where the system allows one, or
 * the screen lock alone. Nothing here draws a screen of the application's own, since a screen the
 * page can press proves nothing.
 *
 * What this phone can ask is [ask], by the rule the voice call's ceremony follows too. A phone that
 * can ask nothing strong enough is refused, never asked for something weaker.
 *
 * The prompt is shown, answered and cancelled on the main thread. It answers once: with what the
 * system said, with "not confirmed" when the time given runs out (the prompt is withdrawn), and with
 * "unavailable" when the phone has nothing to ask. One prompt is up at a time, since the library
 * keeps one callback for every prompt of an activity: the plugin builds no second prompt while this
 * one is, so what the person answers is never delivered to another request.
 */
class OwnerPrompt(
    private val activity: FragmentActivity,
    private val ask: OwnerAsk,
    private val reason: String,
    private val withinMillis: Long,
    private val reply: (String) -> Unit,
) {
    private val main = Handler(Looper.getMainLooper())
    private var prompt: BiometricPrompt? = null
    private var answered = false
    private val expire = Runnable { finish("not_confirmed", withdraw = true) }

    /** Draws the prompt, and starts the clock. */
    fun show() {
        val wait = OwnerAuthenticators.waitMillis(withinMillis)
        if (wait == 0L) {
            finish("not_confirmed", withdraw = false)
            return
        }
        main.postDelayed(expire, wait)
        val shown = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    finish("confirmed", withdraw = false)
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    finish(outcomeOf(code), withdraw = false)
                }

                override fun onAuthenticationFailed() {
                    // One rejected finger is not an answer: the prompt stays up until the person
                    // succeeds, cancels, or the system gives up and reports an error.
                }
            },
        )
        prompt = shown
        shown.authenticate(information(ask))
    }

    private fun finish(outcome: String, withdraw: Boolean) {
        if (answered) return
        answered = true
        main.removeCallbacks(expire)
        if (withdraw) prompt?.cancelAuthentication()
        prompt = null
        reply(outcome)
    }

    private fun information(ask: OwnerAsk): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Confirm on this phone")
            .setSubtitle(reason)
            // A face the system sees on its own is not enough: the person presses to confirm.
            .setConfirmationRequired(true)
        return when (ask) {
            OwnerAsk.STRONG_BIOMETRIC_OR_SCREEN_LOCK ->
                builder.setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
            OwnerAsk.SCREEN_LOCK_ONLY -> builder.setAllowedAuthenticators(Authenticators.DEVICE_CREDENTIAL)
            OwnerAsk.STRONG_BIOMETRIC_ONLY ->
                builder.setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG).setNegativeButtonText("Cancel")
        }.build()
    }

    companion object {
        /** What this phone can ask of its owner now, or null when it can ask nothing strong enough. */
        fun ask(activity: FragmentActivity): OwnerAsk? {
            val manager = BiometricManager.from(activity)
            val newEnough = Build.VERSION.SDK_INT >= OwnerAuthenticators.FIRST_SDK_WITH_AUTHENTICATOR_SETS
            return OwnerAuthenticators.choose(
                sdk = Build.VERSION.SDK_INT,
                strongBiometric = manager.canAuthenticate(Authenticators.BIOMETRIC_STRONG) ==
                    BiometricManager.BIOMETRIC_SUCCESS,
                // Asking about the lock alone is meaningful from the version it can be named in.
                screenLock = newEnough &&
                    manager.canAuthenticate(Authenticators.DEVICE_CREDENTIAL) == BiometricManager.BIOMETRIC_SUCCESS,
                deviceSecure = activity.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true,
            )
        }

        /**
         * What the system's error says of the ceremony: that the phone had nothing to ask, or that
         * the person did not confirm it (cancelled it, ran it out, or lost it to another screen).
         */
        fun outcomeOf(code: Int): String = when (code) {
            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_NO_BIOMETRICS,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> "unavailable"
            else -> "not_confirmed"
        }
    }
}
