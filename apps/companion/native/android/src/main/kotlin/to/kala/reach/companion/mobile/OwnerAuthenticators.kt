package to.kala.reach.companion.mobile

/**
 * What an Android phone asks of the person who owns it, to be sure they are in front of it now.
 *
 * Two ceremonies on this phone ask it: the one that confirms a voice call's sensitive action, and
 * the one that confirms an action a host the phone owns waits for. Both go by this one rule, so a
 * phone that can ask one can ask the other, and neither asks for less than the other.
 */
enum class OwnerAsk {
    /** A strong biometric, with the screen lock as the fallback. */
    STRONG_BIOMETRIC_OR_SCREEN_LOCK,

    /** A strong biometric alone: the system names no fallback it can combine with it. */
    STRONG_BIOMETRIC_ONLY,

    /** The screen lock alone: the phone has no strong biometric set up. */
    SCREEN_LOCK_ONLY,
}

object OwnerAuthenticators {
    /** The first version of Android whose authenticator set can be a value of its own. */
    const val FIRST_SDK_WITH_AUTHENTICATOR_SETS: Int = 30

    /**
     * The longest a ceremony is waited for, however much time the challenge it confirms has left:
     * a challenge outlives the patience of anyone looking at a prompt.
     */
    const val LONGEST_WAIT_MILLIS: Long = 10 * 60 * 1000L

    /**
     * What this phone can ask, or null when it can ask nothing strong enough.
     *
     * From Android 11 the authenticator set is a value: strong biometrics with the screen lock as
     * the fallback, or the lock alone. Before it, the only way to name the lock is a flag that also
     * admits weak biometrics, so that flag is not used: those versions ask for strong biometrics
     * alone, and only on a phone that is locked by something (a strong biometric on a phone with no
     * lock is not an unlocked-screen confirmation). A phone without them is refused rather than
     * asked something weaker.
     *
     * @param strongBiometric the system can authenticate with a strong biometric now
     * @param screenLock the system can authenticate with the screen lock now
     * @param deviceSecure the phone is locked by a PIN, a pattern, a password or a biometric
     */
    fun choose(sdk: Int, strongBiometric: Boolean, screenLock: Boolean, deviceSecure: Boolean): OwnerAsk? {
        if (sdk >= FIRST_SDK_WITH_AUTHENTICATOR_SETS) {
            return when {
                strongBiometric -> OwnerAsk.STRONG_BIOMETRIC_OR_SCREEN_LOCK
                screenLock -> OwnerAsk.SCREEN_LOCK_ONLY
                else -> null
            }
        }
        return if (strongBiometric && deviceSecure) OwnerAsk.STRONG_BIOMETRIC_ONLY else null
    }

    /** The word the application's Rust half reads for the ceremony an ask is. */
    fun kind(ask: OwnerAsk?): String = when (ask) {
        OwnerAsk.STRONG_BIOMETRIC_OR_SCREEN_LOCK, OwnerAsk.STRONG_BIOMETRIC_ONLY -> "biometric"
        OwnerAsk.SCREEN_LOCK_ONLY -> "screen_lock"
        null -> "none"
    }

    /**
     * How long to wait for the person, from the time the challenge has left: none at all when it has
     * none, and never more than [LONGEST_WAIT_MILLIS].
     */
    fun waitMillis(leftMillis: Long): Long = leftMillis.coerceIn(0L, LONGEST_WAIT_MILLIS)
}
