package to.kala.reach.companion.mobile

/**
 * What the application may sign, and when.
 *
 * The same rule as on the other platform: the application signs an action only after its required
 * authentication, and a receiver or a background worker never signs at all. A worker holds one key
 * that opens a preview and can do nothing else.
 */

/** Whether this process has the authentication signing requires. */
sealed interface AuthenticationState {
    object None : AuthenticationState

    data class Verified(val atMillis: Long) : AuthenticationState
}

/** Why a signature was refused. */
enum class SigningRefusal {
    NOT_AUTHENTICATED,
    AUTHENTICATION_EXPIRED,
    NOT_THE_APPLICATION
}

/** How long an authentication stands before the application asks again. */
const val AUTHENTICATION_LIFETIME_MILLIS: Long = 5 * 60 * 1000

/** Decides whether an action may be signed now. */
data class SigningGate(
    /** True in the application's own process, false in a receiver or a worker. */
    val isApplication: Boolean,
    val state: AuthenticationState
) {
    /** The refusal, or null when the action may be signed. */
    fun refusal(nowMillis: Long): SigningRefusal? {
        if (!isApplication) return SigningRefusal.NOT_THE_APPLICATION
        return when (state) {
            is AuthenticationState.None -> SigningRefusal.NOT_AUTHENTICATED
            is AuthenticationState.Verified ->
                when {
                    nowMillis < state.atMillis -> SigningRefusal.AUTHENTICATION_EXPIRED
                    nowMillis - state.atMillis > AUTHENTICATION_LIFETIME_MILLIS ->
                        SigningRefusal.AUTHENTICATION_EXPIRED
                    else -> null
                }
        }
    }
}
