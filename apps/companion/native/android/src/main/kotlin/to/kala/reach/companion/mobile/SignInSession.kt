package to.kala.reach.companion.mobile

/**
 * One sign-in attempt's browser tab, and which of the application's own events belong to it.
 *
 * An Auth Tab returns its answer once, as the result of the launch that opened it, so a result is
 * the current attempt's only when that attempt launched it: a tab left open by an earlier attempt
 * cannot end a later one. A Custom Tab returns nothing to its launch, and some browsers answer the
 * launch at once while the tab stays open, so a Custom Tab is known closed by the application
 * coming back to the front after the tab covered it; its answer arrives as a verified link, which
 * nothing but a Custom Tab attempt accepts.
 */
class SignInSession {
    /** How the current attempt is carried. */
    enum class Mode { AUTH_TAB, CUSTOM_TAB }

    private var attempt: String? = null
    private var mode: Mode? = null
    private var covered = false

    /** The attempt under way, if one is. */
    fun current(): String? = attempt

    /** Starts [attempt] in [mode]; answers the attempt it replaces, which is now over. */
    fun begin(attempt: String, mode: Mode): String? {
        val earlier = this.attempt
        this.attempt = attempt
        this.mode = mode
        covered = false
        return earlier
    }

    /** The application went behind something: for a Custom Tab attempt, the tab. */
    fun paused() {
        if (attempt != null && mode == Mode.CUSTOM_TAB) covered = true
    }

    /** The application came back to the front: answers the attempt whose tab closed, if one did. */
    fun resumed(): String? {
        val current = attempt ?: return null
        if (mode != Mode.CUSTOM_TAB || !covered) return null
        covered = false
        return current
    }

    /** A verified link to the callback arrived: answers the attempt it is for, if any. */
    fun link(): String? = attempt.takeIf { mode == Mode.CUSTOM_TAB }

    /** Whether an Auth Tab result from the launch for [launchedFor] belongs to the current attempt. */
    fun result(launchedFor: String): Boolean = mode == Mode.AUTH_TAB && launchedFor == attempt

    /** Ends [attempt] if it is the current one, and answers whether it was. */
    fun ended(attempt: String): Boolean {
        if (attempt != this.attempt) return false
        this.attempt = null
        mode = null
        covered = false
        return true
    }
}
