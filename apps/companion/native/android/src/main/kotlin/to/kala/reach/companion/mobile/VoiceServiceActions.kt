package to.kala.reach.companion.mobile

/**
 * What the voice call's foreground service does with each action it is sent.
 *
 * Every action names the call it was made for. The platform keeps a notification's actions after
 * the call they were made for has ended, and an action already on its way can arrive after another
 * call started; either one names its own call, and an action naming a call other than the one the
 * service is running for changes nothing. So a stale "Mute" or "Stop" can never reach the call that
 * replaced the one it was shown for.
 */
object VoiceServiceActions {
    /** Enter the foreground for a call the host permitted. */
    const val START = "to.kala.reach.companion.voice.START"

    /** End the call. Reachable from the notification while the screen is locked. */
    const val STOP = "to.kala.reach.companion.voice.STOP"

    /** Mute or unmute the person's own microphone, from the notification. */
    const val TOGGLE_MUTE = "to.kala.reach.companion.voice.TOGGLE_MUTE"

    /** Show on the notification what the microphone is doing now. */
    const val CAPTURE = "to.kala.reach.companion.voice.CAPTURE"

    /** What the service does. */
    enum class Act {
        /** Enter the foreground for the call the action names. */
        START,

        /** End the call the action names, and the service with it. */
        STOP,

        /** Change the mute of the call the service is running for. */
        TOGGLE_MUTE,

        /** Show what the microphone of the call the service is running for is doing. */
        CAPTURE,

        /** Change nothing: the action is for a call this service is not running for. */
        IGNORE,

        /** End the service: it is running for no call, and this action gives it none. */
        END,
    }

    /**
     * What to do with `action`, which names the call `named`, in a service running for the call
     * `own`, or for none when `own` is null.
     */
    fun decide(action: String?, named: Long, own: Long?): Act =
        when {
            action == START -> Act.START
            own == null -> if (action == STOP) Act.STOP else Act.END
            named != own -> Act.IGNORE
            action == STOP -> Act.STOP
            action == TOGGLE_MUTE -> Act.TOGGLE_MUTE
            action == CAPTURE -> Act.CAPTURE
            // Anything else, including a restart the system decided on its own, is not a call the
            // person started, and opening the microphone for it would be the silent activation
            // section 15 paragraph 22 forbids.
            else -> Act.END
        }

    /**
     * The address a call's notification actions carry, different for every call.
     *
     * The platform tells pending actions apart by their address, not by what they carry. Two calls
     * whose actions shared an address would share one pending action, and publishing the second
     * call's notification would rewrite the first call's actions to name the second call.
     */
    fun callAddress(call: Long): String = "kalareach-voice-call:$call"
}
