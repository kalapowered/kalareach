package to.kala.reach.companion.mobile

/**
 * What a running call's notification offers while the screen is locked, and when an unmute may
 * reopen the microphone.
 *
 * Mute and stop only take something away from the phone, so they work from the lock screen with no
 * unlock. Unmute opens the microphone again, which only a person at the phone, with the phone
 * unlocked, may do: the call was started explicitly and a muted microphone is not reopened by
 * whoever is holding a locked phone.
 *
 * From Android 12 (API 31) the platform can ask for the unlock before a single action runs, so the
 * notification keeps its Unmute and marks it as needing one. Before that the platform has no such
 * lock for one action, so while the phone is locked the notification offers no Unmute at all and
 * an Unmute that arrives anyway is refused; the person unlocks and uses the notification in the
 * shade or the call's own screen.
 */
object VoiceNotificationControls {
    /** The first platform release that can ask for the unlock before one notification action runs. */
    const val UNLOCK_PER_ACTION_SDK = 31

    /** What the notification's microphone control is. */
    enum class Toggle { MUTE, UNMUTE, NONE }

    /** The microphone control the notification offers, and whether its action needs the unlock. */
    data class Controls(val toggle: Toggle, val needsUnlock: Boolean)

    fun controls(muted: Boolean, locked: Boolean, sdk: Int): Controls = when {
        !muted -> Controls(Toggle.MUTE, needsUnlock = false)
        sdk >= UNLOCK_PER_ACTION_SDK -> Controls(Toggle.UNMUTE, needsUnlock = true)
        locked -> Controls(Toggle.NONE, needsUnlock = false)
        else -> Controls(Toggle.UNMUTE, needsUnlock = false)
    }

    /**
     * Whether an unmute that reaches the call now may reopen the microphone. From API 31 the
     * platform has already asked for the unlock before the action was sent.
     */
    fun mayUnmute(locked: Boolean, sdk: Int): Boolean = sdk >= UNLOCK_PER_ACTION_SDK || !locked
}
