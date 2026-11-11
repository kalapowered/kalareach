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
 * an Unmute that arrives anyway is refused; the person unlocks the phone and uses the notification
 * in the shade.
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
     * Whether the person's microphone is muted once a mute or an unmute has reached the call that
     * is `muted` now. A mute always leaves it muted, however many times it arrives. An unmute opens
     * it only on a phone that is not locked, on every platform release: from API 31 the platform
     * asks for the unlock before it sends the notification's own Unmute, which then arrives on an
     * unlocked phone, but any other holder of the action's pending intent (an enabled notification
     * listener) can send it at any time, and the platform does not ask that sender for anything.
     */
    fun mutedAfter(unmute: Boolean, muted: Boolean, locked: Boolean): Boolean = when {
        !unmute -> true
        locked -> muted
        else -> false
    }
}
