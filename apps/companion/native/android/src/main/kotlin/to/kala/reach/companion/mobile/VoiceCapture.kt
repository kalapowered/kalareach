package to.kala.reach.companion.mobile

/**
 * What the microphone is doing, and what that means for authority.
 *
 * Section 15 paragraph 22 asks for two things that are easy to confuse. The first is a display: if
 * capture is muted or unavailable, say so. The second is a refusal, and it is the one that matters:
 * reject any claim that unreceived speech authorised an action. A screen that showed a muted
 * microphone while the application acted on words nobody captured would satisfy the first and fail
 * the second.
 *
 * So the state is not a label on a view. It is the thing asked before a spoken instruction is
 * allowed to become anything, and it answers no whenever the microphone was not actually carrying
 * the person's voice. Nothing here touches an Android class, so its tests run without a device.
 */
enum class VoiceCaptureState(val display: String) {
    /** The microphone is open and carrying speech to the call. */
    CAPTURING("Microphone on"),

    /** The person muted it. Their own choice, and reversible by them. */
    MUTED_BY_PERSON("Microphone muted"),

    /** Audio focus was lost: a phone call, an alarm, another application. */
    FOCUS_LOST("Microphone taken by another app"),

    /** The route changed and capture has not been re-established on the new one yet. */
    ROUTE_CHANGING("Switching audio device"),

    /** The system suspended capture, or the foreground service was stopped under it. */
    SUSPENDED_BY_SYSTEM("Microphone paused by Android"),

    /** There is no microphone, or the person has not granted access to one. */
    UNAVAILABLE("No microphone available"),

    /** No call is running, so nothing is being captured. */
    IDLE("Not in a call");

    /**
     * Whether speech could have reached the call in this state.
     *
     * This is the whole point of the type. Every state but [CAPTURING] answers false, including the
     * ones a person caused themselves: a muted microphone heard nothing, whoever muted it.
     */
    val speechCouldHaveBeenHeard: Boolean get() = this == CAPTURING
}

/** Why a spoken instruction was not allowed to become an action. */
sealed class VoiceAuthorityRefusal {
    /** The microphone was not carrying speech when the words were supposed to have been said. */
    data class SpeechNotHeard(val state: VoiceCaptureState) : VoiceAuthorityRefusal()

    /** The action needs a confirmation taken on the unlocked screen, and there is none. */
    object NeedsUnlockedScreenConfirmation : VoiceAuthorityRefusal()

    /** What a person is told. */
    val message: String
        get() = when (this) {
            is SpeechNotHeard ->
                "${state.display}. Nothing spoken while the microphone was not carrying your " +
                    "voice can authorise an action."
            is NeedsUnlockedScreenConfirmation ->
                "This needs your confirmation on the unlocked screen of this device."
        }
}

/**
 * The one gate a spoken instruction passes before it can become a host action.
 *
 * Section 15 paragraph 8 says a model statement that the user confirmed an operation is not a
 * native-screen confirmation, and the provider is inside the trust boundary for interpreting
 * speech. So the question "could this person have been heard?" is answered from the device's own
 * record of its microphone rather than from anything that arrived over the call.
 */
data class VoiceAuthorityGate(
    val capture: VoiceCaptureState,
    val holdsUnlockedScreenConfirmation: Boolean = false,
) {
    /**
     * Whether a delegation the provider announced may be submitted to the host.
     *
     * @param needsConfirmation true for the five action classes of section 15 paragraph 13.
     * @return null when it may, or the refusal when it may not.
     */
    fun refusal(needsConfirmation: Boolean): VoiceAuthorityRefusal? {
        if (!capture.speechCouldHaveBeenHeard) {
            return VoiceAuthorityRefusal.SpeechNotHeard(capture)
        }
        if (needsConfirmation && !holdsUnlockedScreenConfirmation) {
            return VoiceAuthorityRefusal.NeedsUnlockedScreenConfirmation
        }
        return null
    }
}
