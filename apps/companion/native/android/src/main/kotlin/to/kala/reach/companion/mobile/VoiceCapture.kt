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
