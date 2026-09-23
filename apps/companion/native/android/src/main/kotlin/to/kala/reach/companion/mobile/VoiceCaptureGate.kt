package to.kala.reach.companion.mobile

/**
 * Whether the microphone may carry the person's voice, decided in one place.
 *
 * Section 15 paragraphs 21 and 22 ask for two things at once: a call the person started keeps its
 * microphone through a screen lock, and nothing opens the microphone without a fresh permitted
 * active-call context. This class is the second half. Capture is on only while every one of these
 * holds, and each is kept apart from the others so that none of them can stand in for another:
 *
 * - a permit: the host answered a start with a voice session and a deadline, and the call applied
 *   that answer. A permit belongs to one generation, and a revocation naming an older generation is
 *   refused, so one that arrives late cannot touch the call that replaced the one it was about;
 * - the deadline, on this device's monotonic clock, has not passed;
 * - the person has not muted the microphone;
 * - the system has not taken it: audio focus lost to another application or a phone call, or
 *   capture suspended;
 * - the audio route is settled on a device that has an input;
 * - the platform's recorder reports itself running. Until it starts, and after it stops or fails,
 *   nothing is being recorded, and the display says the microphone is unavailable rather than on;
 * - the call has not been stopped. A stopped gate never opens again.
 *
 * It also keeps the intervals in which capture was on, so a claim that something was said when
 * nothing could have been heard is refused from this device's own record rather than from anything
 * that arrived over the call. The record answers for the past only: an instant later than the time
 * it is asked at is not one anything was heard in.
 *
 * Every method takes the time from its caller, on the monotonic clock, so the tests drive time
 * instead of waiting for it, and nothing here touches an Android class. Every method is
 * synchronised: the platform reports focus, routes and the notification's actions on threads of
 * its own, and the one answer to "is the microphone on" cannot be assembled from two halves.
 */
class VoiceCaptureGate(private val keptIntervals: Int = 64) {
    /** One permitted call, as the host's answer to a start bound it. */
    data class Permit(val generation: Long, val voiceSessionId: String, val deadlineMs: Long)

    /** What the system has done to the microphone, apart from anything the person chose. */
    enum class Taken {
        /** Nothing. */
        NONE,

        /** Audio focus went to another application or to a phone call. */
        FOCUS_LOST,

        /** The system suspended capture. */
        SUSPENDED,
    }

    private var generation = 0L
    private var permit: Permit? = null
    private var mutedByPerson = false
    private var taken = Taken.NONE
    private var routeChanging = false
    private var inputAvailable = true
    private var recorderRunning = false
    private var stopped = false

    /** Where the interval capture is in now began, and the deadline it cannot outlast. */
    private var openedAtMs: Long? = null
    private var openedUntilMs: Long = Long.MAX_VALUE
    private val heard = ArrayDeque<LongRange>()

    /** The permit capture runs under now, or null. */
    @get:Synchronized
    val current: Permit?
        get() = permit

    /** Whether the person muted the microphone. Unchanged by anything the system does. */
    @get:Synchronized
    val isMutedByPerson: Boolean
        get() = mutedByPerson

    /** Whether the gate was stopped. It does not open again after that. */
    @get:Synchronized
    val isStopped: Boolean
        get() = stopped

    /**
     * Binds the gate to the host's answer, and returns the permit.
     *
     * Null when the gate is stopped, when it already holds a permit, or when the deadline has
     * already passed: a call is permitted once, by an answer that is still current.
     */
    @Synchronized
    fun permit(voiceSessionId: String, deadlineMs: Long, nowMs: Long): Permit? {
        if (stopped || permit != null || deadlineMs <= nowMs) return null
        generation += 1
        val made = Permit(generation, voiceSessionId, deadlineMs)
        permit = made
        settle(nowMs)
        return made
    }

    /** Withdraws the permit of one generation. False, and nothing changed, for any other. */
    @Synchronized
    fun revoke(generation: Long, nowMs: Long): Boolean {
        val held = permit ?: return false
        if (held.generation != generation) return false
        permit = null
        settle(nowMs)
        return true
    }

    /** The person's own mute. What the system does to the microphone never changes it. */
    @Synchronized
    fun setMutedByPerson(muted: Boolean, nowMs: Long) {
        mutedByPerson = muted
        settle(nowMs)
    }

    /** What the system has done to the microphone. */
    @Synchronized
    fun taken(by: Taken, nowMs: Long) {
        taken = by
        settle(nowMs)
    }

    /** The audio route, as the platform reports it. */
    @Synchronized
    fun route(changing: Boolean, inputAvailable: Boolean, nowMs: Long) {
        routeChanging = changing
        this.inputAvailable = inputAvailable
        settle(nowMs)
    }

    /**
     * Whether the platform's recorder is running, as the platform reports it.
     *
     * Reported by the audio device itself: when it starts, when it stops and when it fails. A
     * recorder that has not started heard nothing, whatever the call was permitted to do.
     */
    @Synchronized
    fun recorder(running: Boolean, nowMs: Long) {
        recorderRunning = running
        settle(nowMs)
    }

    /** Stops the gate for good. */
    @Synchronized
    fun stop(nowMs: Long) {
        stopped = true
        permit = null
        settle(nowMs)
    }

    /** Whether the microphone may carry speech now. */
    @Synchronized
    fun captureEnabled(nowMs: Long): Boolean {
        settle(nowMs)
        return enabled(nowMs)
    }

    /**
     * What a person is told about the microphone now.
     *
     * [VoiceCaptureState.CAPTURING] exactly when [captureEnabled] is true, so the display and the
     * refusal of unheard speech can never disagree.
     */
    @Synchronized
    fun displayed(nowMs: Long): VoiceCaptureState {
        settle(nowMs)
        val held = permit
        // What the system did is said first: it is why the recorder stopped, when it did.
        return when {
            stopped || held == null || nowMs >= held.deadlineMs -> VoiceCaptureState.IDLE
            taken == Taken.FOCUS_LOST -> VoiceCaptureState.FOCUS_LOST
            taken == Taken.SUSPENDED -> VoiceCaptureState.SUSPENDED_BY_SYSTEM
            routeChanging -> VoiceCaptureState.ROUTE_CHANGING
            !inputAvailable || !recorderRunning -> VoiceCaptureState.UNAVAILABLE
            mutedByPerson -> VoiceCaptureState.MUTED_BY_PERSON
            else -> VoiceCaptureState.CAPTURING
        }
    }

    /**
     * Whether the microphone was carrying speech at `atMs`, asked at `nowMs`.
     *
     * Answered from the intervals this gate kept. An instant later than `nowMs` answers false: a
     * permit that is still running is permission to capture, not a record that anything was heard.
     * An instant older than the oldest kept interval answers false too: a record that no longer
     * reaches back that far cannot vouch for it.
     */
    @Synchronized
    fun couldHaveHeard(atMs: Long, nowMs: Long): Boolean {
        settle(nowMs)
        if (atMs > nowMs) return false
        val open = openedAtMs
        if (open != null && atMs >= open && atMs < openedUntilMs) return true
        return heard.any { atMs in it }
    }

    /**
     * Whether a permit is running: given, not withdrawn, not stopped and not past its deadline.
     *
     * What the platform's audio device is allowed to run for. Whether the microphone carries
     * speech is [captureEnabled]'s, which asks everything else as well.
     */
    @Synchronized
    fun live(nowMs: Long): Boolean {
        val held = permit ?: return false
        return !stopped && nowMs < held.deadlineMs
    }

    private fun enabled(nowMs: Long): Boolean {
        val held = permit ?: return false
        return !stopped &&
            nowMs < held.deadlineMs &&
            !mutedByPerson &&
            taken == Taken.NONE &&
            !routeChanging &&
            inputAvailable &&
            recorderRunning
    }

    /** Opens or closes the interval capture is in, to match what is true now. */
    private fun settle(nowMs: Long) {
        val on = enabled(nowMs)
        val open = openedAtMs
        if (on && open == null) {
            openedAtMs = nowMs
            openedUntilMs = permit?.deadlineMs ?: nowMs
        } else if (!on && open != null) {
            // Capture that ran out at the deadline ended there, not whenever somebody next asked.
            val end = minOf(nowMs, openedUntilMs)
            if (end > open) {
                heard.addLast(open until end)
                while (heard.size > keptIntervals) heard.removeFirst()
            }
            openedAtMs = null
            openedUntilMs = Long.MAX_VALUE
        }
    }
}
