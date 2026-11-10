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
 * - the system reports the call's recording and has not silenced it. A phone that reports no
 *   recording of the call is refused, as one that silences it is, and the display says the
 *   system paused the microphone;
 * - the call has not been stopped. A stopped gate never opens again.
 *
 * It also keeps the intervals in which capture was on, so a claim that something was said when
 * nothing could have been heard is refused from this device's own record rather than from anything
 * that arrived over the call. The record answers for the past only: an instant later than the time
 * it is asked at is not one anything was heard in.
 *
 * It also counts, for the call's life, how many times capture opened and how many times it was
 * broken (it went off after an opening, or what the recorder delivered showed a gap), so whether
 * capture was unbroken is read from this record under the one lock and not from news told after
 * the moment it is about.
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

    /** What the system reports of the call's recording, apart from anything the person chose. */
    enum class Recording {
        /** The system has not reported a recording of this call, or reports none. */
        UNREPORTED,

        /** The system reports the recording, and the audio reaches the call. */
        AUDIBLE,

        /** The system reports the recording and silences it: another application holds the microphone. */
        SILENCED,
    }

    /**
     * What this gate has recorded of capture, read in one step under its lock.
     *
     * [opened] is true from the first opening to the end of the call. [progressAgeMs] is how long ago
     * the freshest buffer from the recorder was seen since capture last opened, or null when none has
     * been.
     */
    data class Proof(
        val state: VoiceCaptureState,
        val opened: Boolean,
        val openings: Long,
        val breaks: Long,
        val progressAgeMs: Long?,
    )

    private var generation = 0L
    private var permit: Permit? = null
    private var mutedByPerson = false
    private var taken = Taken.NONE
    private var routeChanging = false
    private var inputAvailable = true
    private var recorderRunning = false
    private var recording = Recording.UNREPORTED
    private var stopped = false

    /** Where the interval capture is in now began, and the deadline it cannot outlast. */
    private var openedAtMs: Long? = null
    private var openedUntilMs: Long = Long.MAX_VALUE
    private val heard = ArrayDeque<LongRange>()

    /** How many times capture went from off to on in this call, the first opening included. */
    private var openings = 0L

    /** How many times capture was broken: it went off after an opening, or showed a gap in progress. */
    private var breaks = 0L

    /** When the freshest buffer from the recorder was seen since capture last opened, or null. */
    private var progressAtMs: Long? = null

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

    /**
     * What the system reports of the call's recording. Capture is on only while it reports the
     * recording and does not silence it, so a recording it has said nothing of yet is not taken for
     * one it has not silenced.
     */
    @Synchronized
    fun recording(state: Recording, nowMs: Long) {
        recording = state
        settle(nowMs)
    }

    /**
     * A buffer arrived from the recorder, at `nowMs`. Answers whether it may be carried, as
     * [captureEnabled] does, and notes the arrival: two buffers that arrive while capture is on more
     * than [MAX_BUFFER_GAP_MS] apart are a break, since audio was lost between them that no state
     * change tells. The first buffer after capture opens is where the counting starts.
     */
    @Synchronized
    fun buffered(nowMs: Long): Boolean {
        settle(nowMs)
        val on = enabled(nowMs)
        if (on) {
            val previous = progressAtMs
            if (previous != null && nowMs - previous > MAX_BUFFER_GAP_MS) breaks += 1
            progressAtMs = nowMs
        }
        return on
    }

    /** What this gate has recorded of capture, as it stands at `nowMs`. */
    @Synchronized
    fun proof(nowMs: Long): Proof {
        settle(nowMs)
        return Proof(
            state = shown(nowMs),
            opened = openings > 0,
            openings = openings,
            breaks = breaks,
            progressAgeMs = progressAtMs?.let { nowMs - minOf(it, nowMs) },
        )
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
     * Whether the call's microphone track may be on: a permit is running, and neither the person nor
     * the system has closed the microphone.
     *
     * Unlike [captureEnabled] it never asks whether the recorder runs or whether the system lists the
     * call's recording. The recorder runs only while the track is on, so a track that waited for the
     * recorder would stay off once the recorder stopped with it, and nothing, the person's unmute
     * included, would bring capture back. What the recorder hands the call is still carried only
     * while [captureEnabled] holds.
     */
    @Synchronized
    fun microphoneWanted(nowMs: Long): Boolean {
        settle(nowMs)
        return microphoneIsOpen(nowMs)
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
        return shown(nowMs)
    }

    /** What is displayed at `nowMs`, after [settle], under the lock. */
    private fun shown(nowMs: Long): VoiceCaptureState {
        val held = permit
        // What the system did is said first: it is why the recorder stopped, when it did.
        return when {
            stopped || held == null || nowMs >= held.deadlineMs -> VoiceCaptureState.IDLE
            taken == Taken.FOCUS_LOST -> VoiceCaptureState.FOCUS_LOST
            taken == Taken.SUSPENDED -> VoiceCaptureState.SUSPENDED_BY_SYSTEM
            recording == Recording.SILENCED -> VoiceCaptureState.SUSPENDED_BY_SYSTEM
            routeChanging -> VoiceCaptureState.ROUTE_CHANGING
            !inputAvailable || !recorderRunning || recording == Recording.UNREPORTED ->
                VoiceCaptureState.UNAVAILABLE
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

    /** What the person and the system leave open, whatever the recorder is doing. */
    private fun microphoneIsOpen(nowMs: Long): Boolean {
        val held = permit ?: return false
        return !stopped &&
            nowMs < held.deadlineMs &&
            !mutedByPerson &&
            taken == Taken.NONE &&
            !routeChanging &&
            inputAvailable
    }

    private fun enabled(nowMs: Long): Boolean =
        microphoneIsOpen(nowMs) && recorderRunning && recording == Recording.AUDIBLE

    /** Opens or closes the interval capture is in, to match what is true now. */
    private fun settle(nowMs: Long) {
        val on = enabled(nowMs)
        val open = openedAtMs
        if (on && open == null) {
            openedAtMs = nowMs
            openedUntilMs = permit?.deadlineMs ?: nowMs
            openings += 1
            progressAtMs = null
        } else if (!on && open != null) {
            breaks += 1
            progressAtMs = null
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

    companion object {
        /**
         * The longest time that may pass between two buffers from the recorder while capture is on,
         * in milliseconds. A recorder delivers a buffer every few milliseconds, so a longer wait is
         * audio that was lost. A test parameter, not a safety bound.
         */
        const val MAX_BUFFER_GAP_MS = 40L
    }
}

/**
 * What the system reports of one recording: where its audio comes from, whether it is silenced, and
 * the audio session of the application that records it.
 */
data class RecordingReport(val source: Int, val silenced: Boolean, val session: Int)

/**
 * What the system's lists of active recordings say of this call's recording.
 *
 * The call's recorder takes its audio from [callSource]. The system shows an application a stripped
 * copy of the recordings of the others, which still carries the audio session of each, so the
 * recordings from [callSource] that the system held when this call's audio device was turned on are
 * told by their sessions: they belong to other applications and are left out, silenced or not, so
 * one that ends later, or that the system silences, says nothing of this call. Any other recording
 * from [callSource] is this call's. A list with none is a phone that reports none of ours, and is
 * refused. A silenced recording among ours is a break that did not happen, never one that was hidden.
 *
 * What a session cannot tell, and leaves open for a physical phone: another application that starts
 * recording from the same source after this call's device is on, and before the system lists this
 * call's own recording, has a session that is not in the baseline and reads as this call's; the call
 * does not know its own recorder's session. A phone whose lists give every recording the same session
 * would refuse this call whenever another application records at the baseline.
 */
class RecordingWatch(private val callSource: Int) {
    /** The sessions of the recordings from the call's source the system held when its device came on. */
    private var otherSessions: Set<Int> = emptySet()

    /**
     * Takes the system's list of active recordings at the moment this call's audio device is turned
     * on, before it records: every recording from the call's source in it belongs to another application.
     */
    fun deviceComesOn(reports: List<RecordingReport>) {
        otherSessions = reports.filter { it.source == callSource }.map { it.session }.toSet()
    }

    /** Reads one list of the system's active recordings while this call's audio device runs. */
    fun read(reports: List<RecordingReport>): VoiceCaptureGate.Recording {
        val ours = reports.filter { it.source == callSource && it.session !in otherSessions }
        return when {
            ours.isEmpty() -> VoiceCaptureGate.Recording.UNREPORTED
            ours.any { it.silenced } -> VoiceCaptureGate.Recording.SILENCED
            else -> VoiceCaptureGate.Recording.AUDIBLE
        }
    }
}
