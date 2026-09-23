package to.kala.reach.companion.mobile

/**
 * The switches a call's media runs through on the platform.
 *
 * [VoiceCallControl] sets every one of them, from its gate, in one place, and nothing else sets
 * them. An implementation holds every switch off from the moment its connection exists, before
 * anything is negotiated, so there is no window in which the platform could start recording on its
 * own.
 */
interface VoiceMediaSwitches {
    /** Whether the platform's audio device runs at all: the recorder, and the player beside it. */
    fun setAudioDevice(on: Boolean)

    /** Whether what the recorder hears is carried to the provider. */
    fun setMicrophone(on: Boolean)

    /** Whether the provider's voice comes out of this device. */
    fun setPlayback(on: Boolean)
}

/** What a call needs from the platform besides its media. */
interface VoiceCallPlatform {
    /** This device's monotonic clock, in milliseconds. */
    fun nowMs(): Long

    /** The wall clock, in milliseconds since the epoch. */
    fun epochMs(): Long

    /** Takes audio focus for the call. False when the platform refuses it. */
    fun acquireFocus(): Boolean

    /** Gives audio focus back. */
    fun releaseFocus()

    /**
     * Asks for the foreground service that keeps the microphone through a screen lock.
     *
     * False, or an exception, when the platform refuses at once. Whether the service then entered
     * the foreground arrives later, through [VoiceCallControl.servicePromoted] or
     * [VoiceCallControl.serviceRefused].
     */
    fun startService(): Boolean

    /** Ends the service. Called only for a call that asked for one. */
    fun stopService()

    /**
     * Runs `task` once at `atMs` on the monotonic clock, on a thread of the call's own rather than
     * the main thread. The answer cancels it.
     */
    fun schedule(atMs: Long, task: () -> Unit): () -> Unit

    /** Tells the screen what the microphone is doing. */
    fun publish(state: VoiceCaptureState)

    /** Tells the notification what the microphone is doing. Called only once the service was asked for. */
    fun publishToService(state: VoiceCaptureState)

    /** The call has ended: whatever the platform holds for it, the connection first, goes now. */
    fun ended()
}

/**
 * A call's hold on the microphone, from the host's answer to the end of the call.
 *
 * Every decision about the microphone is made here, and the platform code around it only carries
 * the decisions out, so the tests run the same code the application does. A permitted call goes
 * through three steps, and capture waits for all of them:
 *
 * 1. [permit] takes the host's answer: the voice session and the moment the service closes the
 *    call. It refuses a stopped or already permitted call and an answer whose moment has passed,
 *    takes audio focus and asks for the foreground service. A refusal of either undoes both and ends
 *    the call. The call's end is scheduled for that moment, on the call's own thread.
 * 2. The service enters the foreground ([servicePromoted]). Only then is the gate permitted, with
 *    the clock read again, so time the platform took counts against the deadline instead of
 *    extending it.
 * 3. The platform's recorder reports itself running ([recorder]). Only then may capture carry
 *    speech.
 *
 * Every change ends in `apply`, the one place a switch is set. Any change made after the deadline
 * ends the call there and then, so a late timer never leaves the microphone open, and every frame
 * the recorder produces is asked about separately through [carries].
 *
 * Locks are taken in one order: this control's, then the platform's. A change holds this control's
 * lock while it sets the platform's switches, so nothing this control is asked while the platform
 * holds its own lock may wait for this one: [isStopped], [isPlaybackMuted], [isMutedByPerson],
 * [carries], [couldHaveHeard] and [displayed] never take it.
 */
class VoiceCallControl(
    private val platform: VoiceCallPlatform,
    private val switches: VoiceMediaSwitches,
    keptIntervals: Int = 64,
) {
    private data class Asked(val voiceSessionId: String, val deadlineMs: Long)

    private val lock = Any()
    private val gate = VoiceCaptureGate(keptIntervals)
    private var asked: Asked? = null
    private var deviceOn = false
    private var focusHeld = false
    private var serviceAsked = false
    private var cancelExpiry: (() -> Unit)? = null
    private var focusLost = false

    // Written under the lock, read without it: the platform code asks these while holding a lock of
    // its own, and a read that waited for this lock could wait for a change that is itself waiting
    // for the platform's lock.
    @Volatile
    private var playbackMuted = false

    @Volatile
    private var stopped = false

    init {
        switches.setMicrophone(false)
        switches.setPlayback(false)
        switches.setAudioDevice(false)
    }

    /** Whether the person muted their own microphone. */
    val isMutedByPerson: Boolean
        get() = gate.isMutedByPerson

    /** Whether the person silenced the provider's voice on this device. Never waits for a change. */
    val isPlaybackMuted: Boolean
        get() = playbackMuted

    /** Whether the call has ended. It never starts again. Never waits for a change. */
    val isStopped: Boolean
        get() = stopped

    /**
     * Takes the host's answer to the start: the voice session and the moment the service closes
     * the call, in milliseconds since the epoch.
     *
     * @return true when focus is held and the service was asked for; capture then waits for the
     * service to enter the foreground and for the recorder to start. False when the call is stopped
     * or already permitted, and false with the call ended when the moment has passed or the
     * platform refused focus or the service.
     */
    fun permit(voiceSessionId: String, closesAtEpochMs: Long): Boolean =
        synchronized(lock) {
            if (stopped || asked != null || gate.current != null) return false
            val now = platform.nowMs()
            val remaining = closesAtEpochMs - platform.epochMs()
            if (remaining <= 0) {
                stopLocked()
                return false
            }
            val deadline = now + minOf(remaining, LONGEST_CALL_MS)
            if (!platform.acquireFocus()) {
                stopLocked()
                return false
            }
            focusHeld = true
            val started = try {
                platform.startService()
            } catch (refused: RuntimeException) {
                false
            }
            // Asked for either way, so the end of the call stops whatever did start.
            serviceAsked = true
            if (!started || platform.nowMs() >= deadline) {
                stopLocked()
                return false
            }
            asked = Asked(voiceSessionId, deadline)
            cancelExpiry = platform.schedule(deadline) { stop() }
            true
        }

    /** The service entered the foreground. The gate is permitted now, if the answer still holds. */
    fun servicePromoted() {
        synchronized(lock) {
            val pending = asked ?: return
            asked = null
            if (stopped) return
            val now = platform.nowMs()
            if (gate.permit(pending.voiceSessionId, pending.deadlineMs, now) == null) {
                stopLocked()
                return
            }
            applyLocked(now)
        }
    }

    /** The service could not enter the foreground, so nothing may be recorded and the call ends. */
    fun serviceRefused() {
        synchronized(lock) { stopLocked() }
    }

    /**
     * The platform's recorder started, stopped or failed.
     *
     * A start counts only while the audio device is on; one reported while it is off is from before,
     * or from a device this call did not turn on.
     */
    fun recorder(running: Boolean) = change { now -> gate.recorder(running && deviceOn, now) }

    /** The person's own mute. Nothing the system does changes it. */
    fun setMutedByPerson(muted: Boolean) = change { now -> gate.setMutedByPerson(muted, now) }

    /** The person silencing the provider's voice, which changes playback and nothing else. */
    fun setPlaybackMuted(muted: Boolean) = change { playbackMuted = muted }

    /** Audio focus went to someone else, or came back. Losing it silences the speaker too. */
    fun focus(lost: Boolean) = change { now ->
        focusLost = lost
        gate.taken(if (lost) VoiceCaptureGate.Taken.FOCUS_LOST else VoiceCaptureGate.Taken.NONE, now)
    }

    /** The audio route, as the platform reports it. */
    fun route(changing: Boolean, inputAvailable: Boolean) = change { now ->
        gate.route(changing, inputAvailable, now)
    }

    /** Something about the media changed, such as a track arriving, and the switches are set again. */
    fun refresh() = change { }

    /**
     * Whether a frame the recorder has just produced may be carried.
     *
     * Asked on the audio thread for every frame, so capture ends at the deadline within one frame
     * whatever the timers are doing. It sets no switch: a switch set from the audio thread would
     * wait for the very thread that is asking.
     */
    fun carries(): Boolean = gate.captureEnabled(platform.nowMs())

    /** Whether the microphone was carrying speech at `atMs` on the monotonic clock. Never later than now. */
    fun couldHaveHeard(atMs: Long): Boolean = gate.couldHaveHeard(atMs, platform.nowMs())

    /** What the microphone is doing now. */
    fun displayed(): VoiceCaptureState = gate.displayed(platform.nowMs())

    /** Ends the call. Local and immediate, and the second time does nothing. */
    fun stop() {
        synchronized(lock) { stopLocked() }
    }

    private inline fun change(body: (Long) -> Unit) {
        synchronized(lock) {
            if (stopped) return
            val now = platform.nowMs()
            body(now)
            applyLocked(now)
        }
    }

    private fun applyLocked(now: Long) {
        if (gate.current != null && !gate.live(now)) {
            // The deadline passed. The scheduled end may be late or may never run; this change is
            // the call's end instead.
            stopLocked()
            return
        }
        val live = gate.live(now)
        if (live != deviceOn) {
            // A recorder is heard from afresh each time the device comes on: until the platform
            // reports it started, nothing is being recorded, and a report from before does not count.
            gate.recorder(false, now)
            deviceOn = live
        }
        val shown = gate.displayed(now)
        switches.setAudioDevice(live)
        switches.setMicrophone(gate.captureEnabled(now))
        switches.setPlayback(live && !playbackMuted && !focusLost)
        publishLocked(shown)
    }

    private fun stopLocked() {
        if (stopped) return
        stopped = true
        asked = null
        gate.stop(platform.nowMs())
        cancelExpiry?.invoke()
        cancelExpiry = null
        switches.setMicrophone(false)
        switches.setPlayback(false)
        switches.setAudioDevice(false)
        deviceOn = false
        if (focusHeld) {
            platform.releaseFocus()
            focusHeld = false
        }
        publishLocked(VoiceCaptureState.IDLE)
        if (serviceAsked) {
            platform.stopService()
            serviceAsked = false
        }
        platform.ended()
    }

    private fun publishLocked(state: VoiceCaptureState) {
        platform.publish(state)
        if (serviceAsked) platform.publishToService(state)
    }

    companion object {
        /** The furthest deadline a call is given: a day. No call runs that long. */
        const val LONGEST_CALL_MS = 86_400_000L
    }
}
