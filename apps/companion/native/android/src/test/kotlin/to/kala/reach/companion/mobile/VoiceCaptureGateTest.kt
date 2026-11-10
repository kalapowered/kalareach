package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Whether the microphone may carry speech, and what the person is told about it.
 *
 * KR-REQ-15.34 and KR-REQ-15.36: nothing opens the microphone without a fresh permitted call, and
 * muted or unavailable capture is displayed. KR-REQ-15.35: focus loss, a route change and a stop are
 * each their own state. KR-ACC-014: unheard speech never authorises, answered from the intervals
 * this device kept.
 */
class VoiceCaptureGateTest {
    /** A permitted gate whose recorder reported itself running at the same moment. */
    private fun permitted(nowMs: Long = 1_000, deadlineMs: Long = 61_000): Pair<VoiceCaptureGate, VoiceCaptureGate.Permit> {
        val gate = VoiceCaptureGate()
        val permit = gate.permit("voice-session-1", deadlineMs, nowMs)
        assertNotNull("a current answer permits the call", permit)
        gate.recording(VoiceCaptureGate.Recording.AUDIBLE, nowMs)
        gate.recorder(running = true, nowMs = nowMs)
        return gate to permit!!
    }

    /** KR-REQ-15.34: a call with no permit captures nothing, whatever else is true. */
    @Test
    fun nothing_is_captured_without_a_permit() {
        val gate = VoiceCaptureGate()
        assertFalse(gate.captureEnabled(1_000))
        assertEquals(VoiceCaptureState.IDLE, gate.displayed(1_000))
        gate.setMutedByPerson(false, 1_100)
        gate.taken(VoiceCaptureGate.Taken.NONE, 1_200)
        gate.route(changing = false, inputAvailable = true, nowMs = 1_300)
        gate.recorder(running = true, nowMs = 1_350)
        assertFalse("no event other than a permit opens the microphone", gate.captureEnabled(1_400))
        assertFalse(gate.live(1_400))
    }

    /**
     * KR-REQ-15.36: a permitted call captures nothing until the recorder reports itself running,
     * and says the microphone is unavailable until then and once it fails.
     */
    @Test
    fun capture_waits_for_the_recorder_and_ends_with_it() {
        val gate = VoiceCaptureGate()
        assertNotNull(gate.permit("voice-session-1", 61_000, 1_000))
        gate.recording(VoiceCaptureGate.Recording.AUDIBLE, 1_000)
        assertTrue(gate.live(1_000))
        assertFalse("the recorder has not started", gate.captureEnabled(1_000))
        assertEquals(VoiceCaptureState.UNAVAILABLE, gate.displayed(1_000))
        gate.recorder(running = true, nowMs = 1_200)
        assertTrue(gate.captureEnabled(1_200))
        assertEquals(VoiceCaptureState.CAPTURING, gate.displayed(1_200))
        gate.recorder(running = false, nowMs = 5_000)
        assertFalse("a recorder that failed hears nothing", gate.captureEnabled(5_000))
        assertEquals(VoiceCaptureState.UNAVAILABLE, gate.displayed(5_000))
        assertFalse(gate.couldHaveHeard(1_100, 6_000))
        assertTrue(gate.couldHaveHeard(1_200, 6_000))
        assertFalse(gate.couldHaveHeard(5_000, 6_000))
    }

    /** KR-REQ-15.34: a permit is given once, by an answer that is still current. */
    @Test
    fun a_permit_is_refused_when_stale_repeated_or_after_a_stop() {
        assertNull(VoiceCaptureGate().permit("s", deadlineMs = 1_000, nowMs = 1_000))

        val (gate, _) = permitted()
        assertNull("a second permit over a held one", gate.permit("s-2", 90_000, 2_000))

        gate.stop(3_000)
        assertNull("a stopped gate never opens again", gate.permit("s-3", 90_000, 4_000))
        assertFalse(gate.captureEnabled(4_000))
    }

    /** KR-REQ-15.34: capture ends at the deadline with no event at all, and the record says so. */
    @Test
    fun capture_ends_at_the_deadline_by_itself() {
        val (gate, _) = permitted(nowMs = 1_000, deadlineMs = 11_000)
        assertTrue(gate.captureEnabled(10_999))
        assertFalse(gate.captureEnabled(11_000))
        assertFalse(gate.live(11_000))
        assertEquals(VoiceCaptureState.IDLE, gate.displayed(15_000))
        assertTrue(gate.couldHaveHeard(10_999, 15_000))
        assertFalse(
            "capture ended at the deadline, not when it was next asked",
            gate.couldHaveHeard(12_000, 15_000),
        )
    }

    /** KR-ACC-014: a running permit vouches for nothing that has not happened yet. */
    @Test
    fun a_future_instant_is_never_vouched_for() {
        val (gate, _) = permitted(nowMs = 1_000, deadlineMs = 61_000)
        assertTrue(gate.captureEnabled(1_000))
        assertFalse("permission to capture is not a record of speech", gate.couldHaveHeard(50_000, 1_000))
        assertTrue(gate.couldHaveHeard(1_000, 1_000))
        assertTrue(gate.couldHaveHeard(20_000, 30_000))
    }

    /**
     * KR-REQ-15.35: the person's mute and the system taking the microphone are kept apart.
     * Unmuting while another application holds focus does not open the microphone, and regaining
     * focus restores what the person chose.
     */
    @Test
    fun the_persons_mute_and_the_system_are_separate() {
        val (gate, _) = permitted()
        gate.taken(VoiceCaptureGate.Taken.FOCUS_LOST, 2_000)
        assertEquals(VoiceCaptureState.FOCUS_LOST, gate.displayed(2_000))

        gate.setMutedByPerson(false, 2_100)
        assertFalse("unmuting during a focus loss must not open capture", gate.captureEnabled(2_200))

        gate.setMutedByPerson(true, 2_300)
        gate.taken(VoiceCaptureGate.Taken.NONE, 2_400)
        assertFalse("focus came back to a microphone the person muted", gate.captureEnabled(2_500))
        assertEquals(VoiceCaptureState.MUTED_BY_PERSON, gate.displayed(2_500))

        gate.setMutedByPerson(false, 2_600)
        assertTrue(gate.captureEnabled(2_700))
    }

    /** KR-REQ-15.35 and 15.36: a route in change or without an input keeps capture off and says so. */
    @Test
    fun a_route_change_and_a_missing_input_keep_capture_off() {
        val (gate, _) = permitted()
        gate.route(changing = true, inputAvailable = true, nowMs = 2_000)
        assertEquals(VoiceCaptureState.ROUTE_CHANGING, gate.displayed(2_000))
        assertFalse(gate.captureEnabled(2_000))

        gate.route(changing = false, inputAvailable = false, nowMs = 3_000)
        assertEquals(VoiceCaptureState.UNAVAILABLE, gate.displayed(3_000))
        assertFalse(gate.captureEnabled(3_000))

        gate.route(changing = false, inputAvailable = true, nowMs = 4_000)
        assertTrue(gate.captureEnabled(4_000))
    }

    /** KR-REQ-15.35: a revocation names its generation, and a late one for an older call is refused. */
    @Test
    fun only_the_current_generation_can_be_revoked() {
        val (gate, permit) = permitted()
        assertFalse(gate.revoke(permit.generation - 1, 2_000))
        assertTrue(gate.captureEnabled(2_000))
        assertTrue(gate.revoke(permit.generation, 3_000))
        assertFalse(gate.captureEnabled(3_000))
        assertNull(gate.current)
    }

    /** KR-ACC-014: what was said is checked against when the microphone was on, and nothing else. */
    @Test
    fun speech_is_vouched_for_only_inside_the_kept_intervals() {
        val (gate, _) = permitted(nowMs = 1_000, deadlineMs = 100_000)
        gate.setMutedByPerson(true, 5_000)
        gate.setMutedByPerson(false, 9_000)

        assertTrue(gate.couldHaveHeard(1_000, 10_000))
        assertTrue(gate.couldHaveHeard(4_999, 10_000))
        assertFalse("muted from 5 s to 9 s", gate.couldHaveHeard(5_000, 10_000))
        assertFalse(gate.couldHaveHeard(8_999, 10_000))
        assertTrue("the interval capture is in now", gate.couldHaveHeard(9_000, 10_000))
        assertFalse("before the call was permitted", gate.couldHaveHeard(999, 10_000))

        val bounded = VoiceCaptureGate(keptIntervals = 2)
        bounded.permit("s", 100_000, 0)
        bounded.recording(VoiceCaptureGate.Recording.AUDIBLE, 0)
        bounded.recorder(running = true, nowMs = 0)
        for (start in listOf(10_000L, 20_000L, 30_000L)) {
            bounded.setMutedByPerson(true, start)
            bounded.setMutedByPerson(false, start + 5_000)
        }
        assertFalse(
            "an interval older than the record reaches is not vouched for",
            bounded.couldHaveHeard(1_000, 40_000),
        )
        assertTrue(bounded.couldHaveHeard(26_000, 40_000))
    }

    /**
     * KR-REQ-15.36: what the person is told and whether anything could be heard never disagree,
     * in every combination of the inputs.
     */
    @Test
    fun the_display_and_the_microphone_agree_in_every_combination() {
        for (muted in listOf(false, true)) {
            for (taken in VoiceCaptureGate.Taken.entries) {
                for (changing in listOf(false, true)) {
                    for (input in listOf(false, true)) {
                        for (recording in listOf(false, true)) {
                            val (gate, _) = permitted()
                            gate.setMutedByPerson(muted, 2_000)
                            gate.taken(taken, 2_000)
                            gate.route(changing, input, 2_000)
                            gate.recorder(recording, 2_000)
                            assertEquals(
                                "muted=$muted taken=$taken changing=$changing input=$input " +
                                    "recording=$recording",
                                gate.captureEnabled(3_000),
                                gate.displayed(3_000).speechCouldHaveBeenHeard,
                            )
                        }
                    }
                }
            }
        }
    }

    /**
     * KR-REQ-15.36: the gate counts every opening and every break of capture itself, under its own
     * lock, so whether capture was unbroken is read from this record and not from news told after
     * the moment it is about.
     */
    @Test
    fun the_record_counts_every_opening_and_every_break() {
        val gate = VoiceCaptureGate()
        assertEquals(VoiceCaptureGate.Proof(VoiceCaptureState.IDLE, false, 0, 0, null), gate.proof(500))
        gate.permit("voice-session-1", 61_000, 1_000)
        gate.recording(VoiceCaptureGate.Recording.AUDIBLE, 1_000)
        assertEquals("a permit alone opens nothing", 0L, gate.proof(1_000).openings)
        gate.recorder(running = true, nowMs = 1_200)
        assertEquals(VoiceCaptureGate.Proof(VoiceCaptureState.CAPTURING, true, 1, 0, null), gate.proof(1_200))

        gate.setMutedByPerson(true, 2_000)
        assertEquals(VoiceCaptureGate.Proof(VoiceCaptureState.MUTED_BY_PERSON, true, 1, 1, null), gate.proof(2_000))
        gate.setMutedByPerson(true, 2_100)
        assertEquals("a change that changes nothing is no break", 1L, gate.proof(2_100).breaks)
        gate.setMutedByPerson(false, 3_000)
        assertEquals(VoiceCaptureGate.Proof(VoiceCaptureState.CAPTURING, true, 2, 1, null), gate.proof(3_000))
    }

    /**
     * KR-REQ-15.36: whatever takes capture off after it opened is one break, whichever way it goes:
     * the person, the system, the system's silencing, a route, the recorder, a withdrawn permit, the
     * end and the deadline.
     */
    @Test
    fun every_way_capture_goes_off_after_an_opening_is_one_break() {
        val closes = listOf<Pair<String, (VoiceCaptureGate) -> Unit>>(
            "the person's mute" to { it.setMutedByPerson(true, 2_000) },
            "focus lost" to { it.taken(VoiceCaptureGate.Taken.FOCUS_LOST, 2_000) },
            "a suspension" to { it.taken(VoiceCaptureGate.Taken.SUSPENDED, 2_000) },
            "the system silencing the recording" to { it.recording(VoiceCaptureGate.Recording.SILENCED, 2_000) },
            "the system reporting none" to { it.recording(VoiceCaptureGate.Recording.UNREPORTED, 2_000) },
            "a route in change" to { it.route(changing = true, inputAvailable = true, nowMs = 2_000) },
            "a missing input" to { it.route(changing = false, inputAvailable = false, nowMs = 2_000) },
            "the recorder stopping" to { it.recorder(running = false, nowMs = 2_000) },
            "a withdrawn permit" to { it.revoke(1, 2_000) },
            "the end of the call" to { it.stop(2_000) },
            "the deadline" to { it.captureEnabled(61_000) },
        )
        // Each proof is read just after its close, well before the permit's deadline, which closes
        // capture by itself: only the deadline's own case is read at the deadline.
        val failed = closes.mapNotNull { (name, close) ->
            val (gate, _) = permitted()
            close(gate)
            val proof = gate.proof(if (name == "the deadline") 61_000 else 2_000)
            val closedOnce = proof.openings == 1L && proof.breaks == 1L && proof.opened &&
                proof.state != VoiceCaptureState.CAPTURING
            if (closedOnce) null else "$name: $proof"
        }
        assertEquals("these did not close capture as one break", emptyList<String>(), failed)
    }

    /**
     * KR-REQ-15.36: two buffers from the recorder more than 40 ms apart while capture is on are a
     * break, whether the call's state changed or not; 40 ms and less are not. A 60 ms gap is one.
     */
    @Test
    fun a_gap_of_more_than_forty_milliseconds_between_two_buffers_is_a_break() {
        val (gate, _) = permitted(nowMs = 1_000, deadlineMs = 61_000)
        for (at in 1_010L..1_100L step 10) assertTrue(gate.buffered(at))
        assertEquals("buffers every 10 ms are no break", 0L, gate.proof(1_100).breaks)

        assertTrue(gate.buffered(1_140))
        assertEquals("a wait of exactly 40 ms is no break", 0L, gate.proof(1_140).breaks)
        assertTrue(gate.buffered(1_181))
        assertEquals("41 ms is one", 1L, gate.proof(1_181).breaks)

        assertTrue(gate.buffered(1_191))
        assertTrue(gate.buffered(1_251))
        val proof = gate.proof(1_251)
        assertEquals("a 60 ms gap is a second break", 2L, proof.breaks)
        assertEquals("and the state never changed", VoiceCaptureState.CAPTURING, proof.state)
        assertEquals(1L, proof.openings)
    }

    /**
     * KR-REQ-15.36: a buffer is carried only while capture is on, and a wait that spans a closed gate
     * is no break: nothing was carried then, and the first buffer after an opening is where the
     * counting starts.
     */
    @Test
    fun a_wait_that_spans_a_closed_gate_is_no_break_and_a_closed_gate_carries_nothing() {
        val (gate, _) = permitted(nowMs = 1_000, deadlineMs = 61_000)
        assertTrue(gate.buffered(1_010))
        gate.setMutedByPerson(true, 1_020)
        assertFalse("a muted microphone carries nothing", gate.buffered(1_030))
        gate.setMutedByPerson(false, 1_500)
        assertTrue(gate.buffered(1_510))
        val proof = gate.proof(1_510)
        assertEquals("the mute is the one break", 1L, proof.breaks)
        assertEquals(2L, proof.openings)
        assertEquals("only the first buffer after the opening is seen so far", 0L, proof.progressAgeMs)
    }

    /** KR-REQ-15.36: the proof says how long ago a buffer was last seen, and nothing before one was. */
    @Test
    fun the_proof_says_how_long_ago_a_buffer_was_seen() {
        val (gate, _) = permitted(nowMs = 1_000, deadlineMs = 61_000)
        assertEquals(null, gate.proof(1_005).progressAgeMs)
        gate.buffered(1_010)
        assertEquals(5L, gate.proof(1_015).progressAgeMs)
        assertEquals("it ages with the clock", 490L, gate.proof(1_500).progressAgeMs)
        gate.setMutedByPerson(true, 1_600)
        gate.setMutedByPerson(false, 1_700)
        assertEquals("a new opening starts with none seen", null, gate.proof(1_700).progressAgeMs)
    }

    /**
     * KR-REQ-15.36: a recording the system silences closes the gate and shows the microphone paused
     * by the system, and a phone that reports nothing of the recording is refused, as is the first
     * moment of a recorder the system has not reported yet.
     */
    @Test
    fun a_silenced_recording_closes_the_gate_and_shows_the_system_paused_the_microphone() {
        val gate = VoiceCaptureGate()
        gate.permit("voice-session-1", 61_000, 1_000)
        gate.recorder(running = true, nowMs = 1_000)
        assertFalse("the system has not reported the recording", gate.captureEnabled(1_100))
        assertEquals(VoiceCaptureState.UNAVAILABLE, gate.displayed(1_100))
        assertEquals(0L, gate.proof(1_100).openings)

        gate.recording(VoiceCaptureGate.Recording.AUDIBLE, 1_200)
        assertTrue(gate.captureEnabled(1_200))
        gate.recording(VoiceCaptureGate.Recording.SILENCED, 1_300)
        assertFalse(gate.captureEnabled(1_300))
        assertEquals(VoiceCaptureState.SUSPENDED_BY_SYSTEM, gate.displayed(1_300))
        assertFalse(gate.buffered(1_310))

        gate.recording(VoiceCaptureGate.Recording.AUDIBLE, 1_400)
        val proof = gate.proof(1_400)
        assertEquals(VoiceCaptureState.CAPTURING, proof.state)
        assertEquals("the silence was one break and the return a second opening", 1L, proof.breaks)
        assertEquals(2L, proof.openings)
    }

    /**
     * What the system lists of the recordings, and which of them is this call's: those from its source
     * whose sessions the system held when its audio device came on are other applications', and any
     * other from the source is its own.
     */
    @Test
    fun the_recording_of_the_call_is_the_one_from_its_source_that_was_not_there_when_the_device_came_on() {
        val call = 7
        val watch = RecordingWatch(call)
        watch.deviceComesOn(emptyList())
        assertEquals(
            "the device is on and the system lists no recording",
            VoiceCaptureGate.Recording.UNREPORTED,
            watch.read(emptyList()),
        )
        assertEquals(
            "another source's recording is not this call's",
            VoiceCaptureGate.Recording.UNREPORTED,
            watch.read(listOf(RecordingReport(source = 1, silenced = false, session = 9))),
        )
        assertEquals(
            VoiceCaptureGate.Recording.AUDIBLE,
            watch.read(listOf(RecordingReport(1, true, 9), RecordingReport(call, false, 2))),
        )
        assertEquals(
            VoiceCaptureGate.Recording.SILENCED,
            watch.read(listOf(RecordingReport(call, true, 2))),
        )
    }

    /**
     * KR-REQ-15.36: another application's recording from the call's source, held when the call's own
     * recorder was turned on, does not stand in for the call's, whatever becomes of it: with nothing
     * else listed the call's recording is not reported, and what the system does to theirs, silencing
     * it or ending it, does not change what is said of ours.
     */
    @Test
    fun another_applications_recording_from_the_same_source_is_not_the_calls_own() {
        val call = 7
        val watch = RecordingWatch(call)
        val theirs = RecordingReport(call, silenced = false, session = 1)
        val ours = RecordingReport(call, silenced = false, session = 2)
        watch.deviceComesOn(listOf(theirs))

        assertEquals(
            "a list that holds only theirs",
            VoiceCaptureGate.Recording.UNREPORTED,
            watch.read(listOf(theirs)),
        )
        assertEquals(
            "a silenced recording of theirs is not ours either",
            VoiceCaptureGate.Recording.UNREPORTED,
            watch.read(listOf(theirs.copy(silenced = true))),
        )
        assertEquals(
            "theirs and ours",
            VoiceCaptureGate.Recording.AUDIBLE,
            watch.read(listOf(theirs, ours)),
        )
        assertEquals(
            "theirs silenced, ours not",
            VoiceCaptureGate.Recording.AUDIBLE,
            watch.read(listOf(theirs.copy(silenced = true), ours)),
        )
        assertEquals(
            "theirs ended while ours runs",
            VoiceCaptureGate.Recording.AUDIBLE,
            watch.read(listOf(ours)),
        )
        assertEquals(
            "ours silenced, theirs not",
            VoiceCaptureGate.Recording.SILENCED,
            watch.read(listOf(theirs, ours.copy(silenced = true))),
        )
    }
}
