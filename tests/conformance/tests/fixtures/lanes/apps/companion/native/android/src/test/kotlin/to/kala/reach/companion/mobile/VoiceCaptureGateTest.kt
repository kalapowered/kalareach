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
}
