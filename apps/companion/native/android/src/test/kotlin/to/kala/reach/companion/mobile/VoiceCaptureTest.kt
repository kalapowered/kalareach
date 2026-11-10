package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the microphone's state means for authority.
 *
 * KR-REQ-15.36 and KR-ACC-014: muted or unavailable capture is displayed, and a claim that
 * unreceived speech authorised an action is rejected. The gate also refuses an action that needs
 * a confirmation on the unlocked screen while the phone holds none.
 */
class VoiceCaptureTest {
    private val notCapturing = listOf(
        VoiceCaptureState.MUTED_BY_PERSON,
        VoiceCaptureState.FOCUS_LOST,
        VoiceCaptureState.ROUTE_CHANGING,
        VoiceCaptureState.SUSPENDED_BY_SYSTEM,
        VoiceCaptureState.UNAVAILABLE,
        VoiceCaptureState.IDLE,
    )

    /** KR-REQ-15.36: only an open microphone could have heard anything. */
    @Test
    fun only_capturing_could_have_heard_speech() {
        assertTrue(VoiceCaptureState.CAPTURING.speechCouldHaveBeenHeard)
        notCapturing.forEach {
            assertFalse("$it is not a state in which the person was heard", it.speechCouldHaveBeenHeard)
        }
    }

    /** KR-REQ-15.36: every state a person can be in is displayed, and none of them reads as a code. */
    @Test
    fun every_state_says_something_a_person_can_read() {
        VoiceCaptureState.entries.forEach {
            assertTrue(it.display.isNotBlank())
            assertFalse("${it.display} reads as a fault, not a state", it.display.contains("error"))
            assertEquals(it.display, it.display.trim())
        }
    }
}
