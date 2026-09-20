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
 * unreceived speech authorised an action is rejected. KR-REQ-15.13: an action that needs a
 * confirmation on the unlocked screen does not proceed without one.
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

    /**
     * KR-REQ-15.36, KR-ACC-014: unreceived speech authorises nothing, whatever muted the
     * microphone. The person's own mute is included deliberately.
     */
    @Test
    fun unreceived_speech_authorises_nothing() {
        notCapturing.forEach { state ->
            val gate = VoiceAuthorityGate(state, holdsUnlockedScreenConfirmation = true)
            assertEquals(
                "$state must refuse even an action needing no confirmation",
                VoiceAuthorityRefusal.SpeechNotHeard(state),
                gate.refusal(needsConfirmation = false),
            )
            assertEquals(
                "a held confirmation does not make unheard speech heard",
                VoiceAuthorityRefusal.SpeechNotHeard(state),
                gate.refusal(needsConfirmation = true),
            )
        }
    }

    /**
     * KR-REQ-15.13: the five unlocked-screen classes need the confirmation, and an open microphone
     * is not a substitute for it.
     */
    @Test
    fun an_unlocked_screen_action_needs_its_confirmation() {
        val withoutIt = VoiceAuthorityGate(VoiceCaptureState.CAPTURING)
        assertEquals(
            VoiceAuthorityRefusal.NeedsUnlockedScreenConfirmation,
            withoutIt.refusal(needsConfirmation = true),
        )
        assertNull(withoutIt.refusal(needsConfirmation = false))

        val withIt = VoiceAuthorityGate(VoiceCaptureState.CAPTURING, holdsUnlockedScreenConfirmation = true)
        assertNull(withIt.refusal(needsConfirmation = true))
    }

    /** The refusal says what is true rather than naming a fault, and names what would change it. */
    @Test
    fun a_refusal_explains_itself() {
        val muted = VoiceAuthorityRefusal.SpeechNotHeard(VoiceCaptureState.MUTED_BY_PERSON)
        assertTrue(muted.message.contains("Microphone muted"))
        assertTrue(muted.message.contains("authorise"))
        assertTrue(
            VoiceAuthorityRefusal.NeedsUnlockedScreenConfirmation.message.contains("unlocked screen"),
        )
    }
}
