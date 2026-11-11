package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * KR-ACC-014: on the lock screen a running call can be muted and stopped with no unlock, and a
 * muted microphone is not reopened by anyone holding a locked phone.
 */
class VoiceNotificationControlsTest {
    private val platformWithPerActionUnlock = VoiceNotificationControls.UNLOCK_PER_ACTION_SDK
    private val platformWithout = VoiceNotificationControls.UNLOCK_PER_ACTION_SDK - 1

    /** Muting takes the microphone away from the call, so it never asks for the unlock. */
    @Test
    fun mute_needs_no_unlock_on_any_platform() {
        for (sdk in listOf(platformWithout, platformWithPerActionUnlock, 36)) {
            for (locked in listOf(true, false)) {
                assertEquals(
                    VoiceNotificationControls.Controls(VoiceNotificationControls.Toggle.MUTE, needsUnlock = false),
                    VoiceNotificationControls.controls(muted = false, locked = locked, sdk = sdk),
                )
            }
        }
    }

    /** Where the platform can ask for the unlock per action, Unmute is offered and asks for it. */
    @Test
    fun unmute_asks_for_the_unlock_where_the_platform_can_ask() {
        for (locked in listOf(true, false)) {
            assertEquals(
                VoiceNotificationControls.Controls(VoiceNotificationControls.Toggle.UNMUTE, needsUnlock = true),
                VoiceNotificationControls.controls(muted = true, locked = locked, sdk = platformWithPerActionUnlock),
            )
        }
    }

    /** Where it cannot, a locked phone's notification offers no Unmute and an unlocked one does. */
    @Test
    fun unmute_is_not_offered_on_a_locked_phone_where_the_platform_cannot_ask() {
        assertEquals(
            VoiceNotificationControls.Toggle.NONE,
            VoiceNotificationControls.controls(muted = true, locked = true, sdk = platformWithout).toggle,
        )
        assertEquals(
            VoiceNotificationControls.Toggle.UNMUTE,
            VoiceNotificationControls.controls(muted = true, locked = false, sdk = platformWithout).toggle,
        )
    }

    /** An Unmute that reaches a locked phone's call is refused where the platform did not ask. */
    @Test
    fun an_unmute_on_a_locked_phone_is_refused_where_the_platform_did_not_ask() {
        assertFalse(VoiceNotificationControls.mayUnmute(locked = true, sdk = platformWithout))
        assertTrue(VoiceNotificationControls.mayUnmute(locked = false, sdk = platformWithout))
        assertTrue(VoiceNotificationControls.mayUnmute(locked = true, sdk = platformWithPerActionUnlock))
    }
}
