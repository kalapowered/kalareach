package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * KR-REQ-15.35: the notification's actions reach the call they were shown for, or nothing.
 */
class VoiceServiceActionsTest {
    private val old = 7L
    private val current = 8L

    /**
     * An action already on its way when its call ended, delivered to a service now running for the
     * next call, changes nothing, whichever action it is.
     */
    @Test
    fun an_action_for_an_earlier_call_changes_nothing() {
        for (action in listOf(VoiceServiceActions.STOP, VoiceServiceActions.TOGGLE_MUTE, VoiceServiceActions.CAPTURE)) {
            assertEquals(action, VoiceServiceActions.Act.IGNORE, VoiceServiceActions.decide(action, old, current))
        }
    }

    /** The same actions naming the call the service runs for do what they say. */
    @Test
    fun an_action_for_the_running_call_acts() {
        assertEquals(VoiceServiceActions.Act.STOP, VoiceServiceActions.decide(VoiceServiceActions.STOP, current, current))
        assertEquals(
            VoiceServiceActions.Act.TOGGLE_MUTE,
            VoiceServiceActions.decide(VoiceServiceActions.TOGGLE_MUTE, current, current),
        )
        assertEquals(
            VoiceServiceActions.Act.CAPTURE,
            VoiceServiceActions.decide(VoiceServiceActions.CAPTURE, current, current),
        )
        assertEquals(VoiceServiceActions.Act.START, VoiceServiceActions.decide(VoiceServiceActions.START, current, null))
    }

    /** A service running for no call ends itself for anything but a start or a stop. */
    @Test
    fun a_service_with_no_call_ends_itself() {
        assertEquals(VoiceServiceActions.Act.END, VoiceServiceActions.decide(VoiceServiceActions.TOGGLE_MUTE, old, null))
        assertEquals(VoiceServiceActions.Act.END, VoiceServiceActions.decide(VoiceServiceActions.CAPTURE, old, null))
        assertEquals(VoiceServiceActions.Act.END, VoiceServiceActions.decide(null, old, null))
        assertEquals(VoiceServiceActions.Act.STOP, VoiceServiceActions.decide(VoiceServiceActions.STOP, old, null))
        assertEquals(VoiceServiceActions.Act.END, VoiceServiceActions.decide("something.else", current, current))
    }

    /**
     * A pending action kept from an earlier call's notification is a different pending action from
     * the next call's, so publishing the next call's actions cannot rewrite the earlier ones to name
     * it.
     */
    @Test
    fun each_call_gives_its_actions_their_own_address() {
        assertNotEquals(VoiceServiceActions.callAddress(old), VoiceServiceActions.callAddress(current))
        assertEquals(VoiceServiceActions.callAddress(current), VoiceServiceActions.callAddress(current))
    }
}
