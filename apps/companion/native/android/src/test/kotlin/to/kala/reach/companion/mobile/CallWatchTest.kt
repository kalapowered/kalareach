package to.kala.reach.companion.mobile

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A call whose owner has stopped giving signs of life ends itself, so that a microphone is never
 * left open under an application whose owner of the call is gone.
 */
class CallWatchTest {
    private var now = 0L
    private val watch = CallWatch({ now }, beforePermit = 1_000L, afterPermit = 100L)

    @Test
    fun `a call that is opened and never permitted waits the longer bound for its owner`() {
        now = 999L
        assertFalse(watch.expired())

        now = 1_000L

        assertTrue("the longer bound has passed", watch.expired())
    }

    @Test
    fun `a sign of life starts the wait again`() {
        now = 900L
        watch.sign()
        now = 1_800L
        assertFalse("900 ms since the sign is inside the bound", watch.expired())

        now = 1_900L

        assertTrue(watch.expired())
    }

    @Test
    fun `a permitted call waits the shorter bound, counted from the permit`() {
        now = 500L
        watch.permitted()

        now = 599L
        assertFalse(watch.expired())
        now = 600L

        assertTrue("the shorter bound passed after the permit", watch.expired())
    }

    @Test
    fun `an owner that is gone is found once`() {
        now = 5_000L
        assertTrue(watch.expired())

        now = 9_000L

        assertFalse("the call is ended once, not each time it is looked at", watch.expired())
    }
}
