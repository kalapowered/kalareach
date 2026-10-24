package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The read of the registration token: the provider's when it answers in time, else the stored one. */
class PushTokenTest {
    private var kept: String? = null

    private fun read(stored: String?, source: CurrentToken?, waitMs: Long = 5_000L): String? =
        PushToken.read({ stored }, source, { kept = it }, waitMs)

    @Test
    fun aTokenTheProviderGivesInTimeIsKeptAndReadInPlaceOfTheStoredOne() {
        val token = read("old", CurrentToken { done -> done("new") })

        assertEquals("new", token)
        assertEquals("new", kept)
    }

    @Test
    fun theStoredTokenIsNotKeptAgain() {
        val token = read("same", CurrentToken { done -> done("same") })

        assertEquals("same", token)
        assertNull(kept)
    }

    @Test
    fun anAnswerThatComesAfterTheWaitIsLetGoAndTheStoredTokenStands() {
        var late: ((String?) -> Unit)? = null

        val token = read("old", CurrentToken { done -> late = done }, waitMs = 20L)
        late?.invoke("new")

        assertEquals("old", token)
        assertNull("a late answer is not kept", kept)
    }

    @Test
    fun aProviderWithNoTokenLeavesTheStoredOne() {
        assertEquals("old", read("old", CurrentToken { done -> done(null) }))
        assertNull(kept)
    }

    @Test
    fun aProviderThatCannotBeAskedLeavesTheStoredOne() {
        val failing = CurrentToken { throw IllegalStateException("no provider configuration") }

        assertEquals("old", read("old", failing))
        assertEquals("old", read("old", null))
        assertNull(kept)
    }

    @Test
    fun noStoredTokenAndNoAnswerIsNoToken() {
        assertNull(read(null, CurrentToken { done -> done(null) }))
    }
}
