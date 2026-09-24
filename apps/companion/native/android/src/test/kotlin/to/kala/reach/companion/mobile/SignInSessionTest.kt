package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SignInSessionTest {
    @Test
    fun aCustomTabThatCoveredTheAppAndClosedIsReportedOnceForItsAttempt() {
        val session = SignInSession()
        assertNull(session.begin("7", SignInSession.Mode.CUSTOM_TAB))
        session.paused()
        assertEquals("7", session.resumed())
        // Only once: a second resume without the tab covering the app again says nothing.
        assertNull(session.resumed())
    }

    @Test
    fun aResumeTheTabNeverCausedSaysNothing() {
        val session = SignInSession()
        session.begin("7", SignInSession.Mode.CUSTOM_TAB)
        assertNull(session.resumed())
    }

    @Test
    fun anAuthTabIsNeverReportedClosedByTheAppsOwnLifecycle() {
        val session = SignInSession()
        session.begin("7", SignInSession.Mode.AUTH_TAB)
        session.paused()
        assertNull(session.resumed())
    }

    @Test
    fun aVerifiedLinkAnswersOnlyACustomTabAttempt() {
        val session = SignInSession()
        assertNull(session.link())
        session.begin("7", SignInSession.Mode.AUTH_TAB)
        assertNull(session.link())
        session.ended("7")
        session.begin("8", SignInSession.Mode.CUSTOM_TAB)
        assertEquals("8", session.link())
    }

    @Test
    fun anAuthTabResultBelongsOnlyToTheAttemptThatLaunchedIt() {
        val session = SignInSession()
        session.begin("7", SignInSession.Mode.AUTH_TAB)
        assertTrue(session.result("7"))
        assertTrue(session.ended("7"))
        session.begin("8", SignInSession.Mode.AUTH_TAB)
        assertFalse(session.result("7"))
        assertTrue(session.result("8"))
    }

    @Test
    fun aNewAttemptNamesTheOneItEnds() {
        val session = SignInSession()
        assertNull(session.begin("7", SignInSession.Mode.CUSTOM_TAB))
        session.paused()
        assertEquals("7", session.begin("8", SignInSession.Mode.CUSTOM_TAB))
        // The earlier tab's cover does not carry over to the new attempt.
        assertNull(session.resumed())
    }

    @Test
    fun afterTheAttemptEndsNothingIsReported() {
        val session = SignInSession()
        session.begin("7", SignInSession.Mode.CUSTOM_TAB)
        session.paused()
        assertFalse(session.ended("6"))
        assertTrue(session.ended("7"))
        assertNull(session.resumed())
        assertNull(session.link())
        assertFalse(session.result("7"))
        assertFalse(session.ended("7"))
    }
}
