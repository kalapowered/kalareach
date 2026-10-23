package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OwnerAuthenticatorsTest {
    private val android10 = 29
    private val android11 = 30

    /**
     * KR-REQ-10.06, the ceremony the phone asks for: a strong biometric first, with the screen lock
     * as its fallback from Android 11, the screen lock alone on a phone with no strong biometric,
     * and nothing on a phone with neither. Not shown here: the ceremony running, a synthesised
     * desktop click refused as proof of presence, and the host recording the verification and the
     * challenge's consumption.
     */
    @Test
    fun a_strong_biometric_is_asked_with_the_screen_lock_as_its_fallback_from_android_11() {
        assertEquals(
            OwnerAsk.STRONG_BIOMETRIC_OR_SCREEN_LOCK,
            OwnerAuthenticators.choose(android11, strongBiometric = true, screenLock = true, deviceSecure = true)
        )
        assertEquals(
            OwnerAsk.SCREEN_LOCK_ONLY,
            OwnerAuthenticators.choose(android11, strongBiometric = false, screenLock = true, deviceSecure = true)
        )
        assertNull(
            OwnerAuthenticators.choose(android11, strongBiometric = false, screenLock = false, deviceSecure = false)
        )
    }

    /**
     * KR-REQ-10.06, the ceremony the phone asks for before Android 11: only a strong biometric on a
     * locked phone. The screen lock alone is not asked, since naming it would admit weak biometrics,
     * and a strong biometric on a phone with no lock is not asked either. Not shown here: the
     * ceremony running, a synthesised desktop click refused as proof of presence, and the host
     * recording the verification and the challenge's consumption.
     */
    @Test
    fun before_android_11_only_a_strong_biometric_on_a_locked_phone_is_asked() {
        assertEquals(
            OwnerAsk.STRONG_BIOMETRIC_ONLY,
            OwnerAuthenticators.choose(android10, strongBiometric = true, screenLock = true, deviceSecure = true)
        )
        // The screen lock alone cannot be named without admitting weak biometrics: nothing is asked.
        assertNull(
            OwnerAuthenticators.choose(android10, strongBiometric = false, screenLock = true, deviceSecure = true)
        )
        // A strong biometric on a phone with no lock is not an unlocked-screen confirmation.
        assertNull(
            OwnerAuthenticators.choose(android10, strongBiometric = true, screenLock = false, deviceSecure = false)
        )
    }

    /** The word the application's Rust half reads is the ceremony the person will see. */
    @Test
    fun the_ceremony_is_named_for_what_the_person_will_be_asked() {
        assertEquals("biometric", OwnerAuthenticators.kind(OwnerAsk.STRONG_BIOMETRIC_OR_SCREEN_LOCK))
        assertEquals("biometric", OwnerAuthenticators.kind(OwnerAsk.STRONG_BIOMETRIC_ONLY))
        assertEquals("screen_lock", OwnerAuthenticators.kind(OwnerAsk.SCREEN_LOCK_ONLY))
        assertEquals("none", OwnerAuthenticators.kind(null))
    }

    /** A challenge with no time left is not waited for, and a long one is capped. */
    @Test
    fun the_wait_is_the_time_the_challenge_has_left_and_never_more_than_the_longest() {
        assertEquals(0L, OwnerAuthenticators.waitMillis(-5L))
        assertEquals(0L, OwnerAuthenticators.waitMillis(0L))
        assertEquals(45_000L, OwnerAuthenticators.waitMillis(45_000L))
        assertEquals(OwnerAuthenticators.LONGEST_WAIT_MILLIS, OwnerAuthenticators.waitMillis(Long.MAX_VALUE))
    }
}
