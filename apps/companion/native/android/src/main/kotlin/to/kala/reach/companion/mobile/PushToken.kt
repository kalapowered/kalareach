package to.kala.reach.companion.mobile

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Where the provider is asked for the registration token it holds now. */
fun interface CurrentToken {
    /** Asks for the token, and answers `done` with it, or with null when the provider has none. */
    fun fetch(done: (String?) -> Unit)
}

/**
 * Where the application puts the way to ask the provider for its current token, and the plugin finds
 * it.
 *
 * The provider tells the messaging service when the token changes, but a service that was not running
 * when it did, or that the system ended before it wrote the token, leaves the stored token behind the
 * provider's. Asking the provider at each read mends that without waiting for the next change.
 * Nothing is registered in a build with no provider configuration, and the stored token stands.
 */
object CurrentTokenHolder {
    @Volatile
    var source: CurrentToken? = null
        private set

    /** Registers the application's way of asking, made only when none is registered yet. */
    @Synchronized
    fun registerOnce(make: () -> CurrentToken) {
        if (source == null) source = make()
    }
}

/** The registration token this installation holds. */
object PushToken {
    /** The longest a read waits for the provider before it answers with the stored token. */
    const val WAIT_MS = 2_000L

    /**
     * The token the provider holds now when it answers within [waitMs], which is stored when it is
     * not the stored one; otherwise the stored token, or null when there is none. A read never waits
     * longer, so a phone with no network still answers. An answer that comes after the wait is
     * let go: the provider tells the messaging service of a change by itself.
     */
    fun read(
        stored: () -> String?,
        source: CurrentToken?,
        keep: (String) -> Unit,
        waitMs: Long = WAIT_MS
    ): String? {
        val held = stored()
        if (source == null) return held
        val answered = CountDownLatch(1)
        val answer = arrayOfNulls<String>(1)
        try {
            source.fetch { token ->
                synchronized(answer) {
                    if (answered.count > 0L) {
                        answer[0] = token
                        answered.countDown()
                    }
                }
            }
        } catch (failure: Exception) {
            return held
        }
        val inTime = answered.await(waitMs, TimeUnit.MILLISECONDS)
        val current = synchronized(answer) {
            // From here an answer is late: it is no longer taken.
            if (!inTime) answered.countDown()
            if (inTime) answer[0] else null
        }
        if (current.isNullOrEmpty()) return held
        if (current != held) keep(current)
        return current
    }
}
