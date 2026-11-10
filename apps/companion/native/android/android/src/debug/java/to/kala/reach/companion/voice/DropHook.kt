package to.kala.reach.companion.voice

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * The device run's way to take audio out of the call's recorder. The peer arms it with a length of
 * time, and the recorder's thread stalls for that long before it hands the next buffer to the call,
 * so two buffers reach the call that far apart, as when a recorder loses audio.
 *
 * Only a debug build has it; a release build has a hook that does nothing.
 */
object DropHook {
    private val pending = AtomicLong()
    private val done = AtomicInteger()

    /** Has the next buffer wait [milliseconds] before it is handed on. */
    fun arm(milliseconds: Long) {
        if (milliseconds > 0) pending.set(milliseconds)
    }

    /** How many stalls the recorder's thread has made. */
    fun stalls(): Int = done.get()

    /** Called on the recorder's thread before each buffer is handed on. */
    fun beforeBuffer() {
        val wait = pending.getAndSet(0)
        if (wait > 0) {
            Thread.sleep(wait)
            done.incrementAndGet()
        }
    }
}
