package to.kala.reach.companion.mobile

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * The one rule that keeps a preview from being shown after the person turned previews off.
 *
 * A receiver decides whether to show a preview in several steps (it reads the keys, opens the
 * sealed text, and posts the notification), and turning previews off takes the keys away. If the two
 * could overlap, a receiver that read the keys before the change could post the preview after it.
 * So every change of the keys waits until the decisions in progress have posted, and a decision
 * that starts after the change reads the keys as they then are. A receiver and the application are
 * one process on this platform, so one lock in the process is the whole of the rule.
 *
 * Decisions share the lock with each other and a change has it alone: two messages are never made
 * to wait for one another, and a change never runs beside a decision.
 */
object PreviewKeyGate {
    private val lock = ReentrantReadWriteLock()

    /** Runs a decision, from the first read of the keys to the post of what it decided. */
    fun <T> deciding(decision: () -> T): T = lock.read(decision)

    /** Runs a change of the keys, alone. */
    fun <T> changing(change: () -> T): T = lock.write(change)
}
