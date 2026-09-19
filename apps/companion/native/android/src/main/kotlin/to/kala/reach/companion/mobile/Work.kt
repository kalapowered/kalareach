package to.kala.reach.companion.mobile

/**
 * What a push receiver may finish where it stands, and what it must hand on.
 *
 * A message callback has a few seconds. Work that reaches a host over the network, waits on a
 * keystore that may be locked, or writes a journal does not reliably fit in that, and a callback
 * that runs over is a process the system kills with the work half done.
 *
 * So the receiver decides, at the moment it is handed a message, whether the work is short enough
 * to do now. Everything else goes to the platform's own scheduler, which runs it when the device
 * allows and retries it if it is interrupted. The decision is a value, so a test can hold it
 * rather than trusting a receiver to remember it.
 */

/** How long a message callback may take before the system stops trusting it, in milliseconds. */
const val CALLBACK_BUDGET_MILLIS: Long = 10_000

/** A safety margin: work is handed on well before the budget, not at the edge of it. */
const val CALLBACK_MARGIN_MILLIS: Long = 2_000

/** What the receiver does with one message. */
enum class WorkPlacement {
    /** Short enough to finish in the callback: show the notification and return. */
    IN_CALLBACK,

    /** Handed to the platform's scheduler, which runs it beyond the callback's budget. */
    DEFERRED
}

/** What one message asks for. */
data class IncomingWork(
    /** True when the notification's content is decided by the payload alone. */
    val decidedByPayload: Boolean,
    /** True when answering needs the host, which is a round trip of unknown length. */
    val needsHost: Boolean,
    /** How much of the callback's budget is already spent when the decision is made. */
    val elapsedMillis: Long = 0
)

/** Decides where one message's work runs. */
fun placeWork(work: IncomingWork): WorkPlacement {
    if (work.needsHost) return WorkPlacement.DEFERRED
    if (!work.decidedByPayload) return WorkPlacement.DEFERRED
    val remaining = CALLBACK_BUDGET_MILLIS - work.elapsedMillis
    return if (remaining > CALLBACK_MARGIN_MILLIS) WorkPlacement.IN_CALLBACK else WorkPlacement.DEFERRED
}
