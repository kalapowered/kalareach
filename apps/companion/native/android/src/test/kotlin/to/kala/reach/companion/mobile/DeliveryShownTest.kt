package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * KR-REQ-16.15: what the receiver has put in front of the person when a preview is being opened. The
 * opening is native code in a process the system may end, so the alert goes up first and a preview
 * that opens replaces it.
 */
class DeliveryShownTest {
    private val sealed =
        PushMessage.Delivery(
            notificationId = "n-1",
            collapseId = "thread-1",
            alert = "A KalaReach session needs attention.",
            data = mapOf("alert" to "A KalaReach session needs attention.", "preview" to "{}")
        )

    private val plain =
        PushMessage.Delivery(
            notificationId = "n-2",
            collapseId = "thread-2",
            alert = "A KalaReach session needs attention.",
            data = mapOf("alert" to "A KalaReach session needs attention.")
        )

    /** What was posted: the tag, the words and how. */
    private class Posts(private val takesReplacements: Boolean = true) {
        val all = mutableListOf<Triple<String, String, Posting>>()

        fun show(plan: NotificationPlan, posting: Posting): Boolean {
            all += Triple(plan.tag, plan.body, posting)
            return takesReplacements || posting != Posting.REPLACEMENT
        }
    }

    /** The process is taken away in the middle of the open. */
    private class ProcessEnded : Error()

    @Test
    fun aPreviewThatOpensReplacesTheAlertAlreadyUpWithoutSoundingAgain() {
        val posts = Posts()

        val plan =
            showDelivery(
                sealed,
                decide = { PreviewDecision.Reveal("Allow scripts/release.sh?") },
                show = posts::show
            )

        assertEquals(
            listOf(
                Triple("thread-1", sealed.alert, Posting.NEW),
                Triple("thread-1", "Allow scripts/release.sh?", Posting.REPLACEMENT)
            ),
            posts.all
        )
        assertEquals("", plan.reason)
    }

    @Test
    fun aPreviewThatOpenedOverAnAlertThePersonActedOnIsReportedAsNotPosted() {
        val posts = Posts(takesReplacements = false)

        val plan =
            showDelivery(
                sealed,
                decide = { PreviewDecision.Reveal("Allow scripts/release.sh?") },
                show = posts::show
            )

        assertEquals(ALERT_GONE, plan.reason)
    }

    @Test
    fun aProcessEndedInTheMiddleOfTheOpenLeavesTheAlertUp() {
        val posts = Posts()

        assertThrows(ProcessEnded::class.java) {
            showDelivery(sealed, decide = { throw ProcessEnded() }, show = posts::show)
        }

        assertEquals(listOf(Triple("thread-1", sealed.alert, Posting.NEW)), posts.all)
    }

    @Test
    fun aPreviewThatStaysClosedAndAMessageWithNoPreviewAreEachShownOnce() {
        val closed = Posts()
        val none = Posts()

        val plan =
            showDelivery(
                sealed,
                decide = { PreviewDecision.Generic(GenericReason.SENDER_UNKNOWN) },
                show = closed::show
            )
        showDelivery(
            plain,
            decide = { PreviewDecision.Generic(GenericReason.NO_PREVIEW) },
            show = none::show
        )

        assertEquals(listOf(Triple("thread-1", sealed.alert, Posting.NEW)), closed.all)
        assertEquals("sender_unknown", plan.reason)
        assertEquals(listOf(Triple("thread-2", plain.alert, Posting.NEW)), none.all)
    }

    @Test
    fun aTryAfterAnInterruptionDoesNotSoundTheAlertAgain() {
        val opened = Posts()
        val none = Posts()

        showDelivery(
            sealed,
            repeated = true,
            decide = { PreviewDecision.Reveal("Allow scripts/release.sh?") },
            show = opened::show
        )
        showDelivery(
            plain,
            repeated = true,
            decide = { PreviewDecision.Generic(GenericReason.NO_PREVIEW) },
            show = none::show
        )

        assertEquals(
            listOf(Posting.REPEAT, Posting.REPLACEMENT),
            opened.all.map { it.third }
        )
        assertEquals(listOf(Posting.REPEAT), none.all.map { it.third })
    }
}
