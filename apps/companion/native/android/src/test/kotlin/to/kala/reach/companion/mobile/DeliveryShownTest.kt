package to.kala.reach.companion.mobile

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * KR-REQ-16.15: what the receiver has put in front of the person when a preview is being opened. The
 * opening is native code in a process the system may end, so the alert goes up first and a preview
 * that opens replaces it.
 */
class DeliveryShownTest {
    @get:Rule val folder = TemporaryFolder()

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
    private class Posts(
        private val takesReplacements: Boolean = true,
        private val takesAlerts: Boolean = true
    ) {
        val all = mutableListOf<Triple<String, String, Posting>>()

        fun show(plan: NotificationPlan, posting: Posting): Boolean {
            all += Triple(plan.tag, plan.body, posting)
            return if (posting == Posting.REPLACEMENT) takesReplacements else takesAlerts
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
    fun anAlertThatCannotBePostedIsNotFollowedByTheOpeningOfItsPreview() {
        val posts = Posts(takesAlerts = false)

        val plan =
            showDelivery(
                sealed,
                decide = { throw AssertionError("the keys are not read for an alert nobody sees") },
                show = posts::show
            )

        assertEquals(NOT_POSTED, plan.reason)
        assertEquals(listOf(Triple("thread-1", sealed.alert, Posting.NEW)), posts.all)
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

    private object Plain : Sealer {
        override fun seal(plain: ByteArray, associated: ByteArray) = plain

        override fun open(sealed: ByteArray, associated: ByteArray) = sealed
    }

    /**
     * KR-REQ-16.11: previews turned off while a sealed preview is being opened. The change of the keys
     * is made once the receiver has posted what it decided, so no preview is posted from keys the
     * person had already taken away; it is not made beside the receiver. The case decides by where
     * the change is (waiting at the gate, or made), never by a delay.
     */
    @Test
    fun aChangeOfTheKeysThatLandsWhileAPreviewIsBeingOpenedWaitsForThePreviewToBePosted() {
        val limited = PushStores.limited(folder.newFolder("no-backup"), Plain)
        limited.replace(
            PreviewKeySet.of(
                listOf(ByteArray(32) { 1 } to ByteArray(32) { 2 }),
                listOf(ByteArray(32) { 3 } to ByteArray(32) { 4 })
            )
        )
        val order = CopyOnWriteArrayList<String>()
        val opening = CountDownLatch(1)
        val letGo = CountDownLatch(1)

        val receiver =
            thread {
                showDelivery(
                    sealed,
                    decide = {
                        opening.countDown()
                        letGo.await(30, TimeUnit.SECONDS)
                        PreviewDecision.Reveal("Allow scripts/release.sh?")
                    },
                    show = { _, posting ->
                        order += "post $posting"
                        true
                    }
                )
            }
        assertTrue("the receiver is opening the preview", opening.await(30, TimeUnit.SECONDS))
        val off =
            thread {
                limited.replace(PreviewKeySet.of(emptyList(), emptyList()))
                order += "off"
            }
        // The change either waits for the receiver or, if nothing holds it, is made at once.
        val end = System.nanoTime() + 30_000_000_000L
        while (off.isAlive && off.state != Thread.State.WAITING) {
            assertTrue("the change reached the gate", System.nanoTime() < end)
            Thread.yield()
        }
        letGo.countDown()
        receiver.join(30_000)
        off.join(30_000)

        assertEquals(listOf("post NEW", "post REPLACEMENT", "off"), order.toList())
        assertEquals(
            "the keys the person left are the ones a later receiver reads",
            null,
            limited.read()!!.senderKey(ByteArray(32) { 3 })
        )
    }
}
