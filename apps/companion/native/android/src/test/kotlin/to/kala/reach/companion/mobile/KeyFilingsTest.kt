package to.kala.reach.companion.mobile

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * KR-REQ-16.11: the keys are filed off the thread that asks, because a change waits for the
 * receivers that are deciding and the command arrives on the main thread. The sets are filed in the
 * order they were asked.
 */
class KeyFilingsTest {
    @get:Rule val folder = TemporaryFolder()

    private object Plain : Sealer {
        override fun seal(plain: ByteArray, associated: ByteArray) = plain

        override fun open(sealed: ByteArray, associated: ByteArray) = sealed
    }

    private fun senders(vararg byte: Int) =
        PreviewKeySet.of(
            listOf(ByteArray(32) { 1 } to ByteArray(32) { 2 }),
            byte.map { ByteArray(32) { _ -> it.toByte() } to ByteArray(32) { 9 } }
        )

    @Test
    fun aFilingThatWaitsForADecidingReceiverDoesNotHoldTheThreadThatAsks() {
        val limited = PushStores.limited(folder.newFolder("no-backup"), Plain)
        val filings = KeyFilings { limited }
        val deciding = CountDownLatch(1)
        val letGo = CountDownLatch(1)
        val receiver =
            thread {
                PreviewKeyGate.deciding {
                    deciding.countDown()
                    letGo.await(30, TimeUnit.SECONDS)
                }
            }
        assertTrue("a receiver is deciding", deciding.await(30, TimeUnit.SECONDS))
        val order = CopyOnWriteArrayList<String>()
        val asked = CountDownLatch(1)
        val done = CountDownLatch(2)

        // The thread that asks is another one, as the main thread is: it must come back.
        thread {
            filings.file(senders(3)) {
                order += "first ${it?.message}"
                done.countDown()
            }
            filings.file(senders(4)) {
                order += "second ${it?.message}"
                done.countDown()
            }
            asked.countDown()
        }
        assertTrue("the thread that asks came back", asked.await(30, TimeUnit.SECONDS))
        assertTrue("nothing was filed while the receiver was deciding", order.isEmpty())

        letGo.countDown()
        assertTrue("both were filed", done.await(30, TimeUnit.SECONDS))
        receiver.join(30_000)

        assertEquals(listOf("first null", "second null"), order.toList())
        val held = limited.read()!!
        assertNull("the first set was replaced", held.senderKey(ByteArray(32) { 3 }))
        assertTrue("the last set asked for stands", held.senderKey(ByteArray(32) { 4 }) != null)
    }
}
