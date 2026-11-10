package to.kala.reach.companion.voice

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import to.kala.reach.companion.mobile.CaptureProofRead
import to.kala.reach.companion.mobile.VoiceCaptureState
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * The marker a capture proof asks for, on the call's own thread: the record is read and the marker
 * told in one block of the thread that every provider event and every report of the system passes
 * through, so what the thread had waiting before the block is told before the marker.
 */
@RunWith(AndroidJUnit4::class)
class VoiceCaptureProofTest {
    /** What a call told the application, in order, with the first provider event held on the thread. */
    private class Order : VoiceCall.Observer {
        val told = LinkedBlockingQueue<String>()
        val firstEventHeld = CountDownLatch(1)
        val release = CountDownLatch(1)

        override fun onCaptureState(state: VoiceCaptureState) {
            told.add("capture $state")
        }

        override fun onProviderEvent(bytes: ByteArray) {
            told.add("event ${bytes.size}")
            if (bytes.size == 1) {
                firstEventHeld.countDown()
                release.await(SECONDS, TimeUnit.SECONDS)
            }
        }

        override fun onPlayout() {}

        override fun onBarrier(token: Long) {
            told.add("barrier $token")
        }
    }

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private var call: VoiceCall? = null

    @After
    fun end() {
        call?.stop()
    }

    private fun next(order: Order): String =
        order.told.poll(SECONDS, TimeUnit.SECONDS) ?: error("the call told nothing more")

    /**
     * Two provider events are on the call's thread, the first held inside the observer, when the
     * proof is queued; a third comes after it. The marker is told after the two and before the
     * third, and the answer carries its number.
     */
    @Test
    fun the_marker_is_told_behind_what_the_calls_thread_had_waiting() {
        val order = Order()
        val started = VoiceCall.start(context, order).also { call = it }

        started.receive(byteArrayOf(1))
        assertTrue("the thread is inside the first event", order.firstEventHeld.await(SECONDS, TimeUnit.SECONDS))
        started.receive(byteArrayOf(1, 2))
        val answered = LinkedBlockingQueue<List<CaptureProofRead?>>()
        assertTrue("the block is queued", started.postCaptureProof(barrier = true) { answered.add(listOf(it)) })
        started.receive(byteArrayOf(1, 2, 3))
        order.release.countDown()

        assertEquals("event 1", next(order))
        assertEquals("event 2", next(order))
        assertEquals("barrier 1", next(order))
        assertEquals("event 3", next(order))
        val read = answered.poll(SECONDS, TimeUnit.SECONDS)?.single()
        assertNotNull(read)
        assertEquals(1L, read!!.barrier)
        assertEquals("a call that was not permitted captures nothing", VoiceCaptureState.IDLE, read.proof.state)
        assertEquals(0L, read.proof.openings)
    }

    /** Each marker has a number of its own, one that asks for none tells none, and an ended call answers nothing. */
    @Test
    fun each_marker_has_its_own_number_and_an_ended_call_answers_none() {
        val order = Order().apply { release.countDown() }
        val started = VoiceCall.start(context, order).also { call = it }

        assertEquals(1L, started.captureProof(barrier = true)!!.barrier)
        assertNull(started.captureProof(barrier = false)!!.barrier)
        assertEquals(2L, started.captureProof(barrier = true)!!.barrier)
        assertEquals("barrier 1", next(order))
        assertEquals("barrier 2", next(order))

        started.stop()
        assertNull("a call that has ended reads no record", started.captureProof(barrier = true))
    }

    private companion object {
        const val SECONDS = 10L
    }
}
