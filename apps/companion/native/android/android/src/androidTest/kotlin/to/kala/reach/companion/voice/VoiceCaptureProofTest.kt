package to.kala.reach.companion.voice

import android.Manifest
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioRecordingConfiguration
import android.media.MediaRecorder
import android.os.Handler
import android.os.Looper
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
import to.kala.reach.companion.mobile.RecordingReport
import to.kala.reach.companion.mobile.VoiceCaptureGate
import to.kala.reach.companion.mobile.VoiceCaptureState
import to.kala.reach.companion.mobile.RecordingWatch
import to.kala.reach.companion.mobile.VoiceCallControl
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

        // What the microphone shows is no part of the order this case holds: a call reports its own
        // state when it starts.
        override fun onCaptureState(state: VoiceCaptureState) {}

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

    /**
     * The system lists a recording this application makes from the source the call's recorder uses,
     * and the call reads it as heard and not silenced: what a phone that reports the call's
     * recording shows, and the report the gate opens on. A real recording is started and stopped by
     * the test; nothing is sent anywhere.
     */
    @Test
    fun a_recording_from_the_calls_source_is_listed_by_the_system_and_reads_as_audible() {
        assertEquals(
            "the source the call looks for is the platform's own",
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            VoiceCallControl.RECORDER_SOURCE,
        )
        InstrumentationRegistry.getInstrumentation().uiAutomation
            .grantRuntimePermission(context.packageName, Manifest.permission.RECORD_AUDIO)
        val manager = context.getSystemService(AudioManager::class.java)
        val watch = RecordingWatch(VoiceCallControl.RECORDER_SOURCE)
        fun reports(configs: List<AudioRecordingConfiguration>) =
            configs.map { RecordingReport(it.clientAudioSource, it.isClientSilenced) }
        // What is recording before this call's recorder runs belongs to others.
        watch.read(reports(manager.activeRecordingConfigurations), deviceOn = false)
        val seen = LinkedBlockingQueue<VoiceCaptureGate.Recording>()
        val callback = object : AudioManager.AudioRecordingCallback() {
            override fun onRecordingConfigChanged(configs: List<AudioRecordingConfiguration>) {
                seen.add(watch.read(reports(configs), deviceOn = true))
            }
        }
        manager.registerAudioRecordingCallback(callback, Handler(Looper.getMainLooper()))
        val size = AudioRecord.getMinBufferSize(16_000, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val record = AudioRecord(
            VoiceCallControl.RECORDER_SOURCE,
            16_000,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            maxOf(size, 4_096),
        )
        try {
            assertEquals("the recorder is made", AudioRecord.STATE_INITIALIZED, record.state)
            record.startRecording()
            val reports = mutableListOf<VoiceCaptureGate.Recording>()
            while (VoiceCaptureGate.Recording.AUDIBLE !in reports) {
                reports += seen.poll(SECONDS, TimeUnit.SECONDS) ?: break
            }
            assertTrue("the system reported the recording heard: $reports", VoiceCaptureGate.Recording.AUDIBLE in reports)
        } finally {
            record.stop()
            record.release()
            manager.unregisterAudioRecordingCallback(callback)
        }
    }

    private companion object {
        const val SECONDS = 10L
    }
}
