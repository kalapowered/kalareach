package to.kala.reach.companion.voice

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import to.kala.reach.companion.mobile.VoiceCaptureState
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * What a call offers the provider, and what it hears back, against a peer in this process.
 *
 * The peer answers an offer the way the provider's side does: it applies the offer, answers with its
 * own candidates, and reads the channel the offer names. Nothing here goes near a network beyond this
 * device's own interfaces, a broker, or the microphone.
 */
@RunWith(AndroidJUnit4::class)
class VoiceNegotiationTest {
    /** What a call told the application, kept for the test to read. */
    private class Told : VoiceCall.Observer {
        val events = LinkedBlockingQueue<ByteArray>()

        override fun onCaptureState(state: VoiceCaptureState) {}

        override fun onProviderEvent(bytes: ByteArray) {
            events.add(bytes)
        }

        override fun onFirstAudio() {}
    }

    /** A peer in this process that answers an offer and reads the channel the offer names. */
    private class AnsweringPeer {
        private val factory = PeerConnectionFactory.builder().createPeerConnectionFactory()
        private val gathered = CountDownLatch(1)

        /** Counted down when the channel the offer names is open at this end. */
        val channelOpen = CountDownLatch(1)

        @Volatile
        var channelLabel: String? = null

        @Volatile
        private var channel: DataChannel? = null

        private val connection: PeerConnection = factory.createPeerConnection(
            PeerConnection.RTCConfiguration(emptyList()).apply {
                sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
                // Once, so that the gathering reports itself done and the answer carries every
                // candidate.
                continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_ONCE
            },
            object : PeerConnection.Observer {
                override fun onDataChannel(opened: DataChannel) {
                    channel = opened
                    channelLabel = opened.label()
                    opened.registerObserver(object : DataChannel.Observer {
                        override fun onBufferedAmountChange(previous: Long) {}
                        override fun onMessage(buffer: DataChannel.Buffer) {}
                        override fun onStateChange() {
                            if (opened.state() == DataChannel.State.OPEN) channelOpen.countDown()
                        }
                    })
                    if (opened.state() == DataChannel.State.OPEN) channelOpen.countDown()
                }

                override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {
                    if (state == PeerConnection.IceGatheringState.COMPLETE) gathered.countDown()
                }

                override fun onSignalingChange(state: PeerConnection.SignalingState) {}
                override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {}
                override fun onIceConnectionReceivingChange(receiving: Boolean) {}
                override fun onIceCandidate(candidate: IceCandidate) {}
                override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) {}
                override fun onAddStream(stream: MediaStream) {}
                override fun onRemoveStream(stream: MediaStream) {}
                override fun onRenegotiationNeeded() {}
                override fun onAddTrack(receiver: RtpReceiver, streams: Array<out MediaStream>) {}
            },
        ) ?: error("the peer could not open a connection")

        /** Applies `offer` and answers it, with the candidates this peer gathered. */
        fun answer(offer: String): String {
            await { connection.setRemoteDescription(it, SessionDescription(SessionDescription.Type.OFFER, offer)) }
            val constraints = MediaConstraints().apply {
                mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
            }
            var made: SessionDescription? = null
            await({ made = it }) { connection.createAnswer(it, constraints) }
            await { connection.setLocalDescription(it, made!!) }
            assertTrue("the peer gathered its candidates", gathered.await(SECONDS, TimeUnit.SECONDS))
            return connection.localDescription.description
        }

        /** Sends `text` on the channel the offer named. */
        fun send(text: String) {
            val open = channel ?: error("the channel the offer names has not arrived")
            open.send(DataChannel.Buffer(ByteBuffer.wrap(text.toByteArray()), false))
        }

        fun close() {
            channel?.dispose()
            connection.dispose()
            factory.dispose()
        }

        private fun await(created: (SessionDescription) -> Unit = {}, ask: (SdpObserver) -> Unit) {
            val done = CountDownLatch(1)
            var failure: String? = null
            ask(object : SdpObserver {
                override fun onCreateSuccess(description: SessionDescription) {
                    created(description)
                    done.countDown()
                }

                override fun onSetSuccess() = done.countDown()

                override fun onCreateFailure(reason: String) {
                    failure = reason
                    done.countDown()
                }

                override fun onSetFailure(reason: String) {
                    failure = reason
                    done.countDown()
                }
            })
            assertTrue("a description was made or applied", done.await(SECONDS, TimeUnit.SECONDS))
            assertNull(failure, failure)
        }
    }

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private var call: VoiceCall? = null
    private var peer: AnsweringPeer? = null

    @After
    fun end() {
        call?.stop()
        peer?.close()
    }

    /** A call and a peer that have exchanged an offer and an answer. */
    private fun negotiated(told: Told): Pair<VoiceCall, String> {
        val started = VoiceCall.start(context, told).also { call = it }
        val offer = started.offer()
        val answering = AnsweringPeer().also { peer = it }
        started.accept(answering.answer(offer))
        return started to offer
    }

    /**
     * KR-REQ-15.10: the call creates the provider's events channel before it makes the offer, so
     * the offer names it and the provider has one to write to.
     */
    @Test
    fun the_offer_names_the_providers_event_channel() {
        val (_, offer) = negotiated(Told())

        assertTrue("the offer holds a data channel section", offer.contains("m=application"))
        assertTrue(peer!!.channelOpen.await(SECONDS, TimeUnit.SECONDS))
        assertEquals("oai-events", peer!!.channelLabel)
    }

    /** KR-REQ-15.10: what the provider writes on that channel reaches the application as bytes. */
    @Test
    fun an_event_the_provider_writes_reaches_the_application() {
        val told = Told()
        negotiated(told)

        assertTrue(peer!!.channelOpen.await(SECONDS, TimeUnit.SECONDS))
        peer!!.send("{\"type\":\"session.created\"}")
        val event = told.events.poll(SECONDS, TimeUnit.SECONDS)
        assertNotNull("the event reached the application", event)
        assertEquals("{\"type\":\"session.created\"}", String(event!!))
    }

    /**
     * KR-REQ-15.03: the offer carries the candidates this device had gathered by the time it was
     * made, because the provider is answered once and the candidates that come later are not sent.
     */
    @Test
    fun the_offer_carries_the_candidates_gathered_so_far() {
        val started = VoiceCall.start(context, Told()).also { call = it }
        assertTrue(
            "the offer names at least one address to reach",
            started.offer().contains("a=candidate:"),
        )
    }

    /**
     * KR-REQ-15.34: the call knows whether the provider's answer has been applied, and what it says
     * of discontinuous transmission, only once it has been. A host's answer is taken only after
     * that, which the call's control decides.
     */
    @Test
    fun the_call_knows_the_answer_only_once_it_is_applied() {
        val started = VoiceCall.start(context, Told()).also { call = it }
        val offer = started.offer()
        assertFalse(started.answerIsApplied)
        assertNull(started.answerUsesDtx)

        val answering = AnsweringPeer().also { peer = it }
        started.accept(answering.answer(offer))
        assertTrue(started.answerIsApplied)
        assertEquals(false, started.answerUsesDtx)
    }

    private companion object {
        /** How long the two ends are given to connect before a test calls it a failure. */
        const val SECONDS = 120L
    }
}
