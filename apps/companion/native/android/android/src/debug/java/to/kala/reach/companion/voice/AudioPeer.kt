package to.kala.reach.companion.voice

import android.content.Context
import org.json.JSONObject
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RTCStats
import org.webrtc.RtpReceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import org.webrtc.audio.JavaAudioDeviceModule
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteOrder
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.PI
import kotlin.math.sin

/**
 * The other end of a device run's call: a peer in this process that answers the call's offer and
 * sends and receives audio, so that the call's media is measured by what each end receives.
 *
 * A script puts `kr-probe/peer.json` in the application's data directory, naming a loopback port
 * and a token. The peer serves four routes on that port, and only to a request that carries the
 * token. `POST /answer` takes the call's offer and answers with the peer's own answer, marked as
 * the provider's is (an ICE-lite agent), and the stand-in voice service on the machine the
 * emulator runs beside relays it as the provider's; with `?dtx=1` the answer also turns Opus
 * discontinuous transmission on. `GET /figures` says what the peer received and sent.
 * `POST /events` writes its body, as text, to the call's `oai-events` channel as the provider
 * would, and `POST /drop?ms=N` has the call's recorder wait N milliseconds before it hands on its
 * next buffer (the device run's drop hook, [DropHook]).
 *
 * The peer's audio is its own: a second factory whose audio device records nothing from the
 * hardware, makes a tone for its microphone and counts what it is played. It shares nothing with
 * the call's factory and its audio device.
 *
 * Compiled into debug builds only. A release build has no peer and reads no file.
 */
internal class AudioPeer private constructor(context: Context, private val token: String) {
    private val tonesMade = AtomicLong()
    private val played = AtomicLong()
    private val errors = CopyOnWriteArrayList<String>()
    private var phase = 0.0

    init {
        // The library is initialised before any factory is made, as the call does for its own.
        PeerConnectionFactory.initialize(
            PeerConnectionFactory.InitializationOptions.builder(context.applicationContext)
                .createInitializationOptions(),
        )
    }

    private val module: JavaAudioDeviceModule =
        JavaAudioDeviceModule.builder(context)
            .setAudioRecordErrorCallback(
                object : JavaAudioDeviceModule.AudioRecordErrorCallback {
                    override fun onWebRtcAudioRecordInitError(message: String) {
                        errors.add("record init: $message")
                    }

                    override fun onWebRtcAudioRecordStartError(
                        code: JavaAudioDeviceModule.AudioRecordStartErrorCode,
                        message: String,
                    ) {
                        errors.add("record start: $message")
                    }

                    override fun onWebRtcAudioRecordError(message: String) {
                        errors.add("record: $message")
                    }
                },
            )
            .setAudioBufferCallback { buffer, _, channels, rate, _, _ ->
                // On the recorder's thread, once for each buffer. The module reads no hardware, so
                // this makes the audio and is the pace: ten milliseconds of tone take ten
                // milliseconds.
                buffer.order(ByteOrder.LITTLE_ENDIAN)
                val frames = buffer.capacity() / (2 * channels.coerceAtLeast(1))
                val step = 2 * PI * TONE_HERTZ / rate
                for (frame in 0 until frames) {
                    val sample = (sin(phase) * TONE_PEAK).toInt().toShort()
                    phase += step
                    for (channel in 0 until channels.coerceAtLeast(1)) {
                        buffer.putShort((frame * channels.coerceAtLeast(1) + channel) * 2, sample)
                    }
                }
                tonesMade.addAndGet(frames.toLong())
                Thread.sleep(frames * 1000L / rate)
                System.nanoTime()
            }
            .setPlaybackSamplesReadyCallback { samples -> played.addAndGet((samples.data.size / 2).toLong()) }
            .createAudioDeviceModule()
            .also {
                it.setAudioRecordEnabled(false)
                // What the peer is played is counted and not heard: no output route of the device sounds it.
                it.setSpeakerMute(true)
            }

    private val factory: PeerConnectionFactory =
        PeerConnectionFactory.builder().setAudioDeviceModule(module).createPeerConnectionFactory()

    @Volatile
    private var connection: PeerConnection? = null

    /** The channel the call made for the provider's events, once the connection has carried it. */
    @Volatile
    private var events: DataChannel? = null
    private val eventsSent = AtomicLong()

    @Volatile
    private var addressFound = CountDownLatch(1)

    /** Applies [offer] and answers it, with the candidates found by the first, marked ICE-lite. */
    private fun answer(offer: String, dtx: Boolean): String {
        val found = CountDownLatch(1)
        addressFound = found
        val made = factory.createPeerConnection(
            PeerConnection.RTCConfiguration(emptyList()).apply {
                sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
                continualGatheringPolicy = PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            },
            object : PeerConnection.Observer {
                override fun onIceCandidate(candidate: IceCandidate) = found.countDown()
                override fun onDataChannel(channel: DataChannel) {
                    events = channel
                }
                override fun onSignalingChange(state: PeerConnection.SignalingState) {}
                override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {}
                override fun onIceConnectionReceivingChange(receiving: Boolean) {}
                override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {}
                override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) {}
                override fun onAddStream(stream: MediaStream) {}
                override fun onRemoveStream(stream: MediaStream) {}
                override fun onRenegotiationNeeded() {}
                override fun onAddTrack(receiver: RtpReceiver, streams: Array<out MediaStream>) {}
            },
        ) ?: throw IllegalStateException("the peer could not open a connection")
        connection = made
        set { made.setRemoteDescription(it, SessionDescription(SessionDescription.Type.OFFER, offer)) }
        val source = factory.createAudioSource(MediaConstraints())
        made.addTrack(factory.createAudioTrack("kr-peer-tone", source), listOf("kr-peer"))
        val answer = create { observer ->
            made.createAnswer(
                observer,
                MediaConstraints().apply {
                    mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
                },
            )
        }
        set { made.setLocalDescription(it, answer) }
        // A peer that finds no address answers with what it has after this long.
        found.await(DESCRIPTION_SECONDS, TimeUnit.SECONDS)
        val sdp = asIceLite(made.localDescription?.description ?: answer.description)
        return if (dtx) withDtx(sdp) else sdp
    }

    /**
     * The answer with Opus discontinuous transmission turned on (`usedtx=1`), as an answer that
     * asks for it reads. The peer's own connection runs as it was answered; only what the call is
     * told changes.
     */
    private fun withDtx(sdp: String): String {
        val lines = sdp.split("\r\n").toMutableList()
        val rtpmap = Regex("^a=rtpmap:(\\d+) opus/")
        val payload = lines.firstNotNullOfOrNull { rtpmap.find(it)?.groupValues?.get(1) } ?: return sdp
        val fmtp = lines.indexOfFirst { it.startsWith("a=fmtp:$payload ") }
        if (fmtp >= 0) {
            if (!lines[fmtp].contains("usedtx=")) lines[fmtp] = lines[fmtp] + ";usedtx=1"
        } else {
            lines.add(lines.indexOfFirst { rtpmap.containsMatchIn(it) } + 1, "a=fmtp:$payload usedtx=1")
        }
        return lines.joinToString("\r\n")
    }

    /** Writes [bytes] to the call's events channel as one text message, and says whether it was written. */
    private fun send(bytes: ByteArray): Boolean {
        val channel = events ?: return false
        if (channel.state() != DataChannel.State.OPEN) return false
        val written = channel.send(DataChannel.Buffer(java.nio.ByteBuffer.wrap(bytes), false))
        if (written) eventsSent.incrementAndGet()
        return written
    }

    /**
     * The answer as the provider's reads: an ICE-lite agent answers the checks it is sent. The
     * peer is a full agent, which WebRTC offers no way to make lite, so the run shows that the call
     * connects and carries audio to such an answer, and not that the provider's own does.
     */
    private fun asIceLite(sdp: String): String {
        if (sdp.contains("a=ice-lite")) return sdp
        val media = sdp.indexOf("m=")
        return if (media < 0) sdp else sdp.substring(0, media) + "a=ice-lite\r\n" + sdp.substring(media)
    }

    private fun create(ask: (SdpObserver) -> Unit): SessionDescription {
        val latch = CountDownLatch(1)
        var made: SessionDescription? = null
        var failure: String? = null
        ask(object : Observer() {
            override fun onCreateSuccess(description: SessionDescription) {
                made = description
                latch.countDown()
            }

            override fun onCreateFailure(reason: String) {
                failure = reason
                latch.countDown()
            }
        })
        check(latch.await(DESCRIPTION_SECONDS, TimeUnit.SECONDS)) { "the peer made no answer in time" }
        return made ?: throw IllegalStateException(failure ?: "the peer could not make an answer")
    }

    private fun set(ask: (SdpObserver) -> Unit) {
        val latch = CountDownLatch(1)
        var failure: String? = null
        ask(object : Observer() {
            override fun onSetSuccess() = latch.countDown()

            override fun onSetFailure(reason: String) {
                failure = reason
                latch.countDown()
            }
        })
        check(latch.await(DESCRIPTION_SECONDS, TimeUnit.SECONDS)) { "the peer applied no description in time" }
        failure?.let { throw IllegalStateException(it) }
    }

    private abstract class Observer : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription) {}
        override fun onSetSuccess() {}
        override fun onCreateFailure(reason: String) {}
        override fun onSetFailure(reason: String) {}
    }

    /** What the peer received and sent, and what its audio device did. */
    private fun figures(): String {
        val out = JSONObject()
            .put("recorderStarted", tonesMade.get() > 0)
            .put("recordedFrames", tonesMade.get())
            .put("playedFrames", played.get())
            .put("eventsOpen", events?.state() == DataChannel.State.OPEN)
            .put("eventsSent", eventsSent.get())
            .put("dropsDone", DropHook.stalls())
            .put("recorderStops", DropHook.recorderStops())
            .put("errors", org.json.JSONArray(errors.toList()))
        val open = connection
        if (open != null) {
            val latch = CountDownLatch(1)
            open.getStats { report ->
                report.statsMap.values.forEach { stats: RTCStats ->
                    val audio = stats.members["kind"] == "audio"
                    if (stats.type == "inbound-rtp" && audio) {
                        (stats.members["packetsReceived"] as? Number)?.let { out.put("packetsReceived", it.toLong()) }
                    }
                    if (stats.type == "outbound-rtp" && audio) {
                        (stats.members["packetsSent"] as? Number)?.let { out.put("packetsSent", it.toLong()) }
                    }
                }
                latch.countDown()
            }
            latch.await(2, TimeUnit.SECONDS)
        }
        return out.toString()
    }

    /** One connection: nothing it does, a timeout or a peer that went away included, ends the process. */
    private fun serve(socket: Socket) {
        try {
            serveChecked(socket)
        } catch (failure: Throwable) {
            errors.add("connection: $failure")
        }
    }

    private fun serveChecked(socket: Socket) {
        socket.use {
            socket.soTimeout = 60_000
            val input = socket.getInputStream()
            val head = StringBuilder()
            while (!head.endsWith("\r\n\r\n")) {
                val next = input.read()
                if (next < 0 || head.length > 16_384) return
                head.append(next.toChar())
            }
            val lines = head.toString().split("\r\n")
            val first = lines[0].split(" ")
            val headers = lines.drop(1).filter { ':' in it }.associate {
                it.substringBefore(':').lowercase() to it.substringAfter(':').trim()
            }
            val length = headers["content-length"]?.toIntOrNull() ?: 0
            if (length !in 0..MAX_BODY_BYTES) return
            val body = ByteArray(length)
            var read = 0
            while (read < length) {
                val count = input.read(body, read, length - read)
                if (count < 0) return
                read += count
            }
            val target = first.getOrElse(1) { "" }
            val path = target.substringBefore('?')
            val query = target.substringAfter('?', "").split('&').filter { '=' in it }
                .associate { it.substringBefore('=') to it.substringAfter('=') }
            val (status, text) = when {
                headers["x-peer-token"] != token -> 401 to ""
                first.size >= 2 && first[0] == "POST" && path == "/answer" ->
                    try {
                        200 to answer(String(body, Charsets.UTF_8), query["dtx"] == "1")
                    } catch (failure: Exception) {
                        errors.add("answer: ${failure.message}")
                        500 to (failure.message ?: "")
                    }
                first.size >= 2 && first[0] == "GET" && path == "/figures" -> 200 to figures()
                first.size >= 2 && first[0] == "POST" && path == "/events" ->
                    if (send(body)) 200 to "sent" else 409 to "the events channel is not open"
                first.size >= 2 && first[0] == "POST" && path == "/drop" -> {
                    val wait = query["ms"]?.toLongOrNull()
                    if (wait != null && wait in 1..MAX_DROP_MS) {
                        DropHook.arm(wait)
                        200 to "armed"
                    } else {
                        400 to "ms is a whole number of milliseconds up to $MAX_DROP_MS"
                    }
                }
                else -> 404 to ""
            }
            val bytes = text.toByteArray(Charsets.UTF_8)
            val header = "HTTP/1.1 $status X\r\ncontent-type: text/plain\r\ncontent-length: ${bytes.size}\r\n" +
                "connection: close\r\n\r\n"
            socket.getOutputStream().apply {
                write(header.toByteArray(Charsets.UTF_8))
                write(bytes)
                flush()
            }
        }
    }

    companion object {
        private const val TONE_HERTZ = 440.0
        private const val TONE_PEAK = 9_000.0
        private const val DESCRIPTION_SECONDS = 30L
        private const val MAX_BODY_BYTES = 262_144
        private const val MAX_DROP_MS = 2_000L

        private var started = false

        /**
         * Starts the peer when the run asked for one: `kr-probe/peer.json` holds a port and a token.
         * It starts on a thread of its own and never takes the application down: a peer that cannot
         * start leaves the run's checks to report that the call had none.
         */
        @Synchronized
        fun startIfRequested(context: Context) {
            if (started) return
            started = true
            val file = File(context.dataDir, "kr-probe/peer.json")
            val request = try {
                JSONObject(file.readText())
            } catch (_: Exception) {
                return
            }
            Thread({
                try {
                    val peer = AudioPeer(context.applicationContext, request.getString("token"))
                    val listener = ServerSocket(request.getInt("port"), 8, InetAddress.getByName("127.0.0.1"))
                    while (true) {
                        val socket = listener.accept()
                        Thread({ peer.serve(socket) }, "kr-peer-connection").start()
                    }
                } catch (failure: Exception) {
                    android.util.Log.w("KalaReachPeer", "the device run's peer stopped: $failure")
                }
            }, "kr-peer-server").start()
        }
    }
}
