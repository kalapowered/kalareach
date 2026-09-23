package to.kala.reach.companion.voice

import android.content.Context
import android.media.AudioDeviceCallback
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.telephony.TelephonyManager
import org.webrtc.AudioTrack
import org.webrtc.DataChannel
import org.webrtc.DefaultVideoDecoderFactory
import org.webrtc.DefaultVideoEncoderFactory
import org.webrtc.EglBase
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import to.kala.reach.companion.mobile.VoiceCaptureGate
import to.kala.reach.companion.mobile.VoiceCaptureState
import to.kala.reach.companion.push.AudioSession
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * The native voice call: WebRTC's own peer connection, and the microphone the platform owns.
 *
 * Section 15 paragraph 2 is the constraint this file exists to satisfy, and it admits no exception:
 * native WebRTC and native platform audio own capture and playback, not a background WebView
 * `getUserMedia` path. Nothing here goes near the WebView. The offer is made by this process, the
 * answer is applied by this process, and the audio flows between this device and the provider
 * without passing through the interface or through KalaReach.
 *
 * Section 15 paragraph 6 is the other constraint: the provider's data channel is read-only. This
 * connection creates no channel of its own and sends zero bytes on the one the provider opens.
 *
 * A call has two stages, and the microphone belongs only to the second. [start] builds the
 * connection and a microphone track that is off, for the offer and the answer; nothing is captured
 * and neither audio focus nor the foreground service is taken. [permit] is given the host's answer
 * to the start, the voice session and the moment the call closes, and only then is focus taken, the
 * service started and capture allowed. Whether the microphone is on is decided by one
 * [VoiceCaptureGate], under one lock, from the permit, the person's mute, what the system did to
 * focus and the route; every change goes to the screen and to the notification together.
 */
class VoiceCall private constructor(
    private val context: Context,
    private val factory: PeerConnectionFactory,
    private val observer: Observer,
    /** This call's identity in the process, which the service's actions name. */
    val id: Long,
) {
    /** What a running call tells the application about. */
    interface Observer {
        /** The microphone's state changed, for the screen and for the authority gate. */
        fun onCaptureState(state: VoiceCaptureState)

        /** The provider sent something on its read-only channel. */
        fun onProviderEvent(bytes: ByteArray)

        /** The first remote audio arrived. KR-PERF-010's first-audio figure is taken here. */
        fun onFirstAudio()
    }

    /** Held by every change to what the microphone and the speaker are allowed to do. */
    private val lock = Any()
    private val gate = VoiceCaptureGate()
    private var connection: PeerConnection? = null
    private var microphone: AudioTrack? = null
    private var announcedFirstAudio = false
    private var routeCallback: AudioDeviceCallback? = null
    private val main = Handler(Looper.getMainLooper())
    private var expiry: Runnable? = null

    /**
     * Whether [permit] started the foreground service for this call.
     *
     * Nothing talks to the service before that: a mute pressed before the host answered must not
     * create a service with no call to keep, and a service started from the background is refused
     * by the platform outright.
     */
    private var serviceStarted = false

    /**
     * The one focus request this call holds.
     *
     * The instance that asked for focus is the instance that gives it back, and it carries the
     * listener that turns a focus loss into a state the screen and the notification show.
     */
    private val audioSession = AudioSession(context) { change -> onFocusChange(change) }

    /** Whether this call has already been stopped. Stopping twice must do nothing the second time. */
    @Volatile
    private var stopped = false

    /** Whether the person has muted their own microphone. */
    val isMutedByPerson: Boolean
        get() = gate.isMutedByPerson

    /** Whether the person has silenced the model's voice on this device. */
    @Volatile
    var isPlaybackMuted: Boolean = false
        private set

    companion object {
        /** How long a description may take to be created or applied before the call is closed. */
        private const val DESCRIPTION_TIMEOUT_SECONDS = 30L

        private val calls = AtomicLong()

        /**
         * Builds a call for its offer and its answer, with the microphone off.
         *
         * The call is claimed as this process's one call before anything is built, in one step, so
         * two starts cannot both pass a check and both publish. Nothing here opens the microphone:
         * that waits for [permit].
         */
        @JvmStatic
        fun start(context: Context, observer: Observer): VoiceCall {
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(context.applicationContext)
                    .createInitializationOptions(),
            )
            val egl = EglBase.create()
            val factory = PeerConnectionFactory.builder()
                // Audio processing is the platform's where the device offers it: libwebrtc's
                // Android audio device uses the built-in acoustic echo canceller and noise
                // suppressor when they exist, and its own otherwise. Either way it is one
                // canceller, not two fighting.
                .setVideoEncoderFactory(DefaultVideoEncoderFactory(egl.eglBaseContext, true, true))
                .setVideoDecoderFactory(DefaultVideoDecoderFactory(egl.eglBaseContext))
                .createPeerConnectionFactory()
            val call = VoiceCall(context.applicationContext, factory, observer, calls.incrementAndGet())
            // One microphone, one call. A second call started over a running one would leave the
            // first one's track and connection live with nothing owning them.
            if (!VoiceCallHolder.claim(call)) {
                factory.dispose()
                throw IllegalStateException("a voice call is already running on this device")
            }
            try {
                call.open()
            } catch (failure: Throwable) {
                call.stop()
                throw failure
            }
            return call
        }
    }

    private fun open() {
        synchronized(lock) {
            if (stopped) throw IllegalStateException("this call was stopped while it was opening")
            val configuration = PeerConnection.RTCConfiguration(emptyList()).apply {
                // The provider's answer names its own candidates. No KalaReach relay is
                // configured: media travels between this device and the provider, and a relay of
                // KalaReach's would be a third party in a path section 15 paragraph 3 says has two.
                sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
                continualGatheringPolicy =
                    PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
            }
            val made = factory.createPeerConnection(configuration, PeerObserver())
                ?: throw IllegalStateException("this device could not open a connection")
            connection = made
            val source = factory.createAudioSource(MediaConstraints())
            // Off until the call is permitted. The offer describes a track, and a described track
            // carries nothing until the gate lets it.
            microphone = factory.createAudioTrack("kr-voice-microphone", source).also {
                it.setEnabled(false)
                made.addTrack(it, listOf("kr-voice"))
            }
            observer.onCaptureState(VoiceCaptureState.IDLE)
        }
    }

    /**
     * Opens the microphone for a call the host started.
     *
     * Takes the host's answer: the voice session and the moment the service closes the call, in
     * UTC milliseconds. Audio focus and the foreground service are taken here and nowhere else, so
     * nothing but a permitted call can open the microphone, and the call stops itself when that
     * moment comes, whether or not anything else happened.
     *
     * @return false, and nothing opened, when this call is stopped, already permitted, past its
     * deadline or refused audio focus.
     */
    fun permit(voiceSessionId: String, closesAtEpochMs: Long): Boolean {
        synchronized(lock) {
            if (stopped || gate.current != null) return false
            val now = SystemClock.elapsedRealtime()
            val deadline = now + (closesAtEpochMs - System.currentTimeMillis())
            if (deadline <= now) return false
            if (!audioSession.activate()) {
                publish(VoiceCaptureState.UNAVAILABLE)
                return false
            }
            gate.permit(voiceSessionId, deadline, now) ?: run {
                audioSession.deactivate()
                return false
            }
            // The service is what keeps capture alive once the screen locks, and it is started
            // for a call the host permitted rather than by anything that could fire on its own.
            VoiceCallService.start(context, id)
            serviceStarted = true
            watchRoute()
            val ends = Runnable { stop() }
            expiry = ends
            main.postDelayed(ends, deadline - now)
            apply(now)
            return true
        }
    }

    /**
     * Makes this call's SDP offer.
     *
     * Section 15 paragraph 3: the client creates the offer. The host forwards it and never
     * generates one.
     */
    fun offer(): String {
        val constraints = MediaConstraints().apply {
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveAudio", "true"))
            mandatory.add(MediaConstraints.KeyValuePair("OfferToReceiveVideo", "false"))
        }
        val open = openConnection()
        val made = awaitDescription { observer -> open.createOffer(observer, constraints) }
        awaitSet { observer -> open.setLocalDescription(observer, made) }
        return made.description
    }

    /** Applies the provider's SDP answer. Opening the microphone is [permit]'s, not this. */
    fun accept(answerSdp: String) {
        val answer = SessionDescription(SessionDescription.Type.ANSWER, answerSdp)
        val open = openConnection()
        awaitSet { observer -> open.setRemoteDescription(observer, answer) }
    }

    /** The connection, when the call is still open. */
    private fun openConnection(): PeerConnection =
        synchronized(lock) {
            connection.takeIf { !stopped }
                ?: throw IllegalStateException("this voice call has ended")
        }

    /**
     * Stops the person's voice reaching the model, without ending the call.
     *
     * Local and immediate. Section 15 paragraph 10 requires local microphone and speaker mute to
     * remain available if the broker fails, so this touches the track and nothing that could be
     * waiting on a network answer. Unmuting is the person's choice and nothing more: it does not
     * open a microphone the system has taken or a call has not been permitted.
     */
    fun setMutedByPerson(muted: Boolean) {
        synchronized(lock) {
            val now = SystemClock.elapsedRealtime()
            gate.setMutedByPerson(muted, now)
            apply(now)
        }
    }

    /**
     * Stops the model's voice coming out of this device, without ending the call.
     *
     * This is playback, and section 15 paragraph 13 is explicit that speech interruption stops
     * playback and not a coding task. Nothing here cancels anything on a host.
     */
    fun setPlaybackMuted(muted: Boolean) {
        synchronized(lock) {
            isPlaybackMuted = muted
            apply(SystemClock.elapsedRealtime())
        }
    }

    /**
     * Whether the microphone was carrying speech at `atMs` on the monotonic clock.
     *
     * What a claim that something was said is checked against, from this device's own record.
     */
    fun couldHaveHeard(atMs: Long): Boolean = gate.couldHaveHeard(atMs)

    /** Ends the call and gives the microphone back. Local and immediate, as mute is. */
    fun stop() {
        synchronized(lock) {
            if (stopped) return
            stopped = true
            gate.stop(SystemClock.elapsedRealtime())
            expiry?.let { main.removeCallbacks(it) }
            expiry = null
            // Cleared only if this call is the one published: a call that was already replaced must
            // not take its replacement's place in the holder with it.
            VoiceCallHolder.claimStopped(this)
            microphone?.setEnabled(false)
            routeCallback?.let {
                context.getSystemService(AudioManager::class.java)
                    ?.unregisterAudioDeviceCallback(it)
            }
            routeCallback = null
            connection?.close()
            audioSession.deactivate()
            if (serviceStarted) VoiceCallService.stop(context, id)
            observer.onCaptureState(VoiceCaptureState.IDLE)
        }
    }

    /**
     * Acts on what the system did to the microphone, and then says so.
     *
     * Losing focus takes the microphone and the speaker away: the track is disabled rather than
     * only relabelled, because a state that says the person is not being heard while the track is
     * still live would be the claim section 15 paragraph 22 forbids. Regaining it restores what
     * the person chose, which is their own mute if they set one, and nothing the person does while
     * focus is gone opens the microphone early.
     */
    fun onFocusChange(change: Int) {
        synchronized(lock) {
            if (stopped) return
            val now = SystemClock.elapsedRealtime()
            when (change) {
                AudioManager.AUDIOFOCUS_LOSS, AudioManager.AUDIOFOCUS_LOSS_TRANSIENT ->
                    gate.taken(VoiceCaptureGate.Taken.FOCUS_LOST, now)
                AudioManager.AUDIOFOCUS_GAIN -> gate.taken(VoiceCaptureGate.Taken.NONE, now)
                else -> return
            }
            apply(now)
        }
    }

    /** True while the platform reports a call on the cellular radio. */
    fun isInPhoneCall(): Boolean =
        context.getSystemService(TelephonyManager::class.java)?.callState !=
            TelephonyManager.CALL_STATE_IDLE

    /**
     * Makes the microphone and the speaker what the gate says, and tells both surfaces.
     *
     * Called under [lock] after every change, so there is one place the tracks are set and one
     * statement about capture, never one per event.
     */
    private fun apply(now: Long) {
        microphone?.setEnabled(gate.captureEnabled(now))
        val focused = gate.displayed(now) != VoiceCaptureState.FOCUS_LOST
        connection?.receivers?.forEach {
            (it.track() as? AudioTrack)?.setEnabled(!isPlaybackMuted && focused)
        }
        publish(gate.displayed(now))
    }

    /**
     * Tells the application and the notification the same thing.
     *
     * While the screen is locked the notification is the only surface there is, so a state that
     * reached the screen and not the notification would be a state half the surfaces disagree
     * about.
     */
    private fun publish(state: VoiceCaptureState) {
        observer.onCaptureState(state)
        if (serviceStarted) VoiceCallService.publishCapture(context, id, state)
    }

    private fun watchRoute() {
        val manager = context.getSystemService(AudioManager::class.java) ?: return
        val callback = object : AudioDeviceCallback() {
            override fun onAudioDevicesAdded(added: Array<out AudioDeviceInfo>?) = changed()
            override fun onAudioDevicesRemoved(removed: Array<out AudioDeviceInfo>?) = changed()

            private fun changed() {
                // A Bluetooth headset arriving or leaving. The state says so while capture is
                // re-established rather than claiming the person is still being heard, and both
                // surfaces are told.
                synchronized(lock) {
                    if (stopped) return
                    val now = SystemClock.elapsedRealtime()
                    gate.route(changing = true, inputAvailable = true, nowMs = now)
                    apply(now)
                    val hasInput = manager.getDevices(AudioManager.GET_DEVICES_INPUTS).isNotEmpty()
                    gate.route(changing = false, inputAvailable = hasInput, nowMs = now)
                    apply(now)
                }
            }
        }
        routeCallback = callback
        manager.registerAudioDeviceCallback(callback, null)
    }

    private inner class PeerObserver : PeerConnection.Observer {
        override fun onDataChannel(channel: DataChannel) {
            // The provider opened its channel. This end reads it and never writes to it.
            channel.registerObserver(object : DataChannel.Observer {
                override fun onBufferedAmountChange(previous: Long) {}
                override fun onStateChange() {}
                override fun onMessage(buffer: DataChannel.Buffer) {
                    val bytes = ByteArray(buffer.data.remaining())
                    (buffer.data as ByteBuffer).get(bytes)
                    // Handed up as bytes. What is a known event is decided by the frozen provider
                    // profile, one level above this file, and an unknown one is dropped there.
                    observer.onProviderEvent(bytes)
                }
            })
        }

        override fun onAddTrack(receiver: RtpReceiver, streams: Array<out MediaStream>) {
            if (receiver.track() !is AudioTrack || announcedFirstAudio) return
            announcedFirstAudio = true
            observer.onFirstAudio()
        }

        override fun onSignalingChange(state: PeerConnection.SignalingState) {}
        override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {}
        override fun onIceConnectionReceivingChange(receiving: Boolean) {}
        override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {}
        override fun onIceCandidate(candidate: org.webrtc.IceCandidate) {}
        override fun onIceCandidatesRemoved(candidates: Array<out org.webrtc.IceCandidate>) {}
        override fun onAddStream(stream: MediaStream) {}
        override fun onRemoveStream(stream: MediaStream) {}
        override fun onRenegotiationNeeded() {}
    }

    private fun awaitDescription(ask: (SdpObserver) -> Unit): SessionDescription {
        val latch = CountDownLatch(1)
        var made: SessionDescription? = null
        var failure: String? = null
        ask(object : SimpleSdpObserver() {
            override fun onCreateSuccess(description: SessionDescription) {
                made = description
                latch.countDown()
            }

            override fun onCreateFailure(reason: String) {
                failure = reason
                latch.countDown()
            }
        })
        if (!latch.await(DESCRIPTION_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            stop()
            throw IllegalStateException("this device did not finish making an offer in time")
        }
        return made ?: throw IllegalStateException(failure ?: "this device could not make an offer")
    }

    /**
     * Waits for one description to be applied.
     *
     * A timeout is a failure, not a success. Returning normally when no callback arrived would
     * leave a half-negotiated connection that the caller believes is ready, so the call is closed
     * and the caller is told.
     */
    private fun awaitSet(ask: (SdpObserver) -> Unit) {
        val latch = CountDownLatch(1)
        var failure: String? = null
        ask(object : SimpleSdpObserver() {
            override fun onSetSuccess() = latch.countDown()

            override fun onSetFailure(reason: String) {
                failure = reason
                latch.countDown()
            }
        })
        if (!latch.await(DESCRIPTION_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            stop()
            throw IllegalStateException("this device did not apply a session description in time")
        }
        failure?.let {
            stop()
            throw IllegalStateException(it)
        }
    }

    private abstract class SimpleSdpObserver : SdpObserver {
        override fun onCreateSuccess(description: SessionDescription) {}
        override fun onSetSuccess() {}
        override fun onCreateFailure(reason: String) {}
        override fun onSetFailure(reason: String) {}
    }
}

/**
 * The one call this process has, so the notification's actions reach it.
 *
 * A running call is process-wide because the microphone is, and the notification's mute and stop
 * are pressed while no interface is running at all. Every action names the call it was for, so an
 * action that arrives late reaches that call or nothing, never the call that replaced it.
 */
object VoiceCallHolder {
    @JvmStatic
    @Volatile
    var current: VoiceCall? = null
        private set

    /** Publishes `call` as this process's call, in one step, unless one is already running. */
    @JvmStatic
    @Synchronized
    fun claim(call: VoiceCall): Boolean {
        if (current != null) return false
        current = call
        return true
    }

    /** The running call, when it is the one `id` names. */
    @JvmStatic
    fun current(id: Long): VoiceCall? = current?.takeIf { it.id == id }

    /**
     * Clears the holder, but only when the call that stopped is the one it holds.
     *
     * A call that was already replaced clearing the holder would leave its replacement running with
     * nothing published, and the service's stop would then find nothing to stop.
     */
    @JvmStatic
    @Synchronized
    fun claimStopped(call: VoiceCall) {
        if (current === call) current = null
    }
}
