package to.kala.reach.companion.voice

import android.content.Context
import android.media.AudioDeviceCallback
import android.media.AudioDeviceInfo
import android.media.AudioManager
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
import to.kala.reach.companion.mobile.VoiceCaptureState
import to.kala.reach.companion.push.AudioSession
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

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
 */
class VoiceCall private constructor(
    private val context: Context,
    private val factory: PeerConnectionFactory,
    private val observer: Observer,
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

    private lateinit var connection: PeerConnection
    private var microphone: AudioTrack? = null
    private var announcedFirstAudio = false
    private var routeCallback: AudioDeviceCallback? = null

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
    var isMutedByPerson: Boolean = false
        private set

    /** Whether the model's voice is coming out of this device. */
    var isPlaybackMuted: Boolean = false
        private set

    companion object {
        /** How long a description may take to be created or applied before the call is closed. */
        private const val DESCRIPTION_TIMEOUT_SECONDS = 30L

        /**
         * Opens the microphone and builds a call.
         *
         * The audio focus, the foreground service and the track are taken on one path, so there is
         * no window in which a track exists and the service that keeps it alive does not.
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
            val call = VoiceCall(context.applicationContext, factory, observer)
            call.open()
            return call
        }
    }

    private fun open() {
        if (!audioSession.activate()) {
            observer.onCaptureState(VoiceCaptureState.UNAVAILABLE)
            throw IllegalStateException("this device would not give up audio focus for a call")
        }
        // The service is what keeps capture alive once the screen locks, and it is started for a
        // call the person started rather than by anything that could fire on its own.
        VoiceCallService.start(context)

        val configuration = PeerConnection.RTCConfiguration(emptyList()).apply {
            // The provider's answer names its own candidates. No KalaReach relay is configured:
            // media travels between this device and the provider, and a relay of KalaReach's would
            // be a third party in a path section 15 paragraph 3 says has two.
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            continualGatheringPolicy =
                PeerConnection.ContinualGatheringPolicy.GATHER_CONTINUALLY
        }
        connection = factory.createPeerConnection(configuration, PeerObserver())
            ?: throw IllegalStateException("this device could not open a connection")

        val source = factory.createAudioSource(MediaConstraints())
        microphone = factory.createAudioTrack("kr-voice-microphone", source).also {
            connection.addTrack(it, listOf("kr-voice"))
        }
        observer.onCaptureState(VoiceCaptureState.CAPTURING)
        watchRoute()
        // The notification's mute and stop act on this call, and they are pressed while no
        // interface is running. Publishing the call is what connects them to the media; without it
        // they change a notification and nothing else.
        VoiceCallHolder.current = this
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
        val made = awaitDescription { observer -> connection.createOffer(observer, constraints) }
        awaitSet { observer -> connection.setLocalDescription(observer, made) }
        return made.description
    }

    /** Applies the provider's SDP answer. */
    fun accept(answerSdp: String) {
        val answer = SessionDescription(SessionDescription.Type.ANSWER, answerSdp)
        awaitSet { observer -> connection.setRemoteDescription(observer, answer) }
    }

    /**
     * Stops the person's voice reaching the model, without ending the call.
     *
     * Local and immediate. Section 15 paragraph 10 requires local microphone and speaker mute to
     * remain available if the broker fails, so this touches the track and nothing that could be
     * waiting on a network answer.
     */
    fun setMutedByPerson(muted: Boolean) {
        isMutedByPerson = muted
        microphone?.setEnabled(!muted)
        observer.onCaptureState(
            if (muted) VoiceCaptureState.MUTED_BY_PERSON else VoiceCaptureState.CAPTURING,
        )
    }

    /**
     * Stops the model's voice coming out of this device, without ending the call.
     *
     * This is playback, and section 15 paragraph 13 is explicit that speech interruption stops
     * playback and not a coding task. Nothing here cancels anything on a host.
     */
    fun setPlaybackMuted(muted: Boolean) {
        isPlaybackMuted = muted
        connection.receivers.forEach { (it.track() as? AudioTrack)?.setEnabled(!muted) }
    }

    /** Ends the call and gives the microphone back. Local and immediate, as mute is. */
    fun stop() {
        if (stopped) return
        stopped = true
        // Cleared before the service is told, so the service's own stop cannot re-enter this call.
        VoiceCallHolder.current = null
        microphone?.setEnabled(false)
        routeCallback?.let {
            context.getSystemService(AudioManager::class.java)?.unregisterAudioDeviceCallback(it)
        }
        routeCallback = null
        connection.close()
        audioSession.deactivate()
        VoiceCallService.stop(context)
        observer.onCaptureState(VoiceCaptureState.IDLE)
    }

    /** Reports what the system did to the microphone, so each is an explicit state. */
    fun onFocusChange(change: Int) {
        val state = when (change) {
            AudioManager.AUDIOFOCUS_LOSS, AudioManager.AUDIOFOCUS_LOSS_TRANSIENT ->
                VoiceCaptureState.FOCUS_LOST
            AudioManager.AUDIOFOCUS_GAIN -> VoiceCaptureState.CAPTURING
            else -> return
        }
        observer.onCaptureState(state)
    }

    /** True while the platform reports a call on the cellular radio. */
    fun isInPhoneCall(): Boolean =
        context.getSystemService(TelephonyManager::class.java)?.callState !=
            TelephonyManager.CALL_STATE_IDLE

    private fun watchRoute() {
        val manager = context.getSystemService(AudioManager::class.java) ?: return
        val callback = object : AudioDeviceCallback() {
            override fun onAudioDevicesAdded(added: Array<out AudioDeviceInfo>?) = changed()
            override fun onAudioDevicesRemoved(removed: Array<out AudioDeviceInfo>?) = changed()

            private fun changed() {
                // A Bluetooth headset arriving or leaving. The state says so while capture is
                // re-established rather than claiming the person is still being heard.
                observer.onCaptureState(VoiceCaptureState.ROUTE_CHANGING)
                val hasInput = manager
                    .getDevices(AudioManager.GET_DEVICES_INPUTS)
                    .isNotEmpty()
                observer.onCaptureState(
                    when {
                        !hasInput -> VoiceCaptureState.UNAVAILABLE
                        isMutedByPerson -> VoiceCaptureState.MUTED_BY_PERSON
                        else -> VoiceCaptureState.CAPTURING
                    },
                )
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
 * are pressed while no interface is running at all.
 */
object VoiceCallHolder {
    @JvmStatic
    @Volatile
    var current: VoiceCall? = null
}
