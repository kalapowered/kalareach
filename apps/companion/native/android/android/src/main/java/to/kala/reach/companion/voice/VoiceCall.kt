package to.kala.reach.companion.voice

import android.content.Context
import android.media.AudioDeviceCallback
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.os.Handler
import android.os.HandlerThread
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
import org.webrtc.audio.JavaAudioDeviceModule
import to.kala.reach.companion.mobile.VoiceCallControl
import to.kala.reach.companion.mobile.VoiceCallPlatform
import to.kala.reach.companion.mobile.VoiceCaptureState
import to.kala.reach.companion.mobile.VoiceMediaSwitches
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
 * Every decision about the microphone is [VoiceCallControl]'s; this class carries them out. The
 * platform's recorder is held off from the moment the connection exists, before anything is
 * negotiated, so applying an answer starts nothing on its own. The control turns it on only for a
 * call the host permitted whose foreground service holds the foreground, and every frame the
 * recorder produces is asked about separately and silenced unless the control says it may be
 * carried. Timers and the platform's reports run on this call's own thread, never the main one.
 */
class VoiceCall private constructor(
    private val context: Context,
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

    /** The call's own thread: its timers, and everything the platform reports. */
    private val thread = HandlerThread("kr-voice-call-$id").apply { start() }
    private val handler = Handler(thread.looper)

    /** Held by every change to the connection and the tracks; never while waiting on WebRTC. */
    private val lock = Any()
    private var connection: PeerConnection? = null
    private var microphone: AudioTrack? = null
    private var announcedFirstAudio = false
    private var routeCallback: AudioDeviceCallback? = null
    private var audioDeviceOn: Boolean? = null

    /**
     * The one focus request this call holds. Its listener reports on this call's thread.
     *
     * The instance that asked for focus is the instance that gives it back.
     */
    private val audioSession =
        AudioSession(context) { change -> handler.post { onFocusChange(change) } }

    /**
     * The platform audio device, built for this call.
     *
     * Its recorder reports starting, stopping and failing to the control, on this call's thread,
     * and it hands every frame to [VoiceCallControl.carries] before the frame goes anywhere: a frame
     * the control does not let through is replaced with silence where it lies.
     */
    private val audioDevice: JavaAudioDeviceModule =
        JavaAudioDeviceModule.builder(context)
            .setAudioRecordStateCallback(
                object : JavaAudioDeviceModule.AudioRecordStateCallback {
                    override fun onWebRtcAudioRecordStart() {
                        handler.post { control.recorder(true) }
                    }

                    override fun onWebRtcAudioRecordStop() {
                        handler.post { control.recorder(false) }
                    }
                },
            )
            .setAudioRecordErrorCallback(
                object : JavaAudioDeviceModule.AudioRecordErrorCallback {
                    override fun onWebRtcAudioRecordInitError(message: String) {
                        handler.post { control.recorder(false) }
                    }

                    override fun onWebRtcAudioRecordStartError(
                        code: JavaAudioDeviceModule.AudioRecordStartErrorCode,
                        message: String,
                    ) {
                        handler.post { control.recorder(false) }
                    }

                    override fun onWebRtcAudioRecordError(message: String) {
                        handler.post { control.recorder(false) }
                    }
                },
            )
            .setAudioBufferCallback { buffer, _, _, _, bytesRead, captureTimeNs ->
                // On the audio thread, for every frame, before it reaches the encoder. Answered
                // from the gate alone, so no switch is set from here.
                if (!control.carries()) {
                    for (index in 0 until minOf(bytesRead, buffer.capacity())) buffer.put(index, 0)
                }
                captureTimeNs
            }
            .createAudioDeviceModule()
            .also { it.setMicrophoneMute(true) }

    private val egl: EglBase = EglBase.create()
    private val factory: PeerConnectionFactory =
        PeerConnectionFactory.builder()
            // Audio processing is the platform's where the device offers it: the audio device
            // uses the built-in acoustic echo canceller and noise suppressor when they exist, and
            // its own otherwise. Either way it is one canceller, not two fighting.
            .setAudioDeviceModule(audioDevice)
            .setVideoEncoderFactory(DefaultVideoEncoderFactory(egl.eglBaseContext, true, true))
            .setVideoDecoderFactory(DefaultVideoDecoderFactory(egl.eglBaseContext))
            .createPeerConnectionFactory()

    /** Every decision about the microphone, the speaker and the end of this call. */
    private val control = VoiceCallControl(Platform(), Switches())

    /** Whether the person has muted their own microphone. */
    val isMutedByPerson: Boolean
        get() = control.isMutedByPerson

    /** Whether the person has silenced the model's voice on this device. */
    val isPlaybackMuted: Boolean
        get() = control.isPlaybackMuted

    companion object {
        /** How long a description may take to be created or applied before the call is closed. */
        private const val DESCRIPTION_TIMEOUT_SECONDS = 30L

        private val calls = AtomicLong()

        /**
         * Builds a call for its offer and its answer, with the recorder off.
         *
         * The call is claimed as this process's one call before anything is opened, in one step,
         * so two starts cannot both pass a check and both publish. Nothing here opens the
         * microphone: that waits for [permit], the foreground service and the recorder.
         */
        @JvmStatic
        fun start(context: Context, observer: Observer): VoiceCall {
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(context.applicationContext)
                    .createInitializationOptions(),
            )
            val call = VoiceCall(context.applicationContext, observer, calls.incrementAndGet())
            // One microphone, one call. A second call started over a running one would leave the
            // first one's track and connection live with nothing owning them.
            if (!VoiceCallHolder.claim(call)) {
                call.stop()
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
            if (control.isStopped) throw IllegalStateException("this call was stopped while it was opening")
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
            // Off before anything is negotiated. Left on, applying the answer would start the
            // recorder by itself, whether or not the host ever permitted the call.
            made.setAudioRecording(false)
            made.setAudioPlayout(false)
            audioDeviceOn = false
            connection = made
            val source = factory.createAudioSource(MediaConstraints())
            // Off until the control turns it on. The offer describes a track, and a described
            // track carries nothing until the control lets it.
            microphone = factory.createAudioTrack("kr-voice-microphone", source).also {
                it.setEnabled(false)
                made.addTrack(it, listOf("kr-voice"))
            }
        }
        watchRoute()
    }

    /**
     * Opens the microphone for a call the host started.
     *
     * Takes the host's answer: the voice session and the moment the service closes the call, in
     * UTC milliseconds. Focus and the foreground service are asked for here; the recorder waits
     * for the service to hold the foreground and then for the recorder itself to report running.
     *
     * @return false, and the call ended, when the moment has passed or the platform refused focus
     * or the service; false and nothing changed when this call is stopped or already permitted.
     */
    fun permit(voiceSessionId: String, closesAtEpochMs: Long): Boolean =
        control.permit(voiceSessionId, closesAtEpochMs)

    /** The foreground service holds the foreground. Called by the service, for this call only. */
    fun servicePromoted() {
        handler.post { control.servicePromoted() }
    }

    /** The foreground service could not enter the foreground. The call ends. */
    fun serviceRefused() {
        handler.post { control.serviceRefused() }
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

    /** Applies the provider's SDP answer. It starts nothing: the recorder stays off until [permit]. */
    fun accept(answerSdp: String) {
        val answer = SessionDescription(SessionDescription.Type.ANSWER, answerSdp)
        val open = openConnection()
        awaitSet { observer -> open.setRemoteDescription(observer, answer) }
    }

    /** The connection, when the call is still open. */
    private fun openConnection(): PeerConnection =
        synchronized(lock) {
            connection.takeIf { !control.isStopped }
                ?: throw IllegalStateException("this voice call has ended")
        }

    /**
     * Stops the person's voice reaching the model, without ending the call.
     *
     * Local and immediate. Section 15 paragraph 10 requires local microphone and speaker mute to
     * remain available if the broker fails, so this touches the track and nothing that could be
     * waiting on a network answer. Unmuting is the person's choice and nothing more: it does not
     * open a microphone the system has taken or a call that has not been permitted.
     */
    fun setMutedByPerson(muted: Boolean) = control.setMutedByPerson(muted)

    /**
     * Stops the model's voice coming out of this device, without ending the call.
     *
     * This is playback, and section 15 paragraph 13 is explicit that speech interruption stops
     * playback and not a coding task. Nothing here cancels anything on a host.
     */
    fun setPlaybackMuted(muted: Boolean) = control.setPlaybackMuted(muted)

    /**
     * Whether the microphone was carrying speech at `atMs` on the monotonic clock.
     *
     * What a claim that something was said is checked against, from this device's own record.
     */
    fun couldHaveHeard(atMs: Long): Boolean = control.couldHaveHeard(atMs)

    /** Ends the call and gives the microphone back. Local and immediate, as mute is. */
    fun stop() = control.stop()

    /** Acts on what the system did to audio focus. */
    private fun onFocusChange(change: Int) {
        when (change) {
            AudioManager.AUDIOFOCUS_LOSS, AudioManager.AUDIOFOCUS_LOSS_TRANSIENT ->
                control.focus(lost = true)
            AudioManager.AUDIOFOCUS_GAIN -> control.focus(lost = false)
            else -> Unit
        }
    }

    /** True while the platform reports a call on the cellular radio. */
    @Suppress("DEPRECATION")
    fun isInPhoneCall(): Boolean =
        context.getSystemService(TelephonyManager::class.java)?.callState !=
            TelephonyManager.CALL_STATE_IDLE

    private fun hasInput(manager: AudioManager): Boolean =
        manager.getDevices(AudioManager.GET_DEVICES_INPUTS).isNotEmpty()

    private fun watchRoute() {
        val manager = context.getSystemService(AudioManager::class.java) ?: return
        val callback = object : AudioDeviceCallback() {
            override fun onAudioDevicesAdded(added: Array<out AudioDeviceInfo>?) = changed()

            override fun onAudioDevicesRemoved(removed: Array<out AudioDeviceInfo>?) = changed()

            private fun changed() {
                // A Bluetooth headset arriving or leaving. The state says so while capture is
                // re-established rather than claiming the person is still being heard.
                control.route(changing = true, inputAvailable = true)
                control.route(changing = false, inputAvailable = hasInput(manager))
            }
        }
        synchronized(lock) { routeCallback = callback }
        // Reported on this call's own thread.
        manager.registerAudioDeviceCallback(callback, handler)
        handler.post { control.route(changing = false, inputAvailable = hasInput(manager)) }
    }

    /** The platform, as the control sees it. */
    private inner class Platform : VoiceCallPlatform {
        override fun nowMs(): Long = SystemClock.elapsedRealtime()

        override fun epochMs(): Long = System.currentTimeMillis()

        override fun acquireFocus(): Boolean = audioSession.activate()

        override fun releaseFocus() = audioSession.deactivate()

        override fun startService(): Boolean {
            // The service is what keeps capture alive once the screen locks, and it is asked for
            // for a call the host permitted rather than by anything that could fire on its own.
            VoiceCallService.start(context, id)
            return true
        }

        override fun stopService() {
            try {
                VoiceCallService.stop(context, id)
            } catch (notRunning: IllegalStateException) {
                // The platform refuses to reach a service it would have to start from the
                // background, which means none is running for this call: nothing to stop.
            }
        }

        override fun schedule(atMs: Long, task: () -> Unit): () -> Unit {
            val runnable = Runnable { task() }
            handler.postDelayed(runnable, maxOf(0L, atMs - SystemClock.elapsedRealtime()))
            return { handler.removeCallbacks(runnable) }
        }

        override fun publish(state: VoiceCaptureState) = observer.onCaptureState(state)

        override fun publishToService(state: VoiceCaptureState) {
            try {
                VoiceCallService.publishCapture(context, id, state)
            } catch (notRunning: IllegalStateException) {
                // No service is running for this call, so there is no notification to update.
            }
        }

        override fun ended() {
            val (open, callback) = synchronized(lock) {
                val held = connection to routeCallback
                connection = null
                microphone = null
                routeCallback = null
                held
            }
            // Cleared only if this call is the one published: a call that was already replaced
            // must not take its replacement's place in the holder with it.
            VoiceCallHolder.claimStopped(this@VoiceCall)
            callback?.let {
                context.getSystemService(AudioManager::class.java)?.unregisterAudioDeviceCallback(it)
            }
            open?.dispose()
            factory.dispose()
            audioDevice.release()
            egl.release()
            thread.quitSafely()
        }
    }

    /** The media, as the control sets it. */
    private inner class Switches : VoiceMediaSwitches {
        override fun setAudioDevice(on: Boolean) {
            val open = synchronized(lock) {
                if (audioDeviceOn == on) return
                audioDeviceOn = on
                connection
            } ?: return
            open.setAudioRecording(on)
            open.setAudioPlayout(on)
        }

        override fun setMicrophone(on: Boolean) {
            audioDevice.setMicrophoneMute(!on)
            synchronized(lock) { microphone }?.setEnabled(on)
        }

        override fun setPlayback(on: Boolean) {
            val receivers = synchronized(lock) { connection }?.receivers ?: return
            receivers.forEach { (it.track() as? AudioTrack)?.setEnabled(on) }
        }
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
            if (receiver.track() !is AudioTrack) return
            // A track arrives playing; the control decides whether it may.
            handler.post { control.refresh() }
            if (announcedFirstAudio) return
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
