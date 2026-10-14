package to.kala.reach.companion.voice

import android.content.Context
import java.util.concurrent.Executors
import to.kala.reach.companion.mobile.CallBridge
import to.kala.reach.companion.mobile.CallEvent
import to.kala.reach.companion.mobile.CallMute
import to.kala.reach.companion.mobile.CallNews
import to.kala.reach.companion.mobile.CallNewsQueue
import to.kala.reach.companion.mobile.CallRefused
import to.kala.reach.companion.mobile.HeldCall
import to.kala.reach.companion.mobile.VoiceCaptureState

/**
 * What the platform plugin asks of the voice call, carried out on the call.
 *
 * The plugin cannot see this module, so the application registers this at start
 * ([to.kala.reach.companion.mobile.CallBridgeHolder]) and the plugin finds it there. It holds one
 * call, the one the plugin named, and tells that call's news to Rust through a queue of its own,
 * numbered and bounded. It reports facts and carries out requests: nothing here decides when a
 * call opens, is permitted or ends.
 */
class VoiceCallBridge(context: Context) : CallBridge {
    private val context = context.applicationContext

    private class Held(val name: String, val call: VoiceCall, val queue: CallNewsQueue) {
        @Volatile
        var capture: VoiceCaptureState = VoiceCaptureState.IDLE
    }

    private val lock = Any()
    private var held: Held? = null

    /** Sends a call's news one item at a time, off every thread a call reports on. */
    private val sender = Executors.newSingleThreadExecutor { task ->
        Thread(task, "kr-call-news").apply { isDaemon = true }
    }

    override fun open(call: String, news: CallNews) {
        synchronized(lock) {
            if (held != null || VoiceCallHolder.current != null) {
                throw CallRefused(CallRefused.ALREADY_RUNNING, "this device already holds a call")
            }
        }
        val queue = CallNewsQueue(call, news)
        val reporter = Reporter(call, queue)
        val made = try {
            VoiceCall.start(context, reporter)
        } catch (failure: IllegalStateException) {
            throw CallRefused(CallRefused.ENGINE, failure.message ?: "the media engine could not make a call")
        }
        synchronized(lock) { held = Held(call, made, queue).also { reporter.mine = it } }
    }

    private fun named(call: String): Held =
        synchronized(lock) { held }?.takeIf { it.name == call }
            ?: throw CallRefused(CallRefused.NO_SUCH_CALL, "no call by that name is held")

    override fun offer(call: String): String = named(call).call.offer()

    override fun accept(call: String, sdp: String): Boolean {
        val one = named(call).call
        one.accept(sdp)
        return one.answerUsesDtx ?: false
    }

    override fun permit(call: String, voiceSessionId: String, closesAtEpochMs: Long): Boolean =
        named(call).call.permit(voiceSessionId, closesAtEpochMs)

    override fun setMuted(call: String, what: CallMute, muted: Boolean) {
        val one = named(call).call
        when (what) {
            CallMute.MICROPHONE -> one.setMutedByPerson(muted)
            CallMute.PLAYBACK -> one.setPlaybackMuted(muted)
        }
    }

    override fun stop(call: String) {
        named(call).call.stop()
    }

    override fun held(): HeldCall =
        synchronized(lock) { held }?.let { HeldCall(it.name, it.capture, !it.call.isPlaybackMuted) }
            ?: HeldCall(null, VoiceCaptureState.IDLE, playing = false)

    /** What one call tells the bridge, which queues it for Rust. */
    private inner class Reporter(private val name: String, private val queue: CallNewsQueue) :
        VoiceCall.Observer {
        /** The call's record, once it is made. */
        @Volatile
        var mine: Held? = null

        private fun tell(event: CallEvent) = queue.offer(event) { sender.execute(it) }

        override fun onCaptureState(state: VoiceCaptureState) {
            mine?.capture = state
            tell(CallEvent.Capture(state))
        }

        override fun onProviderEvent(bytes: ByteArray) = tell(CallEvent.ProviderEvent(bytes))

        override fun onFirstAudio() = tell(CallEvent.FirstAudio)

        override fun onConnectionState(state: String) = tell(CallEvent.Connection(state))

        override fun onEnded() {
            tell(CallEvent.Ended)
            queue.close()
            synchronized(lock) {
                if (this@VoiceCallBridge.held?.name == name) this@VoiceCallBridge.held = null
            }
        }
    }
}
