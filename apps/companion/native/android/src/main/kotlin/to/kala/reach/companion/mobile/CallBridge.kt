package to.kala.reach.companion.mobile

import org.json.JSONObject
import java.util.Base64

/** Which of the two local silences a mute acts on. */
enum class CallMute(val word: String) {
    /** The person's own microphone. */
    MICROPHONE("microphone"),

    /** The model's voice coming out of this device. */
    PLAYBACK("playback"),
}

/** A request the application's call cannot carry out, with the code the plugin rejects it by. */
class CallRefused(val code: String, message: String) : Exception(message) {
    companion object {
        const val MICROPHONE_REFUSED = "microphone_refused"
        const val ALREADY_RUNNING = "already_running"
        const val NO_SUCH_CALL = "no_such_call"
        const val ENDED = "ended"
        const val ENGINE = "engine"
    }
}

/** What the plugin sends back of a call: one item of its news, numbered, as JSON text. */
fun interface CallNews {
    /** Sends one item. Never blocks on the other end. */
    fun send(frame: String)
}

/** What a held call is doing. */
data class HeldCall(val call: String?, val capture: VoiceCaptureState, val playing: Boolean)

/**
 * What the platform plugin asks of the voice call the application holds.
 *
 * The call is the application's own, in its own module, which the plugin's library cannot see: the
 * application registers its implementation here at start, and the plugin finds it through
 * [CallBridgeHolder]. Nothing is looked up by name, so a build that renames or removes classes
 * cannot break the link without breaking the build. Every method may wait on the media engine, so
 * the plugin calls them off the thread a command arrives on.
 */
interface CallBridge {
    /**
     * Makes the call named [call], with its microphone off, and keeps [news] for what it reports.
     *
     * @throws CallRefused when this device already holds a call, or the engine cannot make one.
     */
    fun open(call: String, news: CallNews)

    /** Makes the call's offer. */
    fun offer(call: String): String

    /** Applies the provider's answer, and answers whether it turns discontinuous transmission on. */
    fun accept(call: String, sdp: String): Boolean

    /** Lets the call carry the microphone until [closesAtEpochMs]; false when it is not ready. */
    fun permit(call: String, voiceSessionId: String, closesAtEpochMs: Long): Boolean

    /** Silences, or ends the silence of, the person's microphone or the model's voice. */
    fun setMuted(call: String, what: CallMute, muted: Boolean)

    /** Ends the call and gives the microphone back. */
    fun stop(call: String)

    /** What the call this device holds is doing, if it holds one. */
    fun held(): HeldCall
}

/** Where the application puts its [CallBridge] and the plugin finds it. */
object CallBridgeHolder {
    @Volatile
    var bridge: CallBridge? = null
        private set

    /** Registers the application's bridge. A later registration replaces the earlier. */
    fun register(registered: CallBridge) {
        bridge = registered
    }
}

/** One item of a call's news. */
sealed interface CallEvent {
    /** The media connection changed state; [state] is one of the wire's connection words. */
    data class Connection(val state: String) : CallEvent

    /** The provider sent [bytes] on its read-only channel. */
    class ProviderEvent(val bytes: ByteArray) : CallEvent

    /** The first remote audio track arrived. */
    data object FirstAudio : CallEvent

    /** The microphone's state changed. */
    data class Capture(val state: VoiceCaptureState) : CallEvent

    /** The call ended. */
    data object Ended : CallEvent
}

/**
 * The commands the platform plugin takes and the news it sends, as the JSON the Rust half speaks.
 *
 * The shapes are the fixtures under `native/platform/fixtures/call`, which the Rust and Swift
 * halves are tested against as well. This is plain Kotlin so that they are tested here, on a
 * developer's machine, and not only on a device.
 */
object CallWire {
    /** The call a command names. */
    fun call(arguments: String): String = JSONObject(arguments).getString("call")

    /** What opening a call answers. */
    fun opened(notificationsAllowed: Boolean): String =
        JSONObject().put("notifications", if (notificationsAllowed) "granted" else "denied").toString()

    /** What making the offer answers. */
    fun offered(sdp: String): String = JSONObject().put("sdp", sdp).toString()

    /** The call and the provider's answer, from the arguments of applying it. */
    class Answer(val call: String, val sdp: String)

    /** Reads the arguments of applying the provider's answer. */
    fun answer(arguments: String): Answer {
        val read = JSONObject(arguments)
        return Answer(read.getString("call"), read.getString("sdp"))
    }

    /** What applying the answer reports. */
    fun answered(usesDtx: Boolean): String = JSONObject().put("usesDtx", usesDtx).toString()

    /** What permitting a call is given. */
    class Permit(val call: String, val voiceSessionId: String, val closesAtEpochMs: Long)

    /** Reads the arguments of permitting a call. */
    fun permit(arguments: String): Permit {
        val read = JSONObject(arguments)
        return Permit(
            read.getString("call"),
            read.getString("voiceSessionId"),
            read.getLong("closesAtEpochMs"),
        )
    }

    /** What permitting a call answers. */
    fun permitted(permitted: Boolean): String = JSONObject().put("permitted", permitted).toString()

    /** What a mute names. */
    class Mute(val call: String, val what: CallMute, val muted: Boolean)

    /** Reads the arguments of a mute; a word that names neither silence is refused. */
    fun mute(arguments: String): Mute {
        val read = JSONObject(arguments)
        val word = read.getString("what")
        val what = CallMute.entries.firstOrNull { it.word == word }
            ?: throw IllegalArgumentException("a mute is of the microphone or of playback")
        return Mute(read.getString("call"), what, read.getBoolean("muted"))
    }

    /** What a command with nothing to report answers. */
    fun nothing(): String = "{}"

    /** What the call this device holds is doing, as the state command answers. */
    fun held(held: HeldCall): String =
        JSONObject()
            .put("call", held.call ?: JSONObject.NULL)
            .put("capture", capture(held.capture))
            .put("playing", held.playing)
            .toString()

    /** The wire's word for what the microphone is doing. */
    fun capture(state: VoiceCaptureState): String =
        when (state) {
            VoiceCaptureState.CAPTURING -> "capturing"
            VoiceCaptureState.MUTED_BY_PERSON -> "muted_by_person"
            VoiceCaptureState.FOCUS_LOST -> "interrupted"
            VoiceCaptureState.ROUTE_CHANGING -> "route_changing"
            VoiceCaptureState.SUSPENDED_BY_SYSTEM -> "suspended_by_system"
            VoiceCaptureState.UNAVAILABLE -> "unavailable"
            VoiceCaptureState.IDLE -> "idle"
        }

    /** One item of news, numbered, as the frame Rust reads. */
    fun frame(call: String, seq: Long, event: CallEvent): String {
        val frame = JSONObject().put("call", call).put("seq", seq)
        when (event) {
            is CallEvent.Connection -> frame.put("kind", "connection").put("state", event.state)
            is CallEvent.ProviderEvent ->
                frame.put("kind", "provider_event")
                    .put("bytes", Base64.getEncoder().encodeToString(event.bytes))
            CallEvent.FirstAudio -> frame.put("kind", "first_audio")
            is CallEvent.Capture -> frame.put("kind", "capture").put("state", capture(event.state))
            CallEvent.Ended -> frame.put("kind", "ended")
        }
        return frame.toString()
    }
}

/**
 * A call's news on its way to Rust: numbered from 1, in order, and bounded.
 *
 * A call reports from several threads, and sending on the channel Rust gave must never hold one of
 * them, so news is queued here and sent by one thread of the queue's own. A provider event that
 * finds the queue full is dropped, and its number is spent: Rust sees the gap as lost news and does
 * not take the quiet for there being nothing to say. Every other kind of news is kept whatever the
 * queue holds, since a state change or the end of the call cannot be missed.
 */
class CallNewsQueue(
    private val call: String,
    private val news: CallNews,
    private val capacity: Int = CAPACITY,
) {
    private val lock = Any()
    private val pending = ArrayDeque<String>()
    private var seq = 0L
    private var draining = false
    private var closed = false

    /**
     * Queues [event]. [after] runs a drain on a thread of the caller's choosing: a drain is
     * started only when none is running, so the sender is called one item at a time, in order.
     */
    fun offer(event: CallEvent, after: (Runnable) -> Unit) {
        val start = synchronized(lock) {
            if (closed) return
            seq += 1
            if (event is CallEvent.ProviderEvent && pending.size >= capacity) return
            pending.addLast(CallWire.frame(call, seq, event))
            if (draining) false else { draining = true; true }
        }
        if (start) after(Runnable { drain() })
    }

    /** Stops queueing; what is queued is still sent. */
    fun close() {
        synchronized(lock) { closed = true }
    }

    private fun drain() {
        while (true) {
            val next = synchronized(lock) {
                val taken = pending.removeFirstOrNull()
                if (taken == null) draining = false
                taken
            } ?: return
            news.send(next)
        }
    }

    companion object {
        /** How many items may wait for the sender. */
        const val CAPACITY = 256
    }
}
