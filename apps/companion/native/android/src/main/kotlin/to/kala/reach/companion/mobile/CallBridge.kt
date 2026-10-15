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

/**
 * What a held call is doing: the microphone as the gate shows it, whether the person has muted it
 * (a fact of its own, since a microphone that is not running shows as unavailable whatever the
 * person did), and whether they have left the model's voice on.
 */
data class HeldCall(
    val call: String?,
    val capture: VoiceCaptureState,
    val microphoneMuted: Boolean,
    val playing: Boolean,
)

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

/**
 * Where the application puts its [CallBridge] and the plugin finds it.
 *
 * The bridge belongs to the process, not to an activity: the application is started again as a new
 * activity whenever the system recreates it, and a call that is running must still be reached by
 * the same bridge then. So the first registration stands and a later one is let go of unused.
 */
object CallBridgeHolder {
    @Volatile
    var bridge: CallBridge? = null
        private set

    /** The one opening of a call that may be under way. */
    val openings = CallOpenings()

    /** Registers the application's bridge, made only when none is registered yet. */
    @Synchronized
    fun registerOnce(make: () -> CallBridge) {
        if (bridge == null) bridge = make()
    }
}

/**
 * The one opening of a call that may be under way at a time.
 *
 * Opening may ask the person a permission question before anything is made, and the platform keeps
 * one answer for that question: a second opening that asked it too would take the first one's
 * answer, and the first would never get one. So an opening is refused while another is under way.
 * An opening waits on the question for a stated time and then goes on with what is allowed, as
 * if the question had been answered. It ends when the call is made or refused ([Opening.end]).
 * The answer ([Opening.answered]), the person's or the time running out, is taken once, and only
 * while the opening still waits for it. Each of these says whether it was the one that acted, so
 * whatever comes second does nothing: a late answer after the time ran out, a second ending. A
 * step that fails answers whoever is waiting only when it was the one that ended the opening. The
 * command that makes the call always answers, because nothing else ends an opening that is making
 * one.
 */
class CallOpenings {
    private var current: Opening? = null

    /** Starts an opening, or null when one is under way. */
    @Synchronized
    fun reserve(): Opening? {
        if (current != null) return null
        return Opening().also { current = it }
    }

    private enum class Stage { STARTING, ASKING, MAKING, ENDED }

    /** One opening of a call. */
    inner class Opening internal constructor() {
        private var stage = Stage.STARTING

        /** The opening now waits for the answer to the permission question. */
        fun asks() {
            synchronized(this@CallOpenings) {
                if (stage == Stage.STARTING) stage = Stage.ASKING
            }
        }

        /** The question was answered: true once, and only if the opening still waited for it. */
        fun answered(): Boolean {
            synchronized(this@CallOpenings) {
                if (stage != Stage.ASKING) return false
                stage = Stage.MAKING
                return true
            }
        }

        /** The call was made or refused: true, and the opening ends, only for the first ending. */
        fun end(): Boolean {
            synchronized(this@CallOpenings) {
                if (stage == Stage.ENDED) return false
                stage = Stage.ENDED
                current = null
                return true
            }
        }
    }
}

/**
 * Which call names a bridge holds and which it has seen end, so that a command naming a call that
 * is not held can say whether the call ended or never was.
 */
class CallNames {
    private var held: String? = null
    private val ended = ArrayDeque<String>()

    /** Whether a call is held. */
    @Synchronized
    fun isHeld(): Boolean = held != null

    /** The name held, if any. */
    @Synchronized
    fun held(): String? = held

    /**
     * Holds [name] as the call held while [make] makes the call, so that two openings cannot both
     * go on to make one. Refuses with [CallRefused.ALREADY_RUNNING] when a call is held already.
     * When [make] throws anything, the name is no longer held, and what was thrown goes on. An end
     * that the call itself reported while it was being made stays recorded by [end].
     */
    fun <T> making(name: String, make: () -> T): T {
        if (!hold(name)) throw CallRefused(CallRefused.ALREADY_RUNNING, "this device already holds a call")
        try {
            return make()
        } catch (failure: Throwable) {
            abandon(name)
            throw failure
        }
    }

    @Synchronized
    private fun hold(name: String): Boolean {
        if (held != null) return false
        held = name
        return true
    }

    @Synchronized
    private fun abandon(name: String) {
        if (held == name) held = null
    }

    /** The call named [name] is over: it is no longer held, and a command that names it says so. */
    @Synchronized
    fun end(name: String) {
        if (held == name) held = null
        ended.addLast(name)
        while (ended.size > REMEMBERED) ended.removeFirst()
    }

    /** Why [name] is not the call held, or null when it is. */
    @Synchronized
    fun refusal(name: String): CallRefused? =
        when {
            held == name -> null
            name in ended -> CallRefused(CallRefused.ENDED, "that call has ended")
            else -> CallRefused(CallRefused.NO_SUCH_CALL, "no call by that name is held")
        }

    companion object {
        /** How many ended calls are remembered by name. */
        const val REMEMBERED = 16
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

    /** Some news was dropped here. Never queued as news: it marks a place in the queue. */
    data object Lost : CallEvent
}

/**
 * The commands the platform plugin takes and the news it sends, as the JSON the Rust half speaks.
 *
 * The shapes are the fixtures under `native/platform/fixtures/call`, which the Rust and Swift
 * halves are tested against as well. This is plain Kotlin so that they are tested here, on a
 * developer's machine, and not only on a device.
 */
object CallWire {
    private fun text(read: JSONObject, key: String): String =
        read.opt(key) as? String ?: throw IllegalArgumentException("$key is not text")

    private fun flag(read: JSONObject, key: String): Boolean =
        read.opt(key) as? Boolean ?: throw IllegalArgumentException("$key is not true or false")

    /** A whole number that is not negative: the other halves read an unsigned one. */
    private fun moment(read: JSONObject, key: String): Long {
        val value = when (val found = read.opt(key)) {
            is Int -> found.toLong()
            is Long -> found
            else -> throw IllegalArgumentException("$key is not a whole number")
        }
        if (value < 0) throw IllegalArgumentException("$key is negative")
        return value
    }

    /** The call a command names. */
    fun call(arguments: String): String = text(JSONObject(arguments), "call")

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
        return Answer(text(read, "call"), text(read, "sdp"))
    }

    /** What applying the answer reports. */
    fun answered(usesDtx: Boolean): String = JSONObject().put("usesDtx", usesDtx).toString()

    /** What permitting a call is given. */
    class Permit(val call: String, val voiceSessionId: String, val closesAtEpochMs: Long)

    /** Reads the arguments of permitting a call. */
    fun permit(arguments: String): Permit {
        val read = JSONObject(arguments)
        return Permit(
            text(read, "call"),
            text(read, "voiceSessionId"),
            moment(read, "closesAtEpochMs"),
        )
    }

    /** What permitting a call answers. */
    fun permitted(permitted: Boolean): String = JSONObject().put("permitted", permitted).toString()

    /** What a mute names. */
    class Mute(val call: String, val what: CallMute, val muted: Boolean)

    /** Reads the arguments of a mute; a word that names neither silence is refused. */
    fun mute(arguments: String): Mute {
        val read = JSONObject(arguments)
        val word = text(read, "what")
        val what = CallMute.entries.firstOrNull { it.word == word }
            ?: throw IllegalArgumentException("a mute is of the microphone or of playback")
        return Mute(text(read, "call"), what, flag(read, "muted"))
    }

    /** What a command with nothing to report answers. */
    fun nothing(): String = "{}"

    /** What the call this device holds is doing, as the state command answers. */
    fun held(held: HeldCall): String =
        JSONObject()
            .put("call", held.call ?: JSONObject.NULL)
            .put("capture", capture(held.capture))
            .put("microphoneMuted", held.microphoneMuted)
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
            CallEvent.Lost -> frame.put("kind", "lost")
        }
        return frame.toString()
    }
}

/**
 * A call's news waiting for the sender: bounded, in order, with a loss kept in its place.
 *
 * At most [limit] items of news wait. A provider event that finds the buffer full is dropped. Any
 * other news that finds it full takes the place of the oldest provider event waiting, or, when
 * there is none, of the oldest news: what was displaced is lost, and the buffer holds the mark of
 * the loss where it happened, one mark for losses that sit together. The end of the call closes the
 * buffer, so nothing is queued after it. It holds no thread: [CallNewsQueue] sends from it.
 */
class CallNewsBuffer(private val limit: Int) {
    /** One place in the buffer. */
    sealed interface Entry {
        /** News. */
        data class News(val event: CallEvent) : Entry

        /** Some news was lost here. */
        data object Lost : Entry
    }

    private val entries = ArrayDeque<Entry>()
    private var events = 0
    private var closed = false

    /** Queues one item of news. */
    fun push(event: CallEvent) {
        if (closed) return
        if (events >= limit) {
            if (event is CallEvent.ProviderEvent) {
                markLost()
                return
            }
            val victim = entries.indexOfFirst { it is Entry.News && it.event is CallEvent.ProviderEvent }
                .takeIf { it >= 0 } ?: entries.indexOfFirst { it is Entry.News }
            if (victim >= 0) {
                entries[victim] = Entry.Lost
                events -= 1
                mergeMarks()
            }
        }
        if (event is CallEvent.Ended) closed = true
        entries.addLast(Entry.News(event))
        events += 1
    }

    /** Records that news was lost after everything queued so far. */
    fun markLost() {
        if (!closed && entries.lastOrNull() != Entry.Lost) entries.addLast(Entry.Lost)
    }

    private fun mergeMarks() {
        val merged = ArrayDeque<Entry>()
        for (entry in entries) {
            if (entry == Entry.Lost && merged.lastOrNull() == Entry.Lost) continue
            merged.addLast(entry)
        }
        entries.clear()
        entries.addAll(merged)
    }

    /** The next place, oldest first. */
    fun pop(): Entry? {
        val entry = entries.removeFirstOrNull()
        if (entry is Entry.News) events -= 1
        return entry
    }
}

/**
 * A call's news on its way to Rust: numbered from 1 as it is sent, in order, and bounded.
 *
 * A call reports from several threads, and sending on the channel Rust gave must never hold one of
 * them, so news is queued in a [CallNewsBuffer] and sent by one thread of the queue's own. News
 * the buffer dropped is sent as a `lost` item in its place.
 */
class CallNewsQueue(
    private val call: String,
    private val news: CallNews,
    limit: Int = CAPACITY,
) {
    private val lock = Any()
    private val buffer = CallNewsBuffer(limit)
    private var seq = 0L
    private var draining = false

    /**
     * Queues [event]. [after] runs a drain on a thread of the caller's choosing: a drain is
     * started only when none is running, so the sender is called one item at a time, in order.
     */
    fun offer(event: CallEvent, after: (Runnable) -> Unit) {
        val start = synchronized(lock) {
            buffer.push(event)
            if (draining) false else { draining = true; true }
        }
        if (start) after(Runnable { drain() })
    }

    private fun drain() {
        while (true) {
            val next = synchronized(lock) {
                val taken = buffer.pop()
                if (taken == null) draining = false
                taken?.let {
                    seq += 1
                    CallWire.frame(call, seq, if (it is CallNewsBuffer.Entry.News) it.event else CallEvent.Lost)
                }
            } ?: return
            news.send(next)
        }
    }

    companion object {
        /** How many items may wait for the sender. */
        const val CAPACITY = 256
    }
}
