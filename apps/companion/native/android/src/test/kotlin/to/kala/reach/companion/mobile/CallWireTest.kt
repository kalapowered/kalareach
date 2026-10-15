package to.kala.reach.companion.mobile

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The commands the Rust half sends and the news it reads are the cases of the fixtures the Rust and
 * Swift halves are tested against too: what this half decodes is what Rust encodes, and what it
 * encodes is what Rust decodes.
 */
class CallWireTest {
    private fun fixture(name: String): JSONArray =
        JSONArray(File(System.getProperty("kr.fixtures"), "call/$name").readText())

    private fun cases(command: String): List<JSONObject> =
        fixture("commands.json").let { all ->
            (0 until all.length()).map { all.getJSONObject(it) }.filter { it.getString("command") == command }
        }

    private fun same(expected: JSONObject, actual: String) {
        assertTrue("expected $expected, got $actual", expected.similar(JSONObject(actual)))
    }

    @Test
    fun `a call is named in the arguments of every command that names one`() {
        for (command in listOf("callOpen", "callOffer", "callStop")) {
            for (case in cases(command)) {
                assertEquals(case.getJSONObject("request").getString("call"), CallWire.call(case.getJSONObject("request").toString()))
            }
        }
    }

    @Test
    fun `what opening, offering and applying an answer say is what Rust reads`() {
        same(cases("callOpen")[0].getJSONObject("response"), CallWire.opened(notificationsAllowed = true))
        same(cases("callOpen")[1].getJSONObject("response"), CallWire.opened(notificationsAllowed = false))
        val offer = cases("callOffer")[0]
        same(offer.getJSONObject("response"), CallWire.offered(offer.getJSONObject("response").getString("sdp")))
        val accept = cases("callAccept")[0]
        val answer = CallWire.answer(accept.getJSONObject("request").toString())
        assertEquals("c1", answer.call)
        assertEquals(accept.getJSONObject("request").getString("sdp"), answer.sdp)
        same(accept.getJSONObject("response"), CallWire.answered(usesDtx = true))
    }

    @Test
    fun `permitting a call reads its session and the moment it closes`() {
        val permit = cases("callPermit")[0]
        val read = CallWire.permit(permit.getJSONObject("request").toString())
        assertEquals("c1", read.call)
        assertEquals("5b2f0a3c-8a56-4c53-bb7e-6a4a4a1c9e01", read.voiceSessionId)
        assertEquals(1_760_300_000_000L, read.closesAtEpochMs)
        same(permit.getJSONObject("response"), CallWire.permitted(permitted = true))
    }

    @Test
    fun `a mute names which silence and whether it is on`() {
        val first = CallWire.mute(cases("callMute")[0].getJSONObject("request").toString())
        assertEquals(CallMute.MICROPHONE, first.what)
        assertTrue(first.muted)
        val second = CallWire.mute(cases("callMute")[1].getJSONObject("request").toString())
        assertEquals(CallMute.PLAYBACK, second.what)
        assertFalse(second.muted)
        same(cases("callMute")[0].getJSONObject("response"), CallWire.nothing())
        same(cases("callStop")[0].getJSONObject("response"), CallWire.nothing())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a mute of anything else is refused`() {
        CallWire.mute("""{"call":"c1","what":"camera","muted":true}""")
    }

    @Test
    fun `what the call is doing is what Rust reads`() {
        same(
            cases("callState")[0].getJSONObject("response"),
            CallWire.held(HeldCall("c1", VoiceCaptureState.MUTED_BY_PERSON, microphoneMuted = true, playing = true)),
        )
        same(
            cases("callState")[1].getJSONObject("response"),
            CallWire.held(HeldCall(null, VoiceCaptureState.IDLE, microphoneMuted = false, playing = false)),
        )
    }

    @Test
    fun `each item of news is the fixture's frame`() {
        val news = fixture("events.json")
        val frames = (0 until news.length()).map { news.getJSONObject(it).getJSONObject("frame") }
        val events = listOf(
            CallEvent.Connection("new"),
            CallEvent.Connection("connecting"),
            CallEvent.Connection("connected"),
            CallEvent.Connection("disconnected"),
            CallEvent.Connection("failed"),
            CallEvent.Connection("closed"),
            CallEvent.ProviderEvent("""{"type":"session.created"}""".toByteArray()),
            CallEvent.FirstAudio,
            CallEvent.Capture(VoiceCaptureState.CAPTURING),
            CallEvent.Capture(VoiceCaptureState.MUTED_BY_PERSON),
            CallEvent.Capture(VoiceCaptureState.FOCUS_LOST),
            CallEvent.Capture(VoiceCaptureState.ROUTE_CHANGING),
            CallEvent.Capture(VoiceCaptureState.SUSPENDED_BY_SYSTEM),
            CallEvent.Capture(VoiceCaptureState.UNAVAILABLE),
            CallEvent.Capture(VoiceCaptureState.IDLE),
            CallEvent.Lost,
            CallEvent.Ended,
        )
        assertEquals(frames.size, events.size)
        for ((index, event) in events.withIndex()) {
            same(frames[index], CallWire.frame("c1", (index + 1).toLong(), event))
        }
    }

    @Test
    fun `a request the other halves refuse is refused here too`() {
        val refusals = fixture("refusals.json")
        assertTrue(refusals.length() >= 15)
        for (index in 0 until refusals.length()) {
            val case = refusals.getJSONObject(index)
            val request = case.getJSONObject("request").toString()
            val refused = try {
                when (case.getString("command")) {
                    "callMute" -> CallWire.mute(request)
                    "callPermit" -> CallWire.permit(request)
                    "callAccept" -> CallWire.answer(request)
                    "callOffer", "callStop" -> CallWire.call(request)
                    else -> error("the fixture names a command ${case.getString("command")}")
                }
                false
            } catch (_: IllegalArgumentException) {
                true
            }
            assertTrue(case.getString("name"), refused)
        }
    }

    @Test
    fun `focus lost is told as the microphone being interrupted`() {
        assertEquals("interrupted", CallWire.capture(VoiceCaptureState.FOCUS_LOST))
    }

    private fun event(kind: String): CallEvent =
        when (kind) {
            "provider" -> CallEvent.ProviderEvent(byteArrayOf(1))
            "connection" -> CallEvent.Connection("connected")
            "capture" -> CallEvent.Capture(VoiceCaptureState.CAPTURING)
            "first_audio" -> CallEvent.FirstAudio
            "ended" -> CallEvent.Ended
            else -> error("the fixture names news of a kind $kind")
        }

    private fun kind(entry: CallNewsBuffer.Entry?): String =
        when (entry) {
            null -> "none"
            CallNewsBuffer.Entry.Lost -> "lost"
            is CallNewsBuffer.Entry.News ->
                when (entry.event) {
                    is CallEvent.ProviderEvent -> "provider"
                    is CallEvent.Connection -> "connection"
                    is CallEvent.Capture -> "capture"
                    CallEvent.FirstAudio -> "first_audio"
                    CallEvent.Ended -> "ended"
                    CallEvent.Lost -> error("a loss is never queued as news")
                }
        }

    @Test
    fun `the buffer keeps the order and tells a loss where it happened`() {
        val cases = fixture("queue.json")
        assertTrue(cases.length() >= 10)
        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            val buffer = CallNewsBuffer(case.getInt("limit"))
            val popped = mutableListOf<String>()
            val ops = case.getJSONArray("ops")
            for (at in 0 until ops.length()) {
                val op = ops.getString(at)
                if (op.startsWith("push ")) buffer.push(event(op.removePrefix("push "))) else popped += kind(buffer.pop())
            }
            val expected = case.getJSONArray("results")
            assertEquals(case.getString("name"), (0 until expected.length()).map { expected.getString(it) }, popped)
        }
    }

    @Test
    fun `news is sent in order, numbered as it is sent, one item at a time, from the thread the caller chose`() {
        val sent = mutableListOf<String>()
        val queue = CallNewsQueue("c1", { sent += it })
        val later = ArrayDeque<Runnable>()
        queue.offer(CallEvent.FirstAudio) { later.addLast(it) }
        queue.offer(CallEvent.Ended) { later.addLast(it) }
        assertEquals("one drain is asked for, not two", 1, later.size)
        assertTrue(sent.isEmpty())

        later.removeFirst().run()

        assertEquals(2, sent.size)
        assertEquals(1, JSONObject(sent[0]).getLong("seq"))
        assertEquals(2, JSONObject(sent[1]).getLong("seq"))
    }

    @Test
    fun `a provider event dropped as the last news is still told as lost`() {
        val sent = mutableListOf<String>()
        val queue = CallNewsQueue("c1", { sent += it }, limit = 1)
        val later = ArrayDeque<Runnable>()
        queue.offer(CallEvent.ProviderEvent(byteArrayOf(1))) { later.addLast(it) }
        queue.offer(CallEvent.ProviderEvent(byteArrayOf(2))) { later.addLast(it) }

        later.removeFirst().run()

        assertEquals(listOf("provider_event", "lost"), sent.map { JSONObject(it).getString("kind") })
        assertEquals(listOf(1L, 2L), sent.map { JSONObject(it).getLong("seq") })
    }

    @Test
    fun `the end of the call is sent even when the queue is full of other news`() {
        val sent = mutableListOf<String>()
        val queue = CallNewsQueue("c1", { sent += it }, limit = 1)
        val later = ArrayDeque<Runnable>()
        queue.offer(CallEvent.ProviderEvent(byteArrayOf(1))) { later.addLast(it) }
        queue.offer(CallEvent.Ended) { later.addLast(it) }
        queue.offer(CallEvent.Capture(VoiceCaptureState.IDLE)) { later.addLast(it) }

        later.removeFirst().run()

        assertEquals("nothing follows the end", listOf("lost", "ended"), sent.map { JSONObject(it).getString("kind") })
    }

    @Test
    fun `the first registration of the bridge stands`() {
        val first = FakeBridge()
        var made = 0
        CallBridgeHolder.registerOnce { first }
        CallBridgeHolder.registerOnce { made += 1; FakeBridge() }

        assertTrue(CallBridgeHolder.bridge === first)
        assertEquals("a second bridge is not even made", 0, made)
    }

    @Test
    fun `only one opening of a call is under way at a time`() {
        val openings = CallOpenings()
        val first = openings.reserve()
        assertTrue(first != null)
        assertEquals("another opening waits its turn", null, openings.reserve())

        assertTrue(first!!.end())

        assertTrue(openings.reserve() != null)
    }

    @Test
    fun `the answer to the question an opening waits on is taken once`() {
        val openings = CallOpenings()
        val opening = openings.reserve()!!
        assertFalse("an opening that asks nothing has no answer to take", opening.answered())
        opening.asks()

        assertTrue("the answer is taken", opening.answered())
        assertFalse("and only once, whoever gives it", opening.answered())
        assertEquals("the opening is still under way", null, openings.reserve())
        assertTrue(opening.end())
        assertFalse("an answer after the end is not taken", opening.answered())
        assertTrue("and another may begin", openings.reserve() != null)
    }

    @Test
    fun `an opening that ended does not end the one that follows it`() {
        val openings = CallOpenings()
        val first = openings.reserve()!!
        assertTrue(first.end())
        val second = openings.reserve()!!

        assertFalse("a second ending of the first does nothing", first.end())
        assertEquals("the second is still the one under way", null, openings.reserve())
        assertTrue(second.end())
    }

    @Test
    fun `a call is held by one name at a time and a name whose call could not be made is let go`() {
        val names = CallNames()
        names.making("c1") {
            val refused = try {
                names.making("c2") { }
                null
            } catch (refused: CallRefused) {
                refused
            }
            assertEquals(CallRefused.ALREADY_RUNNING, refused?.code)
        }
        names.end("c1")
        assertEquals(CallRefused.ENDED, names.refusal("c1")?.code)

        try {
            names.making("c3") { throw LinkageError("the library did not load") }
        } catch (_: LinkageError) {
        }

        assertEquals("a name whose call was never made is not held", false, names.isHeld())
        assertEquals(CallRefused.NO_SUCH_CALL, names.refusal("c3")?.code)
        names.making("c4") { }
        assertTrue(names.isHeld())
    }

    @Test
    fun `a call that ended is told apart from one that never was`() {
        val names = CallNames()
        names.making("c1") { }
        assertEquals(null, names.refusal("c1"))
        assertEquals(CallRefused.NO_SUCH_CALL, names.refusal("c2")?.code)

        names.end("c1")

        assertEquals(CallRefused.ENDED, names.refusal("c1")?.code)
        assertEquals(CallRefused.NO_SUCH_CALL, names.refusal("c2")?.code)
        assertFalse(names.isHeld())
    }

    private class FakeBridge : CallBridge {
        override fun open(call: String, news: CallNews) = Unit
        override fun offer(call: String) = ""
        override fun accept(call: String, sdp: String) = false
        override fun permit(call: String, voiceSessionId: String, closesAtEpochMs: Long) = false
        override fun setMuted(call: String, what: CallMute, muted: Boolean) = Unit
        override fun stop(call: String) = Unit
        override fun held() = HeldCall(null, VoiceCaptureState.IDLE, microphoneMuted = false, playing = false)
    }
}
