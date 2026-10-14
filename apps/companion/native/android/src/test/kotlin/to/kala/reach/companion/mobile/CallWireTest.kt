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
            CallWire.held(HeldCall("c1", VoiceCaptureState.MUTED_BY_PERSON, playing = true)),
        )
        same(
            cases("callState")[1].getJSONObject("response"),
            CallWire.held(HeldCall(null, VoiceCaptureState.IDLE, playing = false)),
        )
    }

    @Test
    fun `each item of news is the fixture's frame`() {
        val news = fixture("events.json")
        val frames = (0 until news.length()).map { news.getJSONObject(it).getJSONObject("frame") }
        val events = listOf(
            CallEvent.Connection("connecting"),
            CallEvent.Connection("connected"),
            CallEvent.ProviderEvent("""{"type":"session.created"}""".toByteArray()),
            CallEvent.FirstAudio,
            CallEvent.Capture(VoiceCaptureState.ROUTE_CHANGING),
            CallEvent.Ended,
        )
        assertEquals(frames.size, events.size)
        for ((index, event) in events.withIndex()) {
            same(frames[index], CallWire.frame("c1", (index + 1).toLong(), event))
        }
    }

    @Test
    fun `focus lost is told as the microphone being interrupted`() {
        assertEquals("interrupted", CallWire.capture(VoiceCaptureState.FOCUS_LOST))
    }

    @Test
    fun `news is sent in order, one item at a time, from the thread the caller chose`() {
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
    fun `a provider event that finds the queue full is dropped and its number is spent`() {
        val sent = mutableListOf<String>()
        val queue = CallNewsQueue("c1", { sent += it }, capacity = 1)
        val later = ArrayDeque<Runnable>()
        queue.offer(CallEvent.ProviderEvent(byteArrayOf(1))) { later.addLast(it) }
        queue.offer(CallEvent.ProviderEvent(byteArrayOf(2))) { later.addLast(it) }
        queue.offer(CallEvent.Ended) { later.addLast(it) }

        later.removeFirst().run()

        val numbers = sent.map { JSONObject(it).getLong("seq") }
        assertEquals("the dropped event leaves a gap Rust reads as lost news", listOf(1L, 3L), numbers)
        assertEquals("ended", JSONObject(sent.last()).getString("kind"))
    }

    @Test
    fun `news that is not a provider event is kept whatever the queue holds`() {
        val sent = mutableListOf<String>()
        val queue = CallNewsQueue("c1", { sent += it }, capacity = 1)
        val later = ArrayDeque<Runnable>()
        queue.offer(CallEvent.ProviderEvent(byteArrayOf(1))) { later.addLast(it) }
        queue.offer(CallEvent.Connection("failed")) { later.addLast(it) }
        queue.offer(CallEvent.Ended) { later.addLast(it) }

        later.removeFirst().run()

        assertEquals(listOf("provider_event", "connection", "ended"), sent.map { JSONObject(it).getString("kind") })
    }
}
