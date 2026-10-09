package to.kala.reach.companion.mobile

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * What the call reads of the provider's SDP answer.
 *
 * The answer is a recording of the real provider's, so the reader is held to what the provider
 * sends and not to what a test imagines it sends.
 */
class VoiceAnswerTest {
    /** The answer the provider gave to an offer in its qualification run, byte for byte. */
    private fun recorded(): String =
        File("../../../../fixtures/voice/provider-answer.sdp").readText(Charsets.UTF_8)

    /**
     * KR-REQ-15.35: the provider's real answer does not turn discontinuous transmission on, so a
     * gap in what it receives is read as a closed microphone.
     */
    @Test
    fun the_providers_answer_does_not_use_dtx() {
        val sdp = recorded()
        assertTrue("the recording is an answer with Opus", sdp.contains("a=rtpmap:111 opus/48000/2"))
        assertFalse(VoiceAnswer.usesDtx(sdp))
    }

    /**
     * KR-REQ-15.35: an answer that does turn it on is read as doing so, wherever among the
     * parameters it stands, and an answer that turns it off is not.
     */
    @Test
    fun an_answer_that_turns_dtx_on_is_read() {
        val sdp = recorded()
        val plain = "a=fmtp:111 minptime=10;useinbandfec=1"
        assertTrue(sdp.contains(plain))
        for (on in listOf(
            "a=fmtp:111 minptime=10;useinbandfec=1;usedtx=1",
            "a=fmtp:111 usedtx=1;minptime=10;useinbandfec=1",
            "a=fmtp:111 minptime=10; usedtx=1; useinbandfec=1",
        )) {
            assertTrue(on, VoiceAnswer.usesDtx(sdp.replace(plain, on)))
        }
        // The payload's name may stand after more than one space.
        assertTrue(
            VoiceAnswer.usesDtx(
                sdp.replace(plain, "a=fmtp:111 minptime=10;usedtx=1")
                    .replace("a=rtpmap:111 opus", "a=rtpmap:111   opus"),
            ),
        )
        assertFalse(
            VoiceAnswer.usesDtx(sdp.replace(plain, "a=fmtp:111 minptime=10;useinbandfec=1;usedtx=0")),
        )
    }

    /**
     * KR-REQ-15.35: the setting counts for the audio the call carries. The same words in a section
     * that carries no audio, or in an audio section the answer rejected, say nothing about it.
     */
    @Test
    fun dtx_in_a_section_that_carries_no_audio_is_not_the_calls() {
        val sdp = recorded()
        val dtx = "a=rtpmap:111 opus/48000/2\r\na=fmtp:111 usedtx=1\r\n"
        assertFalse(VoiceAnswer.usesDtx(sdp + "m=video 9 UDP/TLS/RTP/SAVPF 111\r\n" + dtx))
        assertFalse(VoiceAnswer.usesDtx(sdp + "m=audio 0 UDP/TLS/RTP/SAVPF 111\r\n" + dtx))
        assertTrue(VoiceAnswer.usesDtx(sdp + "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" + dtx))
    }

    /**
     * KR-REQ-15.35: the setting counts for the codec that carries the call. The same word on a
     * payload that is not Opus says nothing about it.
     */
    @Test
    fun dtx_on_another_payload_is_not_the_calls() {
        assertFalse(VoiceAnswer.usesDtx(recorded() + "a=fmtp:96 usedtx=1\r\n"))
    }
}
