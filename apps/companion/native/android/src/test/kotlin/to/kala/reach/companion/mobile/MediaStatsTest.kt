package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** When audio is first played out of the device, and what the media counters leave out. */
class MediaStatsTest {
    /** Little-endian 16-bit samples. */
    private fun pcm(vararg samples: Int): ByteArray {
        val bytes = ByteArray(samples.size * 2)
        for ((index, sample) in samples.withIndex()) {
            bytes[index * 2] = (sample and 0xff).toByte()
            bytes[index * 2 + 1] = ((sample shr 8) and 0xff).toByte()
        }
        return bytes
    }

    /** KR-PERF-010: silence the speaker side plays is not audio, whatever it is told. */
    @Test
    fun `a buffer of silence is not audio played out`() {
        val detector = PlayoutDetector()
        assertFalse(detector.buffer(ByteArray(960), playbackOn = true))
        assertFalse(detector.buffer(pcm(0, 3, -5, 100, -100, 127, -127), playbackOn = true))
    }

    /** KR-PERF-010: the first buffer with a sample above the floor is the first audio, told once. */
    @Test
    fun `the first buffer with sound is the first audio and is told once`() {
        val detector = PlayoutDetector()
        assertFalse(detector.buffer(pcm(0, 0, 0), playbackOn = true))
        assertTrue(detector.buffer(pcm(0, 0, 4000), playbackOn = true))
        assertFalse(detector.buffer(pcm(9000, -9000), playbackOn = true))
    }

    /** KR-PERF-010: a loud negative sample counts as sound, as a loud positive one does. */
    @Test
    fun `a loud negative sample is sound`() {
        assertTrue(PlayoutDetector().buffer(pcm(-4000), playbackOn = true))
        assertTrue(PlayoutDetector().buffer(pcm(-PlayoutDetector.FLOOR), playbackOn = true))
        assertFalse(PlayoutDetector().buffer(pcm(-(PlayoutDetector.FLOOR - 1)), playbackOn = true))
    }

    /** KR-PERF-010: sound handed over while playback is off, muted or interrupted is not played out. */
    @Test
    fun `nothing is played out while playback is off`() {
        val detector = PlayoutDetector()
        assertFalse(detector.buffer(pcm(9000), playbackOn = false))
        assertTrue("a later buffer with playback on is the first audio", detector.buffer(pcm(9000), playbackOn = true))
    }

    /** An odd trailing byte is not a sample. */
    @Test
    fun `half a sample is not read`() {
        assertFalse(PlayoutDetector().buffer(byteArrayOf(0x70), playbackOn = true))
    }

    /** The counters come from the audio entries of a report, and a figure it lacks is null. */
    @Test
    fun `the counters are read from the audio entries and a missing figure is null`() {
        val report = listOf(
            "inbound-rtp" to mapOf("kind" to "audio", "packetsReceived" to 1200L),
            "outbound-rtp" to mapOf("kind" to "audio", "packetsSent" to 1180),
            "media-playout" to mapOf("kind" to "audio", "totalSamplesCount" to 960000.0),
            "inbound-rtp" to mapOf("kind" to "video", "packetsReceived" to 7L),
        )
        assertEquals(
            MediaCounters(packetsReceived = 1200, packetsSent = 1180, playedSamples = 960000),
            MediaCounters.from(report),
        )
        val partial = MediaCounters.from(listOf("inbound-rtp" to mapOf("kind" to "audio", "packetsReceived" to 40L)))
        assertEquals(40L, partial.packetsReceived)
        assertNull(partial.packetsSent)
        assertNull(partial.playedSamples)
        assertTrue(MediaCounters.from(emptyList()).isEmpty)
        assertTrue(MediaCounters.from(listOf("inbound-rtp" to mapOf("kind" to "audio", "packetsReceived" to "40"))).isEmpty)
    }
}
