package to.kala.reach.companion.mobile

/**
 * What a call's media has carried. A figure the statistics did not hold is null, never zero, and
 * is left out of what is sent.
 */
data class MediaCounters(
    val packetsReceived: Long? = null,
    val packetsSent: Long? = null,
    val playedSamples: Long? = null,
) {
    /** Whether the statistics held none of the figures. */
    val isEmpty: Boolean
        get() = packetsReceived == null && packetsSent == null && playedSamples == null

    companion object {
        /**
         * The counters in a statistics report, given as each entry's type and members: the audio
         * packets received and sent, and the samples the speaker side has taken.
         */
        fun from(entries: Collection<Pair<String, Map<String, Any?>>>): MediaCounters {
            var counters = MediaCounters()
            for ((type, members) in entries) {
                val audio = members["kind"] == "audio"
                counters = when {
                    type == "inbound-rtp" && audio ->
                        counters.copy(packetsReceived = whole(members["packetsReceived"]))
                    type == "outbound-rtp" && audio ->
                        counters.copy(packetsSent = whole(members["packetsSent"]))
                    type == "media-playout" ->
                        counters.copy(playedSamples = whole(members["totalSamplesCount"]))
                    else -> counters
                }
            }
            return counters
        }

        private fun whole(value: Any?): Long? =
            when (value) {
                is Long -> value
                is Int -> value.toLong()
                is Number -> value.toLong()
                else -> null
            }
    }
}

/**
 * Says once that audio was played out of the device: the first buffer handed to the speaker side
 * with a sample above a floor, while playback is on, unmuted and uninterrupted. A buffer of
 * silence, as a muted or interrupted track plays, is not audio played out. The buffers come on the
 * audio thread.
 */
class PlayoutDetector(private val floor: Int = FLOOR) {
    private var told = false

    /**
     * Takes one buffer of 16-bit little-endian samples; true the first time one carries sound with
     * [playbackOn].
     */
    @Synchronized
    fun buffer(samples: ByteArray, playbackOn: Boolean): Boolean {
        if (told || !playbackOn) return false
        var index = 0
        while (index + 1 < samples.size) {
            val low = samples[index].toInt() and 0xff
            val high = samples[index + 1].toInt()
            val sample = (high shl 8) or low
            if (kotlin.math.abs(sample) >= floor) {
                told = true
                return true
            }
            index += 2
        }
        return false
    }

    companion object {
        /** About 48 decibels below full scale: above the noise a decoder leaves, far below speech. */
        const val FLOOR = 128
    }
}
