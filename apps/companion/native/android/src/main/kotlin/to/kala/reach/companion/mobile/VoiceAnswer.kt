package to.kala.reach.companion.mobile

/** What the call reads of the provider's SDP answer. */
object VoiceAnswer {
    /**
     * Whether the answer turns Opus discontinuous transmission on: an `a=fmtp` line of an Opus
     * payload type with `usedtx=1`.
     *
     * With it on the sender stops the stream during silence, so a gap in the stream is no longer
     * evidence that the microphone was closed.
     */
    fun usesDtx(sdp: String): Boolean {
        val lines = sdp.split('\r', '\n').filter { it.isNotEmpty() }
        val opus = lines
            .filter { it.startsWith("a=rtpmap:") }
            .mapNotNull { line ->
                // a=rtpmap:111 opus/48000/2
                val parts = line.removePrefix("a=rtpmap:").split(' ', limit = 2)
                parts.takeIf { it.size == 2 && it[1].lowercase().startsWith("opus/") }?.get(0)
            }
            .toSet()
        return lines
            .filter { it.startsWith("a=fmtp:") }
            .any { line ->
                // a=fmtp:111 minptime=10;useinbandfec=1
                val parts = line.removePrefix("a=fmtp:").split(' ', limit = 2)
                parts.size == 2 && parts[0] in opus && parts[1].split(';').any { parameter ->
                    val pair = parameter.split('=', limit = 2).map { it.trim() }
                    pair.size == 2 && pair[0].lowercase() == "usedtx" && pair[1] == "1"
                }
            }
    }
}
