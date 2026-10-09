package to.kala.reach.companion.mobile

/** What the call reads of the provider's SDP answer. */
object VoiceAnswer {
    /**
     * Whether the answer turns Opus discontinuous transmission on: an `a=fmtp` line of an Opus
     * payload type with `usedtx=1`, in an audio section the answer accepted.
     *
     * With it on the sender stops the stream during silence, so a gap in the stream is no longer
     * evidence that the microphone was closed. A section that carries no audio, or one the answer
     * rejected (port 0), says nothing about the call's audio and is not read.
     */
    fun usesDtx(sdp: String): Boolean =
        sections(sdp).filter { acceptedAudio(it.first()) }.any { usesDtxIn(it) }

    /** The answer's media sections, each from its `m=` line to the line before the next. */
    private fun sections(sdp: String): List<List<String>> {
        val found = mutableListOf<MutableList<String>>()
        for (line in sdp.split('\r', '\n').filter { it.isNotEmpty() }) {
            if (line.startsWith("m=")) found.add(mutableListOf(line)) else found.lastOrNull()?.add(line)
        }
        return found
    }

    /** `m=audio <port> ...` with a port other than 0. */
    private fun acceptedAudio(mediaLine: String): Boolean {
        val parts = mediaLine.split(' ').filter { it.isNotEmpty() }
        return parts.size > 1 && parts[0] == "m=audio" && parts[1] != "0"
    }

    private fun usesDtxIn(section: List<String>): Boolean {
        val opus = section
            .filter { it.startsWith("a=rtpmap:") }
            .mapNotNull { line ->
                // a=rtpmap:111 opus/48000/2
                val parts = line.removePrefix("a=rtpmap:").trim().split(' ', limit = 2)
                parts.takeIf { it.size == 2 && it[1].trim().lowercase().startsWith("opus/") }?.get(0)
            }
            .toSet()
        return section
            .filter { it.startsWith("a=fmtp:") }
            .any { line ->
                // a=fmtp:111 minptime=10;useinbandfec=1
                val parts = line.removePrefix("a=fmtp:").trim().split(' ', limit = 2)
                parts.size == 2 && parts[0] in opus && parts[1].split(';').any { parameter ->
                    val pair = parameter.split('=', limit = 2).map { it.trim() }
                    pair.size == 2 && pair[0].lowercase() == "usedtx" && pair[1] == "1"
                }
            }
    }
}
