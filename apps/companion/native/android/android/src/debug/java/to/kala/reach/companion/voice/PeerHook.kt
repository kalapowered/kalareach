package to.kala.reach.companion.voice

import android.content.Context

/** Starts the device run's peer when the run asked for one. Only a debug build has a peer. */
object PeerHook {
    fun start(context: Context) = AudioPeer.startIfRequested(context)
}
