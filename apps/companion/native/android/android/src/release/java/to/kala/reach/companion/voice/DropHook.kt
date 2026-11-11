package to.kala.reach.companion.voice

/** A release build takes nothing out of the recorder. */
object DropHook {
    fun beforeBuffer() {}

    fun recorderStopped() {}
}
