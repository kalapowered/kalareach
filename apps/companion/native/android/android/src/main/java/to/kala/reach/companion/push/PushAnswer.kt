package to.kala.reach.companion.push

import to.kala.reach.companion.mobile.ChallengeCrypto

/**
 * The Rust half's two functions, which the JVM finds by the names the library exports them under.
 *
 * The library is the application's own, so a receiver the system starts alone, with no activity and
 * no WebView, loads it here. Loading it starts nothing else: the functions decide and sign over
 * JSON text and touch no interface, no connection and no file.
 */
object PushAnswer {
    init {
        System.loadLibrary("companion_tauri")
    }

    /** Decides what a message means for the pending registration, with no secret. */
    @JvmStatic external fun classify(input: String): String

    /** Builds the answer and the request that carries it, given the installation's key. */
    @JvmStatic external fun sign(input: String, seed: ByteArray): String
}

/** [PushAnswer] as the receiver's [ChallengeCrypto]. */
class RustChallengeCrypto : ChallengeCrypto {
    override fun classify(input: String): String = PushAnswer.classify(input)

    override fun sign(input: String, seed: ByteArray): String = PushAnswer.sign(input, seed)
}
