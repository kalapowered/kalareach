package to.kala.reach.companion.push

import to.kala.reach.companion.mobile.PreviewOpened
import to.kala.reach.companion.mobile.PreviewOpenerJson
import to.kala.reach.companion.mobile.PreviewOpening

/**
 * The Rust half's function that opens a sealed notification preview, which the JVM finds by the
 * name the library exports it under.
 *
 * The library is the application's own, so a receiver the system starts alone, with no activity
 * and no WebView, loads it here. Loading it starts nothing else: the function reads JSON text and
 * a seed, answers JSON text, and touches no interface, no connection and no file. The seed is held
 * only for the call.
 */
object PreviewOpener {
    init {
        System.loadLibrary("companion_tauri")
    }

    /** Opens the preview `input` names with the phone's preview seed, and answers what to show. */
    @JvmStatic external fun open(input: String, seed: ByteArray): String
}

/** [PreviewOpener] as the receiver's [PreviewOpening]. */
class RustPreviewOpening : PreviewOpening {
    override fun open(
        preview: String,
        alert: String,
        seed: ByteArray,
        senderKey: ByteArray,
        nowMillis: Long
    ): PreviewOpened =
        PreviewOpenerJson.answer(
            PreviewOpener.open(PreviewOpenerJson.input(preview, senderKey, alert, nowMillis), seed)
        )
}
