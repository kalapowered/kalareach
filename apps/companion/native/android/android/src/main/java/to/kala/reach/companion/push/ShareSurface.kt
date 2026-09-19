package to.kala.reach.companion.push

import android.content.Context
import android.content.Intent

/**
 * Sharing out of the application, through the platform's own sheet.
 *
 * A person sharing a transcript or a path expects the sheet every other application on the device
 * shows, with their own shortcuts in it. Building a second one would be building something worse
 * that nobody asked for.
 */
object ShareSurface {
    /** Opens the platform's share sheet for one piece of text. */
    fun share(context: Context, text: String, title: String) {
        val intent =
            Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, text)
                putExtra(Intent.EXTRA_TITLE, title)
            }
        val chooser =
            Intent.createChooser(intent, title).apply {
                // Started from outside an activity when a notification action shares something.
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        context.startActivity(chooser)
    }
}
