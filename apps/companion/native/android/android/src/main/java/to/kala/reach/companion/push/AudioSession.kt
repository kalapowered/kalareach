package to.kala.reach.companion.push

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioFocusRequest
import android.media.AudioManager
import android.os.Build

/**
 * Audio focus, asked for where the platform expects it to be asked for.
 *
 * Focus belongs to the process, not to a page: it survives the interface being backgrounded, and
 * it is what decides whether a person's music is ducked or stopped. Asking from native code is
 * what makes that true.
 *
 * What uses the session is the voice surface, which is built elsewhere. This is the session, and
 * it is deliberately the smallest thing that can be correct.
 */
class AudioSession(private val context: Context) {
    private var request: AudioFocusRequest? = null

    /** Asks for focus for speech. Returns true when the system granted it. */
    fun activate(): Boolean {
        val manager = context.getSystemService(AudioManager::class.java) ?: return false
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            @Suppress("DEPRECATION")
            return manager.requestAudioFocus(
                null,
                AudioManager.STREAM_VOICE_CALL,
                AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK
            ) == AudioManager.AUDIOFOCUS_REQUEST_GRANTED
        }
        // Ducking rather than stopping: an application that silences a person's music the moment
        // it starts is taking something it was not given.
        val made =
            AudioFocusRequest.Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK)
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build()
                )
                .build()
        request = made
        return manager.requestAudioFocus(made) == AudioManager.AUDIOFOCUS_REQUEST_GRANTED
    }

    /** Gives focus back. */
    fun deactivate() {
        val manager = context.getSystemService(AudioManager::class.java) ?: return
        val made = request ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) manager.abandonAudioFocusRequest(made)
        request = null
    }
}
