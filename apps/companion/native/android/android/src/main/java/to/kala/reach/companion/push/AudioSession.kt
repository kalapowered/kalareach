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
 * One session owns one focus request, so the instance that asked is the instance that gives it
 * back. A second instance constructed to release the first one's focus releases nothing.
 *
 * The listener is how a caller learns that the system took focus away: a call that loses focus to
 * an alarm or another application must show that state rather than keep claiming it is being
 * heard.
 */
class AudioSession(
    private val context: Context,
    private val onFocusChange: ((Int) -> Unit)? = null,
) {
    private var request: AudioFocusRequest? = null
    private val listener = AudioManager.OnAudioFocusChangeListener { change ->
        onFocusChange?.invoke(change)
    }

    /** Asks for focus for speech. Returns true when the system granted it. */
    fun activate(): Boolean {
        val manager = context.getSystemService(AudioManager::class.java) ?: return false
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            @Suppress("DEPRECATION")
            return manager.requestAudioFocus(
                listener,
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
                .setOnAudioFocusChangeListener(listener)
                .build()
        request = made
        return manager.requestAudioFocus(made) == AudioManager.AUDIOFOCUS_REQUEST_GRANTED
    }

    /** Gives focus back. Only this instance's own request, and only once. */
    fun deactivate() {
        val manager = context.getSystemService(AudioManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val made = request ?: return
            manager.abandonAudioFocusRequest(made)
        } else {
            @Suppress("DEPRECATION")
            manager.abandonAudioFocus(listener)
        }
        request = null
    }
}
