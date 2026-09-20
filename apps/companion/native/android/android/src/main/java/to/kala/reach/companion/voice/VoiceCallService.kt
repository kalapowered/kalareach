package to.kala.reach.companion.voice

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import to.kala.reach.companion.mobile.VoiceCaptureState

/**
 * The service that owns a running call.
 *
 * Audio focus alone does not keep a microphone open once the screen locks: Android stops capture
 * for a process that is not running a microphone foreground service. Section 15 paragraph 21 asks
 * for live voice to stay usable after screen lock through "Android's appropriate microphone
 * foreground service", and this is it.
 *
 * Its notification is not decoration either. Section 15 paragraph 22 wants user-visible native
 * playback, mute and stop to stay available, and while the screen is locked the notification is
 * the only surface there is. It says a call is running, it says what the microphone is doing, and
 * it carries mute and stop.
 *
 * What it deliberately does not do is start itself. The service is started by the person starting
 * a call and by nothing else, because a service that could start itself would be the unattended
 * microphone activation that same paragraph forbids.
 */
class VoiceCallService : android.app.Service() {
    companion object {
        /** The channel a running call's notification belongs to. */
        const val CHANNEL_ID = "kr-voice-call"

        /** Start the service for a call the person has just started. */
        const val ACTION_START = "to.kala.reach.companion.voice.START"

        /** Stop the call. Reachable from the notification while the screen is locked. */
        const val ACTION_STOP = "to.kala.reach.companion.voice.STOP"

        /** Mute or unmute the person's own microphone, from the notification. */
        const val ACTION_TOGGLE_MUTE = "to.kala.reach.companion.voice.TOGGLE_MUTE"

        /** The notification this service is in the foreground with. */
        const val NOTIFICATION_ID = 0x4B56

        /**
         * Starts a call's service.
         *
         * Takes the call the person started. There is no overload that starts one without a call:
         * the microphone opens for a call and at no other time.
         */
        @JvmStatic
        fun start(context: Context) {
            val intent = Intent(context, VoiceCallService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /** Ends a call's service. */
        @JvmStatic
        fun stop(context: Context) {
            context.startService(
                Intent(context, VoiceCallService::class.java).setAction(ACTION_STOP),
            )
        }
    }

    /** What this service last published about the microphone. */
    var capture: VoiceCaptureState = VoiceCaptureState.IDLE
        set(value) {
            field = value
            if (running) publish()
        }

    private var running = false
    private var muted = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                VoiceCallHolder.current?.stop()
                stopCall()
                return START_NOT_STICKY
            }
            ACTION_TOGGLE_MUTE -> {
                muted = !muted
                VoiceCallHolder.current?.setMutedByPerson(muted)
                capture = if (muted) VoiceCaptureState.MUTED_BY_PERSON else VoiceCaptureState.CAPTURING
                return START_NOT_STICKY
            }
            ACTION_START -> {
                running = true
                capture = VoiceCaptureState.CAPTURING
                startInForeground()
                return START_NOT_STICKY
            }
            else -> {
                // Anything else, including a restart the system decided on its own, is not a call
                // the person started. Opening the microphone here would be exactly the silent
                // activation section 15 paragraph 22 forbids.
                stopCall()
                return START_NOT_STICKY
            }
        }
    }

    override fun onDestroy() {
        running = false
        super.onDestroy()
    }

    private fun startInForeground() {
        ensureChannel()
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification(),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            } else {
                0
            },
        )
    }

    private fun stopCall() {
        running = false
        capture = VoiceCaptureState.IDLE
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun publish() {
        getSystemService(NotificationManager::class.java)
            ?.notify(NOTIFICATION_ID, notification())
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Voice calls",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Shown while a voice call you started is running."
                setShowBadge(false)
            },
        )
    }

    private fun notification(): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Voice call running")
            // What the microphone is doing, in the person's own words, on the one surface that
            // exists while the screen is locked.
            .setContentText(capture.display)
            .setSmallIcon(android.R.drawable.ic_btn_speak_now)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(
                0,
                if (muted) "Unmute" else "Mute",
                pending(ACTION_TOGGLE_MUTE, 1),
            )
            .addAction(0, "Stop", pending(ACTION_STOP, 2))
            .build()

    private fun pending(action: String, code: Int): PendingIntent =
        PendingIntent.getService(
            this,
            code,
            Intent(this, VoiceCallService::class.java).setAction(action),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
}
