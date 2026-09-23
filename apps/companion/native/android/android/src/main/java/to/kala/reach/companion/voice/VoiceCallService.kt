package to.kala.reach.companion.voice

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import to.kala.reach.companion.mobile.VoiceCaptureState
import to.kala.reach.companion.mobile.VoiceServiceActions

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

        /** Start the service for a call the host permitted. */
        const val ACTION_START = VoiceServiceActions.START

        /** Stop the call. Reachable from the notification while the screen is locked. */
        const val ACTION_STOP = VoiceServiceActions.STOP

        /** Mute or unmute the person's own microphone, from the notification. */
        const val ACTION_TOGGLE_MUTE = VoiceServiceActions.TOGGLE_MUTE

        /** Republish the notification with what the microphone is doing now. */
        const val ACTION_CAPTURE = VoiceServiceActions.CAPTURE

        /** The capture state carried by [ACTION_CAPTURE]. */
        const val EXTRA_CAPTURE = "capture"

        /**
         * The call an action is for.
         *
         * Every action names it, so one that arrives late, after its call ended and another
         * started, reaches the call it was for or nothing.
         */
        const val EXTRA_CALL = "call"

        /** The notification this service is in the foreground with. */
        const val NOTIFICATION_ID = 0x4B56

        /**
         * Starts a call's service.
         *
         * Takes the call the person started. There is no overload that starts one without a call:
         * the microphone opens for a call and at no other time.
         */
        @JvmStatic
        fun start(context: Context, call: Long) {
            val intent = Intent(context, VoiceCallService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_CALL, call)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /** Ends a call's service. */
        @JvmStatic
        fun stop(context: Context, call: Long) {
            context.startService(
                Intent(context, VoiceCallService::class.java)
                    .setAction(ACTION_STOP)
                    .putExtra(EXTRA_CALL, call),
            )
        }

        /**
         * Tells the notification what the microphone is doing.
         *
         * The screen and the notification say the same thing about capture, because while the
         * screen is locked the notification is the only one of the two a person can read.
         */
        @JvmStatic
        fun publishCapture(context: Context, call: Long, state: VoiceCaptureState) {
            context.startService(
                Intent(context, VoiceCallService::class.java)
                    .setAction(ACTION_CAPTURE)
                    .putExtra(EXTRA_CALL, call)
                    .putExtra(EXTRA_CAPTURE, state.name),
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

    /** The call this service was started for. Nothing else is its to stop or mute. */
    private var call: Long = 0

    /**
     * Whether the person has muted their own microphone.
     *
     * Read from the running call rather than kept here. Two copies of one fact disagree the first
     * time mute is pressed somewhere else.
     */
    private val muted: Boolean
        get() = VoiceCallHolder.current(call)?.isMutedByPerson == true

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val named = intent?.getLongExtra(EXTRA_CALL, 0) ?: 0
        // Decided from the call the action names: one naming a call other than the one this
        // service runs for arrived late, or from an earlier call's notification, and changes
        // nothing.
        when (VoiceServiceActions.decide(intent?.action, named, if (running) call else null)) {
            VoiceServiceActions.Act.START -> {
                call = named
                // What the microphone is doing arrives from the call itself, straight after.
                capture = VoiceCaptureState.IDLE
                running = true
                // Started as a foreground service, so it enters the foreground whatever it finds:
                // the platform ends an application whose service stops before doing so.
                val promoted = try {
                    startInForeground()
                    true
                } catch (refused: RuntimeException) {
                    false
                }
                val held = VoiceCallHolder.current(named)
                when {
                    // Nothing may be recorded without the foreground, so the call ends.
                    !promoted -> {
                        held?.serviceRefused()
                        stopCall()
                    }
                    // Started for a call that ended in the meantime: no microphone to keep.
                    held == null -> stopCall()
                    else -> held.servicePromoted()
                }
            }
            VoiceServiceActions.Act.STOP -> {
                VoiceCallHolder.current(named)?.stop()
                stopCall()
            }
            VoiceServiceActions.Act.TOGGLE_MUTE -> {
                val held = VoiceCallHolder.current(call)
                if (held != null) {
                    held.setMutedByPerson(!held.isMutedByPerson)
                } else {
                    // No call owns this notification any more, so the microphone is not this
                    // service's to change and the notification should not suggest it is.
                    stopCall()
                }
            }
            VoiceServiceActions.Act.CAPTURE -> {
                val word = intent?.getStringExtra(EXTRA_CAPTURE)
                VoiceCaptureState.entries.firstOrNull { it.name == word }?.let { capture = it }
            }
            VoiceServiceActions.Act.IGNORE -> Unit
            // Anything else, including a restart the system decided on its own, is not a call the
            // person started. Opening the microphone here would be exactly the silent activation
            // section 15 paragraph 22 forbids.
            VoiceServiceActions.Act.END -> stopCall()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        running = false
        // The service going away takes the microphone with it, so the call goes too. A call whose
        // service has been destroyed would be a call with no foreground service holding its
        // capture open, which is the state section 15 paragraph 22 asks to be shown rather than
        // silently carried.
        VoiceCallHolder.current(call)?.stop()
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
            Intent(this, VoiceCallService::class.java)
                .setAction(action)
                // The call's own address, so each call's actions are pending actions of their
                // own and publishing one call's cannot rewrite another's.
                .setData(Uri.parse(VoiceServiceActions.callAddress(call)))
                .putExtra(EXTRA_CALL, call),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
}
