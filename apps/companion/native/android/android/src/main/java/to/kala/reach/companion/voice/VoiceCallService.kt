package to.kala.reach.companion.voice

import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import to.kala.reach.companion.mobile.VoiceCaptureState
import to.kala.reach.companion.mobile.VoiceNotificationControls
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
 * it carries mute and stop. It is on the lock screen of a phone at its default settings, which
 * needs a channel of default importance (the platform keeps lower ones off the lock screen); the
 * channel is silent, so a running call makes no sound and no vibration. Mute and stop work there
 * with no unlock; unmute asks for the unlock (see [VoiceNotificationControls]).
 *
 * What it deliberately does not do is start itself. The service is started by the person starting
 * a call and by nothing else, because a service that could start itself would be the unattended
 * microphone activation that same paragraph forbids.
 */
class VoiceCallService : android.app.Service() {
    companion object {
        /** The channel a running call's notification belongs to. */
        const val CHANNEL_ID = "kr-voice-call-running"

        /**
         * The channel earlier releases put the notification in, with low importance, which keeps a
         * call's notification off the lock screen of a phone at its default settings. A channel's
         * importance cannot be raised once it exists, so the notification moved to a channel of
         * its own and this one is deleted when the service starts.
         *
         * Remove this and its deletion in [ensureChannel] once no installed application can still
         * hold it: when the oldest release an installed application may update from already has
         * [CHANNEL_ID].
         */
        private const val LOW_IMPORTANCE_CHANNEL_ID = "kr-voice-call"

        /** Start the service for a call the host permitted. */
        const val ACTION_START = VoiceServiceActions.START

        /** Stop the call. Reachable from the notification while the screen is locked. */
        const val ACTION_STOP = VoiceServiceActions.STOP

        /** Mute the person's own microphone, from the notification. */
        const val ACTION_MUTE = VoiceServiceActions.MUTE

        /** Open the person's own microphone again, from the notification, after the unlock. */
        const val ACTION_UNMUTE = VoiceServiceActions.UNMUTE

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

    /**
     * Republishes the notification when the phone locks or unlocks, on a platform that cannot ask
     * for the unlock before one action runs: what the notification offers there depends on it.
     */
    private val lockChanges = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (running) publish()
        }
    }
    private var watchingLock = false

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
        val act = VoiceServiceActions.decide(intent?.action, named, if (running) call else null)
        when (act) {
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
            VoiceServiceActions.Act.MUTE, VoiceServiceActions.Act.UNMUTE -> {
                val held = VoiceCallHolder.current(call)
                if (held == null) {
                    // No call owns this notification any more, so the microphone is not this
                    // service's to change and the notification should not suggest it is.
                    stopCall()
                } else {
                    // A muted microphone is not reopened on a locked phone, whoever sent the action:
                    // the notification's own Unmute reaches here after the unlock.
                    val muted = held.isMutedByPerson
                    val after = VoiceNotificationControls.mutedAfter(
                        unmute = act == VoiceServiceActions.Act.UNMUTE,
                        muted = muted,
                        locked = locked,
                    )
                    if (after != muted) held.setMutedByPerson(after)
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

    /**
     * The person swiped the application away from the recent tasks. A call that goes on with no
     * screen of its own is one whose only control is its notification, and its owner is not at
     * hand: it ends, as it does when the person stops it from the notification.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        VoiceCallHolder.current(call)?.stop()
        stopCall()
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        running = false
        unwatchLock()
        // The service going away takes the microphone with it, so the call goes too. A call whose
        // service has been destroyed would be a call with no foreground service holding its
        // capture open, which is the state section 15 paragraph 22 asks to be shown rather than
        // silently carried.
        VoiceCallHolder.current(call)?.stop()
        super.onDestroy()
    }

    private fun startInForeground() {
        ensureChannel()
        watchLock()
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
        unwatchLock()
        capture = VoiceCaptureState.IDLE
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private val locked: Boolean
        get() = getSystemService(KeyguardManager::class.java)?.isKeyguardLocked == true

    private fun watchLock() {
        if (watchingLock || Build.VERSION.SDK_INT >= VoiceNotificationControls.UNLOCK_PER_ACTION_SDK) return
        ContextCompat.registerReceiver(
            this,
            lockChanges,
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_USER_PRESENT)
            },
            // Exported, because the three actions are protected broadcasts that only the system
            // can send, and a receiver that is not exported asks the sender for a permission of
            // this application's own on these platforms, which the system's user interface, the
            // sender of the unlock, does not hold. All the receiver does is republish.
            ContextCompat.RECEIVER_EXPORTED,
        )
        watchingLock = true
    }

    private fun unwatchLock() {
        if (!watchingLock) return
        watchingLock = false
        unregisterReceiver(lockChanges)
    }

    private fun publish() {
        getSystemService(NotificationManager::class.java)
            ?.notify(NOTIFICATION_ID, notification())
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        try {
            manager.deleteNotificationChannel(LOW_IMPORTANCE_CHANNEL_ID)
        } catch (held: SecurityException) {
            // A running service's notification still sits in it: it goes at the next start.
        }
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Voice calls",
                // Default importance is what puts a notification on the lock screen of a phone at
                // its default settings; the sound and the vibration are taken away below.
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = "Shown while a voice call you started is running."
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
            },
        )
    }

    private fun notification(): Notification {
        val isMuted = muted
        val controls = VoiceNotificationControls.controls(isMuted, locked, Build.VERSION.SDK_INT)
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Voice call running")
            // What the microphone is doing, in the person's own words, on the one surface that
            // exists while the screen is locked: the call's own state, said as it is.
            .setContentText(capture.display)
            .setSmallIcon(android.R.drawable.ic_btn_speak_now)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        when (controls.toggle) {
            VoiceNotificationControls.Toggle.MUTE ->
                builder.addAction(action("Mute", ACTION_MUTE, 1, controls.needsUnlock))
            VoiceNotificationControls.Toggle.UNMUTE ->
                builder.addAction(action("Unmute", ACTION_UNMUTE, 3, controls.needsUnlock))
            VoiceNotificationControls.Toggle.NONE -> Unit
        }
        return builder
            .addAction(action("Stop", ACTION_STOP, 2, needsUnlock = false))
            .build()
    }

    /** An action of the notification; one that needs the unlock waits for it on a locked phone. */
    private fun action(title: String, action: String, code: Int, needsUnlock: Boolean) =
        NotificationCompat.Action.Builder(0, title, pending(action, code))
            .setAuthenticationRequired(needsUnlock)
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
