package to.kala.reach.companion.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.Data
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import to.kala.reach.companion.mobile.GenericReason
import to.kala.reach.companion.mobile.IncomingWork
import to.kala.reach.companion.mobile.PreviewDecider
import to.kala.reach.companion.mobile.PreviewDecision
import to.kala.reach.companion.mobile.SharedClientPreviewOpener
import to.kala.reach.companion.mobile.WorkPlacement
import to.kala.reach.companion.mobile.placeWork

/**
 * The receiver the system starts when a push arrives.
 *
 * This is the half of the product that runs when nothing else does. The application may be
 * stopped, swapped out or never started since the device booted, and there is no WebView and no
 * JavaScript context anywhere: the system starts this service, hands it the message, and expects
 * an answer within a few seconds.
 *
 * So the work is placed before it is done. Anything the payload alone decides is finished here and
 * the notification is shown. Anything that needs the host, or that would run past the callback's
 * budget, is handed to the platform's scheduler, which will run it when the device allows and
 * retry it if it is interrupted.
 */
class KalaReachMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        // The token is this device's destination. It is kept where the application will find it,
        // and the registration with the gateway is the application's to make, after its own
        // authentication: a service that registered on its own would be binding a destination
        // nobody proved they own.
        getSharedPreferences(TOKEN_STORE, Context.MODE_PRIVATE)
            .edit()
            .putString(TOKEN_KEY, token)
            .putLong(TOKEN_AT_KEY, System.currentTimeMillis())
            .apply()
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val started = System.currentTimeMillis()
        val data = message.data
        val placement =
            placeWork(
                IncomingWork(
                    decidedByPayload = data.containsKey(ALERT_KEY),
                    needsHost = data[NEEDS_HOST_KEY] == "1",
                    elapsedMillis = System.currentTimeMillis() - started
                )
            )

        if (placement == WorkPlacement.DEFERRED) {
            WorkManager.getInstance(applicationContext)
                .enqueue(
                    OneTimeWorkRequestBuilder<PreviewWorker>()
                        .setInputData(Data.Builder().putAll(data.mapValues { it.value }).build())
                        .build()
                )
            return
        }

        val decider =
            PreviewDecider(
                keys = KeystorePreviewKeys(applicationContext),
                opener = SharedClientPreviewOpener
            )
        show(decider.decide(data, System.currentTimeMillis()), data[ALERT_KEY].orEmpty())
    }

    private fun show(decision: PreviewDecision, generic: String) {
        // Channels arrived after this application's minimum, so the call is guarded rather than
        // assumed: on an older device the notification simply has no channel.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java) ?: return
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, CHANNEL_LABEL, NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val body =
            when (decision) {
                is PreviewDecision.Reveal -> decision.text
                // The alert the host chose stands, unchanged. Nothing this process learned about
                // why it could not read a preview is put in front of a person on a lock screen.
                is PreviewDecision.Generic -> generic
            }
        val reason =
            (decision as? PreviewDecision.Generic)?.reason ?: GenericReason.NO_PREVIEW
        val notification =
            NotificationCompat.Builder(this, CHANNEL)
                .setContentTitle(CHANNEL_LABEL)
                .setContentText(body)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setGroup(reason.wireName)
                .build()
        if (NotificationManagerCompat.from(this).areNotificationsEnabled()) {
            NotificationManagerCompat.from(this).notify(body.hashCode(), notification)
        }
    }

    companion object {
        /** Where the token is kept for the application to read. */
        const val TOKEN_STORE = "to.kala.reach.companion.push"
        const val TOKEN_KEY = "registration_token"
        const val TOKEN_AT_KEY = "registration_token_at_ms"

        /** The generic alert the gateway chose, which is the default body. */
        const val ALERT_KEY = "alert"

        /** Set by the gateway when answering needs the host. */
        const val NEEDS_HOST_KEY = "needs_host"

        private const val CHANNEL = "to.kala.reach.companion.attention"
        private const val CHANNEL_LABEL = "KalaReach"
    }
}
