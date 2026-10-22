package to.kala.reach.companion.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import to.kala.reach.companion.mobile.NotificationPlan
import to.kala.reach.companion.mobile.NotificationRoute

/**
 * Puts one notification in front of the person.
 *
 * Posted under the tag the plan gives, which is the collapse identifier the host chose, and one
 * fixed number: two notifications about one thing are one, the newer replacing the older, and the
 * words never decide which. A tap opens the application on the screen that holds what needs the
 * person, and carries nothing else: no session, no request, nothing from the payload.
 */
object Notifier {
    private const val CHANNEL = "to.kala.reach.attention"
    private const val CHANNEL_LABEL = "KalaReach"
    private const val NOTIFICATION_NUMBER = 0x4b52

    fun show(context: Context, plan: NotificationPlan) {
        // Channels arrived after this application's minimum, so the call is guarded rather than
        // assumed: on an older device the notification simply has no channel.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, CHANNEL_LABEL, NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val launch =
            context.packageManager.getLaunchIntentForPackage(context.packageName)?.apply {
                putExtra(NotificationRoute.EXTRA, NotificationRoute.ATTENTION)
                addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
        val tap =
            launch?.let {
                PendingIntent.getActivity(
                    context,
                    NOTIFICATION_NUMBER,
                    it,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            }
        val notification =
            NotificationCompat.Builder(context, CHANNEL)
                .setContentTitle(CHANNEL_LABEL)
                .setContentText(plan.body)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .setAutoCancel(true)
                .setContentIntent(tap)
                .build()
        val manager = NotificationManagerCompat.from(context)
        if (manager.areNotificationsEnabled()) {
            manager.notify(plan.tag, NOTIFICATION_NUMBER, notification)
        }
    }
}
