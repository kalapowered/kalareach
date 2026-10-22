package to.kala.reach.companion.push

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import to.kala.reach.companion.mobile.PreviewDecider
import to.kala.reach.companion.mobile.PushMessage
import to.kala.reach.companion.mobile.SharedClientPreviewOpener
import to.kala.reach.companion.mobile.planNotification
import to.kala.reach.companion.mobile.readMessage

/**
 * The work a message callback could not finish: a delivery whose notification is shown from here.
 *
 * The scheduler owns this: it runs when the device allows, it survives the process being taken
 * away, and it retries what was interrupted. That is the whole reason work leaves the callback
 * rather than being attempted there and lost.
 *
 * It shows the notification the receiver would have shown, through the same plan, and nothing
 * else. It never signs anything: signing needs the application's own authentication, and a worker
 * has none.
 */
class PreviewWorker(context: Context, parameters: WorkerParameters) :
    Worker(context, parameters) {
    override fun doWork(): Result {
        val data = inputData.keyValueMap.mapValues { it.value.toString() }
        val delivery = readMessage(data) as? PushMessage.Delivery ?: return Result.success()
        val decision =
            PreviewDecider(
                    keys = KeystorePreviewKeys(applicationContext),
                    opener = SharedClientPreviewOpener
                )
                .decide(data, System.currentTimeMillis())
        // Either decision is a finished outcome, not a failure to retry: retrying would produce
        // the same notification again, and a notification already shown is replaced by its own tag.
        Notifier.show(applicationContext, planNotification(delivery, decision))
        return Result.success()
    }
}
