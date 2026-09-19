package to.kala.reach.companion.push

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import to.kala.reach.companion.mobile.PreviewDecider
import to.kala.reach.companion.mobile.PreviewDecision
import to.kala.reach.companion.mobile.SharedClientPreviewOpener

/**
 * The work a message callback could not finish.
 *
 * The scheduler owns this: it runs when the device allows, it survives the process being taken
 * away, and it retries what was interrupted. That is the whole reason work leaves the callback
 * rather than being attempted there and lost.
 *
 * It shows a notification and nothing else. It never signs anything: signing needs the
 * application's own authentication, and a worker has none.
 */
class PreviewWorker(context: Context, parameters: WorkerParameters) :
    Worker(context, parameters) {
    override fun doWork(): Result {
        val data = inputData.keyValueMap.mapValues { it.value.toString() }
        val decider =
            PreviewDecider(
                keys = KeystorePreviewKeys(applicationContext),
                opener = SharedClientPreviewOpener
            )
        val decision = decider.decide(data, System.currentTimeMillis())
        return when (decision) {
            is PreviewDecision.Reveal -> Result.success()
            // A generic alert is a finished outcome, not a failure to retry: retrying would
            // produce the same generic alert and a second notification.
            is PreviewDecision.Generic -> Result.success()
        }
    }
}
