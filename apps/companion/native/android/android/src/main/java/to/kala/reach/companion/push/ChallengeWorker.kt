package to.kala.reach.companion.push

import android.content.Context
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit
import to.kala.reach.companion.mobile.ChallengeOutcome

/**
 * The answer to a registration challenge that did not get to the gateway, asked again.
 *
 * The scheduler owns this: it runs when the device has a network, it survives the process being
 * taken away and it backs off between tries. The answer is the receiver's own ([Challenges]): the
 * decision is made afresh each time from the record, so a registration that was answered, refused
 * or has run out of time is not answered again, and the work ends. It never signs outside the one
 * function the receiver uses.
 */
class ChallengeWorker(context: Context, parameters: WorkerParameters) :
    Worker(context, parameters) {
    override fun doWork(): Result {
        val data = inputData.keyValueMap.mapValues { it.value.toString() }
        return when (Challenges.answerer(applicationContext).answer(data)) {
            is ChallengeOutcome.Retry -> Result.retry()
            else -> Result.success()
        }
    }

    companion object {
        /**
         * How long the safety net waits before it looks at the record: longer than a post is given, so
         * it never answers beside the receiver that is still posting.
         */
        private const val AFTER_SECONDS = 20L

        private fun name(data: Map<String, String>) = "challenge-" + data["kr_registration_id"].orEmpty()

        /**
         * Hands a challenge's data to the scheduler as the safety net of the receiver's own try: it
         * runs when the device has a network, and decides afresh from the record, so a registration
         * the receiver answered has nothing left for it to do. One per registration.
         */
        fun schedule(context: Context, data: Map<String, String>) {
            WorkManager.getInstance(context)
                .enqueueUniqueWork(
                    name(data),
                    ExistingWorkPolicy.KEEP,
                    OneTimeWorkRequestBuilder<ChallengeWorker>()
                        .setInitialDelay(AFTER_SECONDS, TimeUnit.SECONDS)
                        .setConstraints(
                            Constraints.Builder()
                                .setRequiredNetworkType(NetworkType.CONNECTED)
                                .build()
                        )
                        .setInputData(Data.Builder().putAll(data.mapValues { it.value }).build())
                        .build()
                )
        }

        /** Takes the safety net back once the receiver has settled the registration itself. */
        fun cancel(context: Context, data: Map<String, String>) {
            WorkManager.getInstance(context).cancelUniqueWork(name(data))
        }
    }
}
