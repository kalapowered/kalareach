package to.kala.reach.companion.push

import android.content.Context
import androidx.work.Constraints
import androidx.work.Data
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
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
        /** Hands a challenge's data to the scheduler. */
        fun schedule(context: Context, data: Map<String, String>) {
            WorkManager.getInstance(context)
                .enqueue(
                    OneTimeWorkRequestBuilder<ChallengeWorker>()
                        .setConstraints(
                            Constraints.Builder()
                                .setRequiredNetworkType(NetworkType.CONNECTED)
                                .build()
                        )
                        .setInputData(Data.Builder().putAll(data.mapValues { it.value }).build())
                        .build()
                )
        }
    }
}
