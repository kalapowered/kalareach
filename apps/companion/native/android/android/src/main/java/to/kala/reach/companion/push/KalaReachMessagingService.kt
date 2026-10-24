package to.kala.reach.companion.push

import android.content.Context
import android.util.Log
import androidx.work.Data
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import to.kala.reach.companion.mobile.ChallengeOutcome
import to.kala.reach.companion.mobile.IncomingWork
import to.kala.reach.companion.mobile.PreviewDecider
import to.kala.reach.companion.mobile.PushMessage
import to.kala.reach.companion.mobile.PushStores
import to.kala.reach.companion.mobile.WorkPlacement
import to.kala.reach.companion.mobile.placeWork
import to.kala.reach.companion.mobile.planNotification
import to.kala.reach.companion.mobile.readMessage

/**
 * The receiver the system starts when a push arrives.
 *
 * This is the half of the product that runs when nothing else does. The application may be
 * stopped, swapped out or never started since the device booted, and there is no WebView and no
 * JavaScript context anywhere: the system starts this service, hands it the message, and expects
 * an answer within a few seconds.
 *
 * Two kinds of message reach it, and both are data messages, so that this service sees them
 * whatever state the application is in. A registration challenge is answered here, through the
 * one function the application keeps for it, and never shown. A delivery is shown, under the
 * identifier the host gave it.
 *
 * So the work is placed before it is done. Anything the payload alone decides is finished here.
 * Anything that needs the host, or that would run past the callback's budget, is handed to the
 * platform's scheduler, which will run it when the device allows and retry it if it is
 * interrupted.
 */
class KalaReachMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        // The token is this device's destination. It is kept where the application will find it,
        // and the registration with the gateway is the application's to make, after the person
        // asked for it: a service that registered on its own would be binding a destination
        // nobody proved they own. Whether a registration still names it is the application's to
        // compare each time it looks, by the token's digest. It is written before this returns, so
        // that a process the system ends right after still holds the token the provider gave; a
        // write that fails is said in the log (no token in the line), since only this callback
        // hears the provider give a token on this platform.
        val written =
            getSharedPreferences(PushStores.TOKEN_STORE, Context.MODE_PRIVATE)
                .edit()
                .putString(PushStores.TOKEN_KEY, token)
                .putLong(PushStores.TOKEN_AT_KEY, System.currentTimeMillis())
                .commit()
        if (!written) Log.w(TAG, "the registration token could not be kept")
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val started = System.currentTimeMillis()
        val data = message.data
        when (val read = readMessage(data)) {
            is PushMessage.Challenge -> answer(read)
            is PushMessage.Delivery -> deliver(read, started)
            PushMessage.Unrecognised -> Unit
        }
    }

    private fun answer(challenge: PushMessage.Challenge) {
        // The scheduler is handed the answer as a safety net before it is posted, so a process the
        // system ends in the middle of the post leaves a try behind. A challenge that did not get to
        // the gateway is asked again inside the time the record gives it, and the safety net is kept
        // (made again here when the scheduler could not save it before the post). Only an outcome
        // that ends the registration takes it back: a message that was ignored says nothing about
        // the registration, and a net that is no longer wanted finds nothing left to do.
        val outcome =
            Challenges.answerer(applicationContext) {
                    ChallengeWorker.schedule(applicationContext, challenge.data)
                }
                .answer(challenge.data)
        // What became of it, by kind and never by content: nothing of the message or the key.
        Log.i(TAG, "challenge: ${describe(outcome)}")
        when {
            outcome is ChallengeOutcome.Retry -> ChallengeWorker.schedule(applicationContext, challenge.data)
            outcome.settles -> ChallengeWorker.cancel(applicationContext, challenge.data)
        }
    }

    private fun describe(outcome: ChallengeOutcome): String =
        when (outcome) {
            is ChallengeOutcome.Ignored -> "ignored (${outcome.reason})"
            is ChallengeOutcome.GatewayRefused -> "refused by the gateway (${outcome.status})"
            is ChallengeOutcome.Retry -> "to be tried again (${outcome.reason})"
            ChallengeOutcome.Answered -> "answered"
            ChallengeOutcome.NotAChallenge -> "not a challenge"
        }

    private fun deliver(delivery: PushMessage.Delivery, started: Long) {
        val placement =
            placeWork(
                IncomingWork(
                    decidedByPayload = true,
                    needsHost = delivery.data[NEEDS_HOST_KEY] == "1",
                    elapsedMillis = System.currentTimeMillis() - started
                )
            )
        if (placement == WorkPlacement.DEFERRED) {
            WorkManager.getInstance(applicationContext)
                .enqueue(
                    OneTimeWorkRequestBuilder<PreviewWorker>()
                        .setInputData(Data.Builder().putAll(delivery.data.mapValues { it.value }).build())
                        .build()
                )
            return
        }
        val plan = plan(delivery)
        Notifier.show(applicationContext, plan)
        // By reason and never by content: why the alert stands, or that a preview was shown.
        Log.i(TAG, "delivery: shown (${plan.reason.ifEmpty { "revealed" }})")
    }

    private fun plan(delivery: PushMessage.Delivery) =
        planNotification(
            delivery,
            PreviewDecider(
                    keys = KeystorePreviewKeys(applicationContext),
                    opener = RustPreviewOpening()
                )
                .decide(delivery.data, System.currentTimeMillis())
        )

    companion object {
        private const val TAG = "KalaReachPush"

        /** Set by the gateway when answering needs the host. */
        const val NEEDS_HOST_KEY = "needs_host"
    }
}
