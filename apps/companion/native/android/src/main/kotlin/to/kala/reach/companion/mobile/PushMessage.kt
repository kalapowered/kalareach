package to.kala.reach.companion.mobile

/**
 * What one push message is, read from its data.
 *
 * The gateway sends two kinds of data message to a phone and nothing else. A registration challenge
 * goes to a token before the gateway binds it to an installation, and is answered by the receiver
 * (never shown). A delivery is a notification the host asked for: an opaque identifier, a collapse
 * identifier, the generic alert, an expiry and, when previews are on, the sealed preview.
 *
 * Reading is separate from doing so that a message that is neither is dropped here, and so that a
 * test can hold the reading without a receiver.
 */
sealed interface PushMessage {
    /** A registration challenge: the data carries the values an answer repeats. */
    data class Challenge(val data: Map<String, String>) : PushMessage

    /** A notification the host asked for. */
    data class Delivery(
        /** The opaque identifier the host gave it, which the host deduplicates by. */
        val notificationId: String,
        /** The identifier that groups notifications about one thing: the newest replaces the older. */
        val collapseId: String,
        /** The generic alert, one of a fixed few sentences that name nothing of a session. */
        val alert: String,
        /** The message's data, whole, for the decision about a sealed preview. */
        val data: Map<String, String>
    ) : PushMessage

    /** Neither: a message this receiver has nothing to do with. */
    object Unrecognised : PushMessage
}

/** The data key whose presence says a message is a registration challenge. */
const val CHALLENGE_KEY = "kr_challenge"

/** The data key that carries the host's opaque identifier for a notification. */
const val NOTIFICATION_ID_KEY = "notification_id"

/** The data key that carries the identifier notifications about one thing share. */
const val COLLAPSE_ID_KEY = "collapse_id"

/** The data key that carries the generic alert the host chose. */
const val ALERT_KEY = "alert"

/** Reads one message's data. */
fun readMessage(data: Map<String, String>): PushMessage {
    if (data.containsKey(CHALLENGE_KEY)) return PushMessage.Challenge(data)
    val notificationId = data[NOTIFICATION_ID_KEY]
    val alert = data[ALERT_KEY]
    if (notificationId.isNullOrEmpty() || alert.isNullOrEmpty()) return PushMessage.Unrecognised
    // A message with no collapse identifier stands on its own: its own identifier groups nothing
    // with anything else.
    val collapseId = data[COLLAPSE_ID_KEY]?.takeIf { it.isNotEmpty() } ?: notificationId
    return PushMessage.Delivery(notificationId, collapseId, alert, data)
}

/** What a notification is made of: its tag, its words and why they are the generic ones. */
data class NotificationPlan(
    /**
     * The tag the notification is posted under. Two notifications that share it are one: the newer
     * replaces the older, which is what the collapse identifier is for. The words never decide it.
     */
    val tag: String,
    /** What the notification says. */
    val body: String,
    /** Why the alert stands, or the empty string when a preview was shown. */
    val reason: String
)

/** What one delivery shows, given what was decided about its preview. */
fun planNotification(delivery: PushMessage.Delivery, decision: PreviewDecision): NotificationPlan =
    when (decision) {
        is PreviewDecision.Reveal ->
            NotificationPlan(delivery.collapseId, decision.text, reason = "")
        // The alert the host chose stands, unchanged. Nothing this process learned about why it
        // could not read a preview is put in front of a person on a lock screen.
        is PreviewDecision.Generic ->
            NotificationPlan(delivery.collapseId, delivery.alert, decision.reason.wireName)
    }
