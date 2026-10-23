package to.kala.reach.companion.mobile

import java.io.IOException
import org.json.JSONObject

/**
 * Answers a registration challenge, from the receiver or from the worker that retries it.
 *
 * The decision and the signature are the Rust half's, behind two functions ([ChallengeCrypto]):
 * one decides, from the message and the pending record, whether this is the challenge of the
 * registration the phone is waiting for, and needs no secret; the other builds the answer and the
 * signed request that carries it, and is given the installation's key only after the first said to
 * go on. This class keeps the order, reads the key from the secure store at that moment and no
 * earlier, clears it afterwards, posts what it is given to the gateway the record names, and moves
 * the record to what became of it.
 *
 * What it never does: answer a message the decision refused, post anywhere but the address the
 * decision returned, or hold the key past the one call that signs.
 */
class ChallengeAnswerer(
    private val record: PendingFile,
    private val crypto: ChallengeCrypto,
    private val seeds: SeedSource,
    private val gateway: GatewayPost,
    /**
     * Called once the answer is signed and before it is posted: the receiver hands the scheduler a
     * safety net here, which a process that is ended mid-post leaves behind.
     */
    private val beforePosting: () -> Unit = {},
    private val clock: () -> Long = System::currentTimeMillis
) {
    fun answer(data: Map<String, String>): ChallengeOutcome {
        val now = clock()
        val pending =
            try {
                record.read(now)
            } catch (failure: IOException) {
                return ChallengeOutcome.Ignored("record_unreadable")
            }
        val registrationId = pending?.let { JSONObject(it).optString("registration_id") }
        val input =
            JSONObject()
                .put("data", JSONObject(data))
                .put("pending", pending?.let { JSONObject(it) } ?: JSONObject.NULL)
                .put("now_ms", now)
                .toString()

        // The functions live in a library the system loads into this process when it is first
        // called. A process that cannot load it answers nothing and does not crash: the record
        // stays pending and ends at its deadline, which the application says in words.
        val verdict =
            try {
                JSONObject(crypto.classify(input))
            } catch (failure: LinkageError) {
                return ChallengeOutcome.Ignored("library_unavailable")
            }
        when (verdict.getString("verdict")) {
            "not_a_challenge" -> return ChallengeOutcome.NotAChallenge
            "answer" -> Unit
            // A refusal leaves the record as it was: a message that is not this registration's
            // challenge says nothing about this registration, and must not end it.
            else -> return ChallengeOutcome.Ignored(verdict.optString("reason", "refused"))
        }

        // A key that cannot be read answers the same as one that is not there.
        val seed =
            try {
                seeds.read(verdict.getString("seed_item"))
            } catch (failure: Exception) {
                null
            } ?: return ChallengeOutcome.Ignored("key_missing")
        val signed =
            try {
                JSONObject(crypto.sign(input, seed))
            } finally {
                seed.fill(0)
            }
        if (!signed.getBoolean("ok")) {
            return ChallengeOutcome.Ignored(signed.optString("reason", "not_signed"))
        }

        beforePosting()
        return when (val sent = gateway.post(signed.getString("url"), signed.getString("body").toByteArray(Charsets.UTF_8))) {
            is PostResult.Unreachable -> ChallengeOutcome.Retry("unreachable")
            is PostResult.Status ->
                when {
                    sent.code in 200..299 ->
                        if (marked(registrationId, PendingFile.ANSWERED, null)) {
                            ChallengeOutcome.Answered
                        } else {
                            ChallengeOutcome.Retry("record_unwritable")
                        }
                    // The gateway answered and will not take it, or is not able to now. The second
                    // is asked again inside the deadline; the first would be refused again.
                    sent.code == 408 || sent.code == 429 || sent.code >= 500 ->
                        ChallengeOutcome.Retry("status_${sent.code}")
                    marked(registrationId, PendingFile.REFUSED, "gateway_${sent.code}") ->
                        ChallengeOutcome.GatewayRefused(sent.code)
                    else -> ChallengeOutcome.Retry("record_unwritable")
                }
        }
    }

    /**
     * Moves the record of `registrationId` to `state`. A record that cannot be written is a try
     * that is not over: the receiver must not fail because of it, and asks again.
     */
    private fun marked(registrationId: String?, state: String, reason: String?): Boolean =
        try {
            record.mark(registrationId.orEmpty(), state, reason, clock())
            true
        } catch (failure: IOException) {
            false
        }
}

/** What became of one message. */
sealed interface ChallengeOutcome {
    /**
     * Whether the registration is over with this outcome, so that a retry kept for it is no longer
     * wanted. A message that was ignored says nothing about the registration, and a try that must be
     * asked again is not over.
     */
    val settles: Boolean
        get() = false

    /** The message is not a registration challenge. */
    object NotAChallenge : ChallengeOutcome

    /** It is one, and is not answered, for the reason named. The record is as it was. */
    data class Ignored(val reason: String) : ChallengeOutcome

    /** The gateway took the answer. */
    object Answered : ChallengeOutcome {
        override val settles: Boolean
            get() = true
    }

    /** The gateway answered and will not take it. The record says so. */
    data class GatewayRefused(val status: Int) : ChallengeOutcome {
        override val settles: Boolean
            get() = true
    }

    /** The answer did not get there, or the gateway could not take it now: ask again. */
    data class Retry(val reason: String) : ChallengeOutcome
}

/** The Rust half's two functions, over JSON text. */
interface ChallengeCrypto {
    /** Decides what a message means for the pending registration, with no secret. */
    fun classify(input: String): String

    /** Builds the answer and the request that carries it, given the installation's key. */
    fun sign(input: String, seed: ByteArray): String
}

/** Where the installation's key is read from, by the name the decision returned. */
fun interface SeedSource {
    /** The seed, or null when the store holds none. The caller clears it. */
    fun read(item: String): ByteArray?
}

/** The one request this answers with. */
fun interface GatewayPost {
    /** Posts `body` to `url` and says what came back. */
    fun post(url: String, body: ByteArray): PostResult
}

/** What came back from the gateway, or that nothing did. */
sealed interface PostResult {
    /** The gateway answered with this status. */
    data class Status(val code: Int) : PostResult

    /** The request did not reach the gateway or its answer did not come back. */
    object Unreachable : PostResult
}
