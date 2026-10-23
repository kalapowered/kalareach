package to.kala.reach.companion.mobile

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * What the push receiver does with a message, from the message to the record and the gateway.
 *
 * The decision and the signature are the Rust half's and are tested there against the protocol's
 * vectors; here the rest of the receiver is held: the order (decide, then read the key, then sign,
 * then post), what each outcome does to the record, that the key is cleared, and that the record's
 * deadline is a fact of the clock.
 */
class PushReceiverTest {
    @get:Rule val folder = TemporaryFolder()

    private val now = 1_763_000_000_000L

    private val registration = "2e749a03-c158-4d62-a019-6f3bd784215c"

    private fun file() = File(folder.root, "pending.json")

    private fun pendingText(deadlineMillis: Long = now + 60_000, state: String = "pending") =
        JSONObject()
            .put("registration_id", registration)
            .put("token_digest", "vluKsRhhTV5NI9BuJZCyN2OsL1hi2yQbHXhFhtHMqmQ")
            .put("gateway_origin", "https://reach.kala.to")
            .put("platform", "android")
            .put("deadline_ms", deadlineMillis)
            .put("state", state)
            .toString()

    private fun stateOf(record: PendingFile, at: Long = now) =
        record.read(at)?.let { JSONObject(it).getString("state") }

    // The record.

    @Test
    fun aRecordPastItsDeadlineReadsAsExpiredEvenToAReaderThatStartedAfterTheWriter() {
        PendingFile(file()).write(pendingText(deadlineMillis = now + 10))
        assertEquals("pending", stateOf(PendingFile(file()), now))
        assertEquals("expired", stateOf(PendingFile(file()), now + 10))
        // And it stays so for every later reader, whatever its clock then says.
        assertEquals("expired", stateOf(PendingFile(file()), now))
    }

    @Test
    fun onlyAPendingRecordMovesAndAReplacedOrExpiredOneIsLeftAlone() {
        val record = PendingFile(file())
        record.write(pendingText())
        assertTrue(record.mark(registration, PendingFile.ANSWERED, null, now))
        assertEquals("answered", stateOf(record))
        assertFalse("an answered record is not moved again", record.mark(registration, PendingFile.REFUSED, "late", now))
        assertEquals("answered", stateOf(record))

        record.write(pendingText(deadlineMillis = now + 1))
        assertFalse(record.mark(registration, PendingFile.ANSWERED, null, now + 1))
        assertEquals("expired", stateOf(record, now + 1))

        record.clear()
        assertNull(record.read(now))
        assertFalse(record.mark(registration, PendingFile.ANSWERED, null, now))
    }

    @Test
    fun aTryThatOutlivedItsRegistrationCannotMoveItsReplacement() {
        val record = PendingFile(file())
        record.write(pendingText())
        val replacement =
            JSONObject(pendingText())
                .put("registration_id", "9a0f4c2e-6b1d-4c53-8e8a-7d1f2b3c4d5e")
                .toString()
        // The later registration replaces the record while the earlier one's post is in flight.
        PendingFile(file()).write(replacement)
        assertFalse(record.mark(registration, PendingFile.REFUSED, "gateway_403", now))
        assertEquals("pending", stateOf(record))
        assertTrue(record.mark("9a0f4c2e-6b1d-4c53-8e8a-7d1f2b3c4d5e", PendingFile.ANSWERED, null, now))
        assertEquals("answered", stateOf(record))
    }

    @Test
    fun aNewRegistrationReplacesTheOldOneWhole() {
        val record = PendingFile(file())
        record.write(pendingText())
        record.mark(registration, PendingFile.REFUSED, "gateway_403", now)
        record.write(pendingText(deadlineMillis = now + 120_000))
        val read = JSONObject(record.read(now)!!)
        assertEquals("pending", read.getString("state"))
        assertFalse("nothing of the earlier reason is kept", read.has("reason"))
    }

    // The receiver's order.

    private class Crypto(
        private val verdict: String,
        private val signed: String = """{"ok":true,"url":"https://reach.kala.to/api/push/installation/register","body":"{}"}"""
    ) : ChallengeCrypto {
        var classified = 0
        var signedWith: ByteArray? = null

        override fun classify(input: String): String {
            classified += 1
            return verdict
        }

        override fun sign(input: String, seed: ByteArray): String {
            signedWith = seed
            return signed
        }
    }

    private class Seeds(private val seed: ByteArray?) : SeedSource {
        val asked = mutableListOf<String>()

        override fun read(item: String): ByteArray? {
            asked.add(item)
            return seed
        }
    }

    private class Gateway(private val result: PostResult) : GatewayPost {
        val posted = mutableListOf<Pair<String, String>>()

        override fun post(url: String, body: ByteArray): PostResult {
            posted.add(url to body.toString(Charsets.UTF_8))
            return result
        }
    }

    private val goOn = """{"verdict":"answer","url":"https://reach.kala.to/api/push/installation/register","seed_item":"device/device-key/authorisation"}"""

    private val challenge = mapOf("kr_challenge" to "x", "kr_registration_id" to "r")

    private fun answerer(
        crypto: Crypto,
        seeds: Seeds,
        gateway: Gateway,
        record: PendingFile = PendingFile(file()).also { it.write(pendingText()) }
    ) = ChallengeAnswerer(record, crypto, seeds, gateway) { now }

    @Test
    fun aMessageTheDecisionLeavesAloneReadsNoKeyAndPostsNothing() {
        val crypto = Crypto("""{"verdict":"not_a_challenge"}""")
        val seeds = Seeds(ByteArray(32) { 5 })
        val gateway = Gateway(PostResult.Status(200))
        assertEquals(ChallengeOutcome.NotAChallenge, answerer(crypto, seeds, gateway).answer(mapOf("alert" to "a")))
        assertTrue(seeds.asked.isEmpty())
        assertTrue(gateway.posted.isEmpty())
    }

    @Test
    fun aChallengeTheDecisionRefusesReadsNoKeyPostsNothingAndLeavesTheRecordPending() {
        val record = PendingFile(file()).also { it.write(pendingText()) }
        val crypto = Crypto("""{"verdict":"refused","reason":"registration"}""")
        val seeds = Seeds(ByteArray(32) { 5 })
        val gateway = Gateway(PostResult.Status(200))
        assertEquals(
            ChallengeOutcome.Ignored("registration"),
            answerer(crypto, seeds, gateway, record).answer(challenge)
        )
        assertTrue("the key is read only after the decision says to go on", seeds.asked.isEmpty())
        assertTrue(gateway.posted.isEmpty())
        assertNull("nothing was signed", crypto.signedWith)
        assertEquals("pending", stateOf(record))
    }

    @Test
    fun theKeyIsReadByTheNameTheDecisionGaveAndClearedOnceTheAnswerIsSigned() {
        val seed = ByteArray(32) { 5 }
        val crypto = Crypto(goOn)
        val seeds = Seeds(seed)
        val gateway = Gateway(PostResult.Status(200))
        val record = PendingFile(file()).also { it.write(pendingText()) }
        assertEquals(ChallengeOutcome.Answered, answerer(crypto, seeds, gateway, record).answer(challenge))
        assertEquals(listOf("device/device-key/authorisation"), seeds.asked)
        assertTrue("the seed was cleared after the call that signs", seed.all { it == 0.toByte() })
        assertEquals(
            listOf("https://reach.kala.to/api/push/installation/register" to "{}"),
            gateway.posted
        )
        assertEquals("answered", stateOf(record))
    }

    @Test
    fun aProcessThatCannotLoadTheLibraryAnswersNothingAndTheRecordStaysPending() {
        val unloadable =
            object : ChallengeCrypto {
                override fun classify(input: String): String =
                    throw UnsatisfiedLinkError("the library could not be loaded")

                override fun sign(input: String, seed: ByteArray): String = error("not reached")
            }
        val seeds = Seeds(ByteArray(32) { 5 })
        val gateway = Gateway(PostResult.Status(200))
        val record = PendingFile(file()).also { it.write(pendingText()) }
        val outcome = ChallengeAnswerer(record, unloadable, seeds, gateway) { now }.answer(challenge)
        assertEquals(ChallengeOutcome.Ignored("library_unavailable"), outcome)
        assertTrue("no key was read", seeds.asked.isEmpty())
        assertTrue(gateway.posted.isEmpty())
        assertEquals("pending", stateOf(record))
    }

    @Test
    fun aKeyThatIsNotThereIsNotMadeUpAndNothingIsPosted() {
        val gateway = Gateway(PostResult.Status(200))
        assertEquals(
            ChallengeOutcome.Ignored("key_missing"),
            answerer(Crypto(goOn), Seeds(null), gateway).answer(challenge)
        )
        assertTrue(gateway.posted.isEmpty())
    }

    @Test
    fun aKeyThatCannotBeReadIsAnsweredLikeOneThatIsNotThereAndTheReceiverDoesNotFail() {
        val unreadable = SeedSource { throw java.security.GeneralSecurityException("the key store is locked") }
        val gateway = Gateway(PostResult.Status(200))
        val record = PendingFile(file()).also { it.write(pendingText()) }
        val outcome = ChallengeAnswerer(record, Crypto(goOn), unreadable, gateway) { now }.answer(challenge)
        assertEquals(ChallengeOutcome.Ignored("key_missing"), outcome)
        assertTrue(gateway.posted.isEmpty())
        assertEquals("pending", stateOf(record))
    }

    @Test
    fun theSchedulerIsHandedTheAnswerAfterItIsSignedAndBeforeItIsPosted() {
        val order = mutableListOf<String>()
        val gateway =
            object : GatewayPost {
                override fun post(url: String, body: ByteArray): PostResult {
                    order.add("posted")
                    return PostResult.Status(200)
                }
            }
        val crypto =
            object : ChallengeCrypto {
                override fun classify(input: String): String = goOn

                override fun sign(input: String, seed: ByteArray): String {
                    order.add("signed")
                    return """{"ok":true,"url":"https://reach.kala.to/api/push/installation/register","body":"{}"}"""
                }
            }
        val record = PendingFile(file()).also { it.write(pendingText()) }
        val outcome =
            ChallengeAnswerer(record, crypto, Seeds(ByteArray(32)), gateway, { order.add("handed") }) { now }
                .answer(challenge)
        assertEquals(ChallengeOutcome.Answered, outcome)
        assertEquals(listOf("signed", "handed", "posted"), order)

        // A message the decision refuses is handed to nobody.
        var handed = false
        ChallengeAnswerer(
                PendingFile(file()).also { it.write(pendingText()) },
                Crypto("""{"verdict":"refused","reason":"token"}"""),
                Seeds(ByteArray(32)),
                Gateway(PostResult.Status(200)),
                { handed = true }
            ) { now }
            .answer(challenge)
        assertFalse("nothing is handed to the scheduler for a message that is refused", handed)
    }

    @Test
    fun aSignatureTheRustHalfWillNotMakeIsNotPosted() {
        val crypto = Crypto(goOn, """{"ok":false,"reason":"clock"}""")
        val gateway = Gateway(PostResult.Status(200))
        assertEquals(
            ChallengeOutcome.Ignored("clock"),
            answerer(crypto, Seeds(ByteArray(32)), gateway).answer(challenge)
        )
        assertTrue(gateway.posted.isEmpty())
    }

    @Test
    fun aGatewayThatCouldNotBeReachedOrCannotTakeItNowIsAskedAgainAndTheRecordWaits() {
        for (result in listOf(PostResult.Unreachable, PostResult.Status(503), PostResult.Status(429))) {
            val record = PendingFile(file()).also { it.write(pendingText()) }
            val outcome =
                answerer(Crypto(goOn), Seeds(ByteArray(32)), Gateway(result), record).answer(challenge)
            assertTrue("$result: $outcome", outcome is ChallengeOutcome.Retry)
            assertEquals("pending", stateOf(record))
        }
    }

    @Test
    fun aGatewayThatRefusesTheAnswerEndsTheRegistrationWithItsStatus() {
        val record = PendingFile(file()).also { it.write(pendingText()) }
        val outcome =
            answerer(Crypto(goOn), Seeds(ByteArray(32)), Gateway(PostResult.Status(403)), record)
                .answer(challenge)
        assertEquals(ChallengeOutcome.GatewayRefused(403), outcome)
        val read = JSONObject(record.read(now)!!)
        assertEquals("refused", read.getString("state"))
        assertEquals("gateway_403", read.getString("reason"))
    }

    // The limited preview key.

    private object Plain : Sealer {
        override fun seal(plain: ByteArray, associated: ByteArray) = plain

        override fun open(sealed: ByteArray, associated: ByteArray) = sealed
    }

    /**
     * KR-REQ-10.48: the store a receiver reads holds the one key that opens a notification
     * preview, filed by the identifier of its public half, and the application's secure store, with
     * the authorisation key in it, is another directory the limited store neither reads nor writes.
     */
    @Test
    fun theLimitedStoreHoldsTheOneKeyAPreviewOpensWithAndNeverTheAuthorisationKey() {
        val noBackup = folder.newFolder("no-backup")
        val authorisation = ByteArray(32) { 7 }
        PushStores.secrets(noBackup, Plain).write("device/device-key/authorisation", authorisation)

        val recipient = ByteArray(32) { 0x91.toByte() }
        val preview = ByteArray(32) { 3 }
        val limited = PushStores.limited(noBackup, Plain)
        limited.write(recipient, preview)

        assertEquals(preview.toList(), limited.read(recipient)!!.toList())
        assertNull("no other recipient has a key here", limited.read(ByteArray(32) { 1 }))
        assertEquals(
            "the limited store is one file for the one key",
            1,
            File(noBackup, PushStores.LIMITED_DIRECTORY).listFiles()!!.size
        )
        assertEquals(
            "the secure store holds only what it held",
            1,
            File(noBackup, PushStores.SECRETS_DIRECTORY).listFiles()!!.size
        )
        assertEquals(
            authorisation.toList(),
            PushStores.secrets(noBackup, Plain).read("device/device-key/authorisation")!!.toList()
        )
        limited.delete(recipient)
        assertNull(limited.read(recipient))
    }

    // The message.

    @Test
    fun aMessageIsAChallengeADeliveryOrNeither() {
        assertTrue(readMessage(challenge) is PushMessage.Challenge)
        val delivery =
            readMessage(
                mapOf(
                    "notification_id" to "n-1",
                    "collapse_id" to "c-1",
                    "alert" to "A KalaReach session needs attention."
                )
            )
        check(delivery is PushMessage.Delivery)
        assertEquals("c-1", delivery.collapseId)
        assertEquals(PushMessage.Unrecognised, readMessage(mapOf("alert" to "a")))
        assertEquals(PushMessage.Unrecognised, readMessage(mapOf("notification_id" to "n-1")))
        assertEquals(PushMessage.Unrecognised, readMessage(emptyMap()))
    }

    @Test
    fun aNotificationIsPostedUnderTheIdentifierItsKindShareAndNeverUnderItsWords() {
        val delivery =
            PushMessage.Delivery("n-1", "c-1", "A KalaReach session needs attention.", emptyMap())
        val generic = planNotification(delivery, PreviewDecision.Generic(GenericReason.NO_PREVIEW))
        val revealed = planNotification(delivery, PreviewDecision.Reveal("Allow scripts/release.sh?"))
        assertEquals("c-1", generic.tag)
        assertEquals("c-1", revealed.tag)
        assertEquals("A KalaReach session needs attention.", generic.body)
        assertEquals("no_preview", generic.reason)
        assertEquals("Allow scripts/release.sh?", revealed.body)

        // With no collapse identifier a notification stands on its own identifier.
        val alone = readMessage(mapOf("notification_id" to "n-2", "alert" to "a"))
        check(alone is PushMessage.Delivery)
        assertEquals("n-2", planNotification(alone, PreviewDecision.Generic(GenericReason.NO_PREVIEW)).tag)
    }
}
