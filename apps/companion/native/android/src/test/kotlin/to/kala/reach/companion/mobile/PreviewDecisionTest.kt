package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * What the push receiver shows, driven through every case the specification names.
 *
 * The four conditions under which the generic alert stands each have a test, and so does the case
 * where a preview is shown: a rule about when not to reveal something is only meaningful beside
 * the case where revealing is right.
 */
class PreviewDecisionTest {
    private val now = 1_763_000_000_000L
    private val recipient = ByteArray(PreviewEnvelope.KEY_ID_LENGTH) { 0x91.toByte() }
    private val sender = ByteArray(PreviewEnvelope.KEY_ID_LENGTH) { 0x76.toByte() }

    private fun payload(
        expiresAtMillis: Long = now + 60_000,
        recipientKeyId: ByteArray = recipient,
        nonceLength: Int = PreviewEnvelope.NONCE_LENGTH
    ): Map<String, String> =
        mapOf(
            "preview_nonce" to encode(ByteArray(nonceLength) { 1 }),
            "preview_ciphertext" to encode(ByteArray(64) { 2 }),
            "envelope_id" to "e-1",
            "recipient_key_id" to encode(recipientKeyId),
            "sender_key_id" to encode(sender),
            "expires_at_ms" to expiresAtMillis.toString(),
            "size_bucket_bytes" to "1024"
        )

    @Test
    fun aRevealedPreviewReplacesTheAlert() {
        val decision =
            PreviewDecider(providingKeys(), openingTo("Allow scripts/release.sh?"))
                .decide(payload(), now)
        assertEquals(PreviewDecision.Reveal("Allow scripts/release.sh?"), decision)
    }

    @Test
    fun theGenericAlertStandsWhenNoKeyHasBeenProvisioned() {
        val decision =
            PreviewDecider(failingKeys(PreviewKeyUnavailable.NotProvisioned), refusingOpener())
                .decide(payload(), now)
        assertEquals(PreviewDecision.Generic(GenericReason.KEY_UNAVAILABLE), decision)
    }

    @Test
    fun theGenericAlertStandsBeforeTheFirstUnlock() {
        val decision =
            PreviewDecider(
                    failingKeys(PreviewKeyUnavailable.LockedBeforeFirstUnlock),
                    refusingOpener()
                )
                .decide(payload(), now)
        assertEquals(PreviewDecision.Generic(GenericReason.LOCKED_BEFORE_FIRST_UNLOCK), decision)
    }

    @Test
    fun theGenericAlertStandsWhenDecryptionFails() {
        val decision = PreviewDecider(providingKeys(), refusingOpener()).decide(payload(), now)
        assertEquals(PreviewDecision.Generic(GenericReason.DECRYPTION_FAILED), decision)
    }

    @Test
    fun theGenericAlertStandsWhenThisBuildCarriesNoOpener() {
        val decision =
            PreviewDecider(providingKeys(), SharedClientPreviewOpener).decide(payload(), now)
        assertEquals(PreviewDecision.Generic(GenericReason.DECRYPTION_FAILED), decision)
    }

    @Test
    fun aMessageWithNoPreviewIsTheOrdinaryGenericAlert() {
        val decision =
            PreviewDecider(providingKeys(), openingTo("x")).decide(mapOf("alert" to "a"), now)
        assertEquals(PreviewDecision.Generic(GenericReason.NO_PREVIEW), decision)
    }

    @Test
    fun aMalformedPreviewIsNeverInterpreted() {
        val decision =
            PreviewDecider(providingKeys(), openingTo("x")).decide(payload(nonceLength = 12), now)
        assertEquals(PreviewDecision.Generic(GenericReason.MALFORMED_PREVIEW), decision)
    }

    @Test
    fun anExpiredPreviewIsNotOpened() {
        var reads = 0
        val keys = PreviewKeyReading {
            reads += 1
            Result.success(ByteArray(32))
        }
        val decision =
            PreviewDecider(keys, openingTo("secret")).decide(payload(expiresAtMillis = now - 1), now)
        assertEquals(PreviewDecision.Generic(GenericReason.EXPIRED), decision)
        assertEquals(0, reads)
    }

    @Test
    fun aPreviewForAnotherDeviceIsNotOpened() {
        var reads = 0
        val keys = PreviewKeyReading {
            reads += 1
            Result.success(ByteArray(32))
        }
        val held = recipient.joinToString("") { "%02x".format(it) }
        val decision =
            PreviewDecider(keys, openingTo("secret"), setOf(held))
                .decide(payload(recipientKeyId = ByteArray(32) { 0x33 }), now)
        assertEquals(PreviewDecision.Generic(GenericReason.NOT_FOR_THIS_DEVICE), decision)
        assertEquals(0, reads)
    }

    @Test
    fun anEmptyPlaintextIsNotShownAsAPreview() {
        val decision = PreviewDecider(providingKeys(), openingTo("   ")).decide(payload(), now)
        assertEquals(PreviewDecision.Generic(GenericReason.DECRYPTION_FAILED), decision)
    }

    @Test
    fun aFieldNoEncoderCouldHaveProducedIsRefused() {
        val impossible = "A".repeat(33)
        val decision =
            PreviewDecider(providingKeys(), openingTo("x"))
                .decide(payload() + mapOf("preview_nonce" to impossible), now)
        assertEquals(PreviewDecision.Generic(GenericReason.MALFORMED_PREVIEW), decision)
    }

    @Test
    fun theFieldsDecodeToExactlyTheBytesThatWereEncoded() {
        val nonce = ByteArray(PreviewEnvelope.NONCE_LENGTH) { (it * 7 + 3).toByte() }
        val parsed =
            PreviewEnvelope.parse(payload() + mapOf("preview_nonce" to encode(nonce)))
        check(parsed is ParsedPreview.Sealed)
        assertEquals(nonce.toList(), parsed.envelope.nonce.toList())
        assertEquals(
            recipient.toList(),
            parsed.envelope.routing.recipientKeyId.toList()
        )
    }

    @Test
    fun theRoutingIsReadExactlyAsTheProtocolDeclaresIt() {
        val parsed = PreviewEnvelope.parse(payload())
        check(parsed is ParsedPreview.Sealed)
        assertEquals("e-1", parsed.envelope.routing.envelopeId)
        assertEquals(1024L, parsed.envelope.routing.sizeBucketBytes)
        assertEquals(PreviewEnvelope.NONCE_LENGTH, parsed.envelope.nonce.size)
    }

    private fun providingKeys() = PreviewKeyReading { Result.success(ByteArray(32) { 0x44 }) }

    private fun failingKeys(unavailable: PreviewKeyUnavailable) =
        PreviewKeyReading { Result.failure(PreviewKeyUnavailableException(unavailable)) }

    private fun refusingOpener() =
        PreviewOpening { _, _ -> Result.failure(IllegalStateException("does not authenticate")) }

    private fun openingTo(text: String) = PreviewOpening { _, _ -> Result.success(text) }

    /** base64url without padding, written out so the test does not need a platform decoder. */
    private fun encode(bytes: ByteArray): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val bits = bytes.joinToString("") { byte ->
            (byte.toInt() and 0xff).toString(2).padStart(8, '0')
        }
        return buildString {
            var position = 0
            while (position < bits.length) {
                val chunk = bits.substring(position, minOf(position + 6, bits.length)).padEnd(6, '0')
                append(alphabet[chunk.toInt(2)])
                position += 6
            }
        }
    }
}

/** Where a message's work runs, and the signing rule. */
class WorkAndSigningTest {
    private val now = 1_763_000_000_000L

    @Test
    fun workThatNeedsTheHostNeverRunsInTheCallback() {
        assertEquals(
            WorkPlacement.DEFERRED,
            placeWork(IncomingWork(decidedByPayload = true, needsHost = true))
        )
    }

    @Test
    fun workThePayloadDecidesRunsWhereItStands() {
        assertEquals(
            WorkPlacement.IN_CALLBACK,
            placeWork(IncomingWork(decidedByPayload = true, needsHost = false))
        )
    }

    @Test
    fun workIsHandedOnWellBeforeTheCallbackBudgetRunsOut() {
        assertEquals(
            WorkPlacement.DEFERRED,
            placeWork(
                IncomingWork(
                    decidedByPayload = true,
                    needsHost = false,
                    elapsedMillis = CALLBACK_BUDGET_MILLIS - CALLBACK_MARGIN_MILLIS
                )
            )
        )
    }

    @Test
    fun anUnauthenticatedApplicationSignsNothing() {
        assertEquals(
            SigningRefusal.NOT_AUTHENTICATED,
            SigningGate(isApplication = true, state = AuthenticationState.None).refusal(now)
        )
    }

    @Test
    fun anAuthenticatedApplicationSigns() {
        assertNull(
            SigningGate(true, AuthenticationState.Verified(now)).refusal(now + 1000)
        )
    }

    @Test
    fun anOldAuthenticationIsNotAnAuthentication() {
        assertEquals(
            SigningRefusal.AUTHENTICATION_EXPIRED,
            SigningGate(true, AuthenticationState.Verified(now))
                .refusal(now + AUTHENTICATION_LIFETIME_MILLIS + 1)
        )
    }

    @Test
    fun aReceiverNeverSigns() {
        assertEquals(
            SigningRefusal.NOT_THE_APPLICATION,
            SigningGate(false, AuthenticationState.Verified(now)).refusal(now)
        )
    }
}
