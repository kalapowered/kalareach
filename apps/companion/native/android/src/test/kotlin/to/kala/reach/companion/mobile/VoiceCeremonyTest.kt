package to.kala.reach.companion.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class VoiceCeremonyTest {
    private val confirmationId = ByteArray(16) { 0x11.toByte() }
    private val voiceSessionId = ByteArray(16) { 0x12.toByte() }
    private val actionId = ByteArray(16) { 0x22.toByte() }
    private val hostDeviceId = ByteArray(16) { 0x33.toByte() }
    private val clientDeviceId = ByteArray(16) { 0x44.toByte() }
    private val nonce = ByteArray(32) { 0x55.toByte() }
    private val actionDigest = ByteArray(32) { 0xaa.toByte() }
    private val nowMillis = 1_000_000L

    private fun sampleChallenge(
        action: String = "apply_diff",
        digest: ByteArray? = null,
        expiresAt: Long? = null
    ): VoiceConfirmationChallenge {
        return VoiceConfirmationChallenge(
            confirmationId = confirmationId,
            voiceSessionId = voiceSessionId,
            action = action,
            actionDigest = digest ?: actionDigest,
            actionId = actionId,
            hostDeviceId = hostDeviceId,
            clientDeviceId = clientDeviceId,
            nonce = nonce,
            expiresAtMillis = expiresAt ?: (nowMillis + 120_000L)
        )
    }

    /**
     * KR-REQ-15.13: signature covers the action hash and verifies with the paired key.
     */
    @Test
    fun signature_covers_action_hash_and_verifies() {
        val keyPair = VoiceCeremony.generateKeyPair()
        val challenge = sampleChallenge()
        val ceremony = VoiceCeremony { true }

        val proof = ceremony.confirm(challenge, keyPair, nowMillis)

        val result = VoiceCeremony.verify(
            proof = proof,
            expectedAction = "apply_diff",
            expectedActionDigest = actionDigest,
            expectedClientDeviceId = clientDeviceId,
            expectedSignerPublicKey = keyPair.public.encoded,
            nowMillis = nowMillis + 1000L
        )
        assertTrue("Valid proof must verify", result.isSuccess)
    }

    /**
     * Tampering with the action digest causes verification refusal.
     */
    @Test
    fun tampered_action_digest_is_refused() {
        val keyPair = VoiceCeremony.generateKeyPair()
        val challenge = sampleChallenge()
        val ceremony = VoiceCeremony { true }

        val proof = ceremony.confirm(challenge, keyPair, nowMillis)

        val badDigest = actionDigest.clone()
        badDigest[0] = (badDigest[0].toInt() xor 0xff).toByte()

        val result = VoiceCeremony.verify(
            proof = proof,
            expectedAction = "apply_diff",
            expectedActionDigest = badDigest,
            expectedClientDeviceId = clientDeviceId,
            expectedSignerPublicKey = keyPair.public.encoded,
            nowMillis = nowMillis + 1000L
        )
        assertTrue("Tampered digest must be refused", result.isFailure)
        assertEquals(
            VoiceCeremonyRefusal.ConfirmationMismatch,
            result.exceptionOrNull()
        )
    }

    /**
     * Confirmation for one action cannot authorize another action.
     */
    @Test
    fun confirmation_for_one_action_does_not_authorize_another() {
        val keyPair = VoiceCeremony.generateKeyPair()
        val challenge = sampleChallenge(action = "apply_diff")
        val ceremony = VoiceCeremony { true }

        val proof = ceremony.confirm(challenge, keyPair, nowMillis)

        val result = VoiceCeremony.verify(
            proof = proof,
            expectedAction = "shell_input",
            expectedActionDigest = actionDigest,
            expectedClientDeviceId = clientDeviceId,
            expectedSignerPublicKey = keyPair.public.encoded,
            nowMillis = nowMillis + 1000L
        )
        assertTrue("Wrong action must be refused", result.isFailure)
        assertEquals(
            VoiceCeremonyRefusal.ConfirmationMismatch,
            result.exceptionOrNull()
        )
    }

    /**
     * Provider text or model speech cannot produce a confirmation proof without the paired key.
     */
    @Test
    fun provider_text_cannot_produce_confirmation_proof() {
        val pairedKeyPair = VoiceCeremony.generateKeyPair()
        val imposterKeyPair = VoiceCeremony.generateKeyPair()
        val challenge = sampleChallenge()
        val ceremony = VoiceCeremony { true }

        val imposterProof = ceremony.confirm(challenge, imposterKeyPair, nowMillis)

        val result = VoiceCeremony.verify(
            proof = proofMatchesSigner(imposterProof),
            expectedAction = "apply_diff",
            expectedActionDigest = actionDigest,
            expectedClientDeviceId = clientDeviceId,
            expectedSignerPublicKey = pairedKeyPair.public.encoded,
            nowMillis = nowMillis + 1000L
        )
        assertTrue("Signature by imposter key must be refused", result.isFailure)
        assertEquals(
            VoiceCeremonyRefusal.ConfirmationMismatch,
            result.exceptionOrNull()
        )
    }

    /**
     * When owner presence verification fails (e.g. user cancels biometric prompt), ceremony refuses.
     */
    @Test
    fun unverified_presence_refuses_signing() {
        val keyPair = VoiceCeremony.generateKeyPair()
        val challenge = sampleChallenge()
        val ceremony = VoiceCeremony { false }

        try {
            ceremony.confirm(challenge, keyPair, nowMillis)
            fail("Expected PresenceVerificationFailed exception")
        } catch (e: VoiceCeremonyRefusal.PresenceVerificationFailed) {
            // Success
        }
    }

    /**
     * Expired challenge is refused.
     */
    @Test
    fun expired_challenge_is_refused() {
        val keyPair = VoiceCeremony.generateKeyPair()
        val challenge = sampleChallenge(expiresAt = nowMillis - 1L)
        val ceremony = VoiceCeremony { true }

        try {
            ceremony.confirm(challenge, keyPair, nowMillis)
            fail("Expected ConfirmationExpired exception")
        } catch (e: VoiceCeremonyRefusal.ConfirmationExpired) {
            // Success
        }
    }

    private fun proofMatchesSigner(proof: VoiceConfirmationProof): VoiceConfirmationProof = proof

    /**
     * The cross-language vector: the exact bytes the host signs, for one fixed challenge.
     *
     * The same two constants are asserted by the desktop ceremony tests, against the shared
     * protocol's own encoder, and by the iOS ceremony tests. A client that signs anything else
     * produces proofs the host rejects, and no test of this client alone would notice.
     */
    @Test
    fun signing_input_matches_the_cross_language_vector() {
        val challenge = VoiceConfirmationChallenge(
            confirmationId = ByteArray(16) { 0x11.toByte() },
            voiceSessionId = ByteArray(16) { 0x22.toByte() },
            action = "apply_diff",
            actionDigest = ByteArray(32) { 0x33.toByte() },
            actionId = ByteArray(16) { 0x44.toByte() },
            hostDeviceId = ByteArray(16) { 0x55.toByte() },
            clientDeviceId = ByteArray(16) { 0x66.toByte() },
            nonce = ByteArray(32) { 0x77.toByte() },
            expiresAtMillis = 1_700_000_000_000L
        )

        assertEquals(SIGNING_INPUT_VECTOR, hexadecimal(challenge.signingInput()))
    }

    /** The identifier the host derives for the key that signs a proof. */
    @Test
    fun signer_key_identifier_matches_the_cross_language_vector() {
        val identifier = authorisationKeyId(ByteArray(32) { 0x88.toByte() })
        assertEquals(SIGNER_KEY_ID_VECTOR, hexadecimal(identifier))
    }

    /**
     * The encoder at every boundary where the head changes size, for multibyte text and for keys
     * of equal and unequal length. The bytes are the list the desktop test holds the host's own
     * encoder to, so all three clients agree with the host rather than with themselves.
     */
    @Test
    fun the_encoder_writes_the_hosts_bytes_at_every_boundary() {
        val unsigned = listOf(
            0uL to "00",
            23uL to "17",
            24uL to "1818",
            255uL to "18ff",
            256uL to "190100",
            65_535uL to "19ffff",
            65_536uL to "1a00010000",
            4_294_967_295uL to "1affffffff",
            4_294_967_296uL to "1b0000000100000000",
            ULong.MAX_VALUE to "1bffffffffffffffff",
        )
        for ((value, expected) in unsigned) {
            assertEquals("$value", expected, hexadecimal(CanonicalCbor.Unsigned(value).encoded()))
        }
        val heads = listOf(
            Triple(0, "40", "60"),
            Triple(23, "57", "77"),
            Triple(24, "5818", "7818"),
            Triple(255, "58ff", "78ff"),
            Triple(256, "590100", "790100"),
        )
        for ((length, bytesHead, textHead) in heads) {
            assertEquals(
                bytesHead + "01".repeat(length),
                hexadecimal(CanonicalCbor.Bytes(ByteArray(length) { 1 }).encoded()),
            )
            assertEquals(
                textHead + "61".repeat(length),
                hexadecimal(CanonicalCbor.Text("a".repeat(length)).encoded()),
            )
        }
        assertEquals("62c3a9", hexadecimal(CanonicalCbor.Text("é").encoded()))
        assertEquals("66e697a5e69cac", hexadecimal(CanonicalCbor.Text("日本").encoded()))
        val maps = listOf(
            listOf("b" to 1uL, "a" to 2uL) to "a2616102616201",
            listOf("aa" to 1uL, "b" to 2uL) to "a261620262616101",
            listOf("é" to 1uL, "z" to 2uL) to "a2617a0262c3a901",
            listOf("é" to 1uL, "ab" to 2uL) to "a26261620262c3a901",
        )
        for ((entries, expected) in maps) {
            val map = CanonicalCbor.Map(entries.map { (key, value) -> key to CanonicalCbor.Unsigned(value) })
            assertEquals("$entries", expected, hexadecimal(map.encoded()))
        }
    }

    /** A challenge cannot carry a deadline before the epoch, which the host could not write. */
    @Test(expected = IllegalArgumentException::class)
    fun a_negative_deadline_is_not_a_challenge() {
        sampleChallenge(expiresAt = -1L)
    }

    private fun hexadecimal(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private companion object {
        const val SIGNING_INPUT_VECTOR = "82726b722d766f6963652f636f6e6669726d2f31a9656e6f6e6365582077777777777777777777777777777777777777" +
        "7777777777777777777777777766616374696f6e6a6170706c795f6469666669616374696f6e5f696450444444444444" +
        "44444444444444444444696465766963655f696450666666666666666666666666666666666d616374696f6e5f646967" +
        "657374582033333333333333333333333333333333333333333333333333333333333333336d657870697265735f6174" +
        "5f6d731b0000018bcfe568006e686f73745f6465766963655f696450555555555555555555555555555555556f636f6e" +
        "6669726d6174696f6e5f6964501111111111111111111111111111111170766f6963655f73657373696f6e5f69645022" +
        "222222222222222222222222222222"

        const val SIGNER_KEY_ID_VECTOR = "a1e1283a5a7d9396772f55cfbd0867b9836c583a4381dd3f70a7a78afd9dec7f"
    }
}
