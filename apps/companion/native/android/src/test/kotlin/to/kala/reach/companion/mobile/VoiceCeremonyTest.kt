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
}
