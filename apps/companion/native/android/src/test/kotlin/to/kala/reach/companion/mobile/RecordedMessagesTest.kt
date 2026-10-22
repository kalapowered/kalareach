package to.kala.reach.companion.mobile

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The messages a real gateway sent a phone, recorded from a device run, read the way the receiver
 * reads them. The Rust and Swift halves read the same files, so a change to what the gateway sends
 * has to be made in all three at once.
 */
class RecordedMessagesTest {
    private fun dataOf(name: String): Map<String, String> {
        val file = File(System.getProperty("kr.fixtures"), "push/$name")
        val data = JSONObject(file.readText()).getJSONObject("message").getJSONObject("data")
        return data.keys().asSequence().associateWith { data.getString(it) }
    }

    @Test
    fun theChallengeTheGatewaySentIsReadAsAChallengeAndNotAsADelivery() {
        val data = dataOf("recorded-challenge.json")
        val message = readMessage(data)
        assertTrue("$message", message is PushMessage.Challenge)
        assertEquals(data, (message as PushMessage.Challenge).data)
    }

    @Test
    fun theDeliveryTheGatewaySentIsReadWithItsGenericAlertAndItsSealedPreview() {
        val data = dataOf("recorded-delivery-android.json")
        val message = readMessage(data)
        assertTrue("$message", message is PushMessage.Delivery)
        val delivery = message as PushMessage.Delivery
        assertEquals(data["notification_id"], delivery.notificationId)
        assertEquals(data["collapse_id"], delivery.collapseId)
        assertEquals("A KalaReach session is waiting for an answer.", delivery.alert)

        val preview = PreviewEnvelope.parse(data)
        assertTrue("$preview", preview is ParsedPreview.Sealed)
        val sealed = (preview as ParsedPreview.Sealed).envelope
        assertEquals(PreviewEnvelope.NONCE_LENGTH, sealed.nonce.size)
        assertEquals(PreviewEnvelope.KEY_ID_LENGTH, sealed.routing.recipientKeyId.size)
        assertEquals(PreviewEnvelope.KEY_ID_LENGTH, sealed.routing.senderKeyId.size)
        assertEquals(1024L, sealed.routing.sizeBucketBytes)
        assertEquals(data["expires_at_ms"]?.toLong(), sealed.routing.expiresAtMillis)
        assertTrue("the ciphertext fills its bucket", sealed.ciphertext.size > 1024)
    }
}
