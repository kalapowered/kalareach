package to.kala.reach.companion.mobile

import java.io.File
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the receiver hands the Rust opener and reads back, held against the preview the host's own
 * code sealed (the golden the Rust opener and the Swift receiver read too). The opening itself is
 * the Rust function's, tested there; this holds that the receiver finds the right keys by the
 * identifiers the preview names and gives the function the members it reads.
 */
class PreviewOpenerTest {
    private val golden =
        JSONObject(File(System.getProperty("kr.fixtures"), "push/recorded-preview.json").readText())

    private fun urlBytes(text: String): ByteArray = Base64.getUrlDecoder().decode(text)

    private fun standardBytes(text: String): ByteArray = Base64.getDecoder().decode(text)

    private fun message(): Map<String, String> =
        mapOf(
            "notification_id" to "n-1",
            "alert" to golden.getString("alert"),
            "preview" to golden.getString("preview")
        )

    @Test
    fun theKeysAreFoundByTheIdentifiersThePreviewNamesAndTheOpenerIsGivenWhatItReads() {
        val recipientId = urlBytes(golden.getString("recipient_key_id")).toList()
        val senderId = urlBytes(golden.getString("sender_key_id")).toList()
        val keys =
            object : PreviewKeyReading {
                override fun recipientSeed(recipientKeyId: ByteArray): Result<ByteArray> =
                    if (recipientKeyId.toList() == recipientId) {
                        Result.success(standardBytes(golden.getString("recipient_seed")))
                    } else {
                        Result.failure(
                            PreviewKeyUnavailableException(PreviewKeyUnavailable.NotProvisioned)
                        )
                    }

                override fun senderKey(senderKeyId: ByteArray): Result<ByteArray> =
                    if (senderKeyId.toList() == senderId) {
                        Result.success(standardBytes(golden.getString("sender_key")))
                    } else {
                        Result.failure(
                            PreviewKeyUnavailableException(PreviewKeyUnavailable.NotProvisioned)
                        )
                    }
            }
        var input: JSONObject? = null
        var seedGiven: List<Byte>? = null
        val opener = PreviewOpening { preview, alert, seed, senderKey, nowMillis ->
            input = JSONObject(PreviewOpenerJson.input(preview, senderKey, alert, nowMillis))
            seedGiven = seed.toList()
            PreviewOpened.Text(golden.getString("summary"))
        }

        val decision = PreviewDecider(keys, opener).decide(message(), golden.getLong("now_ms"))

        assertEquals(PreviewDecision.Reveal(golden.getString("summary")), decision)
        assertEquals(standardBytes(golden.getString("recipient_seed")).toList(), seedGiven)
        val given = input!!
        assertEquals(
            "exactly the members the Rust function reads",
            setOf("preview", "sender_key", "alert", "now_ms"),
            given.keySet()
        )
        assertEquals(golden.getString("preview"), given.getString("preview"))
        assertEquals(golden.getString("sender_key"), given.getString("sender_key"))
        assertEquals(golden.getString("alert"), given.getString("alert"))
        assertEquals(golden.getLong("now_ms"), given.getLong("now_ms"))
    }

    @Test
    fun theOpenersAnswerIsReadAsTextOrAsTheRefusalItNames() {
        assertEquals(
            PreviewOpened.Text("Allow scripts/release.sh?"),
            PreviewOpenerJson.answer("""{"ok":true,"text":"Allow scripts/release.sh?"}""")
        )
        assertEquals(
            PreviewOpened.Refused("authentication"),
            PreviewOpenerJson.answer("""{"ok":false,"reason":"authentication"}""")
        )
        assertTrue(PreviewOpenerJson.answer("not json") is PreviewOpened.Refused)
        assertTrue(
            "text with no ok is not text",
            PreviewOpenerJson.answer("""{"text":"x"}""") is PreviewOpened.Refused
        )
    }
}
