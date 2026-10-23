package to.kala.reach.companion.push

import android.content.Context
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import to.kala.reach.companion.mobile.ChallengeAnswerer
import to.kala.reach.companion.mobile.GatewayPost
import to.kala.reach.companion.mobile.PendingFile
import to.kala.reach.companion.mobile.PostResult
import to.kala.reach.companion.mobile.PushStores
import to.kala.reach.companion.mobile.SeedSource
import to.kala.reach.platform.KeystoreSealer

/**
 * Where a registration challenge is answered from: the record the application keeps, the
 * installation's key in the application's secure store, and the gateway the record names.
 *
 * What a receiver and the worker that retries it share, so the two cannot answer differently.
 */
object Challenges {
    fun record(context: Context): PendingFile = PushStores.pending(context.noBackupFilesDir)

    fun answerer(context: Context, beforePosting: () -> Unit = {}): ChallengeAnswerer =
        ChallengeAnswerer(
            record = record(context),
            crypto = RustChallengeCrypto(),
            seeds = KeystoreSeeds(context),
            gateway = UrlConnectionPost(),
            beforePosting = beforePosting
        )
}

/** The installation's key, from the same files and under the same Keystore key the application uses. */
private class KeystoreSeeds(private val context: Context) : SeedSource {
    override fun read(item: String): ByteArray? =
        PushStores.secrets(context.noBackupFilesDir, KeystoreSealer()).read(item)
}

/** One POST over the platform's own connection, whose TLS the application's verifier checks. */
private class UrlConnectionPost : GatewayPost {
    override fun post(url: String, body: ByteArray): PostResult {
        var connection: HttpURLConnection? = null
        return try {
            connection = URL(url).openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.connectTimeout = TIMEOUT_MILLIS
            connection.readTimeout = TIMEOUT_MILLIS
            connection.doOutput = true
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("content-type", "application/json")
            connection.outputStream.use { it.write(body) }
            val code = connection.responseCode
            // The answer is read to its end and not looked at: the status is what is acted on.
            (if (code in 200..399) connection.inputStream else connection.errorStream)?.use {
                val buffer = ByteArray(1024)
                while (it.read(buffer) >= 0) {
                    // Read through and dropped.
                }
            }
            PostResult.Status(code)
        } catch (failure: IOException) {
            PostResult.Unreachable
        } finally {
            connection?.disconnect()
        }
    }

    private companion object {
        const val TIMEOUT_MILLIS = 8_000
    }
}
