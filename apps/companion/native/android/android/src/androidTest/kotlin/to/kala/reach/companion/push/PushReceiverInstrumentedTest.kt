package to.kala.reach.companion.push

import android.app.Instrumentation
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkInfo
import androidx.work.WorkManager
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import to.kala.reach.companion.mobile.PendingFile
import to.kala.reach.companion.mobile.PushStores
import to.kala.reach.platform.KeystoreSealer

/**
 * The Android receiver and the scheduler behind it, in the application's own process, with no
 * activity and no WebView started: nothing here opens the application's screen.
 *
 * A message is handed to the application's Firebase receiver the way the provider hands it one: as a
 * broadcast carrying the message's data. The instrumentation runs as the application, which is what
 * the receiver's permission lets in. The delivery path shows a notification inline; the challenge
 * path posts an answer to the gateway the record names, and a post that does not get there is asked
 * again by the scheduler until the gateway takes it.
 */
@RunWith(AndroidJUnit4::class)
class PushReceiverInstrumentedTest {
    private val instrumentation: Instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext
    private val noBackup = context.noBackupFilesDir
    private val notifications = context.getSystemService(NotificationManager::class.java)

    @Before
    fun allowNotifications() {
        instrumentation.uiAutomation.grantRuntimePermission(
            context.packageName,
            "android.permission.POST_NOTIFICATIONS"
        )
        notifications.cancelAll()
        PushStores.pending(noBackup).clear()
    }

    @After
    fun leaveNothing() {
        notifications.cancelAll()
        PushStores.pending(noBackup).clear()
        WorkManager.getInstance(context).cancelAllWork()
    }

    /** Hands the receiver a message's data, as the provider does. */
    private fun deliver(data: Map<String, String>) {
        val intent =
            Intent("com.google.android.c2dm.intent.RECEIVE")
                .setClassName(context.packageName, "com.google.firebase.iid.FirebaseInstanceIdReceiver")
        for ((key, value) in data) intent.putExtra(key, value)
        context.sendBroadcast(intent)
    }

    private fun until(seconds: Int, holds: () -> Boolean): Boolean {
        val end = System.nanoTime() + seconds * 1_000_000_000L
        while (System.nanoTime() < end) {
            if (holds()) return true
            Thread.sleep(200)
        }
        return holds()
    }

    // KR-REQ-16.15, 13.24: a delivery is shown by the receiver with no screen of the application.
    @Test
    fun aDeliveryIsShownByTheReceiverAlone() {
        val tag = "instrumented-" + UUID.randomUUID()
        deliver(
            mapOf(
                "notification_id" to UUID.randomUUID().toString(),
                "collapse_id" to tag,
                "alert" to "Something needs your attention"
            )
        )
        val shown =
            until(30) {
                notifications.activeNotifications.any {
                    it.tag == tag &&
                        it.notification.extras.getCharSequence("android.text")?.toString() ==
                            "Something needs your attention"
                }
            }
        assertTrue("the receiver showed the notification", shown)
    }

    /** A gateway on this device's loopback interface that answers a post with 200 once it is up. */
    private class Gateway(val port: Int, private val whenPosted: () -> Unit = {}) : AutoCloseable {
        val body = AtomicReference<String?>(null)
        private var server: ServerSocket? = null
        private var thread: Thread? = null

        fun start() {
            val socket = ServerSocket(port, 4, InetAddress.getByName("127.0.0.1"))
            server = socket
            thread =
                Thread {
                        while (!socket.isClosed) {
                            val client = try { socket.accept() } catch (e: Exception) { return@Thread }
                            client.use {
                                val input = it.getInputStream()
                                val head = ByteArrayOutputStream()
                                var last = 0
                                while (!head.toString(Charsets.ISO_8859_1.name()).endsWith("\r\n\r\n")) {
                                    last = input.read()
                                    if (last < 0) break
                                    head.write(last)
                                }
                                val text = head.toString(Charsets.ISO_8859_1.name())
                                val length =
                                    Regex("(?i)content-length: *(\\d+)").find(text)?.groupValues?.get(1)?.toInt() ?: 0
                                val bytes = ByteArray(length)
                                var read = 0
                                while (read < length) {
                                    val n = input.read(bytes, read, length - read)
                                    if (n < 0) break
                                    read += n
                                }
                                body.set(String(bytes, Charsets.UTF_8))
                                whenPosted()
                                it.getOutputStream().write(
                                    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".toByteArray()
                                )
                            }
                        }
                    }
                    .also { it.start() }
        }

        override fun close() {
            server?.close()
            thread?.join(2000)
        }
    }

    /**
     * Writes the record of a registration that waits for its challenge at `origin`, and the key the
     * receiver signs with, and returns the registration's identifier and the challenge's data.
     */
    private fun pendingChallenge(origin: String): Pair<String, Map<String, String>> {
        val registration = UUID.randomUUID().toString()
        val digest = "vluKsRhhTV5NI9BuJZCyN2OsL1hi2yQbHXhFhtHMqmQ"
        val challenge = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"
        val now = System.currentTimeMillis()
        PushStores.pending(noBackup)
            .write(
                JSONObject()
                    .put("registration_id", registration)
                    .put("token_digest", digest)
                    .put("gateway_origin", origin)
                    .put("platform", "android")
                    .put("deadline_ms", now + 10 * 60_000)
                    .put("state", "pending")
                    .toString()
            )
        val data =
            mapOf(
                "kr_challenge" to challenge,
                "kr_registration_id" to registration,
                "kr_token_digest" to digest,
                "kr_gateway_origin" to origin,
                "kr_expires_at_ms" to (now + 5 * 60_000).toString()
            )
        // The installation's key is the one thing the receiver reads from the secure store: any
        // seed signs, and the record decides whether the answer is sent at all.
        val verdict =
            JSONObject(
                PushAnswer.classify(
                    JSONObject()
                        .put("data", JSONObject(data))
                        .put("pending", JSONObject(PushStores.pending(noBackup).read(now)!!))
                        .put("now_ms", now)
                        .toString()
                )
            )
        assertEquals("answer", verdict.getString("verdict"))
        PushStores.secrets(noBackup, KeystoreSealer()).write(verdict.getString("seed_item"), ByteArray(32) { 9 })


        return registration to data
    }

    // KR-REQ-16.15: a challenge the receiver cannot post is asked again by the scheduler, and the
    // registration is answered once the gateway is there.
    @Test
    fun aChallengeThatCouldNotBePostedIsAskedAgainByTheSchedulerAndThenAnswered() {
        val free = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val origin = "http://127.0.0.1:$free"
        val (registration, data) = pendingChallenge(origin)
        deliver(data)
        // Nothing is listening, so the post does not get there: the receiver leaves the record
        // pending and hands the answer to the scheduler.
        val scheduled =
            until(30) {
                WorkManager.getInstance(context)
                    .getWorkInfosByTag(ChallengeWorker::class.java.name)
                    .get()
                    .any { it.state == WorkInfo.State.ENQUEUED || it.state == WorkInfo.State.RUNNING }
            }
        assertTrue("the answer that did not get there is with the scheduler", scheduled)
        assertEquals(
            "pending",
            JSONObject(PushStores.pending(noBackup).read(System.currentTimeMillis())!!).getString("state")
        )

        // The gateway comes up, and the scheduler's next try is answered.
        Gateway(free).use { gateway ->
            gateway.start()
            val answered =
                until(180) {
                    JSONObject(PushStores.pending(noBackup).read(System.currentTimeMillis())!!)
                        .getString("state") == "answered"
                }
            assertTrue("the scheduler's retry was taken by the gateway", answered)
            val posted = gateway.body.get()
            assertNotNull("the gateway was given the answer", posted)
            val request = JSONObject(posted!!)
            // The signed request carries the answer to this registration, and nothing else.
            val answer =
                request.getJSONObject("body").getJSONObject("installation_register").getJSONObject("request")
                    .getJSONObject("answer").getJSONObject("answer").getJSONObject("payload")
            assertEquals(registration, answer.getString("registration_id"))
        }
    }

    // KR-REQ-16.15: the scheduler holds the answer's safety net by the time the answer is posted, so
    // a process the system ends in the middle of the post leaves a try behind; once the gateway has
    // taken the answer the safety net is taken back.
    @Test
    fun theSchedulerHoldsTheAnswersSafetyNetWhenItIsPostedAndLetsItGoOnceTheGatewayTakesIt() {
        val free = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val (registration, data) = pendingChallenge("http://127.0.0.1:$free")
        val held = AtomicReference<Boolean?>(null)
        fun net() =
            WorkManager.getInstance(context)
                .getWorkInfosByTag(ChallengeWorker::class.java.name)
                .get()
                .any { it.state == WorkInfo.State.ENQUEUED || it.state == WorkInfo.State.RUNNING }
        Gateway(free) { held.set(net()) }.use { gateway ->
            gateway.start()
            deliver(data)
            val answered =
                until(60) {
                    JSONObject(PushStores.pending(noBackup).read(System.currentTimeMillis())!!)
                        .getString("state") == "answered"
                }
            assertTrue("the gateway took the answer of $registration", answered)
            assertEquals("the safety net was held when the answer was posted", true, held.get())
            assertTrue("the safety net was taken back once the answer was taken", until(30) { !net() })
        }
    }
}
