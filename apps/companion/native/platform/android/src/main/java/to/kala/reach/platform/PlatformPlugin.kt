package to.kala.reach.platform

import android.app.Activity
import android.content.Intent
import android.content.pm.verify.domain.DomainVerificationManager
import android.content.pm.verify.domain.DomainVerificationUserState
import android.net.Uri
import android.os.Build
import android.util.Base64
import android.util.Log
import android.webkit.WebView
import androidx.activity.result.ActivityResult
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import to.kala.reach.companion.mobile.SecretFiles

@InvokeArg
class SessionArguments {
    lateinit var attempt: String
    lateinit var url: String
    lateinit var mode: String
    lateinit var httpsHost: String
    lateinit var httpsPath: String
    lateinit var scheme: String
}

@InvokeArg
class AttemptArguments {
    lateinit var attempt: String
}

@InvokeArg
class NamedArguments {
    lateinit var name: String
}

@InvokeArg
class WrittenArguments {
    lateinit var name: String
    lateinit var value: String
}

/**
 * The Android half of the companion's platform plugin.
 *
 * It reports facts and carries out requests; the plugin's Rust crate decides what the facts mean.
 * A sign-in runs in the default browser's Auth Tab, which returns the answer once as an activity
 * result, or in a Custom Tab, whose answer arrives as a verified link the system hands this
 * activity. Every result carries the attempt it belongs to, so a late one from an earlier attempt
 * is told apart. Secrets are files sealed under a Keystore key.
 */
@TauriPlugin
class PlatformPlugin(private val activity: Activity) : Plugin(activity) {
    private val secrets by lazy {
        SecretFiles(File(activity.noBackupFilesDir, "secrets"), KeystoreSealer())
    }

    private var attempt: String? = null
    private var waiting: Invoke? = null
    private val queued = ArrayDeque<JSObject>()

    override fun load(webView: WebView) {
        // Without its start the verifier refuses every certificate, so an HTTPS request fails and
        // says so; everything that needs no request keeps working, rather than the application
        // failing to start. The log says which happened.
        try {
            TlsVerifier.start(activity.applicationContext)
            Log.i(LOG_TAG, "the platform TLS verifier has the application context")
        } catch (failure: RuntimeException) {
            Log.e(LOG_TAG, "the platform TLS verifier could not start", failure)
        }
    }

    @Command
    fun capabilities(invoke: Invoke) {
        val facts = JSObject()
        facts.put("sdk", Build.VERSION.SDK_INT)
        val browser = CustomTabsClient.getPackageName(activity, null)
        facts.put("customTabs", browser != null)
        facts.put(
            "authTab",
            browser != null && CustomTabsClient.isAuthTabSupported(activity, browser),
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val state = activity.getSystemService(DomainVerificationManager::class.java)
                ?.getDomainVerificationUserState(activity.packageName)
            facts.put(
                "linkVerified",
                state?.hostToStateMap?.get(CALLBACK_HOST) ==
                    DomainVerificationUserState.DOMAIN_STATE_VERIFIED,
            )
            facts.put("linkHandlingAllowed", state?.isLinkHandlingAllowed == true)
        }
        invoke.resolve(facts)
    }

    @Command
    fun authenticate(invoke: Invoke) {
        val arguments = invoke.parseArgs(SessionArguments::class.java)
        attempt?.let { earlier -> deliver(event(earlier, "cancelled")) }
        attempt = arguments.attempt
        queued.clear()
        waiting = invoke
        val address = Uri.parse(arguments.url)
        when (arguments.mode) {
            "authTab" -> {
                // What `AuthTabIntent.launch` puts on the intent, started through the launcher the
                // activity registered when it was created.
                val tab = AuthTabIntent.Builder().setEphemeralBrowsingEnabled(true).build()
                tab.intent.data = address
                tab.intent.putExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_HOST, arguments.httpsHost)
                tab.intent.putExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_PATH, arguments.httpsPath)
                startActivityForResult(invoke, tab.intent, "authTabResult")
            }
            "customTab" -> {
                val tab = CustomTabsIntent.Builder().build()
                tab.intent.data = address
                startActivityForResult(invoke, tab.intent, "customTabClosed")
            }
            else -> {
                attempt = null
                waiting = null
                invoke.reject("a sign-in here runs in an Auth Tab or a Custom Tab")
            }
        }
    }

    @ActivityCallback
    fun authTabResult(invoke: Invoke, result: ActivityResult) {
        val current = attempt ?: return
        val answer = event(current, "result")
        answer.put("code", result.resultCode)
        result.data?.data?.let { answer.put("url", it.toString()) }
        deliver(answer)
        finish()
    }

    @ActivityCallback
    fun customTabClosed(invoke: Invoke, result: ActivityResult) {
        val current = attempt ?: return
        deliver(event(current, "closed"))
    }

    override fun onNewIntent(intent: Intent) {
        val data = intent.data ?: return
        if (intent.action != Intent.ACTION_VIEW || data.scheme != "https" ||
            data.host != CALLBACK_HOST || data.path != CALLBACK_PATH
        ) {
            return
        }
        val current = attempt ?: return
        val link = event(current, "link")
        link.put("url", data.toString())
        deliver(link)
    }

    @Command
    fun nextEvent(invoke: Invoke) {
        val arguments = invoke.parseArgs(AttemptArguments::class.java)
        if (arguments.attempt != attempt) {
            invoke.resolve(event(arguments.attempt, "cancelled"))
            return
        }
        waiting = invoke
        queued.removeFirstOrNull()?.let { deliver(it) }
    }

    @Command
    fun cancel(invoke: Invoke) {
        val arguments = invoke.parseArgs(AttemptArguments::class.java)
        if (arguments.attempt == attempt) {
            deliver(event(arguments.attempt, "cancelled"))
            finish()
        }
        invoke.resolve(done())
    }

    @Command
    fun secretGet(invoke: Invoke) {
        val arguments = invoke.parseArgs(NamedArguments::class.java)
        try {
            val answer = JSObject()
            secrets.read(arguments.name)?.let {
                answer.put("value", Base64.encodeToString(it, Base64.NO_WRAP))
            }
            invoke.resolve(answer)
        } catch (failure: Exception) {
            invoke.reject("the stored item could not be read")
        }
    }

    @Command
    fun secretSet(invoke: Invoke) {
        val arguments = invoke.parseArgs(WrittenArguments::class.java)
        try {
            secrets.write(arguments.name, Base64.decode(arguments.value, Base64.NO_WRAP))
            invoke.resolve(done())
        } catch (failure: Exception) {
            invoke.reject("the item could not be kept")
        }
    }

    @Command
    fun secretDelete(invoke: Invoke) {
        val arguments = invoke.parseArgs(NamedArguments::class.java)
        try {
            secrets.delete(arguments.name)
            invoke.resolve(done())
        } catch (failure: Exception) {
            invoke.reject("the item could not be removed")
        }
    }

    /** Answers the waiting call, or keeps the event for the next one. */
    private fun deliver(answer: JSObject) {
        val invoke = waiting
        if (invoke == null) {
            queued.addLast(answer)
            return
        }
        waiting = null
        invoke.resolve(answer)
    }

    private fun finish() {
        attempt = null
        queued.clear()
    }

    private fun event(attempt: String, kind: String): JSObject {
        val answer = JSObject()
        answer.put("attempt", attempt)
        answer.put("kind", kind)
        return answer
    }

    private fun done(): JSObject {
        val answer = JSObject()
        answer.put("done", true)
        return answer
    }

    private companion object {
        const val LOG_TAG = "KalaReach"
        const val CALLBACK_HOST = "reach.kala.to"
        const val CALLBACK_PATH = "/app/oauth/callback"
    }
}
