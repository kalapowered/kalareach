package to.kala.reach.platform

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.verify.domain.DomainVerificationManager
import android.content.pm.verify.domain.DomainVerificationUserState
import android.net.Uri
import android.os.Build
import android.util.Base64
import android.util.Log
import android.webkit.WebView
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import to.kala.reach.companion.mobile.SecretFiles
import to.kala.reach.companion.mobile.SignInSession

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
 * A sign-in runs in the default browser's Auth Tab, which returns the answer once as the result of
 * the launch that opened it, or in a Custom Tab, whose answer arrives as a verified link the
 * system hands this activity. [SignInSession] decides which of those belongs to the attempt under
 * way. Every result carries the attempt it belongs to. Secrets are files sealed under a Keystore
 * key.
 */
@TauriPlugin
class PlatformPlugin(private val activity: Activity) : Plugin(activity) {
    private val secrets by lazy {
        SecretFiles(File(activity.noBackupFilesDir, "secrets"), KeystoreSealer())
    }

    private val session = SignInSession()
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
        val mode = when (arguments.mode) {
            "authTab" -> SignInSession.Mode.AUTH_TAB
            "customTab" -> SignInSession.Mode.CUSTOM_TAB
            else -> {
                invoke.reject("a sign-in here runs in an Auth Tab or a Custom Tab")
                return
            }
        }
        session.begin(arguments.attempt, mode)?.let { earlier -> deliver(event(earlier, "cancelled")) }
        queued.clear()
        waiting = invoke
        val address = Uri.parse(arguments.url)
        try {
            when (mode) {
                SignInSession.Mode.AUTH_TAB -> {
                    // What `AuthTabIntent.launch` puts on the intent, launched through a launcher of
                    // this attempt's own, so a tab an earlier attempt left open cannot answer it.
                    val tab = AuthTabIntent.Builder().setEphemeralBrowsingEnabled(true).build()
                    tab.intent.data = address
                    tab.intent.putExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_HOST, arguments.httpsHost)
                    tab.intent.putExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_PATH, arguments.httpsPath)
                    launchAuthTab(arguments.attempt, tab.intent)
                }
                SignInSession.Mode.CUSTOM_TAB ->
                    CustomTabsIntent.Builder().build().launchUrl(activity, address)
            }
        } catch (failure: ActivityNotFoundException) {
            end(arguments.attempt, event(arguments.attempt, "failed"))
        }
    }

    private fun launchAuthTab(launchedFor: String, intent: Intent) {
        val registry = (activity as ComponentActivity).activityResultRegistry
        lateinit var launcher: ActivityResultLauncher<Intent>
        launcher = registry.register(
            "to.kala.reach.platform.sign-in.$launchedFor",
            ActivityResultContracts.StartActivityForResult(),
        ) { result ->
            launcher.unregister()
            if (!session.result(launchedFor)) return@register
            val answer = event(launchedFor, "result")
            answer.put("code", result.resultCode)
            result.data?.data?.let { answer.put("url", it.toString()) }
            end(launchedFor, answer)
        }
        launcher.launch(intent)
    }

    override fun onNewIntent(intent: Intent) {
        val data = intent.data ?: return
        if (intent.action != Intent.ACTION_VIEW || data.scheme != "https" ||
            data.host != CALLBACK_HOST || data.path != CALLBACK_PATH
        ) {
            return
        }
        // Only a Custom Tab attempt takes its answer as a link; an Auth Tab's comes from its launch.
        val current = session.link() ?: return
        val link = event(current, "link")
        link.put("url", data.toString())
        deliver(link)
    }

    @Command
    fun nextEvent(invoke: Invoke) {
        val arguments = invoke.parseArgs(AttemptArguments::class.java)
        if (arguments.attempt != session.current()) {
            invoke.resolve(event(arguments.attempt, "cancelled"))
            return
        }
        waiting = invoke
        queued.removeFirstOrNull()?.let { deliver(it) }
    }

    @Command
    fun cancel(invoke: Invoke) {
        val arguments = invoke.parseArgs(AttemptArguments::class.java)
        if (arguments.attempt == session.current()) {
            end(arguments.attempt, event(arguments.attempt, "cancelled"))
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

    /** Ends [attempt] with [answer]: the waiting call is answered, and nothing of it is kept. */
    private fun end(attempt: String, answer: JSObject) {
        if (!session.ended(attempt)) return
        deliver(answer)
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
