package to.kala.reach.platform

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.verify.domain.DomainVerificationManager
import android.content.pm.verify.domain.DomainVerificationUserState
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Base64
import android.util.Log
import android.view.WindowManager
import android.webkit.WebView
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.FragmentActivity
import androidx.core.app.NotificationManagerCompat
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.PermissionState
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import org.json.JSONObject
import java.util.concurrent.Executors
import to.kala.reach.companion.mobile.CallBridge
import to.kala.reach.companion.mobile.CallBridgeHolder
import to.kala.reach.companion.mobile.CallNews
import to.kala.reach.companion.mobile.CallOpenings
import to.kala.reach.companion.mobile.CallRefused
import to.kala.reach.companion.mobile.CallWire
import to.kala.reach.companion.mobile.CurrentTokenHolder
import to.kala.reach.companion.mobile.NotificationRoute
import to.kala.reach.companion.mobile.OwnerAuthenticators
import to.kala.reach.companion.mobile.PreviewKeySet
import to.kala.reach.companion.mobile.PushStores
import to.kala.reach.companion.mobile.PushToken
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
class PresenceArguments {
    lateinit var reason: String
    var withinMs: Long = 0
}

@InvokeArg
class AttemptArguments {
    lateinit var attempt: String
}

@InvokeArg
class KeepAwakeArguments {
    var on: Boolean = false
}

@InvokeArg
class CallOpenArguments {
    lateinit var call: String
    lateinit var events: Channel
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
@TauriPlugin(
    permissions = [
        Permission(strings = [Manifest.permission.RECORD_AUDIO], alias = "microphone"),
        Permission(strings = [Manifest.permission.CAMERA], alias = "camera"),
        Permission(strings = [Manifest.permission.POST_NOTIFICATIONS], alias = "notifications"),
    ],
)
class PlatformPlugin(private val activity: Activity) : Plugin(activity) {
    /**
     * Where a command to the voice call waits for the media engine. A command arrives on the
     * application's main thread, which must not be held, and a stop must be able to run while an
     * offer is still being made, so each command has a thread of its own.
     */
    private val calls = Executors.newCachedThreadPool { task ->
        Thread(task, "kr-call-command").apply { isDaemon = true }
    }

    /**
     * The opening of a call that waits for the person's answer to the permission question, with the
     * request that is waiting. The platform keeps one callback for the answer, so there is at most one.
     */
    private class Asking(val opening: CallOpenings.Opening, val invoke: Invoke)

    private val askingLock = Any()
    private var asking: Asking? = null
    private val deadlines = Handler(Looper.getMainLooper())

    private val secrets by lazy {
        SecretFiles(File(activity.noBackupFilesDir, "secrets"), KeystoreSealer())
    }

    private val session = SignInSession()
    private var waiting: Invoke? = null
    private val queued = ArrayDeque<JSObject>()

    override fun load(webView: WebView) {
        // The screen a tap on a notification opened the application on, if it did: kept until the
        // application asks, which is once.
        activity.intent?.getStringExtra(NotificationRoute.EXTRA)?.let {
            route = it
            activity.intent.removeExtra(NotificationRoute.EXTRA)
        }
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

    // Reading a QR code. The scanner is shown over the application, one at a time, and answers once.

    private var scanning: CodeScanner? = null

    /** Which sources this device reads a code from: its camera, when it has one. */
    @Command
    fun scanSources(invoke: Invoke) {
        val camera = activity.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
        invoke.resolve(JSObject().put("camera", camera).put("photo", false))
    }

    /**
     * What the system says of this application's use of the camera: `granted`, `denied` when the
     * person refused it for good (the system asks no more), and `prompt` otherwise. The attachment
     * picker asks this before it offers the camera, because the WebView's own request for the
     * camera is refused without a word once the system asks no more.
     */
    @Command
    fun cameraAccess(invoke: Invoke) {
        val access = when (getPermissionState("camera")) {
            PermissionState.GRANTED -> "granted"
            PermissionState.DENIED -> "denied"
            else -> "prompt"
        }
        invoke.resolve(JSObject().put("access", access))
    }

    /** Shows the scanner, after the camera is allowed, and answers when it closes. */
    @Command
    fun scanCamera(invoke: Invoke) {
        // One at a time: a newer request ends the older one, which answers with a cancel.
        scanning?.cancel()
        if (getPermissionState("camera") == PermissionState.GRANTED) {
            showScanner(invoke)
        } else {
            requestPermissionForAlias("camera", invoke, "cameraAnswered")
        }
    }

    @PermissionCallback
    fun cameraAnswered(invoke: Invoke) {
        if (getPermissionState("camera") == PermissionState.GRANTED) {
            showScanner(invoke)
        } else {
            invoke.resolve(scanAnswer(ScanOutcome.CameraDenied))
        }
    }

    /** This device offers no picker: the camera is its one way to read a code. */
    @Command
    fun scanPhoto(invoke: Invoke) {
        invoke.reject("this device offers no picker for a code")
    }

    /**
     * Keeps the screen on while a value the person compares with another device's shows, and lets
     * it sleep again afterwards.
     */
    @Command
    fun keepAwake(invoke: Invoke) {
        val arguments = invoke.parseArgs(KeepAwakeArguments::class.java)
        activity.runOnUiThread {
            val window = activity.window
            if (arguments.on) {
                window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            }
            invoke.resolve(done())
        }
    }

    // The owner's presence. The system draws the prompt; one at a time. A request that comes while one
    // is up is not confirmed, and the one that is up is left alone: the library keeps one callback for
    // every prompt of an activity, so a second prompt would take the first one's answer.

    private var ownerPrompt: OwnerPrompt? = null

    /** Which ceremony this phone offers its owner: a strong biometric, the screen lock, or none. */
    @Command
    fun presenceKind(invoke: Invoke) {
        val host = activity as? FragmentActivity
        val kind = if (host == null) "none" else OwnerAuthenticators.kind(OwnerPrompt.ask(host))
        invoke.resolve(JSObject().put("kind", kind))
    }

    /** Runs the ceremony for the words it is given, inside the time it is given, and answers once. */
    @Command
    fun presence(invoke: Invoke) {
        val arguments = invoke.parseArgs(PresenceArguments::class.java)
        activity.runOnUiThread {
            if (ownerPrompt != null) {
                invoke.resolve(JSObject().put("outcome", "not_confirmed"))
                return@runOnUiThread
            }
            val host = activity as? FragmentActivity
            val ask = if (host == null) null else OwnerPrompt.ask(host)
            if (host == null || ask == null) {
                invoke.resolve(JSObject().put("outcome", "unavailable"))
                return@runOnUiThread
            }
            val prompt = OwnerPrompt(host, ask, arguments.reason, arguments.withinMs) { outcome ->
                ownerPrompt = null
                invoke.resolve(JSObject().put("outcome", outcome))
            }
            ownerPrompt = prompt
            prompt.show()
        }
    }

    /** Opens this application's own page in the system's settings, where the camera is allowed. */
    @Command
    fun openSettings(invoke: Invoke) {
        try {
            val page = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", activity.packageName, null))
            page.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(page)
            invoke.resolve(JSObject().put("done", true))
        } catch (failure: ActivityNotFoundException) {
            invoke.reject("the settings page could not be opened")
        }
    }

    // Notifications. What only the platform can say or do: whether the person allowed them, the
    // token the provider gave this installation, the record of the registration being waited for
    // (which the receiver reads without the application running), the limited key store, and the
    // screen a tap on a notification opened the application on.

    private var route: String? = null

    private val noBackup: File
        get() = activity.noBackupFilesDir

    /** Where the person's answer stands: `granted`, `denied` or `unknown`, read without asking. */
    private fun notificationState(): String {
        val enabled = NotificationManagerCompat.from(activity).areNotificationsEnabled()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return if (enabled) "granted" else "denied"
        }
        return when (getPermissionState("notifications")) {
            PermissionState.GRANTED -> if (enabled) "granted" else "denied"
            PermissionState.DENIED -> "denied"
            else -> "unknown"
        }
    }

    @Command
    fun pushPermission(invoke: Invoke) {
        invoke.resolve(JSObject().put("state", notificationState()))
    }

    /** Asks the person when they have not answered, and answers once they have. */
    @Command
    fun pushAskPermission(invoke: Invoke) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && notificationState() == "unknown") {
            requestPermissionForAlias("notifications", invoke, "notificationsAnswered")
        } else {
            invoke.resolve(JSObject().put("state", notificationState()))
        }
    }

    @PermissionCallback
    fun notificationsAnswered(invoke: Invoke) {
        invoke.resolve(JSObject().put("state", notificationState()))
    }

    /**
     * The registration token the provider gave this installation, when it has given one: the
     * provider's current token when it answers within a short time, and the one the messaging
     * service stored otherwise. The wait is off the thread the command arrived on.
     */
    @Command
    fun pushToken(invoke: Invoke) {
        val preferences = activity.getSharedPreferences(PushStores.TOKEN_STORE, Context.MODE_PRIVATE)
        Thread {
            val token = PushToken.read(
                stored = { preferences.getString(PushStores.TOKEN_KEY, null) },
                source = CurrentTokenHolder.source,
                keep = { current ->
                    preferences.edit()
                        .putString(PushStores.TOKEN_KEY, current)
                        .putLong(PushStores.TOKEN_AT_KEY, System.currentTimeMillis())
                        .commit()
                }
            )
            invoke.resolve(JSObject().put("token", token ?: JSONObject.NULL))
        }.start()
    }

    @Command
    fun pushPendingSet(invoke: Invoke) {
        val record = invoke.getArgs().optJSONObject("record")
        if (record == null) {
            invoke.reject("a pending registration is a record")
            return
        }
        try {
            PushStores.pending(noBackup).write(record.toString())
            invoke.resolve(done())
        } catch (failure: Exception) {
            invoke.reject("the pending registration could not be kept")
        }
    }

    @Command
    fun pushPendingGet(invoke: Invoke) {
        try {
            val record = PushStores.pending(noBackup).read(System.currentTimeMillis())
            invoke.resolve(JSObject().put("record", record?.let { JSObject(it) } ?: JSONObject.NULL))
        } catch (failure: Exception) {
            invoke.reject("the pending registration could not be read")
        }
    }

    @Command
    fun pushPendingClear(invoke: Invoke) {
        try {
            PushStores.pending(noBackup).clear()
            invoke.resolve(done())
        } catch (failure: Exception) {
            invoke.reject("the pending registration could not be removed")
        }
    }

    /**
     * Makes the limited store hold exactly the keys the application hands over: the device's
     * preview seeds and the public key of each host that may seal a preview to them. A set that is
     * not made of keys is refused and the store is left as it was.
     */
    @Command
    fun pushPreviewKeys(invoke: Invoke) {
        val keys = PreviewKeySet.parse(invoke.getArgs().toString())
        if (keys == null) {
            invoke.reject("the preview keys are not keys")
            return
        }
        try {
            PushStores.limited(noBackup, KeystoreSealer()).replace(keys)
            invoke.resolve(done())
        } catch (failure: Exception) {
            invoke.reject("the preview keys could not be filed")
        }
    }

    /** The screen a tap on a notification opened the application on, once. */
    @Command
    fun pushRoute(invoke: Invoke) {
        val taken = route
        route = null
        invoke.resolve(JSObject().put("route", taken ?: JSONObject.NULL))
    }

    private fun showScanner(invoke: Invoke) {
        val host = activity as? ComponentActivity
        if (host == null) {
            invoke.reject("there is no screen to show the scanner on")
            return
        }
        val scanner = CodeScanner(host) { outcome ->
            scanning = null
            invoke.resolve(scanAnswer(outcome))
        }
        scanning = scanner
        scanner.show()
    }

    /** The one answer a request to read a code gets, in the words the plugin's Rust half reads. */
    private fun scanAnswer(outcome: ScanOutcome): JSObject = when (outcome) {
        is ScanOutcome.Text -> JSObject().put("outcome", "text").put("text", outcome.text)
        ScanOutcome.Cancelled -> JSObject().put("outcome", "cancelled")
        ScanOutcome.CameraDenied -> JSObject().put("outcome", "camera_denied")
        ScanOutcome.Failed -> JSObject().put("outcome", "failed")
    }

    // The voice call is the application's own, in a module this library cannot see: the application
    // registers its bridge at start, and each command is handed to it off the arriving thread.

    @Command
    fun callOpen(invoke: Invoke) {
        // One opening at a time: it may wait on the person's answer to a permission, and the
        // platform keeps one answer for that question.
        val opening = CallBridgeHolder.openings.reserve()
        if (opening == null) {
            invoke.reject("a call is already being opened", CallRefused.ALREADY_RUNNING)
            return
        }
        guarded(opening, invoke) {
            // The microphone is asked for here, and notifications from Android 13, before anything
            // is made. Refusing notifications does not refuse the call: it is reported, and Rust
            // decides.
            val wanted = buildList {
                if (getPermissionState("microphone") != PermissionState.GRANTED) add("microphone")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    getPermissionState("notifications") != PermissionState.GRANTED
                ) {
                    add("notifications")
                }
            }
            if (wanted.isEmpty()) {
                openCall(invoke, opening)
            } else {
                // The answer may never come (the activity that asked can be gone), and Rust waits
                // for this one: when the time is up the opening goes on with what is allowed then.
                opening.asks()
                synchronized(askingLock) { asking = Asking(opening, invoke) }
                deadlines.postDelayed({ goOnWithAsking(opening) }, ASKING_DEADLINE_MS)
                requestPermissionForAliases(wanted.toTypedArray(), invoke, "callPermissionsAnswered")
            }
        }
    }

    /**
     * Runs one step of an opening. A step that throws ends the opening, so that the next one is
     * not refused for ever, and answers its request, unless something has answered it already.
     */
    private fun guarded(opening: CallOpenings.Opening, invoke: Invoke, step: () -> Unit) {
        try {
            step()
        } catch (failure: Throwable) {
            synchronized(askingLock) { if (asking?.opening === opening) asking = null }
            if (opening.end()) invoke.reject(failure.message ?: failure.toString(), "engine")
        }
    }

    /**
     * The question was answered, or the time for it is up: the opening that waits goes on with what
     * is allowed now, once, whichever of the two comes first. The request it answers is the one
     * that waits, not the one the platform names: the platform keeps one callback, and a request it
     * names may be one that was answered already.
     */
    private fun goOnWithAsking(only: CallOpenings.Opening?) {
        val waiting = synchronized(askingLock) {
            asking?.takeIf { only == null || it.opening === only }?.also { asking = null }
        } ?: return
        if (!waiting.opening.answered()) return
        guarded(waiting.opening, waiting.invoke) { openCall(waiting.invoke, waiting.opening) }
    }

    @PermissionCallback
    fun callPermissionsAnswered(invoke: Invoke) {
        goOnWithAsking(only = null)
    }

    private fun openCall(invoke: Invoke, opening: CallOpenings.Opening) {
        if (getPermissionState("microphone") != PermissionState.GRANTED) {
            if (opening.end()) invoke.reject("the microphone is not allowed", CallRefused.MICROPHONE_REFUSED)
            return
        }
        val arguments = try {
            invoke.parseArgs(CallOpenArguments::class.java)
        } catch (failure: Throwable) {
            if (opening.end()) invoke.reject(failure.message ?: failure.toString(), "engine")
            return
        }
        val notifications = NotificationManagerCompat.from(activity).areNotificationsEnabled()
        carryOut(invoke, afterwards = { opening.end() }) { bridge ->
            bridge.open(arguments.call, CallNews { frame -> arguments.events.send(JSObject(frame)) })
            CallWire.opened(notifications)
        }
    }

    @Command
    fun callOffer(invoke: Invoke) =
        carryOut(invoke) { bridge -> CallWire.offered(bridge.offer(CallWire.call(invoke.getRawArgs()))) }

    @Command
    fun callAccept(invoke: Invoke) =
        carryOut(invoke) { bridge ->
            val answer = CallWire.answer(invoke.getRawArgs())
            CallWire.answered(bridge.accept(answer.call, answer.sdp))
        }

    @Command
    fun callPermit(invoke: Invoke) =
        carryOut(invoke) { bridge ->
            val permit = CallWire.permit(invoke.getRawArgs())
            CallWire.permitted(bridge.permit(permit.call, permit.voiceSessionId, permit.closesAtEpochMs))
        }

    @Command
    fun callMute(invoke: Invoke) =
        carryOut(invoke) { bridge ->
            val mute = CallWire.mute(invoke.getRawArgs())
            bridge.setMuted(mute.call, mute.what, mute.muted)
            CallWire.nothing()
        }

    @Command
    fun callStop(invoke: Invoke) =
        carryOut(invoke) { bridge ->
            bridge.stop(CallWire.call(invoke.getRawArgs()))
            CallWire.nothing()
        }

    @Command
    fun callState(invoke: Invoke) = carryOut(invoke) { bridge -> CallWire.held(bridge.held()) }

    @Command
    fun callAlive(invoke: Invoke) =
        carryOut(invoke) { bridge -> CallWire.held(bridge.alive(CallWire.call(invoke.getRawArgs()))) }

    /**
     * Runs one command on the registered bridge and answers `invoke` with its JSON result, or with
     * why it could not, once whatever happens. `afterwards` runs before the answer is sent, so
     * whoever acts on the answer finds what `afterwards` released released.
     */
    private fun carryOut(invoke: Invoke, afterwards: () -> Unit = {}, command: (CallBridge) -> String) {
        val bridge = CallBridgeHolder.bridge
        if (bridge == null) {
            afterwards()
            invoke.reject("this build holds no voice call", "unavailable")
            return
        }
        calls.execute {
            var result: JSObject? = null
            var rejection: Pair<String, String>? = null
            try {
                result = JSObject(command(bridge))
            } catch (refused: CallRefused) {
                rejection = Pair(refused.message ?: refused.code, refused.code)
            } catch (failure: Throwable) {
                // Anything the command throws is an answer: Rust waits for one and has no deadline.
                rejection = Pair(failure.message ?: failure.toString(), "engine")
            }
            try {
                afterwards()
            } finally {
                if (rejection != null) invoke.reject(rejection.first, rejection.second) else invoke.resolve(result)
            }
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
        intent.getStringExtra(NotificationRoute.EXTRA)?.let {
            route = it
            intent.removeExtra(NotificationRoute.EXTRA)
        }
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

        /** How long an opening waits for the person's answer to the permission question. */
        const val ASKING_DEADLINE_MS = 120_000L

        const val CALLBACK_HOST = "reach.kala.to"
        const val CALLBACK_PATH = "/app/oauth/callback"
    }
}
