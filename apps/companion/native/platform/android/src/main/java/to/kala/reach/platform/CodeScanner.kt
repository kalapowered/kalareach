package to.kala.reach.platform

import android.app.Dialog
import android.content.Context
import android.content.res.Resources
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.os.SystemClock
import android.util.Size
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import to.kala.reach.companion.mobile.QrDecoder

/** What reading a code came to. */
sealed class ScanOutcome {
    /** The text of the code. It holds an invitation's secret, so printing one never shows it. */
    class Text(val text: String) : ScanOutcome() {
        override fun toString(): String = "Text(..)"
    }

    /** The person closed the scanner, or the application stopped being in front. */
    object Cancelled : ScanOutcome()

    /** The camera is not allowed to this application. */
    object CameraDenied : ScanOutcome()
}

/**
 * The full-screen scanner: the camera behind a rounded square, a hint above it, Cancel at the top
 * left and a torch control when the device has a torch.
 *
 * A frame is read for a QR code a few times a second, which is as fast as a person can hold a code
 * up, and the first text read ends the scan. The scanner has no moving decoration: it says nothing
 * the preview does not. When it reads a code the outline takes the accent colour and the scanner
 * closes a moment later, and TalkBack says the code was found. What the camera sees is kept out of
 * the recents screen's picture and out of screenshots (the window is secure), and the scan ends
 * when the application stops being in front. It answers its caller once.
 */
class CodeScanner(
    private val activity: ComponentActivity,
    private val done: (ScanOutcome) -> Unit,
) {
    private val density = activity.resources.displayMetrics.density
    private val dialog = Dialog(activity, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
    private val analysis: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "kr-scanner-frames").apply { isDaemon = true }
    }
    private val preview = PreviewView(activity)
    private val outline = OutlineView(activity)
    private var provider: ProcessCameraProvider? = null
    private var camera: Camera? = null
    private var finished = false
    private var found = false
    private var lastRead = 0L

    private val pausing = LifecycleEventObserver { _, event ->
        if (event == Lifecycle.Event.ON_PAUSE) finish(ScanOutcome.Cancelled)
    }

    /** Shows the scanner and starts the camera. */
    fun show() {
        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        dialog.setContentView(layout())
        // The system's back gesture closes the scanner like Cancel does.
        dialog.setOnCancelListener { finish(ScanOutcome.Cancelled) }
        dialog.show()
        activity.lifecycle.addObserver(pausing)
        val future = ProcessCameraProvider.getInstance(activity)
        future.addListener(
            {
                if (finished) return@addListener
                try {
                    bind(future.get())
                } catch (failure: Exception) {
                    finish(ScanOutcome.CameraDenied)
                }
            },
            ContextCompat.getMainExecutor(activity),
        )
    }

    /** Ends the scan with a cancel, when it has not ended already. */
    fun cancel() = finish(ScanOutcome.Cancelled)

    private fun bind(cameraProvider: ProcessCameraProvider) {
        provider = cameraProvider
        val view = Preview.Builder().build().also { it.setSurfaceProvider(preview.surfaceProvider) }
        // A host's direct invitation is a version-23 code, 109 modules wide: it needs more
        // than the default analysis resolution to be read from a hand's length.
        val selector = ResolutionSelector.Builder()
            .setResolutionStrategy(
                ResolutionStrategy(Size(1920, 1080), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER),
            )
            .build()
        val frames = ImageAnalysis.Builder()
            .setResolutionSelector(selector)
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build()
        frames.setAnalyzer(analysis) { frame -> analyse(frame) }
        cameraProvider.unbindAll()
        camera = cameraProvider.bindToLifecycle(activity, CameraSelector.DEFAULT_BACK_CAMERA, view, frames)
    }

    private fun analyse(frame: ImageProxy) {
        try {
            val now = SystemClock.elapsedRealtime()
            if (found || now - lastRead < READ_EVERY_MS) return
            lastRead = now
            val plane = frame.planes[0]
            val width = frame.width
            val height = frame.height
            val rows = plane.rowStride
            val source = plane.buffer
            // The plane's rows may be padded; the decoder takes them packed.
            val packed = ByteArray(width * height)
            for (row in 0 until height) {
                source.position(row * rows)
                source.get(packed, row * width, width)
            }
            val text = QrDecoder.text(packed, width, height) ?: return
            activity.runOnUiThread { read(text) }
        } finally {
            frame.close()
        }
    }

    /** A code was read: say so, and close once the outline has shown it. */
    private fun read(text: String) {
        if (found || finished) return
        found = true
        outline.accent()
        outline.announceForAccessibility("Code found")
        outline.postDelayed({ finish(ScanOutcome.Text(text)) }, CLOSE_AFTER_MS)
    }

    /** Ends the scan once, whichever of the person, a code or the system ends it first. */
    private fun finish(outcome: ScanOutcome) {
        if (finished) return
        finished = true
        activity.lifecycle.removeObserver(pausing)
        camera?.cameraControl?.enableTorch(false)
        provider?.unbindAll()
        analysis.shutdown()
        dialog.setOnCancelListener(null)
        dialog.dismiss()
        done(outcome)
    }

    // MARK: The screen

    private fun layout(): View {
        val root = FrameLayout(activity)
        root.setBackgroundColor(Color.BLACK)
        root.addView(preview, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        root.addView(outline, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))

        val hint = TextView(activity).apply {
            text = "Point the camera at the code on your host"
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            gravity = Gravity.CENTER
            setPadding(px(24), 0, px(24), 0)
        }
        root.addView(
            hint,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.CENTER_HORIZONTAL),
        )
        // The hint sits above the square, which is centred and 70% of the shorter side.
        root.viewTreeObserver.addOnGlobalLayoutListener {
            val side = minOf(root.width, root.height) * OUTLINE_SHARE
            hint.translationY = (root.height - side) / 2f - hint.height - px(24)
        }

        val cancel = button("Cancel").apply { setOnClickListener { finish(ScanOutcome.Cancelled) } }
        root.addView(cancel, FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, px(48), Gravity.TOP or Gravity.START))

        // The torch control appears once the camera is bound and says it has a torch.
        val torch = button("Torch").apply {
            visibility = View.GONE
            contentDescription = "Torch, off"
        }
        root.addView(torch, FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, px(48), Gravity.TOP or Gravity.END))
        var torchOn = false
        torch.setOnClickListener {
            torchOn = !torchOn
            camera?.cameraControl?.enableTorch(torchOn)
            torch.text = if (torchOn) "Torch on" else "Torch"
            torch.contentDescription = if (torchOn) "Torch, on" else "Torch, off"
        }
        preview.viewTreeObserver.addOnGlobalLayoutListener {
            if (camera?.cameraInfo?.hasFlashUnit() == true) torch.visibility = View.VISIBLE
        }

        ViewCompat.setOnApplyWindowInsetsListener(root) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            (cancel.layoutParams as FrameLayout.LayoutParams).setMargins(px(8) + bars.left, bars.top + px(8), 0, 0)
            (torch.layoutParams as FrameLayout.LayoutParams).setMargins(0, bars.top + px(8), px(8) + bars.right, 0)
            insets
        }
        return root
    }

    private fun button(label: String): Button = Button(activity).apply {
        text = label
        isAllCaps = false
        setTextColor(Color.WHITE)
        setBackgroundColor(Color.TRANSPARENT)
        minHeight = px(48)
        minimumHeight = px(48)
        minWidth = px(48)
        minimumWidth = px(48)
    }

    private fun px(dp: Int): Int = (dp * density).toInt()

    /** The rounded square the code is held in, white until a code is read and then the accent. */
    private class OutlineView(context: Context) : View(context) {
        private val stroke = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeWidth = 4f * Resources.getSystem().displayMetrics.density
            color = Color.WHITE
        }

        init {
            importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
        }

        fun accent() {
            val value = TypedValue()
            stroke.color = if (context.theme.resolveAttribute(android.R.attr.colorAccent, value, true)) value.data else ACCENT
            invalidate()
        }

        override fun onDraw(canvas: Canvas) {
            val side = minOf(width, height) * OUTLINE_SHARE
            val left = (width - side) / 2f
            val top = (height - side) / 2f
            val radius = 24f * Resources.getSystem().displayMetrics.density
            canvas.drawRoundRect(RectF(left, top, left + side, top + side), radius, radius, stroke)
        }
    }

    private companion object {
        /** A frame is read at most this often, in milliseconds. */
        const val READ_EVERY_MS = 120L

        /** The scanner closes this long after a code was read, in milliseconds. */
        const val CLOSE_AFTER_MS = 150L

        /** The square's side as a share of the screen's shorter side. */
        const val OUTLINE_SHARE = 0.7f

        const val ACCENT = 0xFF3DDC84.toInt()
    }
}
