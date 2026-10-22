package to.kala.reach.companion.mobile

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Reads a QR code from a camera frame or from a picture, with ZXing.
 *
 * The text of a direct invitation's code holds the invitation's whole secret, so this is the one
 * place it is read, and what it answers goes no further than native code. A decoder judges nothing
 * about the text: whether it is a KalaReach invitation is the application's own decision, made in
 * Rust where the host's tests reach it.
 */
object QrDecoder {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        // A host's direct invitation is a version-23 code, 109 modules wide: it is worth
        // the time the thorough search takes, which a scanner that reads a few frames a second has.
        DecodeHintType.TRY_HARDER to true,
    )

    /**
     * The text of the first QR code in the luminance plane of a camera frame, which holds [width] ×
     * [height] bytes row after row, or null when it shows none.
     */
    fun text(luminance: ByteArray, width: Int, height: Int): String? {
        require(luminance.size >= width * height) { "the plane is smaller than the frame it names" }
        return read(BinaryBitmap(HybridBinarizer(PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false))))
    }

    /** The text of the first QR code in a picture of [width] × [height] ARGB pixels, or null. */
    fun text(pixels: IntArray, width: Int, height: Int): String? {
        require(pixels.size >= width * height) { "the pixels are fewer than the picture names" }
        return read(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(width, height, pixels))))
    }

    private fun read(bitmap: BinaryBitmap): String? =
        try {
            QRCodeReader().decode(bitmap, hints).text?.takeIf { it.isNotEmpty() }
        } catch (_: NotFoundException) {
            null
        } catch (_: com.google.zxing.ChecksumException) {
            null
        } catch (_: com.google.zxing.FormatException) {
            null
        } catch (_: RuntimeException) {
            // A frame the detector cannot make sense of is a frame with no code, and the next one is
            // read: a camera frame must never end the process.
            null
        }
}
