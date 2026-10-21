package to.kala.reach.companion.mobile

import java.awt.RenderingHints
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The pictures of the pairing fixtures' two QR codes, drawn as the host draws a code (low error
 * correction, a quiet zone of four modules), read back to the text the fixtures hold. The pictures
 * are the ones the host's own test holds equal to its drawing, so this is the phone's decoder
 * against what a host shows.
 */
class QrDecoderTest {
    private val fixtures = File(System.getProperty("kr.pairing.fixtures"))

    private fun text(mode: String): String =
        JSONObject(File(fixtures, "codes.json").readText()).getJSONObject("qr").getJSONObject(mode).getString("text")

    private fun picture(mode: String): BufferedImage = ImageIO.read(File(fixtures, "qr-$mode.png"))

    private fun pixels(image: BufferedImage): IntArray {
        val argb = IntArray(image.width * image.height)
        image.getRGB(0, 0, image.width, image.height, argb, 0, image.width)
        return argb
    }

    /** A camera's luminance plane of the picture, `side` pixels wide, as a phone holds it. */
    private fun frame(image: BufferedImage, side: Int): Triple<ByteArray, Int, Int> {
        val scaled = BufferedImage(side, side, BufferedImage.TYPE_BYTE_GRAY)
        val graphics = scaled.createGraphics()
        graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR)
        graphics.drawImage(image, 0, 0, side, side, null)
        graphics.dispose()
        val plane = ByteArray(side * side)
        scaled.raster.getDataElements(0, 0, side, side, plane)
        return Triple(plane, side, side)
    }

    @Test
    fun theHostsDirectInvitationReadsBackAsTheFixtureHoldsIt() {
        val image = picture("direct")
        assertEquals(text("direct"), QrDecoder.text(pixels(image), image.width, image.height))
    }

    @Test
    fun theHostsCodeInvitationReadsBackAsTheFixtureHoldsIt() {
        val image = picture("code")
        assertEquals(text("code"), QrDecoder.text(pixels(image), image.width, image.height))
    }

    /** A camera frame is far smaller than the picture: the largest code still reads at 1080 pixels. */
    @Test
    fun theLargestCodeReadsFromACameraFrame() {
        val (plane, width, height) = frame(picture("direct"), 1080)
        assertEquals(text("direct"), QrDecoder.text(plane, width, height))
    }

    /**
     * Held at arm's length the code fills a part of the frame: about six pixels to a module is what
     * the largest code gets from a 640-pixel frame, and it is read.
     */
    @Test
    fun theLargestCodeReadsWhenItGetsAboutSixPixelsToAModule() {
        val (plane, width, height) = frame(picture("direct"), 640)
        assertEquals(text("direct"), QrDecoder.text(plane, width, height))
    }

    @Test
    fun aPictureWithNoCodeGivesNothing() {
        assertNull(QrDecoder.text(IntArray(64 * 64) { 0xFF808080.toInt() }, 64, 64))
        assertNull(QrDecoder.text(ByteArray(64 * 64) { 0x80.toByte() }, 64, 64))
    }
}
