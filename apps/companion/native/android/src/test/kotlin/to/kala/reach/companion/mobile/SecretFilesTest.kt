package to.kala.reach.companion.mobile

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** AES-256-GCM under a software key, standing for the Keystore key on the JVM. */
class SoftwareSealer : Sealer {
    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    override fun seal(plain: ByteArray, associated: ByteArray): ByteArray {
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(associated)
        return nonce + cipher.doFinal(plain)
    }

    override fun open(sealed: ByteArray, associated: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
        cipher.updateAAD(associated)
        return cipher.doFinal(sealed, 12, sealed.size - 12)
    }
}

/** A write that stops before the staged file takes the item's place. */
class InterruptedBeforeRename(directory: File, sealer: Sealer) : SecretFiles(directory, sealer) {
    override fun commit(staging: File, target: File) {
        throw IOException("interrupted")
    }
}

/** The control: a writer that writes into the item's own file and stops halfway. */
class InterruptedInPlace(directory: File, sealer: Sealer) : SecretFiles(directory, sealer) {
    override fun commit(staging: File, target: File) {
        val staged = staging.readBytes()
        target.writeBytes(staged.copyOf(staged.size / 2))
        throw IOException("interrupted")
    }
}

class SecretFilesTest {
    private fun directory(): File = Files.createTempDirectory("kr-secret-files").toFile()

    @Test
    fun anItemReadsBackAsItWasWrittenAndAnAbsentOneIsMissing() {
        val files = SecretFiles(directory(), SoftwareSealer())
        assertNull(files.read("account/session"))
        files.write("account/session", "a grant".toByteArray())
        assertArrayEquals("a grant".toByteArray(), files.read("account/session"))
        files.delete("account/session")
        assertNull(files.read("account/session"))
        files.delete("account/session")
    }

    @Test
    fun everyWriteSealsWithAFreshNonce() {
        val root = directory()
        val files = SecretFiles(root, SoftwareSealer())
        files.write("account/session", "the same".toByteArray())
        val first = files.fileFor("account/session").readBytes()
        files.write("account/session", "the same".toByteArray())
        val second = files.fileFor("account/session").readBytes()
        assertFalse(first.contentEquals(second))
        assertFalse(String(first).contains("the same"))
    }

    @Test
    fun anItemMovedUnderAnotherNameDoesNotOpen() {
        val files = SecretFiles(directory(), SoftwareSealer())
        files.write("account/session", "a grant".toByteArray())
        files.fileFor("account/session").copyTo(files.fileFor("account/revoke"))
        try {
            files.read("account/revoke")
            fail("the name is bound to the sealed bytes")
        } catch (expected: SecretUnreadable) {
        }
    }

    @Test
    fun aChangedOrTruncatedItemIsAnErrorAndNotMissing() {
        val files = SecretFiles(directory(), SoftwareSealer())
        files.write("account/session", "a grant".toByteArray())
        val file = files.fileFor("account/session")
        val sealed = file.readBytes()
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 1).toByte()
        file.writeBytes(sealed)
        try {
            files.read("account/session")
            fail("a changed byte does not open")
        } catch (expected: SecretUnreadable) {
        }
        file.writeBytes(sealed.copyOf(5))
        try {
            files.read("account/session")
            fail("a truncated item does not open")
        } catch (expected: SecretUnreadable) {
        }
    }

    @Test
    fun aWriteInterruptedBeforeItsRenameLeavesTheOldItemWhole() {
        val root = directory()
        val sealer = SoftwareSealer()
        SecretFiles(root, sealer).write("account/session", "the old grant".toByteArray())
        try {
            InterruptedBeforeRename(root, sealer).write("account/session", "the new grant".toByteArray())
            fail("the write was interrupted")
        } catch (expected: IOException) {
        }
        assertArrayEquals(
            "the old grant".toByteArray(),
            SecretFiles(root, sealer).read("account/session"),
        )
        assertEquals(1, root.listFiles()!!.size)
    }

    @Test
    fun theControlAWriterThatWritesInPlaceLosesTheItemWhenInterrupted() {
        val root = directory()
        val sealer = SoftwareSealer()
        SecretFiles(root, sealer).write("account/session", "the old grant".toByteArray())
        try {
            InterruptedInPlace(root, sealer).write("account/session", "the new grant".toByteArray())
            fail("the write was interrupted")
        } catch (expected: IOException) {
        }
        var lost = false
        try {
            SecretFiles(root, sealer).read("account/session")
        } catch (expected: SecretUnreadable) {
            lost = true
        }
        assertTrue("writing in place leaves neither the old item nor the new one", lost)
    }
}
