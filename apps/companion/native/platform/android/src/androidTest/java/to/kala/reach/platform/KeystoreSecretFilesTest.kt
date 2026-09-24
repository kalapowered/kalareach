package to.kala.reach.platform

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import to.kala.reach.companion.mobile.SecretFiles
import to.kala.reach.companion.mobile.SecretUnreadable

/**
 * The secret store on a device: files sealed under a key the Android Keystore generated. The file
 * rules have JVM tests with a software key in `:krnative`; these hold the real key.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreSecretFilesTest {
    private lateinit var directory: File

    @Before
    fun makeDirectory() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        directory = File(context.noBackupFilesDir, "secrets-under-test")
        directory.deleteRecursively()
    }

    @After
    fun removeDirectory() {
        directory.deleteRecursively()
    }

    @Test
    fun anItemIsWrittenReadBackReplacedAndDeletedUnderTheKeystoreKey() {
        val store = SecretFiles(directory, KeystoreSealer())
        assertNull(store.read("account/session"))
        store.write("account/session", "a grant".toByteArray())
        assertArrayEquals("a grant".toByteArray(), store.read("account/session"))
        // Another sealer finds the same key, as the next start of the application does.
        val again = SecretFiles(directory, KeystoreSealer())
        assertArrayEquals("a grant".toByteArray(), again.read("account/session"))
        again.write("account/session", "a rotated grant".toByteArray())
        assertArrayEquals("a rotated grant".toByteArray(), store.read("account/session"))
        store.delete("account/session")
        assertNull(store.read("account/session"))
    }

    @Test
    fun aChangedByteIsAnErrorAndNeverMissing() {
        val store = SecretFiles(directory, KeystoreSealer())
        store.write("account/session", "a grant".toByteArray())
        val file = store.fileFor("account/session")
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertThrows(SecretUnreadable::class.java) { store.read("account/session") }
    }

    @Test
    fun anItemMovedUnderAnotherNameDoesNotOpen() {
        val store = SecretFiles(directory, KeystoreSealer())
        store.write("account/session", "a grant".toByteArray())
        store.fileFor("account/session").renameTo(store.fileFor("account/revoke"))
        assertThrows(SecretUnreadable::class.java) { store.read("account/revoke") }
    }
}
