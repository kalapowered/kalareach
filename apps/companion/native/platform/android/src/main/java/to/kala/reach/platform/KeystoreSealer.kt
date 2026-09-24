package to.kala.reach.platform

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import to.kala.reach.companion.mobile.Sealer

/**
 * Seals with AES-256-GCM under a key the Android Keystore generated and never releases.
 *
 * The key needs no user authentication, so a refresh can run while the screen is locked. It never
 * leaves the device, so a copy of the files restored elsewhere cannot be opened. The Keystore
 * chooses each nonce itself; the sealed form is the nonce followed by the ciphertext and its tag.
 */
class KeystoreSealer : Sealer {
    private val key: SecretKey by lazy { existingKey() ?: newKey() }

    private fun existingKey(): SecretKey? {
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        return (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
    }

    private fun newKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    override fun seal(plain: ByteArray, associated: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(associated)
        val sealed = cipher.doFinal(plain)
        return cipher.iv + sealed
    }

    override fun open(sealed: ByteArray, associated: ByteArray): ByteArray {
        require(sealed.size > NONCE_BYTES) { "a sealed item is longer than its nonce" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(TAG_BITS, sealed.copyOfRange(0, NONCE_BYTES)),
        )
        cipher.updateAAD(associated)
        return cipher.doFinal(sealed, NONCE_BYTES, sealed.size - NONCE_BYTES)
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val ALIAS = "kalareach.secrets"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val NONCE_BYTES = 12
        const val TAG_BITS = 128
    }
}
