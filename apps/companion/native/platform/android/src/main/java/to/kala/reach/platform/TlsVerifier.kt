package to.kala.reach.platform

import android.content.Context

/**
 * Hands the platform TLS verifier the JVM and the application context, which it needs before the
 * first certificate it verifies. The native method is in the plugin's Rust crate.
 */
object TlsVerifier {
    @JvmStatic
    external fun start(context: Context)
}
