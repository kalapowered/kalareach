//! The Android TLS verifier's start.
//!
//! The HTTPS client verifies certificates through the platform verifier, which on Android calls
//! into the system's trust manager over JNI and needs the JVM, the application context and a class
//! loader that can see its Kotlin half before its first verification. The plugin's Kotlin half
//! calls [`Java_to_kala_reach_platform_TlsVerifier_start`] with the application context when it
//! loads, which is before any request.
//!
//! The Kotlin half (`org.rustls.platformverifier`) is loaded by name, so a minified build keeps
//! it with the retention rule in the application's `proguard-rules.pro`.

use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JClass, JObject};

/// Gives the platform verifier the JVM and the application context.
///
/// The JVM calls this native method by its exported name, and exporting a name is an unsafe
/// attribute: the name has to be unique in the process, which the package and class in it make it.
/// It is the one place this crate allows unsafe code. It runs the start inside `jni`'s own guard,
/// which turns a failure or a panic into a Java exception rather than an unwind into the JVM.
#[allow(
    unsafe_code,
    reason = "the JVM finds a native method by its exported, unmangled name"
)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_to_kala_reach_platform_TlsVerifier_start<'caller>(
    mut unowned: jni::EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    unowned
        .with_env(|env| -> jni::errors::Result<()> {
            rustls_platform_verifier::android::init_with_env(env, context)?;
            tracing::info!("the platform TLS verifier has the application context");
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// Keeps the native method in the linked library, which the JVM looks it up in by name.
#[used]
static START: for<'caller> extern "system" fn(
    jni::EnvUnowned<'caller>,
    JClass<'caller>,
    JObject<'caller>,
) = Java_to_kala_reach_platform_TlsVerifier_start;
