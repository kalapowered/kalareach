//! The companion's native platform services, shared by every feature that needs them.
//!
//! Six services, each a mechanism with no feature's policy in it:
//!
//! * [`secrets`]: the one secure store the companion keeps secrets in. The Keychain on macOS and
//!   iOS, the Credential Manager on Windows, the Secret Service on Linux, and on Android files
//!   sealed under a non-exportable Keystore key. An account's tokens and a device's keys both live
//!   here, and nothing writes a second store.
//! * [`backup`]: marking a directory as not to be backed up, on the systems whose backup would carry
//!   a record without the key it was made beside.
//! * [`protection`]: whether the device's protected data can be read yet, and the system's word
//!   when it can. iOS holds an application's files and keychain items back from a restart until the
//!   first unlock.
//! * [`browser`]: the browser-backed session a sign-in hands its ceremony to on a phone: iOS's
//!   authentication session, and Android's Auth Tab or a Custom Tab with a verified link.
//! * [`call`]: the voice call that native code holds (capture, playback and the media connection),
//!   the commands that reach it and the news it sends back.
//! * the Android TLS verifier's start: the platform verifier the HTTPS client uses needs the JVM
//!   and the application context before its first connection, and the plugin's Kotlin half hands
//!   them over when it loads.
//!
//! The native halves are this crate's Swift package (`ios/`) and Android library (`android/`),
//! registered with Tauri as one plugin. They report facts; the decisions are taken here, in Rust,
//! where the host's tests reach them.

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager as _, Runtime};

pub mod backup;
pub mod browser;
pub mod call;
pub mod protection;
pub mod secrets;
#[cfg(target_os = "android")]
mod tls;

/// The plugin's name.
pub const NAME: &str = "companion-platform";

/// A platform service that could not do what it was asked.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PlatformError(pub String);

impl PlatformError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// What the plugin holds: the handle to its native halves, on a phone.
pub struct Platform<R: Runtime> {
    #[cfg(mobile)]
    handle: tauri::plugin::PluginHandle<R>,
    #[cfg(not(mobile))]
    _runtime: std::marker::PhantomData<fn() -> R>,
}

#[cfg(mobile)]
impl<R: Runtime> Platform<R> {
    /// Calls one of the native methods and reads its answer.
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        arguments: impl serde::Serialize,
    ) -> Result<T, PlatformError> {
        self.handle
            .run_mobile_plugin_async(method, arguments)
            .await
            .map_err(|error| PlatformError::new(format!("the platform's {method} failed: {error}")))
    }

    /// Calls one of the native methods from a thread that may wait for it. The thread the platform
    /// starts the application on is one: the plugin answers on a queue of its own. Only the iOS
    /// store opens this way; Android's store calls its native half through the handle it keeps.
    #[cfg(target_os = "ios")]
    fn call_blocking<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        arguments: impl serde::Serialize,
    ) -> Result<T, PlatformError> {
        self.handle
            .run_mobile_plugin(method, arguments)
            .map_err(|error| PlatformError::new(format!("the platform's {method} failed: {error}")))
    }
}

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_companion_platform);

/// The plugin. Register it before anything asks for a store or a session.
#[must_use]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new(NAME)
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            let handle = api.register_android_plugin("to.kala.reach.platform", "PlatformPlugin")?;
            #[cfg(target_os = "ios")]
            let handle = api.register_ios_plugin(init_plugin_companion_platform)?;
            #[cfg(not(mobile))]
            let _ = api;
            app.manage(Platform::<R> {
                #[cfg(mobile)]
                handle,
                #[cfg(not(mobile))]
                _runtime: std::marker::PhantomData,
            });
            Ok(())
        })
        .build()
}
