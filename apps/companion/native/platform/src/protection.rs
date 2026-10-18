//! Whether this device's protected data can be read yet.
//!
//! iOS keeps an application's files and keychain items out of its reach from a restart until the
//! person first unlocks the device. A launch in the background before that (a silent push is one)
//! starts the process with nothing it keeps readable, and the system posts a notification when that
//! changes. [`is_available`] asks whether the data can be read now, and [`on_available`] calls a
//! function each time the system says it can be.
//!
//! No other system the companion runs on holds back an application's data in this way, so there
//! the data is always available and nothing is listened for.

use tauri::{AppHandle, Runtime};

use crate::PlatformError;

/// Whether the device's protected data can be read now.
///
/// It is false for a device that has not been unlocked since it started, and for one that is
/// locked again. When the system cannot be asked, the answer is yes: the data is then taken as
/// readable and a failure to read it is reported as the failure it is.
#[must_use]
pub fn is_available<R: Runtime>(app: &AppHandle<R>) -> bool {
    #[cfg(all(debug_assertions, target_os = "ios"))]
    if model::locked() {
        return false;
    }
    available(app)
}

#[cfg(target_os = "ios")]
fn available<R: Runtime>(app: &AppHandle<R>) -> bool {
    use tauri::Manager as _;

    #[derive(serde::Deserialize)]
    struct Answer {
        available: bool,
    }

    let platform = app.state::<crate::Platform<R>>();
    match platform.call_blocking::<Answer>("protectedData", ()) {
        Ok(answer) => answer.available,
        Err(error) => {
            tracing::warn!(%error, "the system was not asked whether protected data is available");
            true
        }
    }
}

#[cfg(not(target_os = "ios"))]
const fn available<R: Runtime>(_app: &AppHandle<R>) -> bool {
    true
}

/// Calls `listener` each time the system says the device's protected data has become available:
/// at the first unlock after the device started, and at each unlock after that.
///
/// The listener runs on the system's thread for the notification, so it starts any work of its
/// own on another. Where nothing is held back, it is never called.
///
/// # Errors
///
/// Returns an error when the native half cannot be asked to listen.
#[cfg(target_os = "ios")]
pub fn on_available<R: Runtime>(
    app: &AppHandle<R>,
    listener: impl Fn() + Send + Sync + 'static,
) -> Result<(), PlatformError> {
    use tauri::Manager as _;

    #[derive(serde::Serialize)]
    struct Watch {
        events: tauri::ipc::Channel<serde_json::Value>,
    }

    let events = tauri::ipc::Channel::<serde_json::Value>::new(move |_| {
        listener();
        Ok(())
    });
    let platform = app.state::<crate::Platform<R>>();
    let _: serde_json::Value = platform.call_blocking("watchProtectedData", Watch { events })?;
    Ok(())
}

/// Where nothing is held back, there is nothing to listen for.
///
/// # Errors
///
/// Never fails here.
#[cfg(not(target_os = "ios"))]
pub fn on_available<R: Runtime>(
    _app: &AppHandle<R>,
    _listener: impl Fn() + Send + Sync + 'static,
) -> Result<(), PlatformError> {
    Ok(())
}

/// The locked device as a debug build on a simulator models it.
///
/// The model has two halves, each at the place the application reads the system. While the device
/// is modelled as locked, the secure store refuses every read and write with the words the
/// keychain gives for a device that has not been unlocked. [`unlock`] ends that and has the
/// system's own notification for protected data posted, which the native half observes as it
/// observes the system's.
#[cfg(all(debug_assertions, target_os = "ios"))]
pub mod model {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use kr_crypto::secret::SecretVec;
    use kr_crypto::store::{SecretName, SecretStore};
    use kr_crypto::{CryptoError, Result};
    use tauri::{AppHandle, Manager as _, Runtime};

    use crate::PlatformError;

    /// The environment variable a simulator launch sets to `1` to start with the device locked.
    pub const ENVIRONMENT: &str = "KR_MODEL_LOCKED_DEVICE";

    static LOCKED: AtomicBool = AtomicBool::new(false);

    /// Starts the model locked when the launch asked for it.
    pub fn arm_from_environment() {
        if std::env::var_os(ENVIRONMENT).is_some_and(|value| value == "1") {
            LOCKED.store(true, Ordering::SeqCst);
        }
    }

    /// Whether the device is modelled as locked now.
    #[must_use]
    pub fn locked() -> bool {
        LOCKED.load(Ordering::SeqCst)
    }

    /// Unlocks the modelled device, as the person does, and has the system's notification that
    /// protected data is available posted.
    ///
    /// # Errors
    ///
    /// Returns an error when the native half cannot post the notification.
    pub fn unlock<R: Runtime>(app: &AppHandle<R>) -> std::result::Result<(), PlatformError> {
        LOCKED.store(false, Ordering::SeqCst);
        let platform = app.state::<crate::Platform<R>>();
        let _: serde_json::Value = platform.call_blocking("postProtectedDataAvailable", ())?;
        Ok(())
    }

    /// `store`, refusing while the device is modelled as locked.
    #[must_use]
    pub fn behind(store: Arc<dyn SecretStore>) -> Arc<dyn SecretStore> {
        Arc::new(Refusing(store))
    }

    /// What the keychain says to a device that has not been unlocked (`errSecInteractionNotAllowed`).
    fn refusal() -> CryptoError {
        CryptoError::SecretStore {
            message: "User interaction is not allowed.".to_owned(),
        }
    }

    struct Refusing(Arc<dyn SecretStore>);

    impl SecretStore for Refusing {
        fn set(&self, name: &SecretName, secret: &[u8]) -> Result<()> {
            if locked() {
                return Err(refusal());
            }
            self.0.set(name, secret)
        }

        fn get(&self, name: &SecretName) -> Result<Option<SecretVec>> {
            if locked() {
                return Err(refusal());
            }
            self.0.get(name)
        }

        fn delete(&self, name: &SecretName) -> Result<()> {
            if locked() {
                return Err(refusal());
            }
            self.0.delete(name)
        }

        fn describe(&self) -> String {
            self.0.describe()
        }
    }
}
