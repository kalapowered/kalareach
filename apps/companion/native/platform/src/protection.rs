//! Standing in for the system's locked device, for the simulator.
//!
//! iOS keeps an application's files and keychain items out of its reach from a restart until the
//! person first unlocks the device. A simulator never does: its files and its keychain are always
//! readable. A debug build on a simulator can be started as if the device were still locked, so
//! that the whole application can be run through its first unlock; only the system's refusal and
//! the system's notification are stood in for, and everything the application does about them is
//! its own.

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
