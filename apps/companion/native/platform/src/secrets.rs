//! The companion's one secure store.
//!
//! Section 10 names the store per platform: the Keychain on macOS and iOS, Keystore-protected
//! storage on Android, the Credential Manager on Windows and the Secret Service on Linux, with the
//! documented 0700 directory only on Linux without a secret service. [`open`] returns that store
//! as one [`SecretStore`], so an account's tokens and a device's keys are kept the same way on
//! every platform.
//!
//! * macOS, Windows and Linux: [`kr_crypto::store::open_store`] under [`STORE_NAME`], with the
//!   application's data directory for the Linux fallback.
//! * iOS: generic passwords in the protected keychain store, in this application's own access group
//!   (read from the value the build wrote into `Info.plist`, and never the group the notification
//!   extension reads), readable after the first unlock, on this device only, not synchronised.
//! * Android: one file per item in the no-backup directory, sealed with AES-256-GCM under a
//!   non-exportable Keystore key with no user-authentication requirement, the item name bound as
//!   the associated data, replaced by an atomic rename. The plugin's Kotlin half does the sealing.
//!
//! The decisions that can be taken without a device are functions here with tests: which access
//! group an item goes in, and what the keychain is asked for.

use std::sync::Arc;

use kr_crypto::store::{SecretName, SecretStore};
use tauri::{AppHandle, Runtime};

use crate::PlatformError;

/// The store's name: the desktop store's service and the iOS keychain items' service.
///
/// The host's own store is `KalaReach`, so a companion and a host on one machine keep separate
/// items.
pub const STORE_NAME: &str = "KalaReach Companion";

/// Where one secret goes in the iOS keychain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainItem {
    /// The item's service.
    pub service: String,
    /// The item's account: the secret's name.
    pub account: String,
    /// The access group the item is written to and read from, named on every call.
    pub access_group: String,
    /// Whether the item is readable only after the device's first unlock, and only on this device.
    pub after_first_unlock_this_device_only: bool,
    /// Whether the item is synchronised to the person's other devices.
    pub synchronised: bool,
}

/// The application's private keychain group, from the value the build wrote into `Info.plist`.
///
/// # Errors
///
/// Refuses a value the build did not expand, an empty one, and the group shared with the
/// notification extension, which must never hold anything but the preview key.
pub fn private_group(written: Option<&str>) -> Result<String, PlatformError> {
    let group = written
        .map(str::trim)
        .filter(|group| !group.is_empty() && !group.contains("$("))
        .ok_or_else(|| PlatformError::new("the build wrote no private keychain group"))?;
    if group.ends_with(".shared") {
        return Err(PlatformError::new(
            "the private keychain group is the one the notification extension reads",
        ));
    }
    Ok(group.to_owned())
}

/// What the keychain is asked for, for one secret.
#[must_use]
pub fn keychain_item(access_group: &str, name: &SecretName) -> KeychainItem {
    KeychainItem {
        service: STORE_NAME.to_owned(),
        account: name.as_str().to_owned(),
        access_group: access_group.to_owned(),
        after_first_unlock_this_device_only: true,
        synchronised: false,
    }
}

/// Opens this platform's store.
///
/// # Errors
///
/// Returns an error when the platform's store cannot be opened; on a platform whose section 10
/// store is missing, that is an error and never a downgrade.
pub fn open<R: Runtime>(app: &AppHandle<R>) -> Result<Arc<dyn SecretStore>, PlatformError> {
    #[cfg(desktop)]
    {
        use tauri::Manager as _;
        let directory = app
            .path()
            .app_data_dir()
            .map_err(|error| PlatformError::new(format!("no application data directory: {error}")))?
            .join("secrets");
        let opened = kr_crypto::store::open_store(STORE_NAME, &directory)
            .map_err(|error| PlatformError::new(error.to_string()))?;
        Ok(Arc::from(opened.store))
    }
    #[cfg(target_os = "ios")]
    {
        use tauri::Manager as _;
        let platform = app.state::<crate::Platform<R>>();
        let capabilities: crate::browser::Capabilities =
            platform.call_blocking("capabilities", ())?;
        let group = private_group(capabilities.private_keychain_group.as_deref())?;
        Ok(Arc::new(ios::KeychainStore { group }))
    }
    #[cfg(target_os = "android")]
    {
        use tauri::Manager as _;
        let platform = app.state::<crate::Platform<R>>();
        Ok(Arc::new(android::KeystoreStore {
            handle: platform.handle.clone(),
        }))
    }
}

#[cfg(target_os = "ios")]
mod ios {
    use apple_native_keyring_store::protected::{AccessPolicy, Cred};
    use kr_crypto::secret::SecretVec;
    use kr_crypto::store::{SecretName, SecretStore};
    use kr_crypto::{CryptoError, Result};

    use super::keychain_item;

    /// The protected keychain store, in the application's own group.
    pub(super) struct KeychainStore {
        pub(super) group: String,
    }

    fn failed(error: impl std::fmt::Display) -> CryptoError {
        CryptoError::SecretStore {
            message: error.to_string(),
        }
    }

    impl KeychainStore {
        fn entry(&self, name: &SecretName) -> Result<keyring_core::Entry> {
            let item = keychain_item(&self.group, name);
            let policy = if item.after_first_unlock_this_device_only {
                AccessPolicy::AfterFirstUnlockThisDeviceOnly
            } else {
                AccessPolicy::WhenUnlockedThisDeviceOnly
            };
            Cred::build(
                &item.service,
                &item.account,
                policy,
                Some(item.access_group),
                item.synchronised,
            )
            .map_err(failed)
        }
    }

    impl SecretStore for KeychainStore {
        fn set(&self, name: &SecretName, secret: &[u8]) -> Result<()> {
            self.entry(name)?.set_secret(secret).map_err(failed)
        }

        fn get(&self, name: &SecretName) -> Result<Option<SecretVec>> {
            match self.entry(name)?.get_secret() {
                Ok(bytes) => Ok(Some(SecretVec::new(bytes))),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(error) => Err(failed(error)),
            }
        }

        fn delete(&self, name: &SecretName) -> Result<()> {
            match self.entry(name)?.delete_credential() {
                Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
                Err(error) => Err(failed(error)),
            }
        }

        fn describe(&self) -> String {
            "the iOS keychain, in this application's own access group".to_owned()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The real keychain: an item is written, read back, replaced and deleted in the group the
        /// run names. The process needs that group's entitlement, which only a simulator or device
        /// run carries, so this is ignored in ordinary runs. Run it in a booted simulator:
        /// `xcrun simctl spawn <device> <test binary> --ignored --exact <name>`, with
        /// `SIMCTL_CHILD_KR_KEYCHAIN_GROUP` naming the group and the binary linked with an
        /// `__entitlements` section that grants it.
        #[test]
        #[ignore = "needs a simulator or device, and the keychain group's entitlement"]
        fn the_keychain_keeps_reads_back_replaces_and_deletes_one_item() {
            let group =
                std::env::var("KR_KEYCHAIN_GROUP").expect("KR_KEYCHAIN_GROUP names a group");
            let store = KeychainStore { group };
            let name = SecretName::new("test/round-trip").expect("a name");
            store
                .delete(&name)
                .expect("a delete of an item that may be absent");
            assert!(store.get(&name).expect("a read").is_none());
            store.set(&name, b"a grant").expect("a write");
            let read = store.get(&name).expect("a read").expect("the item");
            assert_eq!(read.expose(), b"a grant");
            store
                .set(&name, b"a rotated grant")
                .expect("a second write");
            let read = store.get(&name).expect("a read").expect("the item");
            assert_eq!(read.expose(), b"a rotated grant");
            store.delete(&name).expect("a delete");
            assert!(store.get(&name).expect("a read").is_none());
            println!("keychain: written, read back, replaced and deleted");
        }
    }
}

#[cfg(target_os = "android")]
mod android {
    use base64::Engine as _;
    use kr_crypto::secret::SecretVec;
    use kr_crypto::store::{SecretName, SecretStore};
    use kr_crypto::{CryptoError, Result};
    use tauri::Runtime;

    /// Files sealed under the Keystore key, through the plugin's Kotlin half.
    pub(super) struct KeystoreStore<R: Runtime> {
        pub(super) handle: tauri::plugin::PluginHandle<R>,
    }

    #[derive(serde::Serialize)]
    struct Named<'a> {
        name: &'a str,
    }

    #[derive(serde::Serialize)]
    struct Written<'a> {
        name: &'a str,
        value: String,
    }

    #[derive(serde::Deserialize)]
    struct Read {
        value: Option<String>,
    }

    fn failed(error: impl std::fmt::Display) -> CryptoError {
        CryptoError::SecretStore {
            message: error.to_string(),
        }
    }

    impl<R: Runtime> SecretStore for KeystoreStore<R> {
        fn set(&self, name: &SecretName, secret: &[u8]) -> Result<()> {
            self.handle
                .run_mobile_plugin::<serde_json::Value>(
                    "secretSet",
                    Written {
                        name: name.as_str(),
                        value: base64::engine::general_purpose::STANDARD.encode(secret),
                    },
                )
                .map(|_| ())
                .map_err(failed)
        }

        fn get(&self, name: &SecretName) -> Result<Option<SecretVec>> {
            let read: Read = self
                .handle
                .run_mobile_plugin(
                    "secretGet",
                    Named {
                        name: name.as_str(),
                    },
                )
                .map_err(failed)?;
            read.value
                .map(|value| {
                    base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .map(SecretVec::new)
                        .map_err(failed)
                })
                .transpose()
        }

        fn delete(&self, name: &SecretName) -> Result<()> {
            self.handle
                .run_mobile_plugin::<serde_json::Value>(
                    "secretDelete",
                    Named {
                        name: name.as_str(),
                    },
                )
                .map(|_| ())
                .map_err(failed)
        }

        fn describe(&self) -> String {
            "files in the no-backup directory, sealed under a Keystore key".to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The application's own group is the one the build expanded, and never the shared one.
    #[test]
    fn the_private_group_is_the_expanded_one_and_never_the_shared_one() {
        assert_eq!(
            private_group(Some("JT6GW3W9W6.to.kala.reach")).expect("a group"),
            "JT6GW3W9W6.to.kala.reach"
        );
        for refused in [
            None,
            Some(""),
            Some("$(AppIdentifierPrefix)to.kala.reach"),
            Some("JT6GW3W9W6.to.kala.reach.shared"),
        ] {
            assert!(private_group(refused).is_err(), "{refused:?}");
        }
    }

    /// Every item is in the private group, readable after first unlock on this device only, and
    /// not synchronised; an item for the shared group is not what this store asks for.
    #[test]
    fn a_keychain_item_is_private_this_device_only_and_not_synchronised() {
        let name = SecretName::new("account/session").expect("a name");
        let item = keychain_item("JT6GW3W9W6.to.kala.reach", &name);
        assert_eq!(
            item,
            KeychainItem {
                service: "KalaReach Companion".to_owned(),
                account: "account/session".to_owned(),
                access_group: "JT6GW3W9W6.to.kala.reach".to_owned(),
                after_first_unlock_this_device_only: true,
                synchronised: false,
            }
        );
        assert_ne!(
            item,
            keychain_item("JT6GW3W9W6.to.kala.reach.shared", &name),
            "the shared group is another item"
        );
    }
}
