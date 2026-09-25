//! This computer's identity as it pairs with hosts.
//!
//! Section 10 asks a companion and a host on one computer to hold separate identities, so the
//! companion keeps its keys in a store named for it: the platform's own secret store (the Keychain,
//! the Credential Manager, the Secret Service), or the documented directory on a Linux desktop that
//! has none. The daemon's store is `KalaReach`; this one is [`SECRET_SERVICE`].

use std::sync::Arc;

use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{SecretStore, load_device_keys, store_device_keys};
use kr_protocol::pairing::{DeviceName, DevicePlatform};

use crate::error::{CommandError, Result};

/// The secret store this application keeps its keys in.
pub const SECRET_SERVICE: &str = "KalaReach Companion";

/// The scope this computer's keys, and its attempt budget's key, are stored under.
pub const SCOPE: &str = "device";

/// What this computer declares when it pairs, and the store its secrets live in.
pub struct DeviceIdentity {
    /// This computer's keys, created once per installation.
    pub keys: DeviceKeys,
    /// The name it offers a host.
    pub name: DeviceName,
    /// Its platform.
    pub platform: DevicePlatform,
    /// The store its secrets live in.
    pub secrets: Arc<dyn SecretStore>,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("endpoint_id", self.keys.transport.public())
            .field("name", &self.name)
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// This computer's identity from `secrets`, with keys created the first time.
    ///
    /// # Errors
    ///
    /// Returns a local failure when the store cannot be read or written.
    pub fn in_store(secrets: Arc<dyn SecretStore>) -> Result<Self> {
        let stored = load_device_keys(&*secrets, SCOPE).map_err(|error| {
            CommandError::local_failure(format!("this computer's keys could not be read: {error}"))
        })?;
        let keys = match stored {
            Some(keys) => keys,
            None => {
                let keys = DeviceKeys::generate().map_err(|error| {
                    CommandError::local_failure(format!("keys could not be made: {error}"))
                })?;
                store_device_keys(&*secrets, SCOPE, &keys).map_err(|error| {
                    CommandError::local_failure(format!(
                        "this computer's keys could not be kept: {error}"
                    ))
                })?;
                keys
            }
        };
        Ok(Self {
            keys,
            name: this_computer(),
            platform: this_platform(),
            secrets,
        })
    }
}

/// The name this computer offers a host: its host name, without the local network's suffix.
fn this_computer() -> DeviceName {
    sysinfo::System::host_name()
        .map(|name| name.trim().trim_end_matches(".local").to_owned())
        .and_then(|name| DeviceName::new(name).ok())
        .unwrap_or_else(|| DeviceName::new("A KalaReach companion").expect("a fixed name"))
}

/// The platform this build runs on.
const fn this_platform() -> DevicePlatform {
    if cfg!(target_os = "macos") {
        DevicePlatform::Macos
    } else if cfg!(target_os = "windows") {
        DevicePlatform::Windows
    } else if cfg!(target_os = "ios") {
        DevicePlatform::Ios
    } else if cfg!(target_os = "android") {
        DevicePlatform::Android
    } else {
        DevicePlatform::Linux
    }
}
