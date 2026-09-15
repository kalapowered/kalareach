//! Secret storage.
//!
//! Section 10 stores secrets in the macOS and iOS Keychain, Android Keystore-protected storage,
//! Windows DPAPI or Credential Manager, and the Linux Secret Service. On Linux without a secret
//! service it uses a user-owned directory with mode 0700 and files with mode 0600, and documents
//! that this depends on operating-system account isolation and disk encryption.
//!
//! [`SecretStore`] is that choice as one interface. [`PlatformStore`] is the `keyring` crate,
//! which selects the platform store; [`FileStore`] is the documented fallback; [`MemoryStore`] is
//! for tests and never touches a disk.
//!
//! # Why every purpose has its own item
//!
//! Each device key is stored under its own name, so loading a device's keys reads four items and
//! hands each one to the purpose that owns it. There is no item that holds two purposes and no way
//! to load one purpose's seed into another purpose's type.

use std::fmt;
use std::path::{Path, PathBuf};

use kr_protocol::pairing::KeyPurpose;

use crate::error::{CryptoError, Result};
use crate::keys::{
    AuthorisationKeyPair, AuthorisationSeed, DeviceKeys, NotificationPreviewKeyPair,
    NotificationPreviewSeed, StoredEnvelopeKeyPair, StoredEnvelopeSeed, TransportIdentityKeyPair,
    TransportSeed,
};
use crate::secret::SecretVec;
use crate::sodium;

/// Maximum length of a secret item name, in bytes.
pub const MAX_SECRET_NAME_LEN: usize = 128;

/// The name of one stored secret.
///
/// Names are restricted to lower-case ASCII, digits, `.`, `-`, `_` and `/`, so a name is also a
/// safe file name in the fallback store and a safe account name in a platform store.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretName(String);

impl SecretName {
    /// Validates and wraps a name.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SecretStore`] when the name is empty, too long, contains a character
    /// outside the permitted set, or contains a path traversal segment.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let invalid = |message: &str| CryptoError::SecretStore {
            message: format!("{message}: {name:?}"),
        };
        if name.is_empty() {
            return Err(invalid("a secret name is not empty"));
        }
        if name.len() > MAX_SECRET_NAME_LEN {
            return Err(invalid("a secret name is at most 128 bytes"));
        }
        if !name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'_' | b'/')
        }) {
            return Err(invalid(
                "a secret name uses lower-case ASCII, digits, '.', '-', '_' and '/'",
            ));
        }
        if name.starts_with('/') || name.ends_with('/') || name.split('/').any(|part| part == "..")
        {
            return Err(invalid("a secret name has no empty or traversing segment"));
        }
        Ok(Self(name))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the name of one device key's seed inside `scope`.
    ///
    /// # Errors
    ///
    /// Returns an error when the resulting name breaks a name rule.
    pub fn device_key(scope: &str, purpose: KeyPurpose) -> Result<Self> {
        Self::new(format!("{scope}/device-key/{}", purpose.as_str()))
    }

    /// Returns the name of the recovery seed inside `scope`.
    ///
    /// # Errors
    ///
    /// Returns an error when the resulting name breaks a name rule.
    pub fn recovery_seed(scope: &str) -> Result<Self> {
        Self::new(format!("{scope}/recovery-seed"))
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A place secrets are kept.
pub trait SecretStore: Send + Sync {
    /// Writes a secret, replacing any previous value.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SecretStore`] when the store rejects the write.
    fn set(&self, name: &SecretName, secret: &[u8]) -> Result<()>;

    /// Reads a secret, or `None` when the item does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SecretStore`] when the store fails for a reason other than a missing
    /// item.
    fn get(&self, name: &SecretName) -> Result<Option<SecretVec>>;

    /// Deletes a secret. Deleting a missing item succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SecretStore`] when the store rejects the deletion.
    fn delete(&self, name: &SecretName) -> Result<()>;

    /// Describes the store for diagnostics. It never names a secret.
    fn describe(&self) -> String;
}

/// The operating system's own credential store, through the `keyring` crate.
///
/// macOS and iOS use Keychain Services, Windows uses the Credential Manager and other Unix systems
/// use the Secret Service.
#[derive(Debug, Clone)]
pub struct PlatformStore {
    service: String,
}

impl PlatformStore {
    /// Opens the platform store under `service`, checking that one is actually available.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SecretStore`] when the platform has no usable credential store, so
    /// the caller can fall back deliberately rather than discovering it at the first write.
    pub fn open(service: impl Into<String>) -> Result<Self> {
        keyring::Entry::store_status()
            .as_ref()
            .map_err(|error| CryptoError::SecretStore {
                message: format!("no platform credential store: {error}"),
            })?;
        Ok(Self {
            service: service.into(),
        })
    }

    fn entry(&self, name: &SecretName) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, name.as_str()).map_err(|error| {
            CryptoError::SecretStore {
                message: error.to_string(),
            }
        })
    }
}

impl SecretStore for PlatformStore {
    fn set(&self, name: &SecretName, secret: &[u8]) -> Result<()> {
        self.entry(name)?
            .set_secret(secret)
            .map_err(|error| CryptoError::SecretStore {
                message: error.to_string(),
            })
    }

    fn get(&self, name: &SecretName) -> Result<Option<SecretVec>> {
        match self.entry(name)?.get_secret() {
            Ok(secret) => Ok(Some(SecretVec::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(CryptoError::SecretStore {
                message: error.to_string(),
            }),
        }
    }

    fn delete(&self, name: &SecretName) -> Result<()> {
        match self.entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(CryptoError::SecretStore {
                message: error.to_string(),
            }),
        }
    }

    fn describe(&self) -> String {
        format!(
            "the platform credential store for service {:?}",
            self.service
        )
    }
}

/// The documented fallback for a Unix system with no secret service.
///
/// The directory is created with mode 0700 and every file with mode 0600. That is the whole
/// protection: it depends on operating-system account isolation and on disk encryption, and it
/// protects nothing from code already running as the same user.
#[derive(Debug, Clone)]
pub struct FileStore {
    directory: PathBuf,
}

impl FileStore {
    /// Opens the fallback store at `directory`, creating it with mode 0700.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SecretStore`] when the directory cannot be created or its
    /// permissions cannot be set.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        std::fs::create_dir_all(&directory).map_err(|error| CryptoError::SecretStore {
            message: format!("create {}: {error}", directory.display()),
        })?;
        set_mode(&directory, 0o700)?;
        Ok(Self { directory })
    }

    /// Returns the directory secrets are written to.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn path(&self, name: &SecretName) -> PathBuf {
        // The name is validated, so no segment traverses and none is empty. A '/' becomes a
        // subdirectory, which keeps one scope's items together.
        let mut path = self.directory.clone();
        for part in name.as_str().split('/') {
            path.push(part);
        }
        path
    }
}

impl SecretStore for FileStore {
    fn set(&self, name: &SecretName, secret: &[u8]) -> Result<()> {
        let path = self.path(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| CryptoError::SecretStore {
                message: format!("create {}: {error}", parent.display()),
            })?;
            set_mode(parent, 0o700)?;
        }
        // Write to a temporary file, restrict it, then rename, so a reader never observes a
        // partially written secret and never observes one with the wrong mode.
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, secret).map_err(|error| CryptoError::SecretStore {
            message: format!("write {}: {error}", temporary.display()),
        })?;
        set_mode(&temporary, 0o600)?;
        std::fs::rename(&temporary, &path).map_err(|error| CryptoError::SecretStore {
            message: format!("rename into {}: {error}", path.display()),
        })
    }

    fn get(&self, name: &SecretName) -> Result<Option<SecretVec>> {
        match std::fs::read(self.path(name)) {
            Ok(bytes) => Ok(Some(SecretVec::new(bytes))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(CryptoError::SecretStore {
                message: error.to_string(),
            }),
        }
    }

    fn delete(&self, name: &SecretName) -> Result<()> {
        let path = self.path(name);
        // Overwrite before unlinking. On a journalling or copy-on-write filesystem this is not a
        // guarantee, which is why the fallback is documented as depending on disk encryption.
        if let Ok(metadata) = std::fs::metadata(&path) {
            let len = usize::try_from(metadata.len()).unwrap_or(0);
            let mut zeroes = vec![0u8; len];
            let _ = std::fs::write(&path, &zeroes);
            sodium::memzero(&mut zeroes);
        }
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(CryptoError::SecretStore {
                message: error.to_string(),
            }),
        }
    }

    fn describe(&self) -> String {
        format!(
            "the 0700 fallback directory at {} (protected only by OS account isolation and disk encryption)",
            self.directory.display()
        )
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|error| {
        CryptoError::SecretStore {
            message: format!("set mode {mode:o} on {}: {error}", path.display()),
        }
    })
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    // The fallback exists for Unix systems without a secret service. Windows and the mobile
    // platforms always have a platform store, so this build never relies on file modes.
    Err(CryptoError::SecretStore {
        message: "the file fallback store is only available on Unix".to_owned(),
    })
}

/// An in-memory store for tests. It never writes to a disk.
#[derive(Debug, Default)]
pub struct MemoryStore {
    items: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
}

impl MemoryStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemoryStore {
    fn set(&self, name: &SecretName, secret: &[u8]) -> Result<()> {
        let mut items = self.items.lock().map_err(|_| CryptoError::SecretStore {
            message: "the in-memory store is poisoned".to_owned(),
        })?;
        items.insert(name.as_str().to_owned(), secret.to_vec());
        Ok(())
    }

    fn get(&self, name: &SecretName) -> Result<Option<SecretVec>> {
        let items = self.items.lock().map_err(|_| CryptoError::SecretStore {
            message: "the in-memory store is poisoned".to_owned(),
        })?;
        Ok(items.get(name.as_str()).cloned().map(SecretVec::new))
    }

    fn delete(&self, name: &SecretName) -> Result<()> {
        let mut items = self.items.lock().map_err(|_| CryptoError::SecretStore {
            message: "the in-memory store is poisoned".to_owned(),
        })?;
        if let Some(mut secret) = items.remove(name.as_str()) {
            sodium::memzero(&mut secret);
        }
        Ok(())
    }

    fn describe(&self) -> String {
        "an in-memory store".to_owned()
    }
}

impl Drop for MemoryStore {
    fn drop(&mut self) {
        if let Ok(mut items) = self.items.lock() {
            for secret in items.values_mut() {
                sodium::memzero(secret);
            }
        }
    }
}

/// Opens the platform store, falling back to a 0700 directory when there is none.
///
/// The result says which store was opened, so setup can report whether the host is relying on the
/// documented fallback rather than on a platform store.
///
/// # Errors
///
/// Returns [`CryptoError::SecretStore`] when neither store can be opened.
pub fn open_store(
    service: &str,
    fallback_directory: &Path,
) -> Result<(Box<dyn SecretStore>, StoreKind)> {
    match PlatformStore::open(service) {
        Ok(store) => Ok((Box::new(store), StoreKind::Platform)),
        Err(platform_error) => match FileStore::open(fallback_directory) {
            Ok(store) => Ok((Box::new(store), StoreKind::FileFallback)),
            Err(fallback_error) => Err(CryptoError::SecretStore {
                message: format!(
                    "no platform store ({platform_error}) and no fallback ({fallback_error})"
                ),
            }),
        },
    }
}

/// Which store was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreKind {
    /// The operating system's own credential store.
    Platform,
    /// The documented 0700 directory fallback.
    FileFallback,
}

/// Writes a device's four seeds, one item per purpose.
///
/// # Errors
///
/// Returns an error when the store rejects a write.
pub fn store_device_keys(store: &dyn SecretStore, scope: &str, keys: &DeviceKeys) -> Result<()> {
    store.set(
        &SecretName::device_key(scope, KeyPurpose::Transport)?,
        keys.transport.seed().expose(),
    )?;
    store.set(
        &SecretName::device_key(scope, KeyPurpose::Authorisation)?,
        keys.authorisation.seed().expose(),
    )?;
    store.set(
        &SecretName::device_key(scope, KeyPurpose::StoredEnvelope)?,
        keys.stored_envelope.seed().expose(),
    )?;
    store.set(
        &SecretName::device_key(scope, KeyPurpose::NotificationPreview)?,
        keys.notification_preview.seed().expose(),
    )?;
    Ok(())
}

/// Reads a device's four seeds back, or `None` when the device has no stored keys.
///
/// A partially written set is an error rather than a silent regeneration: regenerating one purpose
/// would change that public key and silently break every record that names it.
///
/// # Errors
///
/// Returns an error when the store fails, when a stored seed is the wrong length, or when some but
/// not all of the four items exist.
pub fn load_device_keys(store: &dyn SecretStore, scope: &str) -> Result<Option<DeviceKeys>> {
    let transport = store.get(&SecretName::device_key(scope, KeyPurpose::Transport)?)?;
    let authorisation = store.get(&SecretName::device_key(scope, KeyPurpose::Authorisation)?)?;
    let stored_envelope = store.get(&SecretName::device_key(scope, KeyPurpose::StoredEnvelope)?)?;
    let preview = store.get(&SecretName::device_key(
        scope,
        KeyPurpose::NotificationPreview,
    )?)?;

    let present = [&transport, &authorisation, &stored_envelope, &preview]
        .iter()
        .filter(|item| item.is_some())
        .count();
    if present == 0 {
        return Ok(None);
    }
    if present != 4 {
        return Err(CryptoError::SecretStore {
            message: format!("{scope} has {present} of 4 device key items stored"),
        });
    }
    let unwrap = |item: Option<SecretVec>| item.expect("all four items are present");
    Ok(Some(DeviceKeys {
        transport: TransportIdentityKeyPair::from_seed(TransportSeed::from_stored_bytes(
            unwrap(transport).expose(),
        )?)?,
        authorisation: AuthorisationKeyPair::from_seed(AuthorisationSeed::from_stored_bytes(
            unwrap(authorisation).expose(),
        )?)?,
        stored_envelope: StoredEnvelopeKeyPair::from_seed(StoredEnvelopeSeed::from_stored_bytes(
            unwrap(stored_envelope).expose(),
        )?)?,
        notification_preview: NotificationPreviewKeyPair::from_seed(
            NotificationPreviewSeed::from_stored_bytes(unwrap(preview).expose())?,
        )?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_rejects_traversal_and_uppercase() {
        assert!(SecretName::new("host/device-key/transport").is_ok());
        assert!(SecretName::new("host/device-key/stored_envelope").is_ok());
        assert!(SecretName::new("host/device key").is_err());
        assert!(SecretName::new("host/../escape").is_err());
        assert!(SecretName::new("Host/device-key").is_err());
        assert!(SecretName::new("/host").is_err());
        assert!(SecretName::new("host/").is_err());
        assert!(SecretName::new("").is_err());
        assert!(SecretName::new("a".repeat(MAX_SECRET_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn the_memory_store_round_trips_and_deletes() {
        let store = MemoryStore::new();
        let name = SecretName::new("host/recovery-seed").expect("a name");
        assert!(store.get(&name).expect("a read").is_none());
        store.set(&name, b"secret").expect("a write");
        assert_eq!(
            store.get(&name).expect("a read").expect("a value").expose(),
            b"secret"
        );
        store.delete(&name).expect("a delete");
        assert!(store.get(&name).expect("a read").is_none());
        store
            .delete(&name)
            .expect("deleting a missing item succeeds");
    }

    #[test]
    fn device_keys_round_trip_through_a_store() {
        let store = MemoryStore::new();
        let keys = DeviceKeys::generate().expect("keys");
        assert!(load_device_keys(&store, "host").expect("a read").is_none());
        store_device_keys(&store, "host", &keys).expect("a write");
        let loaded = load_device_keys(&store, "host")
            .expect("a read")
            .expect("the keys");
        assert_eq!(loaded.public_keys(), keys.public_keys());
    }

    #[test]
    fn a_partial_key_set_is_an_error_rather_than_a_silent_regeneration() {
        let store = MemoryStore::new();
        let keys = DeviceKeys::generate().expect("keys");
        store_device_keys(&store, "host", &keys).expect("a write");
        store
            .delete(&SecretName::device_key("host", KeyPurpose::StoredEnvelope).expect("a name"))
            .expect("a delete");
        assert!(load_device_keys(&store, "host").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_fallback_directory_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "kr-crypto-store-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let store = FileStore::open(&base).expect("a store");
        let name = SecretName::new("host/device-key/transport").expect("a name");
        store.set(&name, b"seed").expect("a write");

        let directory_mode = std::fs::metadata(store.directory())
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);

        let file = store.path(&name);
        let file_mode = std::fs::metadata(&file)
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        let parent_mode = std::fs::metadata(file.parent().expect("a parent"))
            .expect("parent metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent_mode, 0o700);

        assert_eq!(
            store.get(&name).expect("a read").expect("a value").expose(),
            b"seed"
        );
        store.delete(&name).expect("a delete");
        assert!(store.get(&name).expect("a read").is_none());
        let _ = std::fs::remove_dir_all(&base);
    }
}
