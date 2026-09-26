//! Secret storage.
//!
//! Section 10 stores secrets in the macOS and iOS Keychain, Android Keystore-protected storage,
//! Windows DPAPI or Credential Manager, and the Linux Secret Service. On Linux without a secret
//! service it uses a user-owned directory with mode 0700 and files with mode 0600, and documents
//! that this depends on operating-system account isolation and disk encryption.
//!
//! [`SecretStore`] is that choice as one interface. [`PlatformStore`] is the `keyring` crate,
//! which selects Keychain Services on macOS, the Credential Manager on Windows and the Secret
//! Service on other Unix systems; [`FileStore`] is the documented Linux fallback; [`MemoryStore`]
//! is for tests and never touches a disk.
//!
//! # Where the fallback is not allowed
//!
//! Section 10 names a protected store for every platform and offers the 0700 directory only on
//! Linux without a secret service. The fallback is therefore compiled out on macOS, iOS, Android
//! and Windows: on those platforms a missing platform store is an error, not a downgrade. iOS and
//! Android keys are held by the platform layer of the companion application, which owns Keychain
//! and Keystore access; this crate refuses rather than writing them to a file.
//!
//! # Where a test keeps its secrets
//!
//! A test, a bench or a demonstration run must never write to the person's own credential store.
//! An item written there belongs to the account rather than to the run, and outlives it: nothing
//! collects it afterwards, so every run would leave its keys behind. A run that needs a store on
//! disk therefore calls [`open_store_in`], which takes the directory to use and is the only way to
//! reach [`FileStore`] where section 10 offers no fallback; a daemon such a run starts is given
//! `--secret-store file`, which is the same choice made on its command line. [`open_store`] is the
//! door a host uses, and it never returns the directory store where section 10 does not offer it.
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
/// Names are restricted to lower-case ASCII, digits, `.`, `-`, `_` and `/`, and no segment starts
/// with a dot, so a name is a safe file name in the fallback store and a safe account name in a
/// platform store. The dot rule is what keeps a secret from colliding with the fallback store's
/// own staging files and marker, which all start with one.
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
        if name.starts_with('/')
            || name.ends_with('/')
            || name
                .split('/')
                .any(|part| part.is_empty() || part.starts_with('.'))
        {
            return Err(invalid(
                "a secret name has no empty segment and no segment starting with a dot",
            ));
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

    /// Returns the name of one synchronised collection's key, at one epoch, inside `scope`.
    ///
    /// A shared collection's key is not a device key. It belongs to the collection rather than to
    /// the device, every device that may read the collection holds the same one, and it is
    /// replaced when the set of devices that may read it changes. The epoch is part of the name
    /// for that reason: a device keeps the key of an epoch it still has objects from beside the
    /// key of the epoch it writes under, and neither can be mistaken for the other.
    ///
    /// # Errors
    ///
    /// Returns an error when the resulting name breaks a name rule, which is what a collection
    /// identifier spelled in anything but the lower-case form this store admits produces.
    pub fn collection_key(scope: &str, collection: &str, epoch: u64) -> Result<Self> {
        Self::new(format!("{scope}/collection-key/{collection}/{epoch}"))
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
/// macOS uses Keychain Services, Windows uses the Credential Manager and other Unix systems use
/// the Secret Service. This `keyring` version reports iOS and Android as unsupported, which is the
/// same answer section 10 gives: those keys belong to the platform layer of the companion
/// application, and this crate does not hold them.
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
        if !FILE_FALLBACK_SUPPORTED {
            return Err(CryptoError::SecretStore {
                message: "this platform has a protected credential store; the 0700 directory \
                          fallback is offered only on Unix systems without a secret service"
                    .to_owned(),
            });
        }
        let directory = directory.into();
        prepare_private_directory(&directory)?;
        Ok(Self { directory })
    }

    /// Opens the store in a directory the caller named, on any platform.
    ///
    /// This is the constructor [`open_store_in`] uses, and it is deliberately private: a caller
    /// that wants the directory store where section 10 offers no fallback has to say so through
    /// that one named function, and [`FileStore::open`] keeps refusing.
    fn at(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = prepare_named_directory(&directory.into())?;
        Ok(Self { directory })
    }

    /// Returns the directory secrets are written to.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn path(&self, name: &SecretName) -> PathBuf {
        // The name is validated, so no segment is empty, traverses or starts with a dot. A '/'
        // becomes a subdirectory, which keeps one scope's items together.
        let mut path = self.directory.clone();
        for part in name.as_str().split('/') {
            path.push(part);
        }
        path
    }

    /// Flushes each directory from the store's own down to `scope` into the one above it, so that
    /// each of their names survives a crash.
    fn flush_scope(&self, scope: &Path) -> Result<()> {
        let below = scope
            .strip_prefix(&self.directory)
            .map_err(|_| CryptoError::SecretStore {
                message: format!("{} is outside the store", scope.display()),
            })?;
        let mut above = self.directory.clone();
        for part in below.components() {
            flush(&above, kr_flush::NameKind::Directory)?;
            above.push(part);
        }
        Ok(())
    }

    /// Rejects a path whose own entry or any directory below the store root is a link.
    ///
    /// The root is checked when the store opens. Everything under it is checked on use, because a
    /// link that appears afterwards would otherwise redirect a write, a read or a deletion out of
    /// the directory whose mode is the only protection there is.
    fn reject_links(&self, path: &Path) -> Result<()> {
        // A component that does not exist yet is not a link, and `is_symlink` says so, so this
        // walk works before a scope directory has been created as well as after.
        let mut component = path;
        loop {
            if component == self.directory {
                return Ok(());
            }
            if component.is_symlink() {
                return Err(CryptoError::SecretStore {
                    message: format!("{} is a symbolic link", component.display()),
                });
            }
            match component.parent() {
                Some(parent) if parent != component => component = parent,
                _ => {
                    return Err(CryptoError::SecretStore {
                        message: format!("{} is outside the store", path.display()),
                    });
                }
            }
        }
    }
}

impl SecretStore for FileStore {
    fn set(&self, name: &SecretName, secret: &[u8]) -> Result<()> {
        let path = self.path(name);
        let Some(parent) = path.parent() else {
            return Err(CryptoError::SecretStore {
                message: "a secret path has a parent directory".to_owned(),
            });
        };
        // Nothing is created until the path is known to be inside the store: a link left where a
        // scope directory would go must not cause a directory to appear on the other side of it.
        self.reject_links(&path)?;
        std::fs::create_dir_all(parent).map_err(|error| CryptoError::SecretStore {
            message: format!("create {}: {error}", parent.display()),
        })?;
        self.reject_links(&path)?;
        set_mode(parent, 0o700)?;
        // A directory's name is an entry in the one above it, and a crash can undo a directory
        // made just now as it can undo a file's name. Every directory between the store's own and
        // the secret's is flushed into the one above it before the secret is written: the ones
        // this write made, and any an earlier write made and could not flush.
        self.flush_scope(parent)?;

        // The staging name starts with a dot, which no valid secret name can produce, and carries
        // the process and a counter, so two concurrent writes never share a file and a write never
        // destroys a secret that happens to be named like the staging file.
        let staging = parent.join(format!(
            ".{}.{}.{}.staging",
            std::process::id(),
            STAGING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            name.as_str().rsplit('/').next().unwrap_or("secret")
        ));
        write_owner_only(&staging, secret)?;
        // Rename replaces atomically, so a reader sees the old secret or the new one.
        let renamed = std::fs::rename(&staging, &path);
        if renamed.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        renamed.map_err(|error| CryptoError::SecretStore {
            message: format!("rename into {}: {error}", path.display()),
        })?;
        // Persist the directory entry, so a crash cannot leave the secret unreachable.
        sync_directory(parent)
    }

    fn get(&self, name: &SecretName) -> Result<Option<SecretVec>> {
        let path = self.path(name);
        if path.exists() || path.is_symlink() {
            self.reject_links(&path)?;
        }
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(SecretVec::new(bytes))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(CryptoError::SecretStore {
                message: error.to_string(),
            }),
        }
    }

    fn delete(&self, name: &SecretName) -> Result<()> {
        let path = self.path(name);
        if path.exists() || path.is_symlink() {
            self.reject_links(&path)?;
        }
        // Overwrite before unlinking. On a journalling or copy-on-write filesystem this is not a
        // guarantee, which is why the fallback is documented as depending on disk encryption.
        if let Ok(metadata) = std::fs::metadata(&path) {
            let len = usize::try_from(metadata.len()).unwrap_or(0);
            let mut zeroes = vec![0u8; len];
            let _ = std::fs::write(&path, &zeroes);
            sodium::memzero(&mut zeroes);
        }
        let Some(scope) = path.parent() else {
            return Err(CryptoError::SecretStore {
                message: "a secret path has a parent directory".to_owned(),
            });
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            // Nothing here to remove. A deletion before this one may have removed the name and
            // had its flush refused, so the directory is flushed all the same where it is one.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !std::fs::symlink_metadata(scope).is_ok_and(|scope| scope.is_dir()) {
                    return Ok(());
                }
            }
            Err(error) => {
                return Err(CryptoError::SecretStore {
                    message: error.to_string(),
                });
            }
        }
        // The name is gone, and stays gone across a crash once its directory is flushed.
        sync_directory(scope)
    }

    #[cfg(unix)]
    fn describe(&self) -> String {
        format!(
            "the 0700 fallback directory at {} (protected only by OS account isolation and disk encryption)",
            self.directory.display()
        )
    }

    #[cfg(not(unix))]
    fn describe(&self) -> String {
        format!(
            "the directory at {} (protected only by the access-control list it inherits)",
            self.directory.display()
        )
    }
}

/// True on the platforms where section 10 offers the 0700 directory fallback.
///
/// Those are Unix systems that are not macOS, iOS or Android: the ones whose protected store is
/// the Secret Service and may not have one. Everywhere else a missing platform store is an error.
pub const FILE_FALLBACK_SUPPORTED: bool = cfg!(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    ))
));

/// Creates or validates one owner-only directory, without following a link anywhere in its path.
///
/// An existing directory is validated before its mode is changed, so this never relaxes or
/// tightens something that belongs to another account, and the mode it sets is the mode of the
/// directory it believes it is writing to.
fn prepare_private_directory(directory: &Path) -> Result<()> {
    // Every component is checked before anything is created. `create_dir_all` on
    // `parent/link/new` would otherwise create `new` through the link and only then be rejected.
    reject_ancestor_links(directory)?;
    if directory.exists() {
        check_path_is_unresolved(directory)?;
        check_owner_only(directory)?;
    }
    make_directories(directory)?;
    check_path_is_unresolved(directory)?;
    set_mode(directory, 0o700)?;
    check_owner_only(directory)
}

/// Creates or validates one owner-only directory whose ancestors the caller vouches for.
///
/// [`prepare_private_directory`] refuses a directory any ancestor of which is a link, because the
/// store a host keeps its keys in is reached from that host's own root and nothing on the way may
/// be repointed. A directory a caller named is reached from wherever the caller put it. The usual
/// place is the system temporary directory, which on macOS is below `/var`, a link to
/// `/private/var`; the strict rule refuses that path, and refusing it would refuse the ordinary
/// case this door exists for.
///
/// So the named directory carries the rules the fallback root carries: it is not itself a link, it
/// is owner-only, and it gets mode 0700. Every path below it is checked against a link on every
/// read, write and deletion exactly as before. Its ancestors are checked for nothing, and the
/// caller is the one saying they can be trusted.
///
/// The name is reduced to its components first. `store/` and `store/.` name the same directory as
/// `store`, but the kernel resolves a trailing separator or `.` through a link before reporting on
/// it, so the leaf check would pass on a name the strict form rejects. The reduced path is what is
/// returned, and what the store then uses.
fn prepare_named_directory(directory: &Path) -> Result<PathBuf> {
    let directory: PathBuf = directory.components().collect();
    reject_link(&directory)?;
    if directory.exists() {
        check_owner_only(&directory)?;
    }
    make_directories(&directory)?;
    // Again after the creation: what exists now is what the mode below is set on.
    reject_link(&directory)?;
    set_mode(&directory, 0o700)?;
    check_owner_only(&directory)?;
    Ok(directory)
}

/// Makes `directory` and every missing directory above it, and flushes each one it made into the
/// directory above it, so that none of them is lost to a crash.
///
/// A directory that was already there is not flushed: the directory above the store's own is not
/// the store's, and this account may not be able to open it for a flush. So a flush that is refused
/// removes again every directory this call made, and a later call makes and flushes them afresh.
fn make_directories(directory: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut next = Some(directory);
    while let Some(path) = next.filter(|path| !path.as_os_str().is_empty()) {
        match std::fs::symlink_metadata(path) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(path);
                next = path.parent();
            }
            Err(error) => {
                return Err(CryptoError::SecretStore {
                    message: format!("read {}: {error}", path.display()),
                });
            }
        }
    }
    let mut made: Vec<&Path> = Vec::new();
    for path in missing.into_iter().rev() {
        match std::fs::create_dir(path) {
            Ok(()) => made.push(path),
            // Another writer made it meanwhile, and its own flush is that writer's to report.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(CryptoError::SecretStore {
                    message: format!("create {}: {error}", path.display()),
                });
            }
        }
        let above = path
            .parent()
            .filter(|above| !above.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if let Err(refused) = flush(above, kr_flush::NameKind::Directory) {
            for path in made.iter().rev() {
                let _ = std::fs::remove_dir(path);
            }
            return Err(refused);
        }
    }
    Ok(())
}

/// Rejects one path that is a symbolic link.
fn reject_link(path: &Path) -> Result<()> {
    if path.is_symlink() {
        return Err(CryptoError::SecretStore {
            message: format!("{} is a symbolic link", path.display()),
        });
    }
    Ok(())
}

/// Rejects a path if it, or any of its ancestors, is a symbolic link.
///
/// A component that does not exist yet is not a link, so this is meaningful before the directory
/// is created as well as after.
fn reject_ancestor_links(path: &Path) -> Result<()> {
    let mut component = Some(path);
    while let Some(current) = component {
        reject_link(current)?;
        component = current.parent().filter(|parent| *parent != current);
    }
    Ok(())
}

/// Rejects a path any component of which is a link.
fn check_path_is_unresolved(directory: &Path) -> Result<()> {
    let resolved = std::fs::canonicalize(directory).map_err(|error| CryptoError::SecretStore {
        message: format!("resolve {}: {error}", directory.display()),
    })?;
    if resolved != directory {
        return Err(CryptoError::SecretStore {
            message: format!(
                "{} resolves to {}; the store follows no links",
                directory.display(),
                resolved.display()
            ),
        });
    }
    Ok(())
}

/// Distinguishes the staging files of concurrent writers in one process.
static STAGING_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Creates `path` exclusively with mode 0600, writes `secret` and flushes it to the device.
#[cfg(unix)]
pub(crate) fn write_owner_only(path: &Path, secret: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| CryptoError::SecretStore {
            message: format!("create {}: {error}", path.display()),
        })?;
    file.write_all(secret)
        .and_then(|()| file.sync_all())
        .map_err(|error| CryptoError::SecretStore {
            message: format!("write {}: {error}", path.display()),
        })
}

/// Creates `path` exclusively, writes `secret` and flushes it to the device.
///
/// Windows has no mode bits, so the file carries the access-control list it inherits from the
/// directory it is created in. That is why section 10 offers no directory fallback there: the
/// protected store is the Credential Manager, and [`FileStore::open`] keeps refusing. This path is
/// reached only through [`open_store_in`], where the caller named a directory of its own and the
/// file is the caller's to protect.
#[cfg(not(unix))]
pub(crate) fn write_owner_only(path: &Path, secret: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| CryptoError::SecretStore {
            message: format!("create {}: {error}", path.display()),
        })?;
    file.write_all(secret)
        .and_then(|()| file.sync_all())
        .map_err(|error| CryptoError::SecretStore {
            message: format!("write {}: {error}", path.display()),
        })
}

/// Flushes the directory a file's name was just created, replaced or removed in, so the change
/// survives a crash.
pub(crate) fn sync_directory(directory: &Path) -> Result<()> {
    flush(directory, kr_flush::NameKind::File)
}

/// Flushes `directory` after a name of `kind` in it changed, and reports a flush that is refused.
fn flush(directory: &Path, kind: kr_flush::NameKind) -> Result<()> {
    kr_flush::flush_directory(directory, kind).map_err(|error| CryptoError::SecretStore {
        message: format!("sync {}: {error}", directory.display()),
    })
}

/// Rejects a fallback directory that another account owns or can read.
///
/// The ownership check compares the directory with a file this process creates inside it: a freshly
/// created file belongs to the effective user, so if the directory belongs to someone else the two
/// owners differ. That answers the question without calling `getuid`, which would mean an `unsafe`
/// call outside the one module allowed to make them.
#[cfg(unix)]
pub(crate) fn check_owner_only(directory: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::metadata(directory).map_err(|error| CryptoError::SecretStore {
        message: format!("stat {}: {error}", directory.display()),
    })?;
    if !metadata.is_dir() {
        return Err(CryptoError::SecretStore {
            message: format!("{} is not a directory", directory.display()),
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CryptoError::SecretStore {
            message: format!("{} is readable by another account", directory.display()),
        });
    }

    let probe = directory.join(format!(
        ".{}.{}.owner-probe",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    write_owner_only(&probe, b"")?;
    let probe_uid = std::fs::metadata(&probe).map(|probe| probe.uid());
    let _ = std::fs::remove_file(&probe);
    let probe_uid = probe_uid.map_err(|error| CryptoError::SecretStore {
        message: format!("stat {}: {error}", probe.display()),
    })?;
    if metadata.uid() != probe_uid {
        return Err(CryptoError::SecretStore {
            message: format!("{} is owned by another account", directory.display()),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_owner_only(_directory: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|error| {
        CryptoError::SecretStore {
            message: format!("set mode {mode:o} on {}: {error}", path.display()),
        }
    })
}

/// Windows has no mode bits, so there is nothing to set.
///
/// A directory reached through [`open_store_in`] there carries the access-control list it inherits
/// from its parent. Section 10 offers no directory fallback on Windows for that reason, and
/// [`FileStore::open`] keeps refusing.
#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// An in-memory store for tests. It never writes to a disk.
#[derive(Default)]
pub struct MemoryStore {
    items: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.items.lock().map(|items| items.len()).unwrap_or(0);
        write!(formatter, "MemoryStore({count} items, redacted)")
    }
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
        if let Some(mut replaced) = items.insert(name.as_str().to_owned(), secret.to_vec()) {
            sodium::memzero(&mut replaced);
        }
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
/// Once a host has secrets in the fallback directory it keeps using them, even if a secret service
/// appears later. Switching on the strength of whichever backend happens to work today would leave
/// the application looking at an empty platform store while its keys sat in files. The result says
/// a migration is available; moving the secrets is an explicit, verified step the host takes, not
/// something that happens at startup.
///
/// # Errors
///
/// Returns [`CryptoError::SecretStore`] when neither store can be opened.
pub fn open_store(service: &str, fallback_directory: &Path) -> Result<OpenedStore> {
    if !FILE_FALLBACK_SUPPORTED {
        // There is no fallback on this platform, so there is nothing to record and nothing to
        // choose between: the protected store is the only store.
        let store = PlatformStore::open(service)?;
        return Ok(OpenedStore {
            store: Box::new(store),
            kind: StoreKind::Platform,
            migration_available: false,
        });
    }
    let platform = PlatformStore::open(service);
    let recorded = match read_recorded_kind(fallback_directory)? {
        Some(kind) => Some(kind),
        // No record, but secrets are already in the fallback: that is where they stay.
        None if fallback_holds_secrets(fallback_directory)? => Some(StoreKind::FileFallback),
        None => None,
    };
    match recorded {
        Some(StoreKind::Platform) => {
            // The host's secrets are in the platform store. If it has gone away this is an error:
            // falling back would start from an empty store while the secrets still exist.
            let store = platform.map_err(|error| CryptoError::SecretStore {
                message: format!(
                    "this host recorded the platform credential store, which is now unavailable: {error}"
                ),
            })?;
            Ok(OpenedStore {
                store: Box::new(store),
                kind: StoreKind::Platform,
                migration_available: false,
            })
        }
        Some(StoreKind::FileFallback) => {
            // The host's secrets are in files and stay there, even when a secret service appears.
            let store = FileStore::open(fallback_directory)?;
            record_kind(fallback_directory, StoreKind::FileFallback)?;
            Ok(OpenedStore {
                store: Box::new(store),
                kind: StoreKind::FileFallback,
                migration_available: platform.is_ok(),
            })
        }
        None => match platform {
            Ok(store) => {
                record_kind(fallback_directory, StoreKind::Platform)?;
                Ok(OpenedStore {
                    store: Box::new(store),
                    kind: StoreKind::Platform,
                    migration_available: false,
                })
            }
            Err(platform_error) => match FileStore::open(fallback_directory) {
                Ok(store) => {
                    record_kind(fallback_directory, StoreKind::FileFallback)?;
                    Ok(OpenedStore {
                        store: Box::new(store),
                        kind: StoreKind::FileFallback,
                        migration_available: false,
                    })
                }
                Err(fallback_error) => Err(CryptoError::SecretStore {
                    message: format!(
                        "no platform store ({platform_error}) and no fallback ({fallback_error})"
                    ),
                }),
            },
        },
    }
}

/// Which store a host was told to keep its secrets in.
///
/// An installed host takes [`Self::Platform`], and nothing has to say so. A test, a bench or a
/// demonstration run takes [`Self::File`] and has to name it, on a command line or in the setup of
/// the daemon it starts, every time. The selection is not recorded anywhere: it is the caller's,
/// made at each start, and [`open_store`]'s own `.store-kind` record continues to answer for the
/// host rather than for a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreSelection {
    /// The operating system's credential store, with the fallback section 10 offers where it does.
    Platform,
    /// The directory this environment keeps its secrets in, named deliberately.
    File,
}

impl StoreSelection {
    /// Opens the store this selection names, for a host whose secrets directory is `directory`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SecretStore`] when the selected store cannot be opened.
    pub fn open(self, service: &str, directory: &Path) -> Result<OpenedStore> {
        match self {
            Self::Platform => open_store(service, directory),
            Self::File => open_store_in(directory),
        }
    }
}

/// Opens a directory store at the directory the caller names, on any platform.
///
/// [`open_store`] decides which store belongs to a host and offers the directory only where
/// section 10 allows it, so on macOS, iOS, Android and Windows it returns the platform's own
/// credential store or it fails. This takes the directory as an argument instead, and it is the
/// only way to reach a [`FileStore`] on those platforms. A test harness, a bench and a daemon
/// started with `--secret-store file` use it, so a run keeps its device keys in a directory it
/// owns and throws away rather than in the person's own credential store.
///
/// The directory must not be a link, and every path below it is checked against a link on every
/// use. On Unix it is created with mode 0700 and refused unless it belongs to this account.
/// Windows has no mode bits and this crate sets no access-control list, so a directory there
/// carries the one it inherits and the caller is the one protecting it; that is part of why
/// section 10 offers no fallback on Windows. The directory's ancestors are checked for nothing on
/// any platform, which is what lets a run keep its secrets under the system temporary directory.
///
/// It records nothing in the directory. The `.store-kind` marker is [`open_store`]'s record of a
/// choice it made for a host; this choice is not made once and remembered, it is passed in at
/// every start, and a marker claiming a backend [`open_store`] would not pick would be a record
/// that lies.
///
/// # Errors
///
/// Returns [`CryptoError::SecretStore`] when the directory is a link, cannot be created, or on
/// Unix belongs to another account or cannot be made owner-only.
pub fn open_store_in(directory: &Path) -> Result<OpenedStore> {
    Ok(OpenedStore {
        store: Box::new(FileStore::at(directory)?),
        kind: StoreKind::FileFallback,
        migration_available: false,
    })
}

/// The file that records which store a host chose.
///
/// It starts with a dot, which no valid [`SecretName`] can produce, so it can never collide with a
/// stored secret. It carries no secret itself: it names a backend.
const STORE_KIND_MARKER: &str = ".store-kind";

/// The longest a valid marker is. Anything larger is a damaged or foreign file.
const MAX_MARKER_LEN: u64 = 64;

/// Reads the recorded choice.
///
/// `None` means this host has not chosen yet. A marker that cannot be read, is too large or holds
/// anything but a known backend name is an error: it is the record of where a host's secrets live,
/// and guessing would be guessing which store to start from.
fn read_recorded_kind(directory: &Path) -> Result<Option<StoreKind>> {
    let path = directory.join(STORE_KIND_MARKER);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CryptoError::SecretStore {
                message: format!("read {}: {error}", path.display()),
            });
        }
    };
    if !metadata.is_file() {
        return Err(CryptoError::SecretStore {
            message: format!("{} is not a regular file", path.display()),
        });
    }
    if metadata.len() > MAX_MARKER_LEN {
        return Err(CryptoError::SecretStore {
            message: format!(
                "{} is {} bytes; it is damaged",
                path.display(),
                metadata.len()
            ),
        });
    }
    let text = std::fs::read_to_string(&path).map_err(|error| CryptoError::SecretStore {
        message: format!("read {}: {error}", path.display()),
    })?;
    match text.trim() {
        "platform" => Ok(Some(StoreKind::Platform)),
        "file" => Ok(Some(StoreKind::FileFallback)),
        other => Err(CryptoError::SecretStore {
            message: format!("{} names an unknown store {other:?}", path.display()),
        }),
    }
}

/// Records the choice so a later start does not silently pick the other backend.
///
/// The write goes through the same owner-only, exclusive, durable path a secret does, so a crash
/// leaves either the old record or the new one, a link cannot redirect it, and two processes
/// racing to record cannot interleave.
fn record_kind(directory: &Path, kind: StoreKind) -> Result<()> {
    prepare_private_directory(directory)?;

    let text = match kind {
        StoreKind::Platform => "platform",
        StoreKind::FileFallback => "file",
    };
    let staging = directory.join(format!(
        ".{}.{}.store-kind.staging",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    write_owner_only(&staging, text.as_bytes())?;
    let renamed = std::fs::rename(&staging, directory.join(STORE_KIND_MARKER));
    if renamed.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    renamed.map_err(|error| CryptoError::SecretStore {
        message: format!(
            "record the store choice in {}: {error}",
            directory.display()
        ),
    })?;
    sync_directory(directory)
}

/// Returns true when the fallback directory holds anything but the store's own dotted files.
///
/// A host that predates the marker, or whose marker was removed, still has its secrets where it
/// left them. That is what decides the backend when there is no record to read.
fn fallback_holds_secrets(directory: &Path) -> Result<bool> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        // A directory that cannot be read might hold this host's secrets. Reporting "no secrets"
        // would send the host to another backend and start it from nothing.
        Err(error) => {
            return Err(CryptoError::SecretStore {
                message: format!("read {}: {error}", directory.display()),
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| CryptoError::SecretStore {
            message: format!("read an entry of {}: {error}", directory.display()),
        })?;
        if !entry.file_name().to_string_lossy().starts_with('.') {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The store a host opened and what it means.
pub struct OpenedStore {
    /// The store.
    pub store: Box<dyn SecretStore>,
    /// Which store it is.
    pub kind: StoreKind,
    /// True when the host is using the fallback although a platform store is now available.
    ///
    /// Setup reports this. Moving the secrets is a separate, verified step.
    pub migration_available: bool,
}

impl fmt::Debug for OpenedStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedStore")
            .field("kind", &self.kind)
            .field("migration_available", &self.migration_available)
            .field("store", &self.store.describe())
            .finish()
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
    let transport = unwrap(transport);
    let authorisation = unwrap(authorisation);
    let stored_envelope = unwrap(stored_envelope);
    let preview = unwrap(preview);

    // Two purposes sharing a seed is a reused private key, which section 10 forbids. The public
    // keys would differ, because the two algorithms differ, so nothing downstream would notice.
    let seeds = [&transport, &authorisation, &stored_envelope, &preview];
    for (index, left) in seeds.iter().enumerate() {
        if seeds[index + 1..]
            .iter()
            .any(|right| sodium::constant_time_eq(left.expose(), right.expose()))
        {
            return Err(CryptoError::SecretStore {
                message: format!("{scope} stores one seed under two key purposes"),
            });
        }
    }

    Ok(Some(DeviceKeys {
        transport: TransportIdentityKeyPair::from_seed(TransportSeed::from_stored_bytes(
            transport.expose(),
        )?)?,
        authorisation: AuthorisationKeyPair::from_seed(AuthorisationSeed::from_stored_bytes(
            authorisation.expose(),
        )?)?,
        stored_envelope: StoredEnvelopeKeyPair::from_seed(StoredEnvelopeSeed::from_stored_bytes(
            stored_envelope.expose(),
        )?)?,
        notification_preview: NotificationPreviewKeyPair::from_seed(
            NotificationPreviewSeed::from_stored_bytes(preview.expose())?,
        )?,
    }))
}

/// Reads only the notification-preview keypair.
///
/// The notification extension receives that private key and paired sender public keys, and no
/// general stored-envelope, archive, recovery or control-signing private key. It therefore needs a
/// loader that reads one item: [`load_device_keys`] reads all four and is for the host.
///
/// # Errors
///
/// Returns an error when the store fails or the stored seed is not 32 bytes.
pub fn load_notification_preview_key(
    store: &dyn SecretStore,
    scope: &str,
) -> Result<Option<NotificationPreviewKeyPair>> {
    let name = SecretName::device_key(scope, KeyPurpose::NotificationPreview)?;
    let Some(stored) = store.get(&name)? else {
        return Ok(None);
    };
    NotificationPreviewKeyPair::from_seed(NotificationPreviewSeed::from_stored_bytes(
        stored.expose(),
    )?)
    .map(Some)
}

/// Writes the recovery seed to its own item.
///
/// # Errors
///
/// Returns an error when the store rejects the write.
pub fn store_recovery_seed(
    store: &dyn SecretStore,
    scope: &str,
    seed: &crate::kdf::RecoverySeed,
) -> Result<()> {
    store.set(&SecretName::recovery_seed(scope)?, seed.expose())
}

/// Reads the recovery seed back, or `None` when the host has none.
///
/// # Errors
///
/// Returns an error when the store fails or the stored value is not 32 bytes.
pub fn load_recovery_seed(
    store: &dyn SecretStore,
    scope: &str,
) -> Result<Option<crate::kdf::RecoverySeed>> {
    let Some(stored) = store.get(&SecretName::recovery_seed(scope)?)? else {
        return Ok(None);
    };
    crate::kdf::RecoverySeed::from_stored_bytes(stored.expose()).map(Some)
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
        assert!(SecretName::new("host/.staging").is_err());
        assert!(SecretName::new(".store-kind").is_err());
        assert!(SecretName::new("host//x").is_err());
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

    /// KR-REQ-10.03: one stored seed under two purposes is refused rather than loaded.
    #[test]
    fn a_seed_shared_across_two_purposes_is_rejected() {
        let store = MemoryStore::new();
        let keys = DeviceKeys::generate().expect("keys");
        store_device_keys(&store, "host", &keys).expect("a write");
        let shared = store
            .get(&SecretName::device_key("host", KeyPurpose::Transport).expect("a name"))
            .expect("a read")
            .expect("a value");
        store
            .set(
                &SecretName::device_key("host", KeyPurpose::Authorisation).expect("a name"),
                shared.expose(),
            )
            .expect("a write");
        assert!(load_device_keys(&store, "host").is_err());
    }

    #[test]
    fn the_notification_extension_loads_only_its_own_key() {
        let store = MemoryStore::new();
        let keys = DeviceKeys::generate().expect("keys");
        store_device_keys(&store, "host", &keys).expect("a write");
        let preview = load_notification_preview_key(&store, "host")
            .expect("a read")
            .expect("the preview key");
        assert_eq!(preview.public(), keys.notification_preview.public());
        assert!(
            load_notification_preview_key(&store, "other")
                .expect("a read")
                .is_none()
        );
    }

    #[test]
    fn a_recovery_seed_round_trips_through_a_store() {
        let store = MemoryStore::new();
        assert!(
            load_recovery_seed(&store, "host")
                .expect("a read")
                .is_none()
        );
        let seed = crate::kdf::RecoverySeed::generate().expect("a seed");
        store_recovery_seed(&store, "host", &seed).expect("a write");
        let loaded = load_recovery_seed(&store, "host")
            .expect("a read")
            .expect("the seed");
        assert_eq!(loaded.checksum(), seed.checksum());
    }

    #[test]
    fn the_memory_store_redacts_its_contents() {
        let store = MemoryStore::new();
        store
            .set(&SecretName::new("host/x").expect("a name"), b"secret")
            .expect("a write");
        let rendered = format!("{store:?}");
        assert_eq!(rendered, "MemoryStore(1 items, redacted)");
        assert!(!rendered.contains("secret"));
    }

    /// A directory only this test uses, under the system temporary directory.
    fn scratch_directory(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "kr-crypto-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        base
    }

    /// KR-REQ-10.47: the directory fallback exists only on Linux; every other platform uses its
    /// protected store or fails.
    #[test]
    fn the_fallback_is_offered_only_where_section_10_offers_it() {
        // macOS, iOS, Android and Windows always have a protected store, so a missing one is an
        // error rather than a downgrade to files.
        assert_eq!(
            FILE_FALLBACK_SUPPORTED,
            cfg!(all(
                unix,
                not(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "android"
                ))
            ))
        );
        if !FILE_FALLBACK_SUPPORTED {
            let base =
                std::env::temp_dir().join(format!("kr-crypto-refused-{}", std::process::id()));
            assert!(FileStore::open(&base).is_err());
        }
    }

    /// The seam a test, a bench or a demonstration run keeps its secrets in.
    ///
    /// It has to work on every platform the host runs on, including the two whose credential store
    /// section 10 makes the only one a host may use. It also has to leave no `.store-kind` record:
    /// a later `open_store` on the same directory answers about this host, not about a run that
    /// named a directory once.
    #[test]
    fn a_named_directory_is_a_store_on_every_platform() {
        let base = scratch_directory("named");
        let opened = open_store_in(&base).expect("a store in the named directory");
        assert_eq!(opened.kind, StoreKind::FileFallback);
        assert!(!opened.migration_available);
        let name = SecretName::new("host/x").expect("a name");
        opened.store.set(&name, b"seed").expect("a write");
        assert_eq!(
            opened
                .store
                .get(&name)
                .expect("a read")
                .expect("a value")
                .expose(),
            b"seed"
        );
        assert!(
            base.join("host").join("x").is_file(),
            "the secret is a file in the directory the caller named"
        );
        assert!(
            !base.join(STORE_KIND_MARKER).exists(),
            "naming a directory for one run is not a choice recorded against this host"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// KR-REQ-10.47: a secret's name, and the store's record of its choice, are flushed into their
    /// directory through a handle that may add a file to it. While a handle that shares no writing
    /// holds the directory, the flush is refused and says so, where a flush that did nothing would
    /// report the name durable; once it is let go, the same flush is made.
    #[cfg(windows)]
    #[test]
    fn a_name_whose_directory_cannot_be_flushed_is_reported() {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// The right to list a directory, which is all the handle holds.
        const FILE_LIST_DIRECTORY: u32 = 0x0001;
        /// Reading is shared with other handles.
        const FILE_SHARE_READ: u32 = 0x0001;
        /// Deleting is shared; writing is not.
        const FILE_SHARE_DELETE: u32 = 0x0004;
        /// What lets a program open a directory at all.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

        let base = scratch_directory("held");
        let opened = open_store_in(&base).expect("a store in the named directory");
        let name = SecretName::new("host/x").expect("a name");
        opened.store.set(&name, b"seed").expect("a write");
        let scope = base.join("host");
        let holding = std::fs::OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&scope)
            .expect("the directory is held");
        let refused = sync_directory(&scope).expect_err("the flush is refused while it is held");
        assert!(
            matches!(refused, CryptoError::SecretStore { ref message } if message.starts_with("sync ")),
            "{refused}"
        );
        drop(holding);
        sync_directory(&scope).expect("and made once it is let go");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Refuses every flush of one directory until it is dropped, while names can still be created
    /// and removed in it.
    ///
    /// A flush opens the directory itself. On Windows a handle that shares no writing holds it, and
    /// the flush's open, which holds a right to add to the directory, has to be shared that. On
    /// macOS and Linux the directory's read permission is taken away and its write and search
    /// permissions stay: the flush's open reads the directory, and a creation or a removal of a name
    /// in it only writes and searches it.
    struct FlushRefused {
        #[cfg(windows)]
        _holding: std::fs::File,
        #[cfg(unix)]
        directory: PathBuf,
        #[cfg(unix)]
        mode: u32,
    }

    impl FlushRefused {
        #[cfg(windows)]
        fn on(directory: &Path) -> Self {
            use std::os::windows::fs::OpenOptionsExt as _;

            /// The right to list a directory, which is all the handle holds.
            const FILE_LIST_DIRECTORY: u32 = 0x0001;
            /// Reading is shared with other handles.
            const FILE_SHARE_READ: u32 = 0x0001;
            /// Deleting is shared; writing is not.
            const FILE_SHARE_DELETE: u32 = 0x0004;
            /// What lets a program open a directory at all.
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

            let holding = std::fs::OpenOptions::new()
                .access_mode(FILE_LIST_DIRECTORY)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(directory)
                .expect("the directory is held");
            Self { _holding: holding }
        }

        #[cfg(unix)]
        fn on(directory: &Path) -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = std::fs::metadata(directory)
                .expect("the directory's mode")
                .permissions()
                .mode()
                & 0o7777;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o300))
                .expect("write and search only");
            let refused = Self {
                directory: directory.to_path_buf(),
                mode,
            };
            // An account whose privilege overrides the mode would be let through, and for it this
            // arrangement cannot be made.
            assert_eq!(
                std::fs::File::open(directory)
                    .expect_err("a directory without read permission does not open")
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            refused
        }
    }

    #[cfg(unix)]
    impl Drop for FlushRefused {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;

            let _ = std::fs::set_permissions(
                &self.directory,
                std::fs::Permissions::from_mode(self.mode),
            );
        }
    }

    /// Whether `error` is a flush the store reports as refused.
    fn is_refused_flush(error: &CryptoError) -> bool {
        matches!(error, CryptoError::SecretStore { message } if message.starts_with("sync "))
    }

    /// KR-REQ-10.47: a secret set in a scope that has no directory yet makes that directory, and
    /// each directory made for it is flushed into the one above it before the secret is written. A
    /// flush that is refused is reported, where a store that never flushed a directory it made would
    /// report the secret stored while a crash could take the directory, and the secret in it, away.
    /// With nothing held, the same writes succeed and read back.
    #[test]
    fn each_directory_made_for_a_secret_is_flushed_into_the_one_above_it() {
        let base = scratch_directory("made");
        let opened = open_store_in(&base).expect("a store in the named directory");

        // A scope of one directory, made in the store's own.
        let first = SecretName::new("host/x").expect("a name");
        let refused = {
            let _refused = FlushRefused::on(&base);
            opened
                .store
                .set(&first, b"seed")
                .expect_err("the directory made in the store's own is not flushed into it")
        };
        assert!(is_refused_flush(&refused), "{refused}");
        assert!(
            opened.store.get(&first).expect("a read").is_none(),
            "nothing is stored in a directory that is not flushed"
        );
        opened
            .store
            .set(&first, b"seed")
            .expect("with nothing held, the same secret is stored");

        // A scope two deep whose first directory is there already: the second is made in it.
        let nested = SecretName::new("host/device-key/transport").expect("a name");
        let refused = {
            let _refused = FlushRefused::on(&base.join("host"));
            opened
                .store
                .set(&nested, b"key")
                .expect_err("the directory made in the scope's is not flushed into it")
        };
        assert!(is_refused_flush(&refused), "{refused}");
        assert!(
            opened.store.get(&nested).expect("a read").is_none(),
            "nothing is stored in a directory that is not flushed"
        );
        opened
            .store
            .set(&nested, b"key")
            .expect("with nothing held, the nested secret is stored");
        for (name, secret) in [(&first, &b"seed"[..]), (&nested, &b"key"[..])] {
            assert_eq!(
                opened
                    .store
                    .get(name)
                    .expect("a read")
                    .expect("a value")
                    .expose(),
                secret
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// KR-REQ-10.47: the store's own directory, made when the store is opened, is flushed into the
    /// directory above it before the store is used. A flush that is refused is reported and the
    /// directory it could not flush is removed again, so that the next opening makes and flushes it;
    /// with nothing held, the store opens. The same holds for the owner-only fallback where section
    /// 10 offers it.
    #[test]
    fn a_store_directory_made_when_the_store_opens_is_flushed_into_the_one_above_it() {
        let above = scratch_directory("above");
        std::fs::create_dir(&above).expect("the directory above the store's");
        let base = above.join("store");
        let refused = {
            let _refused = FlushRefused::on(&above);
            open_store_in(&base)
                .expect_err("the store's directory is not flushed into the one above it")
        };
        assert!(is_refused_flush(&refused), "{refused}");
        assert!(
            !base.exists(),
            "the directory it could not flush is removed again"
        );
        let opened = open_store_in(&base).expect("with nothing held, the store opens");
        let name = SecretName::new("host/x").expect("a name");
        opened.store.set(&name, b"seed").expect("a write");

        if FILE_FALLBACK_SUPPORTED {
            let fallback = above.join("fallback");
            let refused = {
                let _refused = FlushRefused::on(&above);
                FileStore::open(&fallback)
                    .expect_err("the fallback's directory is not flushed into the one above it")
            };
            assert!(is_refused_flush(&refused), "{refused}");
            assert!(
                !fallback.exists(),
                "the directory it could not flush is removed again"
            );
            FileStore::open(&fallback).expect("with nothing held, the fallback opens");
        }
        let _ = std::fs::remove_dir_all(&above);
    }

    /// KR-REQ-10.47: a deleted secret's name is flushed out of its directory before the deletion is
    /// reported. A flush that is refused is reported, where a store that never flushed the removal
    /// would report the secret gone while a crash could bring its name back. With nothing held, a
    /// deletion succeeds and the secret stays gone.
    #[test]
    fn a_deleted_secret_is_flushed_out_of_its_directory() {
        let base = scratch_directory("deleted");
        let opened = open_store_in(&base).expect("a store in the named directory");
        let name = SecretName::new("host/x").expect("a name");
        opened.store.set(&name, b"seed").expect("a write");

        let refused = {
            let _refused = FlushRefused::on(&base.join("host"));
            opened
                .store
                .delete(&name)
                .expect_err("the removal is not flushed out of the directory")
        };
        assert!(is_refused_flush(&refused), "{refused}");
        assert!(
            opened.store.get(&name).expect("a read").is_none(),
            "the name is gone, and only its flush was refused"
        );

        opened.store.set(&name, b"again").expect("a write");
        opened
            .store
            .delete(&name)
            .expect("with nothing held, the deletion is flushed");
        assert!(opened.store.get(&name).expect("a read").is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A name that reaches the store through a link is refused however it is spelled.
    ///
    /// A trailing separator or a `.` component makes the kernel resolve the link before it reports
    /// on the path, so `link/` and `link/.` name a directory the check on `link` rejects. The name
    /// is reduced to its components before anything looks at it, which is what makes the three
    /// spellings one answer.
    #[cfg(unix)]
    #[test]
    fn a_linked_name_is_refused_however_it_is_spelled() {
        let base = scratch_directory("linked");
        let real = base.join("real");
        let link = base.join("link");
        std::fs::create_dir_all(&real).expect("the directory the link points at");
        set_mode(&real, 0o700).expect("owner-only");
        std::os::unix::fs::symlink(&real, &link).expect("a link to it");
        for name in [
            link.clone(),
            link.join(""),
            link.join("."),
            PathBuf::from(format!("{}/", link.display())),
        ] {
            let refused = open_store_in(&name);
            assert!(
                refused.is_err(),
                "{} named the store through a link and was accepted",
                name.display()
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    #[test]
    fn a_recorded_fallback_is_not_abandoned() {
        let base = scratch_directory("migration");
        let store = FileStore::open(&base).expect("a store");
        store
            .set(&SecretName::new("host/x").expect("a name"), b"seed")
            .expect("a write");
        record_kind(&base, StoreKind::FileFallback).expect("a record");
        let opened = open_store("kalareach-test", &base).expect("a store");
        assert_eq!(opened.kind, StoreKind::FileFallback);
        assert_eq!(
            opened
                .store
                .get(&SecretName::new("host/x").expect("a name"))
                .expect("a read")
                .expect("a value")
                .expose(),
            b"seed"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    /// KR-REQ-10.47: the Linux fallback is a 0700 directory holding 0600 files.
    #[test]
    fn the_fallback_directory_and_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let base = scratch_directory("store");
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
