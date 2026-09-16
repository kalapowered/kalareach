//! The relay tier's keys: one this host holds, two it only ever checks against.
//!
//! Section 17 puts three Ed25519 keys around a relay, and they are not interchangeable:
//!
//! | Key | Held by | Signs | Checked by |
//! | --- | --- | --- | --- |
//! | [`RelayInstanceKeyPair`] | one relay host | consumption receipts, its own registration | the service, against its registry |
//! | [`ServiceAdmissionKey`] | the managed service | relay leases and revocations | the relay, against its pinned list |
//! | Endpoint keys | the two peers | nothing here | the relay's own handshake |
//!
//! # Why this is a purpose of its own
//!
//! [`crate::keys`] gives a *device* four purpose-separated keys, holds their seeds where no caller
//! outside this crate can reach them, and stores them together through [`crate::store`]. A relay
//! instance key is none of those things. It is generated on a headless host at provisioning, kept
//! in one owner-only file that the `kr-relay` service account reads at every start, and its public
//! half is registered with the service, so regenerating it is a key rotation rather than a restart.
//! Borrowing a device's authorisation key for it would mean either exporting a seed the device
//! purposes deliberately hide, or writing three keys the relay never uses beside the one it does.
//!
//! # What this module does not give you
//!
//! There is no way to read the private half out. The keypair is opened, used to sign, and dropped;
//! its seed is zeroised with it. The relay host holds the file, and the file is all anybody needs
//! to hold: [`RelayInstanceKeyPair::open`] writes it once with mode 0600 through the same hardened
//! path the fallback secret store uses, and refuses to read one that is not owner-only or that is
//! reached through a symbolic link.
//!
//! Signing is domain-separated the same way everything else in this crate is: there is no function
//! that signs a bare message, only one that signs `CBOR([domain, object])`. A receipt therefore
//! cannot verify as a lease however the keys are shuffled.

use std::path::Path;

use kr_protocol::scalars::{AuthorisationKey, RelayInstanceKey, ServiceAdmissionKey, Signature64};
use serde::Serialize;

use crate::error::{CryptoError, Result};
use crate::secret::Secret;
use crate::sign::{SigningTranscript, sign, verify};
use crate::sodium;
use crate::store::{check_owner_only, set_mode, sync_directory, write_owner_only};

/// The file the relay instance key is kept in, inside the directory the caller names.
const INSTANCE_KEY_FILE: &str = "instance.key";

/// Bytes in the seed a relay instance key is derived from.
pub const RELAY_SEED_LEN: usize = 32;

/// The Ed25519 key one relay instance signs with.
///
/// It signs consumption receipts, which are the only evidence a bill rests on, and its own
/// registration, which is what proves to the service that the key it is being asked to record is
/// one a host actually holds.
#[derive(Debug, Clone)]
pub struct RelayInstanceKeyPair {
    expanded: Secret<64>,
    public: RelayInstanceKey,
}

impl RelayInstanceKeyPair {
    /// Generates a keypair that is never written anywhere.
    ///
    /// For tests and for the one-shot tools that need a key without a host to keep it on. A relay
    /// uses [`Self::open`], because a key it forgot at restart is a key the service is still
    /// checking its receipts against.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn generate() -> Result<Self> {
        Self::from_seed(Secret::random()?)
    }

    /// Opens the relay's key in `directory`, generating and writing it on the first run.
    ///
    /// The directory is created mode 0700 and the key file mode 0600, neither is reached through a
    /// symbolic link, and one whose permissions have been widened is refused rather than used. The
    /// seed is written once and never rewritten: a second key would silently invalidate every
    /// receipt the first one signed.
    ///
    /// This is a file rather than [`crate::store`]'s platform store on purpose. A device's keys
    /// belong to a person and go wherever that platform protects a person's secrets; a relay
    /// instance key belongs to a service account on a host with no login session, no keyring
    /// daemon and no user to unlock one. The file is the only place it can live, so the checks the
    /// fallback store makes about permissions and links are applied to it directly.
    ///
    /// The fallback store additionally refuses a path any *ancestor* of which is a link, which is
    /// right for a directory under somebody's home and wrong here: a service directory is named by
    /// the unit file and sits under paths the distribution links as it pleases. What is checked is
    /// what this key's safety actually rests on — the directory and the file are not themselves
    /// links, and neither is readable by anyone but its owner.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SecretStore`] when the directory or the file cannot be used safely,
    /// [`CryptoError::StoredSecretLength`] when what is there is not a seed, and a library error
    /// when libsodium fails.
    pub fn open(directory: &Path) -> Result<Self> {
        let owner = open_private_directory(directory)?;
        let path = directory.join(INSTANCE_KEY_FILE);

        match read_seed(&path, owner)? {
            Some(seed) => Self::from_seed(seed),
            None => {
                let seed = Secret::<RELAY_SEED_LEN>::random()?;
                publish_seed(directory, &path, seed.expose())?;
                // Read it back rather than trusting the write: whatever is on disk is what every
                // later start will use, and a key that differs from the one this process is about
                // to sign with would be discovered later, by a receipt that does not verify.
                match read_seed(&path, owner)? {
                    Some(written) => Self::from_seed(written),
                    None => Err(CryptoError::SecretStore {
                        message: format!("{} was not written", path.display()),
                    }),
                }
            }
        }
    }

    /// Derives the keypair from a fixed seed, for the published vectors.
    ///
    /// Crate-private, like the device purposes' seed constructors: a caller outside this crate
    /// that could build a key from raw bytes could build one from somebody else's seed.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub(crate) fn from_seed_bytes(seed: &[u8; RELAY_SEED_LEN]) -> Result<Self> {
        Self::from_seed(Secret::from_bytes(*seed))
    }

    /// Signs a transcript that has already been built, for the published vectors.
    pub(crate) fn sign_transcript(&self, transcript: &SigningTranscript) -> Result<Signature64> {
        let signature = sodium::sign_detached(transcript.as_bytes(), self.expanded.expose())?;
        Ok(Signature64::from_bytes(signature))
    }

    /// Derives the keypair from its seed, wiping the library's own copy of the expanded key.
    fn from_seed(seed: Secret<RELAY_SEED_LEN>) -> Result<Self> {
        let (public, mut expanded) = sodium::sign_seed_keypair(seed.expose())?;
        let held = Secret::from_bytes(expanded);
        // `expanded` is an array, so wrapping it copied it. Wipe the library's own copy.
        sodium::memzero(&mut expanded);
        Ok(Self {
            expanded: held,
            public: RelayInstanceKey::from_bytes(public),
        })
    }

    /// The public half, which is what `relay.instance.register` records.
    #[must_use]
    pub const fn public(&self) -> &RelayInstanceKey {
        &self.public
    }

    /// Signs `CBOR([domain, value])`.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the value is outside KR-CBOR-1, and a library error when
    /// libsodium fails.
    pub fn sign_object<T: Serialize>(&self, domain: &str, value: &T) -> Result<Signature64> {
        self.sign_transcript(&SigningTranscript::from_object(domain, value)?)
    }
}

/// Opens the key directory, refusing one that is unsafe rather than making it safe.
///
/// An existing directory is checked as it is found: widening its permissions to match the rule
/// would be repairing the very thing the rule is there to detect, and by then whatever could read
/// it has already had the chance. Only a directory this call creates has its mode set.
///
/// Returns the account that owns it, which [`check_owner_only`] has just proved is the account
/// this process runs as. That is what the key file is checked against, so neither check needs to
/// ask the operating system who this process is.
#[cfg(unix)]
fn open_private_directory(directory: &Path) -> Result<u32> {
    use std::os::unix::fs::MetadataExt as _;

    if directory.is_symlink() {
        return Err(CryptoError::SecretStore {
            message: format!("{} is a symbolic link", directory.display()),
        });
    }
    if directory.exists() {
        check_owner_only(directory)?;
    } else {
        std::fs::create_dir_all(directory).map_err(|error| CryptoError::SecretStore {
            message: format!("create {}: {error}", directory.display()),
        })?;
        set_mode(directory, 0o700)?;
        check_owner_only(directory)?;
    }
    Ok(std::fs::metadata(directory)
        .map_err(|error| CryptoError::SecretStore {
            message: format!("stat {}: {error}", directory.display()),
        })?
        .uid())
}

/// The relay tier runs on Unix hosts.
#[cfg(not(unix))]
fn open_private_directory(directory: &Path) -> Result<u32> {
    Err(CryptoError::SecretStore {
        message: format!(
            "{} cannot be protected on this platform; the relay runs on Unix hosts",
            directory.display()
        ),
    })
}

/// Reads the seed from `path`, or `None` when there is nothing there yet.
///
/// The file is opened without following a link and then checked through that open handle, so what
/// is checked is what is read: a link swapped in between a check and a read would otherwise let
/// somebody else's seed be read as this host's. It is refused unless it is a regular file, owned
/// by this account, readable by nobody else, and exactly a seed long, so nothing here blocks on a
/// device and nothing allocates for a file somebody made large.
#[cfg(unix)]
fn read_seed(path: &Path, owner: u32) -> Result<Option<Secret<RELAY_SEED_LEN>>> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CryptoError::SecretStore {
                message: format!("open {}: {error}", path.display()),
            });
        }
    };

    let metadata = file.metadata().map_err(|error| CryptoError::SecretStore {
        message: format!("stat {}: {error}", path.display()),
    })?;
    if !metadata.is_file() {
        return Err(CryptoError::SecretStore {
            message: format!("{} is not a regular file", path.display()),
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CryptoError::SecretStore {
            message: format!("{} is readable by another account", path.display()),
        });
    }
    if metadata.uid() != owner {
        return Err(CryptoError::SecretStore {
            message: format!("{} is owned by another account", path.display()),
        });
    }
    if metadata.len() != RELAY_SEED_LEN as u64 {
        return Err(CryptoError::StoredSecretLength {
            name: INSTANCE_KEY_FILE.to_owned(),
            expected: RELAY_SEED_LEN,
            actual: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
        });
    }

    // Into a fixed buffer rather than a growing one: a heap allocation the seed passed through
    // would outlive this function unwiped, which section 20 does not allow.
    let mut bytes = [0u8; RELAY_SEED_LEN];
    let read = (&file).read_exact(&mut bytes);
    let seed = Secret::from_bytes(bytes);
    sodium::memzero(&mut bytes);
    read.map_err(|error| CryptoError::SecretStore {
        message: format!("read {}: {error}", path.display()),
    })?;
    Ok(Some(seed))
}

/// The relay tier runs on Unix hosts; elsewhere there is no owner-only file to read.
#[cfg(not(unix))]
fn read_seed(path: &Path, _owner: u32) -> Result<Option<Secret<RELAY_SEED_LEN>>> {
    Err(CryptoError::SecretStore {
        message: format!(
            "{} cannot be protected on this platform; the relay runs on Unix hosts",
            path.display()
        ),
    })
}

/// `O_NOFOLLOW`, without taking a dependency on a libc binding for one constant.
#[cfg(unix)]
const fn libc_o_nofollow() -> i32 {
    // The value is fixed by each platform's ABI. Linux and the BSDs, including macOS, are the
    // systems a relay runs on.
    #[cfg(target_os = "linux")]
    {
        0o400_000
    }
    #[cfg(not(target_os = "linux"))]
    {
        0x0100
    }
}

/// Writes the seed to a staging file, flushes it, and publishes it without replacing a key.
///
/// The final name appears only once its contents are on the device, so a crash halfway through the
/// first start leaves no truncated key for every later start to fail on. Publishing with a link
/// rather than a rename is what makes it refuse to replace an existing key: a second process that
/// got there first keeps its key, and this one reads that instead.
#[cfg(unix)]
fn publish_seed(directory: &Path, path: &Path, seed: &[u8]) -> Result<()> {
    let staging = directory.join(format!(
        ".{}.{}.instance-key",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    write_owner_only(&staging, seed)?;
    let linked = std::fs::hard_link(&staging, path);
    let _ = std::fs::remove_file(&staging);
    match linked {
        Ok(()) => sync_directory(directory),
        // Somebody else published one first. Theirs is the key this host has, and the caller reads
        // it back rather than overwriting it.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(CryptoError::SecretStore {
            message: format!("publish {}: {error}", path.display()),
        }),
    }
}

/// The relay tier runs on Unix hosts.
#[cfg(not(unix))]
fn publish_seed(_directory: &Path, path: &Path, _seed: &[u8]) -> Result<()> {
    Err(CryptoError::SecretStore {
        message: format!(
            "{} cannot be protected on this platform; the relay runs on Unix hosts",
            path.display()
        ),
    })
}

/// Verifies a signature a relay instance made over `CBOR([domain, value])`.
///
/// The caller decides which key to ask about, and that decision is the whole of the authority: a
/// receipt is evidence because the key it verifies under is the one the registry holds for that
/// instance at that time, not because the receipt says so.
///
/// # Errors
///
/// Returns an encoding error when the value is outside KR-CBOR-1, and
/// [`CryptoError::Authentication`] when the signature does not verify.
pub fn verify_relay_object<T: Serialize>(
    key: &RelayInstanceKey,
    domain: &str,
    value: &T,
    signature: &Signature64,
) -> Result<()> {
    verify(
        &AuthorisationKey::from_bytes(*key.as_bytes()),
        &SigningTranscript::from_object(domain, value)?,
        signature,
    )
}

/// Verifies a signature the managed service made over `CBOR([domain, value])`.
///
/// A relay calls this for a lease or a revocation, having first checked that the key is one it
/// pins. Both halves are needed: a valid signature by a key nobody pinned authorises nothing.
///
/// # Errors
///
/// Returns an encoding error when the value is outside KR-CBOR-1, and
/// [`CryptoError::Authentication`] when the signature does not verify.
pub fn verify_admission_object<T: Serialize>(
    key: &ServiceAdmissionKey,
    domain: &str,
    value: &T,
    signature: &Signature64,
) -> Result<()> {
    verify(
        &AuthorisationKey::from_bytes(*key.as_bytes()),
        &SigningTranscript::from_object(domain, value)?,
        signature,
    )
}

/// Signs `CBOR([domain, value])` with a service admission key, for tests and for the service.
///
/// The managed service signs leases with this in its own process; it is here because the signing
/// and the verifying of one object belong in one place, and because the relay's tests need to
/// produce a lease that a relay will accept.
///
/// # Errors
///
/// Returns an encoding error when the value is outside KR-CBOR-1, and a library error when
/// libsodium fails.
pub fn sign_admission_object<T: Serialize>(
    key: &ServiceAdmissionKeyPair,
    domain: &str,
    value: &T,
) -> Result<Signature64> {
    sign(&key.0, &SigningTranscript::from_object(domain, value)?)
}

/// The Ed25519 key the managed service signs relay leases with.
///
/// In production its private half is a Worker secret and never reaches this crate; this type
/// exists so a test, a local deployment or a one-shot issuing tool can hold one without borrowing
/// a device's authorisation key for the purpose.
#[derive(Debug, Clone)]
pub struct ServiceAdmissionKeyPair(crate::keys::AuthorisationKeyPair);

impl ServiceAdmissionKeyPair {
    /// Generates a fresh admission keypair.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn generate() -> Result<Self> {
        Ok(Self(crate::keys::AuthorisationKeyPair::generate()?))
    }

    /// Derives the keypair from a fixed seed, for the published vectors. Crate-private.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub(crate) fn from_seed_bytes(seed: &[u8; RELAY_SEED_LEN]) -> Result<Self> {
        Ok(Self(crate::keys::AuthorisationKeyPair::from_seed(
            crate::keys::AuthorisationSeed::from_stored_bytes(seed)?,
        )?))
    }

    /// The keypair underneath, for the vector generator's transcript-level signing.
    pub(crate) const fn inner(&self) -> &crate::keys::AuthorisationKeyPair {
        &self.0
    }

    /// The public half, which a relay pins.
    #[must_use]
    pub fn public(&self) -> ServiceAdmissionKey {
        ServiceAdmissionKey::from_bytes(*self.0.public().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::relay::{RELAY_INSTANCE_DOMAIN, RELAY_LEASE_DOMAIN, RELAY_RECEIPT_DOMAIN};
    use kr_protocol::scalars::{Nonce256, TimestampMs};

    use super::*;

    /// A small signable object, so these tests are about the keys rather than about a lease.
    #[derive(Debug, Serialize)]
    struct Statement {
        at_ms: TimestampMs,
        nonce: Nonce256,
    }

    fn statement(byte: u8) -> Statement {
        Statement {
            at_ms: TimestampMs::new(1_800_000_000_000),
            nonce: Nonce256::from_bytes([byte; 32]),
        }
    }

    #[test]
    fn a_relay_signature_verifies_against_the_public_half() {
        let relay = RelayInstanceKeyPair::generate().expect("libsodium is available");
        let object = statement(0x11);
        let signature = relay
            .sign_object(RELAY_RECEIPT_DOMAIN, &object)
            .expect("a signature");

        verify_relay_object(relay.public(), RELAY_RECEIPT_DOMAIN, &object, &signature)
            .expect("the signature verifies");
    }

    #[test]
    fn another_instance_cannot_answer_for_this_one() {
        let relay = RelayInstanceKeyPair::generate().expect("libsodium is available");
        let other = RelayInstanceKeyPair::generate().expect("libsodium is available");
        let object = statement(0x12);
        let signature = other
            .sign_object(RELAY_RECEIPT_DOMAIN, &object)
            .expect("a signature");

        assert!(
            verify_relay_object(relay.public(), RELAY_RECEIPT_DOMAIN, &object, &signature).is_err()
        );
    }

    #[test]
    fn a_receipt_signature_does_not_verify_as_a_registration() {
        let relay = RelayInstanceKeyPair::generate().expect("libsodium is available");
        let object = statement(0x13);
        let signature = relay
            .sign_object(RELAY_RECEIPT_DOMAIN, &object)
            .expect("a signature");

        // The same key, the same object, a different domain: the transcript is different, so the
        // signature is not one anybody made over it.
        assert!(
            verify_relay_object(relay.public(), RELAY_INSTANCE_DOMAIN, &object, &signature)
                .is_err()
        );
    }

    #[test]
    fn a_relay_key_and_an_admission_key_are_not_interchangeable() {
        let relay = RelayInstanceKeyPair::generate().expect("libsodium is available");
        let service = ServiceAdmissionKeyPair::generate().expect("libsodium is available");
        let object = statement(0x14);

        let by_service =
            sign_admission_object(&service, RELAY_LEASE_DOMAIN, &object).expect("a signature");
        verify_admission_object(&service.public(), RELAY_LEASE_DOMAIN, &object, &by_service)
            .expect("the service signature verifies");

        // The relay cannot issue itself a lease, whatever it signs.
        let by_relay = relay
            .sign_object(RELAY_LEASE_DOMAIN, &object)
            .expect("a signature");
        assert!(
            verify_admission_object(&service.public(), RELAY_LEASE_DOMAIN, &object, &by_relay)
                .is_err()
        );
    }

    /// The directory a relay's unit names, which `open` creates owner-only on the first start.
    ///
    /// A temporary directory is not it: the system one is world-traversable, and `open` refuses a
    /// directory it did not make private rather than making it private itself.
    #[cfg(unix)]
    fn key_directory(parent: &tempfile::TempDir) -> std::path::PathBuf {
        parent.path().join("kr-relay")
    }

    #[cfg(unix)]
    #[test]
    fn a_host_gets_the_same_key_back_at_every_start() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().expect("a temporary directory");
        let directory = key_directory(&parent);
        let first = RelayInstanceKeyPair::open(&directory).expect("a first start");
        let again = RelayInstanceKeyPair::open(&directory).expect("a restart");

        // The same key, so the receipts the first run signed still verify after the second.
        assert_eq!(first.public(), again.public());

        let object = statement(0x15);
        let signature = first
            .sign_object(RELAY_RECEIPT_DOMAIN, &object)
            .expect("a signature");
        verify_relay_object(again.public(), RELAY_RECEIPT_DOMAIN, &object, &signature)
            .expect("the restarted relay answers for what the first one signed");

        let mode = std::fs::metadata(&directory)
            .expect("the directory")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "a key directory is owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_anybody_could_read_is_refused_rather_than_repaired() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().expect("a temporary directory");
        let directory = key_directory(&parent);
        RelayInstanceKeyPair::open(&directory).expect("a first start");

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("widened permissions");

        // Narrowing it here would repair the very thing the rule is there to detect, and by then
        // whatever could read the key has already had the chance.
        assert!(RelayInstanceKeyPair::open(&directory).is_err());
        let mode = std::fs::metadata(&directory)
            .expect("the directory")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "the refusal changed nothing");
    }

    #[cfg(unix)]
    #[test]
    fn a_seed_of_the_wrong_length_is_refused_rather_than_stretched() {
        let parent = tempfile::tempdir().expect("a temporary directory");
        let directory = key_directory(&parent);
        RelayInstanceKeyPair::open(&directory).expect("a first start");
        write_owner_only(&directory.join("truncated"), &[0x21; 16]).expect("a short file");
        std::fs::rename(
            directory.join("truncated"),
            directory.join(INSTANCE_KEY_FILE),
        )
        .expect("a replaced key file");

        assert!(RelayInstanceKeyPair::open(&directory).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_key_anybody_could_read_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().expect("a temporary directory");
        let directory = key_directory(&parent);
        RelayInstanceKeyPair::open(&directory).expect("a first start");

        let path = directory.join(INSTANCE_KEY_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("widened permissions");

        // A key the rest of the machine can read is a key the rest of the machine can sign with,
        // and the receipts it signs would still verify. The relay stops rather than pretending.
        assert!(RelayInstanceKeyPair::open(&directory).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_key_reached_through_a_link_is_refused() {
        let parent = tempfile::tempdir().expect("a temporary directory");
        let directory = key_directory(&parent);
        let elsewhere = parent.path().join("elsewhere");
        RelayInstanceKeyPair::open(&directory).expect("a first start");
        RelayInstanceKeyPair::open(&elsewhere).expect("another instance's key");

        // The key file is replaced by a link to somebody else's, which is the swap that a check
        // made separately from the read would miss.
        let path = directory.join(INSTANCE_KEY_FILE);
        std::fs::remove_file(&path).expect("the original key");
        std::os::unix::fs::symlink(elsewhere.join(INSTANCE_KEY_FILE), &path).expect("a link");

        assert!(RelayInstanceKeyPair::open(&directory).is_err());
    }
}
