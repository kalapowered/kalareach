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
        if directory.is_symlink() {
            return Err(CryptoError::SecretStore {
                message: format!("{} is a symbolic link", directory.display()),
            });
        }
        std::fs::create_dir_all(directory).map_err(|error| CryptoError::SecretStore {
            message: format!("create {}: {error}", directory.display()),
        })?;
        set_mode(directory, 0o700)?;
        check_owner_only(directory)?;

        let path = directory.join(INSTANCE_KEY_FILE);
        if path.is_symlink() {
            return Err(CryptoError::SecretStore {
                message: format!("{} is a symbolic link", path.display()),
            });
        }

        match std::fs::read(&path) {
            Ok(stored) => {
                check_file_owner_only(&path)?;
                let seed = Secret::<RELAY_SEED_LEN>::from_slice("the relay instance seed", &stored)
                    .map_err(|_| CryptoError::StoredSecretLength {
                        name: INSTANCE_KEY_FILE.to_owned(),
                        expected: RELAY_SEED_LEN,
                        actual: stored.len(),
                    })?;
                Self::from_seed(seed)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let seed = Secret::<RELAY_SEED_LEN>::random()?;
                write_owner_only(&path, seed.expose())?;
                sync_directory(directory)?;
                Self::from_seed(seed)
            }
            Err(error) => Err(CryptoError::SecretStore {
                message: format!("read {}: {error}", path.display()),
            }),
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

/// Refuses a key file that anyone but its owner can read.
///
/// A key the rest of the machine can read is a key the rest of the machine can sign with, and the
/// receipts it signs would verify. The relay stops rather than pretending otherwise.
#[cfg(unix)]
fn check_file_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::metadata(path).map_err(|error| CryptoError::SecretStore {
        message: format!("stat {}: {error}", path.display()),
    })?;
    if !metadata.is_file() {
        return Err(CryptoError::SecretStore {
            message: format!("{} is not a file", path.display()),
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CryptoError::SecretStore {
            message: format!("{} is readable by another account", path.display()),
        });
    }
    Ok(())
}

/// The relay tier runs on Unix hosts; elsewhere there is no owner-only file to check.
#[cfg(not(unix))]
fn check_file_owner_only(path: &Path) -> Result<()> {
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

    #[cfg(unix)]
    #[test]
    fn a_host_gets_the_same_key_back_at_every_start() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary directory");
        let first = RelayInstanceKeyPair::open(directory.path()).expect("a first start");
        let again = RelayInstanceKeyPair::open(directory.path()).expect("a restart");

        // The same key, so the receipts the first run signed still verify after the second.
        assert_eq!(first.public(), again.public());

        let object = statement(0x15);
        let signature = first
            .sign_object(RELAY_RECEIPT_DOMAIN, &object)
            .expect("a signature");
        verify_relay_object(again.public(), RELAY_RECEIPT_DOMAIN, &object, &signature)
            .expect("the restarted relay answers for what the first one signed");

        let mode = std::fs::metadata(directory.path())
            .expect("the directory")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "a key directory is owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn a_seed_of_the_wrong_length_is_refused_rather_than_stretched() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        RelayInstanceKeyPair::open(directory.path()).expect("a first start");
        write_owner_only(&directory.path().join("truncated"), &[0x21; 16]).expect("a short file");
        std::fs::rename(
            directory.path().join("truncated"),
            directory.path().join(INSTANCE_KEY_FILE),
        )
        .expect("a replaced key file");

        assert!(RelayInstanceKeyPair::open(directory.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_key_anybody_could_read_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("a temporary directory");
        RelayInstanceKeyPair::open(directory.path()).expect("a first start");

        let path = directory.path().join(INSTANCE_KEY_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("widened permissions");

        // A key the rest of the machine can read is a key the rest of the machine can sign with,
        // and the receipts it signs would still verify. The relay stops rather than pretending.
        assert!(RelayInstanceKeyPair::open(directory.path()).is_err());
    }
}
