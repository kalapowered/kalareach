//! The key a synchronised collection is sealed under, and the sealer that uses it.
//!
//! The service that stores settings and drafts holds ciphertext and no keys, so something on the
//! device has to hold the key. This module is that: the interface a sealer asks for a key through,
//! two places a key can be kept, and the production implementation of [`DraftSealer`] over
//! [`kr_crypto::envelope`].
//!
//! # A collection key is not a device key
//!
//! A device's four keypairs identify the device: its transport identity, its authorisation, its
//! stored envelopes and its notification previews. Every one of them is this device's alone, and
//! pairing binds their public halves.
//!
//! A collection key is the opposite kind of thing. It is one symmetric key that every device
//! permitted to read the collection holds, so it cannot be derived from a device's own secret and
//! it has no public half to publish. It is therefore kept separately, named by the collection and
//! by the epoch it belongs to, and it is replaced when the set of devices that may read the
//! collection changes: section 20 requires a mutable shared collection to be re-keyed so that a
//! device removed from it cannot read what is written afterwards. The epoch in the name is what
//! makes that possible without losing what was written before it, and it is why this interface is
//! keyed by collection *and* epoch rather than by collection alone.
//!
//! # A missing key is a missing key
//!
//! Nothing here creates a key that was not found. A device that does not hold a collection's key
//! has not been given it, and a replacement generated in its place would seal content none of the
//! other devices could read while looking, from this device, exactly like success. So
//! [`CollectionKeys::key`] answers a miss with an error and [`MemoryCollectionKeys::put`] and
//! [`StoredCollectionKeys::put`] are the only ways a key arrives.
//!
//! # Where a key is kept
//!
//! [`StoredCollectionKeys`] keeps it where the device's own secrets are kept: the operating
//! system's credential store, with the documented owner-only directory on the systems section 10
//! offers it on, through [`kr_crypto::store::StoreSelection`]. [`MemoryCollectionKeys`] keeps it
//! for the length of a process, which is what a demonstration or a test of the collection rules
//! themselves wants.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use kr_crypto::envelope::{open_sync_object, seal_sync_object};
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_crypto::store::{OpenedStore, SecretName, SecretStore, StoreSelection};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::sync::SealedSyncObject;

use crate::drafts::DraftSealer;
use crate::error::{ClientError, Result};

/// Where the key one synchronised collection is sealed under comes from.
///
/// One key per collection and epoch. An implementation holds keys; it does not make them, and a
/// key it does not hold is an error rather than a new key.
pub trait CollectionKeys: Send + Sync + std::fmt::Debug {
    /// Returns the key this collection is sealed under at this epoch.
    ///
    /// # Errors
    ///
    /// Returns an error naming the collection and the epoch when this device does not hold that
    /// key, and whatever the store failed with otherwise.
    fn key(&self, collection: &str, epoch: u64) -> Result<SymmetricKey>;
}

/// Says that this device does not hold a key, without saying anything about the key.
fn no_key(collection: &str, epoch: u64) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::HostNotConfigured,
        format!(
            "this device does not hold the key for collection {collection} at epoch {epoch}, so it can neither read nor write it"
        ),
    ))
}

/// Turns a sealing or opening failure into something a caller can act on.
///
/// Three answers, and which one a caller gets says who has to do something about it.
///
/// * The content did not authenticate under this key: the key is wrong, or the bytes were changed.
/// * This device cannot do the work. A secret store that will not answer, a stored item that is not
///   the length its purpose requires, a libsodium that will not initialise, a libsodium call that
///   failed and a linked libsodium that disagrees with this build about its own sizes are all the
///   same kind of thing: the caller asked a well-formed question and the device could not carry it
///   out. None of them is anything the caller passed.
/// * What was passed in. That is what is left, and it is the only thing [`ErrorCode::InvalidArgument`]
///   is for here.
fn sealing_failed(error: &kr_crypto::CryptoError) -> ClientError {
    use kr_crypto::CryptoError as Failure;

    let code = match error {
        Failure::Authentication { .. } => ErrorCode::PermissionDenied,
        Failure::SecretStore { .. }
        | Failure::StoredSecretLength { .. }
        | Failure::LibraryUnavailable { .. }
        | Failure::Library { .. }
        | Failure::LibraryMismatch { .. } => ErrorCode::StorageUnavailable,
        _ => ErrorCode::InvalidArgument,
    };
    ClientError::Host(ProtocolError::new(code, error.to_string()))
}

/// Says that what the store holds under this name is not a key.
///
/// The caller's arguments were a collection and an epoch and both were fine; what is wrong is what
/// came back, so this is the device's storage rather than the caller's request. The bytes
/// themselves reach nothing: a stored value that is not a key is still a stored value.
fn corrupt_stored_key(collection: &str, epoch: u64) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::StorageUnavailable,
        format!(
            "what this device holds for collection {collection} at epoch {epoch} is not a key of the length one has"
        ),
    ))
}

/// Collection keys held for the length of a process.
///
/// It is the implementation a demonstration, a bench or a test of the collection rules uses: the
/// keys are put in deliberately, they last as long as the process and they reach no store. It is
/// not a device's own key store, and nothing here writes one to disk.
#[derive(Debug, Default)]
pub struct MemoryCollectionKeys {
    keys: Mutex<BTreeMap<(String, u64), SymmetricKey>>,
}

impl MemoryCollectionKeys {
    /// Returns a set holding no keys.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds `key` for one collection and epoch, replacing whatever was held for it.
    ///
    /// # Errors
    ///
    /// Returns an error when the held keys cannot be reached.
    pub fn put(&self, collection: &str, epoch: u64, key: SymmetricKey) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|_| poisoned())?;
        keys.insert((collection.to_owned(), epoch), key);
        Ok(())
    }

    /// Draws a fresh key for one collection and epoch and holds it.
    ///
    /// A key made here is made deliberately, by a caller that is starting a collection rather than
    /// reading one. [`CollectionKeys::key`] never does this.
    ///
    /// # Errors
    ///
    /// Returns an error when the random generator is unavailable.
    pub fn draw(&self, collection: &str, epoch: u64) -> Result<SymmetricKey> {
        let key = Secret::random().map_err(|error| sealing_failed(&error))?;
        self.put(collection, epoch, key.clone())?;
        Ok(key)
    }

    /// Forgets the key for one collection and epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the held keys cannot be reached.
    pub fn forget(&self, collection: &str, epoch: u64) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|_| poisoned())?;
        keys.remove(&(collection.to_owned(), epoch));
        Ok(())
    }
}

impl CollectionKeys for MemoryCollectionKeys {
    fn key(&self, collection: &str, epoch: u64) -> Result<SymmetricKey> {
        let keys = self.keys.lock().map_err(|_| poisoned())?;
        keys.get(&(collection.to_owned(), epoch))
            .cloned()
            .ok_or_else(|| no_key(collection, epoch))
    }
}

/// Says that the held keys cannot be reached, which is a fault rather than a missing key.
fn poisoned() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::StorageUnavailable,
        "this device's collection keys cannot be reached".to_owned(),
    ))
}

/// Collection keys in the device's own secret store.
///
/// This is where a collection key lives on an installed device: the operating system's credential
/// store, and on the systems section 10 offers it on, the owner-only directory that stands in for
/// one. [`StoreSelection`] is the choice, made by the caller at every start rather than recorded
/// here, and [`StoreKind`] on the opened store says which one answered.
///
/// [`StoreKind`]: kr_crypto::store::StoreKind
pub struct StoredCollectionKeys {
    store: Box<dyn SecretStore>,
    description: String,
    kind: kr_crypto::store::StoreKind,
    scope: String,
}

impl std::fmt::Debug for StoredCollectionKeys {
    /// Names the store and the scope, and never a key or a key's name.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredCollectionKeys")
            .field("store", &self.description)
            .field("kind", &self.kind)
            .field("scope", &self.scope)
            .finish()
    }
}

impl StoredCollectionKeys {
    /// Opens the store `selection` names and keeps this device's collection keys in it.
    ///
    /// `service` is the name the platform store keeps its items under and `directory` is where the
    /// documented fallback keeps its files. `scope` separates one host's secrets from another's
    /// inside one store, exactly as a device key's name is scoped.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected store cannot be opened.
    pub fn open(
        selection: StoreSelection,
        service: &str,
        directory: &Path,
        scope: &str,
    ) -> Result<Self> {
        let opened = selection
            .open(service, directory)
            .map_err(|error| sealing_failed(&error))?;
        Ok(Self::of(opened, scope))
    }

    /// Keeps this device's collection keys in a store that is already open.
    #[must_use]
    pub fn of(opened: OpenedStore, scope: &str) -> Self {
        Self {
            description: opened.store.describe(),
            kind: opened.kind,
            store: opened.store,
            scope: scope.to_owned(),
        }
    }

    /// Which store the keys are in.
    #[must_use]
    pub const fn kind(&self) -> kr_crypto::store::StoreKind {
        self.kind
    }

    /// Writes the key for one collection and epoch, replacing whatever was there.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is not one this store admits or the store rejects the write.
    pub fn put(&self, collection: &str, epoch: u64, key: &SymmetricKey) -> Result<()> {
        let name = self.name(collection, epoch)?;
        self.store
            .set(&name, key.expose())
            .map_err(|error| sealing_failed(&error))
    }

    /// Removes the key for one collection and epoch. Removing one that is not there succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is not one this store admits or the store rejects the
    /// deletion.
    pub fn forget(&self, collection: &str, epoch: u64) -> Result<()> {
        let name = self.name(collection, epoch)?;
        self.store
            .delete(&name)
            .map_err(|error| sealing_failed(&error))
    }

    /// The name this collection's key is kept under, or a refusal.
    ///
    /// A collection identifier the store cannot name is the caller's argument rather than a fault
    /// in the store, and it is refused rather than turned into some other name that would work:
    /// two identifiers that mapped to one name would be one key for two collections.
    fn name(&self, collection: &str, epoch: u64) -> Result<SecretName> {
        SecretName::collection_key(&self.scope, collection, epoch).map_err(|error| {
            ClientError::Host(ProtocolError::new(
                ErrorCode::InvalidArgument,
                error.to_string(),
            ))
        })
    }
}

impl CollectionKeys for StoredCollectionKeys {
    fn key(&self, collection: &str, epoch: u64) -> Result<SymmetricKey> {
        let name = self.name(collection, epoch)?;
        let held = self
            .store
            .get(&name)
            .map_err(|error| sealing_failed(&error))?;
        // A store that holds nothing under this name is a device that was never given the key.
        // Nothing here makes one: a key drawn at this point would seal content the other devices
        // cannot read, and would look from here exactly like success.
        let held = held.ok_or_else(|| no_key(collection, epoch))?;
        // A stored value of the wrong length is the store's content and not the caller's argument,
        // which is why it does not go through the classification the cryptography's own failures
        // do: there is no argument here to have been wrong.
        Secret::from_slice("a collection key", held.expose())
            .map_err(|_| corrupt_stored_key(collection, epoch))
    }
}

/// The sealing a synchronised collection's objects travel under.
///
/// It is [`kr_crypto::envelope`]: authenticated encryption under the domain
/// `kr-sync-object/1`, padded to section 20's declared size buckets so the stored length says
/// which bucket an object is in and nothing more. The key comes from [`CollectionKeys`] on every
/// call rather than being held here, so a key that has been withdrawn stops working at the next
/// call instead of at the next restart.
///
/// One sealer belongs to one collection at one epoch, because that is what one key belongs to.
#[derive(Debug)]
pub struct CollectionSealer {
    keys: Arc<dyn CollectionKeys>,
    collection: String,
    epoch: u64,
}

impl CollectionSealer {
    /// Builds the sealing for one collection at one epoch.
    #[must_use]
    pub fn new(keys: Arc<dyn CollectionKeys>, collection: &str, epoch: u64) -> Self {
        Self {
            keys,
            collection: collection.to_owned(),
            epoch,
        }
    }

    /// The collection this sealer belongs to.
    #[must_use]
    pub fn collection(&self) -> &str {
        &self.collection
    }

    /// The epoch of the key it seals under.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl DraftSealer for CollectionSealer {
    /// Seals one object's canonical bytes and returns the sealed object, encoded.
    ///
    /// What comes back is a [`SealedSyncObject`] in canonical KR-CBOR-1: the nonce, the declared
    /// size bucket and the ciphertext. The service stores those bytes and the same bytes are what
    /// its structure rules are applied to, so what this device writes and what the service holds
    /// are one thing rather than two encodings of it.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.keys.key(&self.collection, self.epoch)?;
        let object = seal_sync_object(&key, plaintext).map_err(|error| sealing_failed(&error))?;
        Ok(kr_cbor::to_canonical_vec(&object)?)
    }

    /// Opens what [`Self::seal`] produced.
    ///
    /// The object's own structure rules run before the key is used, and the domain the ciphertext
    /// was sealed under is inside the authentication, so bytes sealed for another purpose under
    /// the same key do not open here.
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let object: SealedSyncObject =
            kr_cbor::from_canonical_slice(ciphertext, &kr_cbor::Limits::DEFAULT)?;
        let key = self.keys.key(&self.collection, self.epoch)?;
        let opened = open_sync_object(&key, &object).map_err(|error| sealing_failed(&error))?;
        Ok(opened.expose().to_vec())
    }
}

/// Where a collection key is kept, and what a sealer does with it.
///
/// | Row | What proves it |
/// | --- | --- |
/// | KR-REQ-10.47 | `a_key_written_to_the_device_store_is_read_back_from_it`, `a_key_the_device_store_does_not_hold_is_reported_rather_than_made`, `a_forgotten_key_is_gone_from_the_device_store`, `a_stored_value_that_is_not_a_key_is_a_storage_failure_and_not_an_argument_one`, `the_directory_fallback_is_owner_only_and_so_are_its_files`, and `a_key_kept_in_the_platform_store_is_read_back_from_it_and_taken_away_again` for the platform half, which needs a run that says its credential store may be written to |
///
/// # What a test of this module may touch
///
/// The documented directory fallback is a directory the test made and throws away, so every test
/// here uses it freely. The platform store is the machine's own credential store, which on a
/// person's machine is their login keychain: a suite that wrote to it would leave items behind on
/// a machine that is not a fixture. One test reaches it, it does nothing unless
/// `KR_TEST_PLATFORM_SECRET_STORE=1` says the run is prepared for it, and what it writes is named
/// for that run alone and removed on the way out. The removal on a path that panics is an attempt
/// rather than a promise: a destructor that runs while a thread is unwinding cannot report a store
/// that refused it.
#[cfg(test)]
mod tests {
    use super::*;
    use kr_crypto::store::{StoreKind, open_store_in};

    const COLLECTION: &str = "0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b";
    const SCOPE: &str = "kalareach-test";

    fn memory_sealer() -> (Arc<MemoryCollectionKeys>, CollectionSealer) {
        let keys = Arc::new(MemoryCollectionKeys::new());
        keys.draw(COLLECTION, 1).expect("a key");
        let sealer =
            CollectionSealer::new(Arc::clone(&keys) as Arc<dyn CollectionKeys>, COLLECTION, 1);
        (keys, sealer)
    }

    #[test]
    fn an_object_seals_and_opens_again() {
        let (_keys, sealer) = memory_sealer();
        let sealed = sealer.seal(b"a setting").expect("sealed");
        assert_eq!(sealer.open(&sealed).expect("opened"), b"a setting");

        // The stored bytes are the object the service stores, padded to its declared bucket.
        let object: SealedSyncObject =
            kr_cbor::from_canonical_slice(&sealed, &kr_cbor::Limits::DEFAULT).expect("an object");
        assert_eq!(object.size_bucket_bytes.get(), 1024);
        object.check_structure().expect("the service's own rules");
    }

    #[test]
    fn two_objects_of_different_lengths_are_stored_at_one_length() {
        let (_keys, sealer) = memory_sealer();
        let short = sealer.seal(b"on").expect("sealed");
        let longer = sealer.seal(&[b'x'; 900]).expect("sealed");
        let short: SealedSyncObject =
            kr_cbor::from_canonical_slice(&short, &kr_cbor::Limits::DEFAULT).expect("an object");
        let longer: SealedSyncObject =
            kr_cbor::from_canonical_slice(&longer, &kr_cbor::Limits::DEFAULT).expect("an object");
        assert_eq!(short.stored_bytes(), longer.stored_bytes());
        assert_ne!(short.nonce, longer.nonce);
    }

    #[test]
    fn a_ciphertext_sealed_for_another_purpose_does_not_open_as_a_synchronised_object() {
        let keys = Arc::new(MemoryCollectionKeys::new());
        let key = keys.draw(COLLECTION, 1).expect("a key");
        let sealer =
            CollectionSealer::new(Arc::clone(&keys) as Arc<dyn CollectionKeys>, COLLECTION, 1);

        // The same key, the same padded length, another domain.
        let (nonce, ciphertext) =
            kr_crypto::aead::seal(&key, b"kr-other/1", &[0u8; 1024]).expect("sealed elsewhere");
        let elsewhere = SealedSyncObject {
            nonce,
            size_bucket_bytes: kr_protocol::scalars::U64::new(1024),
            ciphertext: kr_protocol::scalars::Bytes::new(ciphertext),
        };
        let encoded = kr_cbor::to_canonical_vec(&elsewhere).expect("encoded");

        let error = sealer.open(&encoded).expect_err("another purpose");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn another_epoch_of_the_same_collection_is_another_key() {
        let keys = Arc::new(MemoryCollectionKeys::new());
        keys.draw(COLLECTION, 1).expect("a key");
        keys.draw(COLLECTION, 2).expect("a key");
        let first =
            CollectionSealer::new(Arc::clone(&keys) as Arc<dyn CollectionKeys>, COLLECTION, 1);
        let second =
            CollectionSealer::new(Arc::clone(&keys) as Arc<dyn CollectionKeys>, COLLECTION, 2);

        let sealed = first.seal(b"a setting").expect("sealed");
        let error = second.open(&sealed).expect_err("another epoch");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn a_missing_key_is_reported_and_no_key_is_made_in_its_place() {
        let keys = Arc::new(MemoryCollectionKeys::new());
        let sealer =
            CollectionSealer::new(Arc::clone(&keys) as Arc<dyn CollectionKeys>, COLLECTION, 7);

        let error = sealer.seal(b"a setting").expect_err("no key");
        assert_eq!(error.code(), ErrorCode::HostNotConfigured);
        assert!(error.to_string().contains("epoch 7"));

        // Nothing was created by asking: the second attempt fails the same way.
        let again = sealer.seal(b"a setting").expect_err("still no key");
        assert_eq!(again.code(), ErrorCode::HostNotConfigured);
        assert!(keys.key(COLLECTION, 7).is_err());
    }

    #[test]
    fn a_key_withdrawn_between_calls_stops_working_at_the_next_call() {
        let (keys, sealer) = memory_sealer();
        let sealed = sealer.seal(b"a setting").expect("sealed");
        keys.forget(COLLECTION, 1).expect("forgotten");
        assert_eq!(
            sealer.open(&sealed).expect_err("withdrawn").code(),
            ErrorCode::HostNotConfigured
        );
    }

    /* ---------------------------------------------------------------------- */
    /* Where the key is kept                                                   */
    /* ---------------------------------------------------------------------- */

    /// KR-REQ-10.47: the key is in the device's own secret store, and what this device wrote is
    /// what the next process reads.
    #[test]
    fn a_key_written_to_the_device_store_is_read_back_from_it() {
        let parent = tempfile::tempdir().expect("a place for one");
        let directory = parent.path().join("secrets");
        let keys = StoredCollectionKeys::open(
            StoreSelection::File,
            "kalareach-collection-keys-test",
            &directory,
            SCOPE,
        )
        .expect("a store");
        assert_eq!(keys.kind(), StoreKind::FileFallback);

        let key: SymmetricKey = Secret::random().expect("a key");
        keys.put(COLLECTION, 3, &key).expect("written");

        // A second opening of the same directory is a second process reading what the first wrote.
        let reopened =
            StoredCollectionKeys::of(open_store_in(&directory).expect("the same store"), SCOPE);
        let read = reopened.key(COLLECTION, 3).expect("read back");
        assert_eq!(read.expose(), key.expose());

        let sealer = CollectionSealer::new(Arc::new(reopened), COLLECTION, 3);
        let sealed = sealer.seal(b"a setting").expect("sealed");
        assert_eq!(sealer.open(&sealed).expect("opened"), b"a setting");
    }

    /// KR-REQ-10.47: a key the store does not hold is reported, and asking wrote nothing.
    #[test]
    fn a_key_the_device_store_does_not_hold_is_reported_rather_than_made() {
        let parent = tempfile::tempdir().expect("a place for one");
        let directory = parent.path().join("secrets");
        let keys = StoredCollectionKeys::open(
            StoreSelection::File,
            "kalareach-collection-keys-test",
            &directory,
            SCOPE,
        )
        .expect("a store");

        let error = keys.key(COLLECTION, 4).expect_err("no key");
        assert_eq!(error.code(), ErrorCode::HostNotConfigured);
        // Asking wrote nothing: the store still holds nothing under that name.
        assert!(keys.key(COLLECTION, 4).is_err());
    }

    /// KR-REQ-10.47: removing a key removes it, and removing one that is not there succeeds.
    #[test]
    fn a_forgotten_key_is_gone_from_the_device_store() {
        let parent = tempfile::tempdir().expect("a place for one");
        let directory = parent.path().join("secrets");
        let keys = StoredCollectionKeys::open(
            StoreSelection::File,
            "kalareach-collection-keys-test",
            &directory,
            SCOPE,
        )
        .expect("a store");
        let key: SymmetricKey = Secret::random().expect("a key");
        keys.put(COLLECTION, 5, &key).expect("written");
        keys.forget(COLLECTION, 5).expect("forgotten");
        assert_eq!(
            keys.key(COLLECTION, 5).expect_err("gone").code(),
            ErrorCode::HostNotConfigured
        );
        // Forgetting one that is not there succeeds.
        keys.forget(COLLECTION, 5).expect("nothing to forget");
    }

    /// KR-REQ-10.47: the documented fallback is an owner-only directory whose key files are
    /// owner-only too.
    #[cfg(unix)]
    #[test]
    fn the_directory_fallback_is_owner_only_and_so_are_its_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().expect("a place for one");
        let directory = parent.path().join("secrets");
        let keys = StoredCollectionKeys::open(
            StoreSelection::File,
            "kalareach-collection-keys-test",
            &directory,
            SCOPE,
        )
        .expect("a store");
        let key: SymmetricKey = Secret::random().expect("a key");
        keys.put(COLLECTION, 6, &key).expect("written");

        let mode = std::fs::metadata(&directory)
            .expect("the directory")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "the directory is owner-only");

        // A key's name is a path inside that directory, and the file at the end of it is
        // owner-only. What keeps the whole tree private is the mode of the directory above it,
        // which no other account can traverse.
        let mut files = 0;
        let mut directories = vec![directory.clone()];
        while let Some(next) = directories.pop() {
            for entry in std::fs::read_dir(&next).expect("the directory") {
                let entry = entry.expect("an entry");
                if entry.file_name().to_string_lossy().starts_with('.') {
                    continue;
                }
                if entry.file_type().expect("an entry").is_dir() {
                    directories.push(entry.path());
                    continue;
                }
                let mode = entry.metadata().expect("an entry").permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "a stored key is owner-only");
                files += 1;
            }
        }
        assert_eq!(files, 1, "one key was written, so one file holds it");
    }

    /// The switch a run sets when it is prepared for this machine's own credential store to be
    /// written to and cleared again.
    ///
    /// `StoreSelection::Platform` means the operating system's credential store, which on a person's
    /// own machine is their login keychain. An ordinary test run must leave it alone, so the only
    /// test that reaches it is this one and it does nothing until a run asks for it.
    const PLATFORM_STORE_SWITCH: &str = "KR_TEST_PLATFORM_SECRET_STORE";

    /// Whether this run asked for the platform store to be exercised.
    fn platform_store_wanted() -> bool {
        std::env::var(PLATFORM_STORE_SWITCH).is_ok_and(|value| value == "1")
    }

    /// A name no other run of this suite and nothing installed on this machine shares.
    fn unique_to_this_run() -> String {
        let mut bytes = [0u8; 8];
        kr_crypto::random_bytes(&mut bytes).expect("a name");
        let mut name = String::from("kalareach-test-");
        for byte in bytes {
            name.push_str(&format!("{byte:02x}"));
        }
        name
    }

    /// Tries to take away what the platform-store test wrote, including when it panicked.
    ///
    /// An attempt rather than a guarantee: a destructor that runs while the thread is unwinding
    /// cannot report a store that refused the deletion, and a process that was killed runs no
    /// destructor at all. The successful path removes the item itself and checks that it is gone;
    /// this is what covers the paths that do not reach that.
    struct Removes {
        keys: StoredCollectionKeys,
        epoch: u64,
    }

    impl Drop for Removes {
        fn drop(&mut self) {
            // Nothing useful can be done with a failure here: the thread may already be unwinding,
            // and panicking inside a destructor during a panic ends the process.
            let _ = self.keys.forget(COLLECTION, self.epoch);
        }
    }

    /// KR-REQ-10.47: the platform store is what an installed device takes, and a key put in it is
    /// read back from it.
    ///
    /// It is the half of the row that only a real credential store can answer, so it runs where a
    /// run says it may: with `KR_TEST_PLATFORM_SECRET_STORE=1` it writes one item under a service
    /// and a scope drawn for this run alone and removes it again on the way out, and without it
    /// the test says why it did nothing. Where the switch is set, a machine with no platform store
    /// is a failure rather than a pass, because the run promised one.
    #[test]
    fn a_key_kept_in_the_platform_store_is_read_back_from_it_and_taken_away_again() {
        if !platform_store_wanted() {
            println!(
                "skipped: this test writes one item to this machine's own credential store and \
                 removes it again. Set {PLATFORM_STORE_SWITCH}=1 to run it."
            );
            return;
        }

        let parent = tempfile::tempdir().expect("a place for one");
        let directory = parent.path().join("secrets");
        let service = unique_to_this_run();
        let scope = unique_to_this_run();
        let epoch = 8;

        let keys =
            StoredCollectionKeys::open(StoreSelection::Platform, &service, &directory, &scope)
                .expect("the platform store this run promised");
        let guard = Removes { keys, epoch };
        assert_eq!(
            guard.keys.kind(),
            StoreKind::Platform,
            "this run promised a platform store"
        );

        let key: SymmetricKey = Secret::random().expect("a key");
        guard.keys.put(COLLECTION, epoch, &key).expect("written");
        assert_eq!(
            guard
                .keys
                .key(COLLECTION, epoch)
                .expect("read back")
                .expose(),
            key.expose()
        );

        // A second opening of the same service and scope reads through a second handle rather
        // than out of anything the first one is holding. It is not a second process, which only a
        // fixture machine could give, but it does establish that the item is in the store.
        let reopened =
            StoredCollectionKeys::open(StoreSelection::Platform, &service, &directory, &scope)
                .expect("the same store");
        assert_eq!(
            reopened.key(COLLECTION, epoch).expect("read back").expose(),
            key.expose()
        );

        guard.keys.forget(COLLECTION, epoch).expect("taken away");
        assert_eq!(
            guard.keys.key(COLLECTION, epoch).expect_err("gone").code(),
            ErrorCode::HostNotConfigured
        );
    }

    /// KR-REQ-10.47: what the store holds is the store's, so a stored value that is not a key is
    /// reported as this device's storage rather than as the caller's mistake.
    #[test]
    fn a_stored_value_that_is_not_a_key_is_a_storage_failure_and_not_an_argument_one() {
        let parent = tempfile::tempdir().expect("a place for one");
        let directory = parent.path().join("secrets");
        let opened = StoreSelection::File
            .open("kalareach-collection-keys-test", &directory)
            .expect("a store");

        // 31 bytes under the name a collection key is kept at: a truncated write, a partly
        // restored backup, a store that gave back something else.
        let name = SecretName::collection_key(SCOPE, COLLECTION, 9).expect("a name");
        opened.store.set(&name, &[0x5a; 31]).expect("written");

        let keys = StoredCollectionKeys::of(opened, SCOPE);
        let error = keys.key(COLLECTION, 9).expect_err("not a key");
        assert_eq!(error.code(), ErrorCode::StorageUnavailable);
        assert!(error.to_string().contains("epoch 9"));
        // Nothing of what was stored is quoted back.
        assert!(!error.to_string().contains("5a"));

        // And the sealer that asks for it reports the same thing rather than a sealing failure.
        let sealer = CollectionSealer::new(Arc::new(keys), COLLECTION, 9);
        assert_eq!(
            sealer.seal(b"a setting").expect_err("not a key").code(),
            ErrorCode::StorageUnavailable
        );
    }

    #[test]
    fn a_device_that_cannot_do_the_work_says_so_and_never_blames_the_caller() {
        use kr_crypto::CryptoError as Failure;

        for failure in [
            Failure::LibraryUnavailable { code: -1 },
            Failure::Library {
                name: "crypto_aead_xchacha20poly1305_ietf_encrypt",
                code: -1,
            },
            Failure::LibraryMismatch {
                name: "crypto_aead_xchacha20poly1305_ietf_keybytes",
                expected: 32,
                actual: 16,
            },
            Failure::SecretStore {
                message: "the store is locked".to_owned(),
            },
            Failure::StoredSecretLength {
                name: "a collection key".to_owned(),
                expected: 32,
                actual: 31,
            },
        ] {
            assert_eq!(
                sealing_failed(&failure).code(),
                ErrorCode::StorageUnavailable,
                "{failure}"
            );
        }

        // What did not authenticate is its own answer, and what the caller passed is the only
        // thing left.
        assert_eq!(
            sealing_failed(&Failure::Authentication {
                what: "a synchronised object"
            })
            .code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            sealing_failed(&Failure::TooLarge {
                what: "a synchronised object",
                limit: 64 * 1024,
                actual: 65_537,
            })
            .code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn a_collection_identifier_this_store_cannot_name_is_refused_rather_than_mangled() {
        let parent = tempfile::tempdir().expect("a place for one");
        let directory = parent.path().join("secrets");
        let keys = StoredCollectionKeys::open(
            StoreSelection::File,
            "kalareach-collection-keys-test",
            &directory,
            SCOPE,
        )
        .expect("a store");

        let error = keys.key("../elsewhere", 1).expect_err("not a name");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_sealer_says_which_collection_and_epoch_it_belongs_to_and_never_the_key() {
        let (_keys, sealer) = memory_sealer();
        assert_eq!(sealer.collection(), COLLECTION);
        assert_eq!(sealer.epoch(), 1);

        let parent = tempfile::tempdir().expect("a place for one");
        let directory = parent.path().join("secrets");
        let keys = StoredCollectionKeys::open(
            StoreSelection::File,
            "kalareach-collection-keys-test",
            &directory,
            SCOPE,
        )
        .expect("a store");
        let key: SymmetricKey = Secret::from_bytes([0x5a; 32]);
        keys.put(COLLECTION, 1, &key).expect("written");
        let rendered = format!("{keys:?}");
        assert!(rendered.contains(SCOPE));
        assert!(!rendered.contains("5a5a5a"));
    }
}
