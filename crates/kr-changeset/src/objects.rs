//! The content-addressed store a captured tree's bytes live in.
//!
//! A blob's name **is** its SHA-256 digest, so storing the same content twice stores it once and a
//! manifest that names a digest names exactly one sequence of bytes. That is what makes a captured
//! tree immutable: nothing in here is ever rewritten, because a write whose content differs has a
//! different name.
//!
//! Every operation goes through an [`kr_transfer::AuthorisedDirectory`], which is an open
//! directory descriptor rather than a path, and a publication is a **link** into the final name
//! rather than a rename over it: a link fails when the name is taken, on every platform, so a blob
//! that is already there is never replaced by one a concurrent capture was still writing.

use std::io::{Read as _, Write as _};

use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::Digest256;
use kr_transfer::{AuthorisedDirectory, ObjectPolicy, RelativeName};
use sha2::{Digest as _, Sha256};

use crate::error::{ChangeSetError, Result};

/// The directory, under this service's own root, that the blobs live in.
pub const OBJECTS_DIRECTORY: &str = "objects";

/// How many bytes one read of a blob moves at a time.
const READ_CHUNK: usize = 64 * 1024;

/// Returns the SHA-256 digest of some bytes.
#[must_use]
pub fn digest_of(bytes: &[u8]) -> Digest256 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Digest256::from_bytes(hasher.finalize().into())
}

/// Returns the lower-case hexadecimal form of a digest.
#[must_use]
pub fn hex_of(digest: Digest256) -> String {
    let mut text = String::with_capacity(64);
    for byte in digest.as_bytes() {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// What reading one object's name back established.
enum ReadBack {
    /// The content the name says it is.
    Content,
    /// Something this host read, that is not that content.
    Damaged,
    /// Nothing this host could read.
    Unreadable(String),
}

/// The blobs of every captured tree in one environment.
#[derive(Debug)]
pub struct ObjectStore {
    root: AuthorisedDirectory,
}

impl ObjectStore {
    /// Opens the store, creating its directory on first use.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StorageUnavailable`] when the directory cannot be prepared.
    pub fn open(parent: &AuthorisedDirectory, environment_id: EnvironmentId) -> Result<Self> {
        parent.check_environment(environment_id)?;
        let name = RelativeName::parse(OBJECTS_DIRECTORY)?;
        let root = parent.create_subdirectory(&name)?;
        Ok(Self { root })
    }

    /// Writes some bytes and returns the digest that names them.
    ///
    /// Storing content that is already there stores nothing and returns the same digest, because
    /// the name is the digest. The publication is a link into a name that must not exist, so a
    /// blob another capture was still writing is never overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StorageUnavailable`] when the write fails.
    pub fn put(&self, bytes: &[u8]) -> Result<Digest256> {
        let digest = digest_of(bytes);
        let hex = hex_of(digest);
        let (fan_out, leaf) = hex.split_at(2);
        let shelf = self
            .root
            .create_subdirectory(&RelativeName::parse(fan_out)?)?;
        let final_name = RelativeName::parse(leaf)?;
        // A name that is already taken should hold this content, because the name is the digest of
        // the content. Should is not is: a damaged file, a directory or a link at that name would
        // make this write report success and throw the valid bytes away, and every later read of
        // it would fail. So what is there is read back before it is believed.
        let mut repair = false;
        if shelf.occupied(&final_name)? {
            match self.reads_back(digest)? {
                ReadBack::Content => {
                    // Somebody's publication is already there. The directory entry is made durable
                    // before this returns, because a caller is about to commit a version row that
                    // names this object and a name that is not durable is a version whose content
                    // a power failure can take away.
                    shelf.sync()?;
                    return Ok(digest);
                }
                // The name **is** the digest of the content, so a file at it that hashes to
                // something else is not content anything can be referring to, and leaving it would
                // make every version that names this digest undeliverable. It is replaced in one
                // step rather than removed and written again: another writer who published the
                // right content in between published *these bytes*, since the name is their
                // digest, and a name that is never empty is never a name a crash leaves absent.
                ReadBack::Damaged => repair = true,
                // Something is at the name and this host could not read it. That is not evidence
                // of damage, and removing it would take away an object a version may name.
                ReadBack::Unreadable(detail) => {
                    return Err(ChangeSetError::StorageUnavailable {
                        detail: format!(
                            "the object {hex} is at its name and this host could not read it, so \
                             it neither replaced it nor reported it stored: {detail}"
                        )
                        .into(),
                    });
                }
            }
        }
        // The temporary's name carries this process's own identity and a fresh value, so two
        // captures writing the same content at the same time never meet at one temporary.
        let temporary = format!(
            "{leaf}.{}.{}",
            std::process::id(),
            hex_of(digest_of(kr_ipc::new_uuid().as_bytes()))
        );
        let temporary = RelativeName::parse(&temporary)?;
        {
            let mut file = shelf.create_new(&temporary)?;
            let handle = file.handle_mut();
            handle
                .write_all(bytes)
                .map_err(ChangeSetError::storage)
                .inspect_err(|_| {
                    let _ = shelf.remove(&temporary);
                })?;
            handle.sync_all().map_err(ChangeSetError::storage)?;
        }
        // A link refuses an occupied name on every platform, so a concurrent capture that got
        // there first keeps its blob and this one removes its own temporary. **Nothing is removed
        // to make room here**: a valid blob another writer published between the check above and
        // this link is the content, and unlinking it would take an object a recorded version
        // names.
        let published = if repair {
            shelf.rename_into(&temporary, &shelf, &final_name)
        } else {
            shelf.link_into(&temporary, &shelf, &final_name)
        };
        let _ = shelf.remove(&temporary);
        match published {
            Ok(()) => {
                shelf.sync()?;
                Ok(digest)
            }
            Err(error) => {
                if matches!(self.reads_back(digest)?, ReadBack::Content) {
                    shelf.sync()?;
                    Ok(digest)
                } else {
                    Err(ChangeSetError::StorageUnavailable {
                        detail: format!(
                            "the object {hex} could not be published and what is at its name is \
                             not its content: {error}"
                        )
                        .into(),
                    })
                }
            }
        }
    }

    /// Returns what reading one digest's name back established.
    ///
    /// The three answers are different things and this host acts differently on each: content is
    /// content, damage is something it replaces, and a name it could not read is one it leaves
    /// exactly as it is.
    fn reads_back(&self, digest: Digest256) -> Result<ReadBack> {
        let hex = hex_of(digest);
        let (fan_out, leaf) = hex.split_at(2);
        let shelf = match self.root.subdirectory(&RelativeName::parse(fan_out)?) {
            Ok(shelf) => shelf,
            Err(kr_transfer::Escape::NotFound { .. }) => {
                return Ok(ReadBack::Unreadable("it is not there".to_owned()));
            }
            Err(error) => return Ok(ReadBack::Unreadable(error.to_string())),
        };
        let mut file =
            match shelf.open_read(&RelativeName::parse(leaf)?, ObjectPolicy::ReadableFile) {
                Ok(file) => file,
                Err(kr_transfer::Escape::NotFound { .. }) => {
                    return Ok(ReadBack::Unreadable("it is not there".to_owned()));
                }
                // A directory or a link at the name is not a blob this host wrote, and it is not
                // something this host can read as one either.
                Err(error) => return Ok(ReadBack::Unreadable(error.to_string())),
            };
        let mut bytes = Vec::new();
        if let Err(error) = file.handle_mut().read_to_end(&mut bytes) {
            return Ok(ReadBack::Unreadable(error.to_string()));
        }
        if digest_of(&bytes) == digest {
            Ok(ReadBack::Content)
        } else {
            Ok(ReadBack::Damaged)
        }
    }

    /// Returns the bytes one digest names.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StorageUnavailable`] when the blob is absent or cannot be read.
    pub fn get(&self, digest: Digest256) -> Result<Vec<u8>> {
        let hex = hex_of(digest);
        let (fan_out, leaf) = hex.split_at(2);
        let shelf = self.root.subdirectory(&RelativeName::parse(fan_out)?)?;
        let mut file = shelf.open_read(&RelativeName::parse(leaf)?, ObjectPolicy::ReadableFile)?;
        let mut bytes = Vec::with_capacity(usize::try_from(file.byte_len()).unwrap_or(READ_CHUNK));
        file.handle_mut()
            .read_to_end(&mut bytes)
            .map_err(ChangeSetError::storage)?;
        // The store is content-addressed, so what comes back is checked against the name it came
        // from. A blob whose bytes no longer hash to its own name is storage damage rather than
        // the content a version names, and serving it would break the one invariant this store
        // exists for.
        if digest_of(&bytes) != digest {
            return Err(ChangeSetError::StorageUnavailable {
                detail: format!(
                    "the stored object {hex} no longer holds the content its name says it holds"
                )
                .into(),
            });
        }
        Ok(bytes)
    }

    /// Returns true when one digest's blob is in the store.
    ///
    /// # Errors
    ///
    /// Returns [`ChangeSetError::StorageUnavailable`] when the storage would not answer.
    pub fn holds(&self, digest: Digest256) -> Result<bool> {
        let hex = hex_of(digest);
        let (fan_out, leaf) = hex.split_at(2);
        let shelf = match self.root.subdirectory(&RelativeName::parse(fan_out)?) {
            Ok(shelf) => shelf,
            Err(kr_transfer::Escape::NotFound { .. }) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        Ok(shelf.occupied(&RelativeName::parse(leaf)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(temporary: &tempfile::TempDir) -> (ObjectStore, EnvironmentId) {
        let environment_id = EnvironmentId::new(kr_ipc::new_uuid());
        let root = AuthorisedDirectory::open_root(environment_id, temporary.path())
            .expect("the test directory opens");
        (
            ObjectStore::open(&root, environment_id).expect("the object store opens"),
            environment_id,
        )
    }

    #[test]
    fn a_blob_is_named_by_its_own_content() {
        let temporary = tempfile::TempDir::new().expect("a directory on the internal disk");
        let (store, _) = store(&temporary);
        let first = store.put(b"the captured content").expect("the first write");
        let second = store
            .put(b"the captured content")
            .expect("the second write");
        assert_eq!(first, second, "the same content has one name");
        let other = store.put(b"different content").expect("another write");
        assert_ne!(first, other, "different content has a different name");
        assert_eq!(store.get(first).expect("a read"), b"the captured content");
        assert_eq!(store.get(other).expect("a read"), b"different content");
    }

    #[test]
    fn an_empty_blob_is_stored_and_read_back() {
        // A working tree holds empty files, and a store that could not name one would lose them.
        let temporary = tempfile::TempDir::new().expect("a directory on the internal disk");
        let (store, _) = store(&temporary);
        let digest = store.put(b"").expect("an empty write");
        assert!(store.holds(digest).expect("the store answers"));
        assert!(store.get(digest).expect("a read").is_empty());
    }

    #[test]
    fn a_digest_the_store_does_not_hold_is_absent_rather_than_an_error() {
        let temporary = tempfile::TempDir::new().expect("a directory on the internal disk");
        let (store, _) = store(&temporary);
        let absent = digest_of(b"never written");
        assert!(!store.holds(absent).expect("the store answers"));
        assert!(store.get(absent).is_err(), "reading it is refused");
    }

    #[test]
    fn a_damaged_blob_is_replaced_rather_than_accepted_as_deduplication() {
        // A name that is taken is not evidence that the content is there. A write that found a
        // damaged file at the digest's name and threw the valid bytes away would leave a version
        // naming content the store cannot deliver.
        let temporary = tempfile::TempDir::new().expect("a directory on the internal disk");
        let (store, _) = store(&temporary);
        let digest = store.put(b"the captured content").expect("a write");
        let hex = hex_of(digest);
        let (fan_out, leaf) = hex.split_at(2);
        let path = temporary
            .path()
            .join(OBJECTS_DIRECTORY)
            .join(fan_out)
            .join(leaf);
        std::fs::write(&path, b"something else entirely").expect("the fixture damages the blob");
        let again = store
            .put(b"the captured content")
            .expect("the write succeeds");
        assert_eq!(again, digest);
        assert_eq!(
            store.get(digest).expect("the content is deliverable"),
            b"the captured content",
            "the valid bytes replaced the damaged ones"
        );
    }

    #[test]
    fn a_blob_whose_bytes_no_longer_match_its_name_is_refused() {
        // The one invariant this store exists for: a digest names exactly one sequence of bytes.
        // Storage damage is refused rather than served as the content a version names.
        let temporary = tempfile::TempDir::new().expect("a directory on the internal disk");
        let (store, _) = store(&temporary);
        let digest = store.put(b"the captured content").expect("a write");
        let hex = hex_of(digest);
        let (fan_out, leaf) = hex.split_at(2);
        let path = temporary
            .path()
            .join(OBJECTS_DIRECTORY)
            .join(fan_out)
            .join(leaf);
        std::fs::write(&path, b"something else entirely").expect("the fixture rewrites the blob");
        let failure = store.get(digest).expect_err("a damaged blob is refused");
        assert!(
            failure.to_string().contains("no longer holds"),
            "the refusal says what is wrong: {failure}"
        );
    }
}
