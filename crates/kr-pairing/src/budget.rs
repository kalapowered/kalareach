//! The candidate's attempt budget, kept on disk.
//!
//! [`crate::client::charge_attempt`] decides what one entered code's record becomes; this is where
//! the records live between one entry and the next, across application restarts and reboots, and
//! how two entries of the same code on one device, in two threads or in two processes, are kept
//! from both seeing four attempts.
//!
//! * The records live in two slot files in an owner-only directory, each holding a whole copy with
//!   a sequence number and a SHA-256 of its contents. A write goes to the slot that does not hold
//!   the newest copy, in place, and is flushed to the device before the charge it records is
//!   reported; a reader takes the valid copy with the higher sequence. A crash part way through a
//!   write leaves that slot failing its digest and the other one holding the copy before it, so a
//!   reader sees the last completed write, whole, on every platform, with no rename whose
//!   durability depends on the file system.
//! * Every operation holds an exclusive lock on a `lock` file in the same directory, which is
//!   created once and never replaced, so the lock two processes take is always on the same file.
//! * The counter's key is a secret of its own, 32 random bytes kept in the secret store the caller
//!   gives (the platform's credential store, or the owner-only directory fallback where section 10
//!   allows one), under `<scope>/pairing-client-budget-key`. It is created under the same lock, so
//!   two first entries agree on one key, and it is never a transport or control key. The records
//!   name the key they were counted under by its digest: once they do, a key that is missing or
//!   different is an error, never a fresh budget.
//! * Records this store cannot read are an error, never an empty budget, and a write that would
//!   make them larger than a reader accepts is refused with the records as they were: forgetting a
//!   device's attempts is exactly what the budget exists to prevent.
//!
//! On Unix the directory is created with mode 0700 and refused when anyone but its owner can reach
//! it. On Windows it carries the access-control list it inherits, so a caller places it under the
//! person's own profile; this crate makes no Windows calls to set one of its own.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_crypto::secret::SymmetricKey;
use kr_crypto::store::{SecretName, SecretStore};
use kr_flush::{NameKind, flush_directory};
use kr_protocol::scalars::Mac256;
use serde::{Deserialize, Serialize};

use crate::error::{PairingError, Result};
use crate::platform::{BootIdentity, ClientAttemptRecord, ClientBudgetStore};

/// The two files the records are written to in turn.
const SLOTS: [&str; 2] = ["records-a", "records-b"];

/// The file every operation locks. It is never written, truncated or replaced.
const LOCK: &str = "lock";

/// The largest slot this store reads or writes. A device keeps a record per entered code for at
/// most a day, which is a few hundred bytes each.
const MAX_RECORDS_BYTES: usize = 4 * 1024 * 1024;

/// The version of the records this store writes and reads.
const FORMAT_VERSION: u32 = 1;

/// The domain the digest that names the budget's key is computed under.
const KEY_ID_DOMAIN: &[u8] = b"kr-pair/client-budget-key-id/1";

/// Returns the name the budget's key is kept under in a secret store.
///
/// # Errors
///
/// Returns [`PairingError::Store`] when `scope` makes the name invalid.
pub fn budget_key_name(scope: &str) -> Result<SecretName> {
    SecretName::new(format!("{scope}/pairing-client-budget-key")).map_err(store)
}

/// A candidate's attempt budget, durable across restarts and shared by every process on this
/// device that opens the same directory.
pub struct DurableClientBudgetStore {
    directory: PathBuf,
    secrets: Arc<dyn SecretStore>,
    key_name: SecretName,
    /// The largest a slot may be, which tests lower to reach it.
    limit: usize,
}

impl std::fmt::Debug for DurableClientBudgetStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableClientBudgetStore")
            .field("directory", &self.directory)
            .field("secrets", &self.secrets.describe())
            .field("key_name", &self.key_name)
            .finish_non_exhaustive()
    }
}

/// The records, and where the newest copy of them is.
struct Held {
    budget: StoredBudget,
    /// The slot holding this copy, when one does.
    slot: Option<usize>,
}

impl DurableClientBudgetStore {
    /// Opens the budget kept in `directory`, creating the directory owner-only, with its key kept
    /// in `secrets` for `scope`.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] when the directory is a link, cannot be created, is open to
    /// anyone but its owner, or its lock and slot files cannot be created.
    pub fn open(
        directory: impl Into<PathBuf>,
        secrets: Arc<dyn SecretStore>,
        scope: &str,
    ) -> Result<Self> {
        let directory = directory.into();
        prepare_directory(&directory)?;
        let store = Self {
            key_name: budget_key_name(scope)?,
            directory,
            secrets,
            limit: MAX_RECORDS_BYTES,
        };
        // The lock and both slots exist from here on, so every later operation opens the same
        // files and a write never creates one.
        let _held = store.lock()?;
        for slot in SLOTS {
            let path = store.directory.join(slot);
            reject_link(&path)?;
            owner_only_options()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|error| io_error("create", &path, &error))?;
        }
        sync_directory(&store.directory, NameKind::File)?;
        Ok(store)
    }

    /// The directory the records and the lock live in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Takes the exclusive lock every operation runs under. It is released when the returned file
    /// is dropped.
    fn lock(&self) -> Result<File> {
        let path = self.directory.join(LOCK);
        reject_link(&path)?;
        let file = owner_only_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| io_error("open", &path, &error))?;
        file.lock()
            .map_err(|error| io_error("lock", &path, &error))?;
        Ok(file)
    }

    /// Reads the newest valid copy of the records.
    ///
    /// Two empty slots are a budget nobody has written yet. One slot failing its digest beside a
    /// valid one is a write that did not finish, and the valid one is the last that did; a damaged
    /// slot beside an empty one is the first write not finishing. Two damaged slots are an error.
    fn read(&self) -> Result<Held> {
        let mut newest: Option<(StoredBudget, usize)> = None;
        let mut damaged = 0;
        for (index, name) in SLOTS.iter().enumerate() {
            match self.read_slot(name)? {
                Slot::Empty => {}
                Slot::Damaged => damaged += 1,
                Slot::Valid(budget) => {
                    if newest
                        .as_ref()
                        .is_none_or(|(held, _)| budget.sequence > held.sequence)
                    {
                        newest = Some((budget, index));
                    }
                }
            }
        }
        match newest {
            Some((budget, slot)) => Ok(Held {
                budget,
                slot: Some(slot),
            }),
            None if damaged < SLOTS.len() => Ok(Held {
                budget: StoredBudget::empty(),
                slot: None,
            }),
            None => Err(PairingError::Store {
                reason: format!(
                    "both copies of the budget's records in {} are damaged",
                    self.directory.display()
                ),
            }),
        }
    }

    fn read_slot(&self, name: &str) -> Result<Slot> {
        let path = self.directory.join(name);
        reject_link(&path)?;
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Slot::Empty),
            Err(error) => return Err(io_error("open", &path, &error)),
        };
        let mut bytes = Vec::new();
        file.take(
            u64::try_from(self.limit)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read", &path, &error))?;
        if bytes.is_empty() {
            return Ok(Slot::Empty);
        }
        Ok(decode_slot(&bytes, self.limit).map_or(Slot::Damaged, Slot::Valid))
    }

    /// Writes `budget` as the next copy, into the slot that does not hold the newest one.
    fn write(&self, held: &Held, mut budget: StoredBudget) -> Result<()> {
        budget.sequence = held.budget.sequence.saturating_add(1);
        let bytes = encode_slot(&budget)?;
        if bytes.len() > self.limit {
            return Err(PairingError::Store {
                reason: format!(
                    "the budget's records would grow past the {} bytes a reader accepts; they \
                     are kept as they were",
                    self.limit
                ),
            });
        }
        let slot = held.slot.map_or(0, |newest| 1 - newest);
        let path = self.directory.join(SLOTS[slot]);
        reject_link(&path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|error| io_error("open", &path, &error))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| io_error("write", &path, &error))
    }
}

impl ClientBudgetStore for DurableClientBudgetStore {
    fn budget_key(&self) -> Result<SymmetricKey> {
        let _held = self.lock()?;
        let held = self.read()?;
        let kept = self.secrets.get(&self.key_name).map_err(store)?;
        match (kept, held.budget.key_id.clone()) {
            (Some(bytes), Some(counted_under)) => {
                let key = SymmetricKey::from_slice("the client budget key", bytes.expose())
                    .map_err(store)?;
                if key_id(&key) != counted_under {
                    return Err(PairingError::Store {
                        reason: "the budget's records were counted under another key".to_owned(),
                    });
                }
                Ok(key)
            }
            (None, Some(_)) => Err(PairingError::Store {
                reason: "the key the budget's records were counted under is gone".to_owned(),
            }),
            (kept, None) => {
                // A budget that names no key has counted nothing yet. Its key is the one already
                // kept, or a new one, kept before the records name it.
                let key = match kept {
                    Some(bytes) => {
                        SymmetricKey::from_slice("the client budget key", bytes.expose())
                            .map_err(store)?
                    }
                    None => {
                        let key = SymmetricKey::random().map_err(store)?;
                        self.secrets
                            .set(&self.key_name, key.expose())
                            .map_err(store)?;
                        key
                    }
                };
                let budget = StoredBudget {
                    key_id: Some(key_id(&key)),
                    ..held.budget.clone()
                };
                self.write(&held, budget)?;
                Ok(key)
            }
        }
    }

    fn update(
        &self,
        code_key: &Mac256,
        decide: &dyn Fn(Option<ClientAttemptRecord>) -> Result<ClientAttemptRecord>,
    ) -> Result<ClientAttemptRecord> {
        let _held = self.lock()?;
        let held = self.read()?;
        let mut records = held.budget.records()?;
        let updated = decide(records.get(code_key.as_bytes()).cloned())?;
        records.insert(*code_key.as_bytes(), updated.clone());
        let budget = held.budget.with_records(&records);
        self.write(&held, budget)?;
        Ok(updated)
    }

    fn load(&self, code_key: &Mac256) -> Result<Option<ClientAttemptRecord>> {
        let _held = self.lock()?;
        Ok(self.read()?.budget.records()?.remove(code_key.as_bytes()))
    }

    fn expire(&self, now_monotonic_ms: u64, boot: BootIdentity, now_wall_ms: u64) -> Result<()> {
        let _held = self.lock()?;
        let held = self.read()?;
        let records = held.budget.records()?;
        let kept: BTreeMap<[u8; 32], ClientAttemptRecord> = records
            .iter()
            .map(|(key, record)| (*key, record.anchored(now_monotonic_ms, boot)))
            .filter(|(_, record)| !record.is_expired(now_monotonic_ms, boot, now_wall_ms))
            .collect();
        if kept != records {
            let budget = held.budget.with_records(&kept);
            self.write(&held, budget)?;
        }
        Ok(())
    }
}

/// What one slot holds.
enum Slot {
    /// Nothing: no copy was ever written to it.
    Empty,
    /// A copy that fails its digest or cannot be read: a write that did not finish.
    Damaged,
    /// A whole copy.
    Valid(StoredBudget),
}

/// Writes a copy as a slot holds it: the SHA-256 of the copy in hexadecimal, a line end, and the
/// copy itself.
fn encode_slot(budget: &StoredBudget) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(budget).map_err(|error| PairingError::Store {
        reason: format!("the budget's records cannot be written: {error}"),
    })?;
    let mut bytes = hex::encode(kr_cbor::sha256(&body)).into_bytes();
    bytes.push(b'\n');
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// Reads a slot back, or nothing when it is not a whole copy of this version.
fn decode_slot(bytes: &[u8], limit: usize) -> Option<StoredBudget> {
    if bytes.len() > limit {
        return None;
    }
    let newline = bytes.iter().position(|byte| *byte == b'\n')?;
    let (digest, body) = (&bytes[..newline], &bytes[newline + 1..]);
    if digest != hex::encode(kr_cbor::sha256(body)).as_bytes() {
        return None;
    }
    let budget: StoredBudget = serde_json::from_slice(body).ok()?;
    (budget.version == FORMAT_VERSION).then_some(budget)
}

/// Names a key by its digest, so the records can say which key they were counted under.
fn key_id(key: &SymmetricKey) -> String {
    let mut message = zeroize::Zeroizing::new(Vec::with_capacity(KEY_ID_DOMAIN.len() + 32));
    message.extend_from_slice(KEY_ID_DOMAIN);
    message.extend_from_slice(key.expose());
    hex::encode(kr_cbor::sha256(&message))
}

/// One copy of the records.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBudget {
    version: u32,
    /// Which copy this is: the higher of two valid copies is the newer.
    sequence: u64,
    /// The digest of the key the records were counted under, once there is one.
    key_id: Option<String>,
    /// Each code's record, by its key in lower-case hexadecimal.
    records: BTreeMap<String, StoredRecord>,
}

impl StoredBudget {
    const fn empty() -> Self {
        Self {
            version: FORMAT_VERSION,
            sequence: 0,
            key_id: None,
            records: BTreeMap::new(),
        }
    }

    fn records(&self) -> Result<BTreeMap<[u8; 32], ClientAttemptRecord>> {
        self.records
            .iter()
            .map(|(key, record)| Ok((decode_hex::<32>(key)?, record.to_record()?)))
            .collect()
    }

    fn with_records(&self, records: &BTreeMap<[u8; 32], ClientAttemptRecord>) -> Self {
        Self {
            records: records
                .iter()
                .map(|(key, record)| (hex::encode(key), StoredRecord::from_record(record)))
                .collect(),
            ..self.clone()
        }
    }
}

/// One code's record as a copy holds it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    attempts: u32,
    first_entry_monotonic_ms: u64,
    boot_identity: String,
    retain_until_monotonic_ms: u64,
    retain_until_wall_ms: u64,
    exhausted: bool,
}

impl StoredRecord {
    fn from_record(record: &ClientAttemptRecord) -> Self {
        Self {
            attempts: record.attempts,
            first_entry_monotonic_ms: record.first_entry_monotonic_ms,
            boot_identity: hex::encode(record.boot_identity.0),
            retain_until_monotonic_ms: record.retain_until_monotonic_ms,
            retain_until_wall_ms: record.retain_until_wall_ms,
            exhausted: record.exhausted,
        }
    }

    fn to_record(&self) -> Result<ClientAttemptRecord> {
        Ok(ClientAttemptRecord {
            attempts: self.attempts,
            first_entry_monotonic_ms: self.first_entry_monotonic_ms,
            boot_identity: BootIdentity(decode_hex::<32>(&self.boot_identity)?),
            retain_until_monotonic_ms: self.retain_until_monotonic_ms,
            retain_until_wall_ms: self.retain_until_wall_ms,
            exhausted: self.exhausted,
        })
    }
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes).map_err(|error| PairingError::Store {
        reason: format!("a budget record holds {text:?}, which is not {N} bytes of hex: {error}"),
    })?;
    Ok(bytes)
}

/// Creates `directory` owner-only, or checks that it already is, without following a link at it,
/// and flushes every entry that finding it again depends on.
///
/// A directory that exists is not thereby durable. Whoever created it may have stopped before it
/// flushed the entry naming it, and an opener that trusted its existence would record charges in
/// a directory a crash can take away. So every open flushes the whole path, whoever made it.
fn prepare_directory(directory: &Path) -> Result<()> {
    reject_link(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .map_err(|error| io_error("create", directory, &error))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(directory).map_err(|error| io_error("create", directory, &error))?;
    reject_link(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = std::fs::symlink_metadata(directory)
            .map_err(|error| io_error("inspect", directory, &error))?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(PairingError::Store {
                reason: format!(
                    "{} is not a directory only its owner can reach",
                    directory.display()
                ),
            });
        }
    }
    let absolute =
        std::path::absolute(directory).map_err(|error| io_error("resolve", directory, &error))?;
    flush_resolution(&absolute)
}

/// How many links one path may pass through before it is refused, as the kernel counts them.
#[cfg(unix)]
const MAX_LINKS_FOLLOWED: usize = 40;

/// Flushes each directory in which an entry is looked up to find `path` again: the directories
/// above it, and, for a link on the way, the directory holding the link and those along its
/// target.
///
/// The path is resolved the way the kernel resolves it, one component at a time. The entry each
/// component names lives in the directory reached so far, so that directory is flushed before
/// the component is followed. A link is then read and its target resolved in its place, so the
/// directories a crash could otherwise take from under the link are flushed as well.
#[cfg(unix)]
fn flush_resolution(path: &Path) -> Result<()> {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::Component;

    /// Puts a path's components in front of what remains to be resolved.
    fn prepend(remaining: &mut VecDeque<OsString>, path: &Path) {
        for component in path.components().rev() {
            match component {
                Component::Normal(name) => remaining.push_front(name.to_os_string()),
                Component::ParentDir => remaining.push_front(OsString::from("..")),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    }

    let mut reached = PathBuf::from("/");
    let mut remaining = VecDeque::new();
    let mut followed = 0;
    prepend(&mut remaining, path);
    while let Some(name) = remaining.pop_front() {
        if name == ".." {
            reached.pop();
            continue;
        }
        sync_directory(&reached, NameKind::Directory)?;
        let next = reached.join(&name);
        let metadata =
            std::fs::symlink_metadata(&next).map_err(|error| io_error("inspect", &next, &error))?;
        if !metadata.is_symlink() {
            reached = next;
            continue;
        }
        followed += 1;
        if followed > MAX_LINKS_FOLLOWED {
            return Err(PairingError::Store {
                reason: format!(
                    "{} passes through more than {MAX_LINKS_FOLLOWED} links",
                    path.display()
                ),
            });
        }
        let target = std::fs::read_link(&next).map_err(|error| io_error("read", &next, &error))?;
        if target.is_absolute() {
            reached = PathBuf::from("/");
        }
        prepend(&mut remaining, &target);
    }
    // The last directory reached holds the lock and the slots; the open flushes it once they are
    // there.
    Ok(())
}

/// Flushes each directory in which an entry is looked up to find `path` again, and the directory
/// itself, through the host's own walk of a path.
///
/// That walk resolves the path the way this platform does, following a junction to where it leads,
/// and passes over a directory on the way that this account may not add to, which holds no name
/// this account made.
#[cfg(not(unix))]
fn flush_resolution(path: &Path) -> Result<()> {
    kr_ipc::paths::flush_path_names(path).map_err(|error| io_error("flush", path, &error))
}

/// Options that create a file only its owner can read and write.
fn owner_only_options() -> OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = OpenOptions::new();
        options.mode(0o600);
        options
    }
    // Windows has no mode bits: a file carries the access-control list of the directory it is
    // created in.
    #[cfg(not(unix))]
    OpenOptions::new()
}

/// Refuses a path that is a symbolic link.
fn reject_link(path: &Path) -> Result<()> {
    if path.is_symlink() {
        return Err(PairingError::Store {
            reason: format!("{} is a symbolic link", path.display()),
        });
    }
    Ok(())
}

/// Flushes a directory's entries to the device, so a name created in it survives a crash.
///
/// `kind` is the name that was created, a file's or a directory's, which is the right the flush's
/// handle asks for on Windows.
fn sync_directory(directory: &Path, kind: NameKind) -> Result<()> {
    #[cfg(all(test, unix))]
    tests::flushed(directory);
    flush_directory(directory, kind).map_err(|error| io_error("flush", directory, &error))
}

fn io_error(what: &str, path: &Path, error: &std::io::Error) -> PairingError {
    PairingError::Store {
        reason: format!("{what} {}: {error}", path.display()),
    }
}

fn store(error: impl std::fmt::Display) -> PairingError {
    PairingError::Store {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{budget_key, charge_attempt};
    use crate::code::EnteredCode;
    use crate::platform::TestClock;
    use kr_crypto::store::MemoryStore;
    use kr_protocol::pairing::{MAX_CLIENT_ATTEMPTS, RendezvousOrigin};

    /// Where a child process of the two-process test finds the directory it shares.
    const CHILD_DIRECTORY: &str = "KR_PAIRING_BUDGET_CHILD_DIRECTORY";

    /// Every directory this test program has flushed, in order. Only Unix flushes a directory.
    #[cfg(unix)]
    static FLUSHED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

    #[cfg(unix)]
    pub(super) fn flushed(directory: &Path) {
        FLUSHED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(directory.to_path_buf());
    }

    #[cfg(unix)]
    fn was_flushed(directory: &Path) -> bool {
        FLUSHED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|flushed| flushed == directory)
    }

    /// A directory under the system's temporary directory, removed when the test is done.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kr-pairing-budget-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn origin() -> RendezvousOrigin {
        RendezvousOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn code() -> EnteredCode {
        EnteredCode::parse("4XkP-Qm7-Zr2").expect("a code")
    }

    fn open(directory: &Path, secrets: &Arc<dyn SecretStore>) -> DurableClientBudgetStore {
        DurableClientBudgetStore::open(directory.join("budget"), Arc::clone(secrets), "client")
            .expect("a budget")
    }

    fn memory() -> Arc<dyn SecretStore> {
        Arc::new(MemoryStore::new())
    }

    /// Charges `times` attempts and returns how many were allowed.
    fn charge(store: &DurableClientBudgetStore, clock: &TestClock, times: u32) -> u32 {
        (0..times)
            .filter(|_| match charge_attempt(store, clock, &origin(), &code()) {
                Ok(_) => true,
                Err(PairingError::ClientAttemptsExhausted) => false,
                Err(other) => panic!("a charge failed: {other}"),
            })
            .count()
            .try_into()
            .expect("a count")
    }

    /// The attempts recorded against the test's code.
    fn attempts(store: &DurableClientBudgetStore) -> Option<u32> {
        let key = budget_key(store, &origin(), &code()).expect("a key");
        store
            .load(&key)
            .expect("readable")
            .map(|record| record.attempts)
    }

    /// KR-REQ-10.32: two stores on one directory, charging the same code from two threads each,
    /// spend five attempts between them and no more.
    #[test]
    fn charges_from_four_threads_spend_five_attempts_between_them() {
        let scratch = Scratch::new("threads");
        let secrets = memory();
        let stores = [open(&scratch.0, &secrets), open(&scratch.0, &secrets)];
        let clock = TestClock::new();
        let allowed: u32 = std::thread::scope(|threads| {
            let handles: Vec<_> = stores
                .iter()
                .flat_map(|store| [store, store])
                .map(|store| threads.spawn(|| charge(store, &clock, MAX_CLIENT_ATTEMPTS)))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("a charging thread"))
                .sum()
        });
        assert_eq!(allowed, MAX_CLIENT_ATTEMPTS);
    }

    /// Run by the two-process test in a child process of its own: opens the shared budget, with
    /// its key in the shared directory store, charges the code five times and prints how many
    /// were allowed.
    #[test]
    #[ignore = "a child of a_budget_shared_by_two_processes_spends_five_attempts"]
    fn charging_child() {
        let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
            return;
        };
        let directory = PathBuf::from(directory);
        let secrets: Arc<dyn SecretStore> = Arc::from(
            kr_crypto::store::open_store_in(&directory.join("secrets"))
                .expect("the shared secrets")
                .store,
        );
        // Said once this child has found the budget's lock held by another process, which is
        // where it then waits.
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join("budget").join(LOCK))
            .expect("the budget's lock");
        match lock.try_lock() {
            Err(std::fs::TryLockError::WouldBlock) => {}
            Ok(()) => panic!("the budget's lock was free while the parent held it"),
            Err(std::fs::TryLockError::Error(error)) => {
                panic!("the lock could not be tried: {error}")
            }
        }
        drop(lock);
        std::fs::write(directory.join(format!("ready-{}", std::process::id())), b"")
            .expect("ready");
        let allowed = charge(
            &open(&directory, &secrets),
            &TestClock::new(),
            MAX_CLIENT_ATTEMPTS,
        );
        // On a line of its own: the harness writes the test's name on the line it starts.
        println!("\nallowed {allowed}");
    }

    /// How long a child of the two-process test is given, far past what charging five attempts
    /// takes.
    const CHILD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

    /// Child processes that end with the test, however it ends.
    ///
    /// Every child stays here until the test is over, whether it has finished or not, so a panic
    /// anywhere leaves each one to be ended and collected when this is dropped.
    struct Children {
        held: Vec<std::process::Child>,
        deadline: std::time::Duration,
    }

    impl Children {
        fn new(held: Vec<std::process::Child>) -> Self {
            Self {
                held,
                deadline: CHILD_DEADLINE,
            }
        }

        /// Waits for every child, within the deadline, and returns how each ended and what it
        /// printed.
        fn finish(&mut self) -> Vec<(std::process::ExitStatus, String)> {
            let started = std::time::Instant::now();
            let mut finished = Vec::new();
            for child in &mut self.held {
                let status = loop {
                    if let Some(status) = child.try_wait().expect("a child's state") {
                        break status;
                    }
                    assert!(
                        started.elapsed() <= self.deadline,
                        "a child did not finish in time"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                };
                let mut printed = String::new();
                if let Some(mut output) = child.stdout.take() {
                    output
                        .read_to_string(&mut printed)
                        .expect("the child's output");
                }
                finished.push((status, printed));
            }
            finished
        }
    }

    impl Drop for Children {
        fn drop(&mut self) {
            for child in &mut self.held {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Run by the test of the children's deadline: waits far longer than that deadline.
    #[test]
    #[ignore = "a child of children_that_miss_the_deadline_are_ended_and_collected"]
    fn waiting_child() {
        if std::env::var_os(CHILD_DIRECTORY).is_some() {
            std::thread::sleep(std::time::Duration::from_secs(120));
        }
    }

    /// A child that does not finish in time fails the test, and is ended and collected rather
    /// than left running.
    #[test]
    fn children_that_miss_the_deadline_are_ended_and_collected() {
        let program = std::env::current_exe().expect("this test program");
        let mut children = Children {
            held: Vec::new(),
            deadline: std::time::Duration::from_millis(200),
        };
        children.held.push(
            std::process::Command::new(&program)
                .args([
                    "budget::tests::waiting_child",
                    "--exact",
                    "--ignored",
                    "--test-threads=1",
                ])
                .env(CHILD_DIRECTORY, "waiting")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("a child process"),
        );
        // Whoever holds the other end of the child's output sees it close only once the child
        // has ended.
        let mut output = children.held[0].stdout.take().expect("the child's output");
        let missed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| children.finish()));
        assert!(missed.is_err(), "a child past its deadline fails the test");
        let ended = std::time::Instant::now();
        drop(children);
        let mut rest = Vec::new();
        output
            .read_to_end(&mut rest)
            .expect("the child's output closes");
        assert!(
            ended.elapsed() < std::time::Duration::from_secs(30),
            "the child was ended rather than left to its sleep"
        );
    }

    /// KR-REQ-10.32: two processes that open one budget while a third holds its lock both wait
    /// for it; once it is released they agree on one key, made by whichever came first, and spend
    /// five attempts between them.
    #[test]
    fn a_budget_shared_by_two_processes_spends_five_attempts() {
        let scratch = Scratch::new("processes");
        // The secret store's directory exists before the children start: what they race on is the
        // budget, its lock and its key.
        kr_crypto::store::open_store_in(&scratch.0.join("secrets")).expect("the shared secrets");
        let budget = open(&scratch.0, &memory());
        let held = budget.lock().expect("the lock");

        let program = std::env::current_exe().expect("this test program");
        // Held before the first child starts, so a child that started is ended and collected
        // however the test goes on, a second start that fails included.
        let mut children = Children::new(Vec::new());
        for _ in 0..2 {
            children.held.push(
                std::process::Command::new(&program)
                    .args([
                        "budget::tests::charging_child",
                        "--exact",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD_DIRECTORY, &scratch.0)
                    .current_dir(&scratch.0)
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("a child process"),
            );
        }
        // Both children say they found the lock held; neither gets it while it is held, and
        // nothing is written meanwhile.
        let started = std::time::Instant::now();
        loop {
            let ready = std::fs::read_dir(&scratch.0)
                .expect("the shared directory")
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("ready-"))
                .count();
            if ready == 2 {
                break;
            }
            assert!(
                started.elapsed() < CHILD_DEADLINE,
                "the children did not reach the lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        for child in &mut children.held {
            assert!(
                child.try_wait().expect("a child's state").is_none(),
                "a child waits while another process holds the lock"
            );
        }
        for slot in SLOTS {
            assert_eq!(
                std::fs::metadata(budget.directory().join(slot))
                    .expect("a slot")
                    .len(),
                0,
                "nothing is written while the lock is held"
            );
        }
        drop(held);

        let outputs = children.finish();
        let allowed: u32 = outputs
            .iter()
            .map(|(status, text)| {
                assert!(status.success(), "the child succeeded: {text}");
                text.lines()
                    .find_map(|line| line.strip_prefix("allowed "))
                    .unwrap_or_else(|| panic!("the child reports: {text}"))
                    .parse::<u32>()
                    .expect("a count")
            })
            .sum();
        assert_eq!(allowed, MAX_CLIENT_ATTEMPTS);
        let secrets: Arc<dyn SecretStore> = Arc::from(
            kr_crypto::store::open_store_in(&scratch.0.join("secrets"))
                .expect("the shared secrets")
                .store,
        );
        assert_eq!(
            attempts(&open(&scratch.0, &secrets)),
            Some(MAX_CLIENT_ATTEMPTS),
            "both charged one record, under one key"
        );
    }

    /// KR-REQ-10.32: the count survives the application going away and coming back, with the same
    /// key.
    #[test]
    fn the_budget_survives_a_restart() {
        let scratch = Scratch::new("restart");
        let secrets = memory();
        let clock = TestClock::new();
        let first = open(&scratch.0, &secrets);
        let key = first.budget_key().expect("a key");
        assert_eq!(charge(&first, &clock, 2), 2);
        drop(first);

        let again = open(&scratch.0, &secrets);
        assert_eq!(
            again.budget_key().expect("a key").expose(),
            key.expose(),
            "the key is kept, not made again"
        );
        let left = charge_attempt(&again, &clock, &origin(), &code()).expect("a third attempt");
        assert_eq!(left, MAX_CLIENT_ATTEMPTS - 3);
    }

    /// KR-REQ-10.32: a reboot expires an unfinished entry, and the store keeps it as spent across
    /// the reboot, so the code cannot be entered again.
    #[test]
    fn a_reboot_leaves_an_unfinished_entry_spent() {
        let scratch = Scratch::new("reboot");
        let secrets = memory();
        let clock = TestClock::new();
        assert_eq!(charge(&open(&scratch.0, &secrets), &clock, 1), 1);

        clock.reboot(7);
        let after = open(&scratch.0, &secrets);
        assert!(matches!(
            charge_attempt(&after, &clock, &origin(), &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
        let key = budget_key(&after, &origin(), &code()).expect("a key");
        let record = after.load(&key).expect("readable").expect("kept");
        assert!(record.exhausted);
        assert_eq!(record.boot_identity, BootIdentity([7; 32]));
    }

    /// KR-REQ-10.32: the counter's key is a random 32-byte secret of its own, kept under the
    /// budget's name in the secret store it was given.
    #[test]
    fn the_key_is_a_secret_of_its_own() {
        let scratch = Scratch::new("key");
        let memory = Arc::new(MemoryStore::new());
        let secrets: Arc<dyn SecretStore> = Arc::clone(&memory) as Arc<dyn SecretStore>;
        let store = open(&scratch.0, &secrets);
        let key = store.budget_key().expect("a key");
        let kept = memory
            .get(&budget_key_name("client").expect("a name"))
            .expect("readable")
            .expect("kept");
        assert_eq!(kept.expose(), key.expose());
        assert_eq!(kept.expose().len(), 32);
    }

    /// KR-REQ-10.32: records counted under a key never start again under another: a key that has
    /// gone, or a store opened for another scope, is an error rather than five fresh attempts.
    #[test]
    fn records_are_never_counted_again_under_another_key() {
        let scratch = Scratch::new("rekey");
        let kept = Arc::new(MemoryStore::new());
        let secrets: Arc<dyn SecretStore> = Arc::clone(&kept) as Arc<dyn SecretStore>;
        let clock = TestClock::new();
        assert_eq!(charge(&open(&scratch.0, &secrets), &clock, 2), 2);

        let other_scope =
            DurableClientBudgetStore::open(scratch.0.join("budget"), memory(), "another")
                .expect("a budget");
        assert!(matches!(
            charge_attempt(&other_scope, &clock, &origin(), &code()),
            Err(PairingError::Store { .. })
        ));

        kept.delete(&budget_key_name("client").expect("a name"))
            .expect("deleted");
        let without_key = open(&scratch.0, &secrets);
        assert!(matches!(
            charge_attempt(&without_key, &clock, &origin(), &code()),
            Err(PairingError::Store { .. })
        ));
        assert!(
            kept.get(&budget_key_name("client").expect("a name"))
                .expect("readable")
                .is_none(),
            "no key is made in place of the one that has gone"
        );
    }

    /// KR-REQ-10.32: a write that did not finish leaves the copy before it: the newest slot
    /// failing its digest is passed over for the other, and both failing is an error.
    #[test]
    fn a_write_that_did_not_finish_leaves_the_copy_before_it() {
        let scratch = Scratch::new("torn");
        let secrets = memory();
        let clock = TestClock::new();
        let store = open(&scratch.0, &secrets);
        assert_eq!(charge(&store, &clock, 2), 2);
        let held = store.read().expect("readable");
        let newest = held.slot.expect("a written copy");
        let written = std::fs::read(store.directory().join(SLOTS[newest])).expect("the copy");
        std::fs::write(
            store.directory().join(SLOTS[newest]),
            &written[..written.len() / 2],
        )
        .expect("torn");
        assert_eq!(
            attempts(&store),
            Some(1),
            "the copy before the torn write is read"
        );

        std::fs::write(store.directory().join(SLOTS[1 - newest]), b"damaged").expect("damaged");
        assert!(matches!(
            charge_attempt(&store, &clock, &origin(), &code()),
            Err(PairingError::Store { .. })
        ));
    }

    /// A write that would make the records larger than a reader accepts is refused, and the
    /// records stay as they were, readable.
    #[test]
    fn a_write_past_the_bound_is_refused_and_the_records_kept() {
        let scratch = Scratch::new("bound");
        let secrets = memory();
        let clock = TestClock::new();
        let mut store = open(&scratch.0, &secrets);
        store.limit = 1024;
        assert_eq!(charge(&store, &clock, 1), 1);
        let mut refused = None;
        for index in 0..64_u8 {
            let other = Mac256::from_bytes([index; 32]);
            if let Err(error) = store.update(&other, &|_| {
                Ok(ClientAttemptRecord {
                    attempts: 1,
                    first_entry_monotonic_ms: 0,
                    boot_identity: BootIdentity([0; 32]),
                    retain_until_monotonic_ms: 1,
                    retain_until_wall_ms: 1,
                    exhausted: false,
                })
            }) {
                refused = Some(error);
                break;
            }
        }
        assert!(matches!(refused, Some(PairingError::Store { .. })));
        assert_eq!(
            attempts(&store),
            Some(1),
            "the records are readable as they were"
        );
    }

    /// The directory a path resolves to, links and all.
    #[cfg(unix)]
    fn resolved(path: &Path) -> PathBuf {
        std::fs::canonicalize(path).expect("a path that resolves")
    }

    /// Every directory the store creates is named durably: the entry for each new directory is
    /// flushed into the directory holding it, and so is every entry above it.
    #[cfg(unix)]
    #[test]
    fn every_directory_it_creates_is_flushed_into_its_parent() {
        let scratch = Scratch::new("nested");
        let budget = scratch.0.join("a").join("b").join("budget");
        let store = DurableClientBudgetStore::open(&budget, memory(), "client").expect("a budget");
        let real = resolved(&scratch.0);
        for flushed in [
            PathBuf::from("/"),
            real.parent()
                .expect("the temporary directory")
                .to_path_buf(),
            real.clone(),
            real.join("a"),
            real.join("a").join("b"),
            // The open flushes the budget's own directory by the path it was given.
            store.directory().to_path_buf(),
        ] {
            assert!(
                was_flushed(&flushed),
                "{} was not flushed",
                flushed.display()
            );
        }
    }

    /// KR-REQ-10.32: directories another opener made and stopped before flushing are flushed by
    /// the next open, before it records a charge: their existence does not make them durable.
    #[cfg(unix)]
    #[test]
    fn a_path_another_opener_made_is_flushed_before_a_charge() {
        use std::os::unix::fs::DirBuilderExt as _;
        let scratch = Scratch::new("stopped");
        let budget = scratch.0.join("a").join("b").join("budget");
        // What an opener that stopped after creating the path and before flushing it left behind.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&budget)
            .expect("the path");
        let real = resolved(&scratch.0);
        for made in [real.join("a"), real.join("a").join("b"), budget.clone()] {
            assert!(
                !was_flushed(&made),
                "{} was flushed already",
                made.display()
            );
        }
        let store = DurableClientBudgetStore::open(&budget, memory(), "client").expect("a budget");
        for flushed in [
            real.clone(),
            real.join("a"),
            real.join("a").join("b"),
            // The open flushes the budget's own directory by the path it was given.
            budget.clone(),
        ] {
            assert!(
                was_flushed(&flushed),
                "{} was not flushed before the charge",
                flushed.display()
            );
        }
        assert_eq!(charge(&store, &TestClock::new(), 1), 1);
    }

    /// KR-REQ-10.32: a budget reached through a link has every directory both the link and its
    /// target depend on flushed, including the ones another opener made under the target and
    /// stopped before flushing.
    #[cfg(unix)]
    #[test]
    fn a_path_through_a_link_is_flushed_along_its_target() {
        use std::os::unix::fs::DirBuilderExt as _;
        let scratch = Scratch::new("linked");
        let target = scratch.0.join("data").join("new").join("parent");
        // What an opener that stopped after creating the path and before flushing it left behind,
        // and a link to it from somewhere else.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(target.join("budget"))
            .expect("the path");
        std::fs::create_dir(scratch.0.join("stable")).expect("a directory for the link");
        std::os::unix::fs::symlink(&target, scratch.0.join("stable").join("link")).expect("a link");
        let real = resolved(&scratch.0);
        for made in [
            real.join("data"),
            real.join("data").join("new"),
            real.join("data").join("new").join("parent"),
            real.join("stable"),
        ] {
            assert!(
                !was_flushed(&made),
                "{} was flushed already",
                made.display()
            );
        }
        let store = DurableClientBudgetStore::open(
            scratch.0.join("stable").join("link").join("budget"),
            memory(),
            "client",
        )
        .expect("a budget");
        for flushed in [
            real.clone(),
            real.join("stable"),
            real.join("data"),
            real.join("data").join("new"),
            real.join("data").join("new").join("parent"),
            // The open flushes the budget's own directory by the path it was given.
            store.directory().to_path_buf(),
        ] {
            assert!(
                was_flushed(&flushed),
                "{} was not flushed before the charge",
                flushed.display()
            );
        }
        assert_eq!(charge(&store, &TestClock::new(), 1), 1);
    }

    /// A path that goes round in links is refused rather than followed for ever.
    #[cfg(unix)]
    #[test]
    fn a_path_that_links_to_itself_is_refused() {
        let scratch = Scratch::new("looped");
        std::os::unix::fs::symlink(scratch.0.join("b"), scratch.0.join("a")).expect("a link");
        std::os::unix::fs::symlink(scratch.0.join("a"), scratch.0.join("b")).expect("a link");
        let refused =
            DurableClientBudgetStore::open(scratch.0.join("a").join("budget"), memory(), "client")
                .expect_err("refused");
        assert!(matches!(refused, PairingError::Store { .. }), "{refused}");
        // The kernel refuses to create under that path before the resolution is asked about it,
        // so the resolution's own bound is asked directly.
        let refused = flush_resolution(&scratch.0.join("a").join("budget")).expect_err("refused");
        assert!(
            refused.to_string().contains("more than 40 links"),
            "{refused}"
        );
    }

    /// A link whose target is relative, and climbs with `..`, is resolved from the directory
    /// holding it, and every directory on that way is flushed.
    #[cfg(unix)]
    #[test]
    fn a_relative_link_is_resolved_from_the_directory_holding_it() {
        let scratch = Scratch::new("relative");
        std::fs::create_dir_all(scratch.0.join("data").join("new").join("parent"))
            .expect("the target");
        std::fs::create_dir(scratch.0.join("stable")).expect("a directory for the link");
        std::os::unix::fs::symlink(
            Path::new("..").join("data").join("new").join("parent"),
            scratch.0.join("stable").join("link"),
        )
        .expect("a relative link");
        let real = resolved(&scratch.0);
        flush_resolution(&scratch.0.join("stable").join("link").join("budget-parent"))
            .expect_err("the last component does not exist");
        for flushed in [
            real.join("stable"),
            real.join("data"),
            real.join("data").join("new"),
            real.join("data").join("new").join("parent"),
        ] {
            assert!(
                was_flushed(&flushed),
                "{} was not flushed",
                flushed.display()
            );
        }
        let store = DurableClientBudgetStore::open(
            scratch.0.join("stable").join("link").join("budget"),
            memory(),
            "client",
        )
        .expect("a budget");
        assert_eq!(
            resolved(store.directory()),
            real.join("data").join("new").join("parent").join("budget")
        );
    }

    /// A directory others can reach is refused rather than used.
    #[cfg(unix)]
    #[test]
    fn a_directory_open_to_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("open");
        let directory = scratch.0.join("budget");
        std::fs::create_dir(&directory).expect("a directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("opened");
        assert!(matches!(
            DurableClientBudgetStore::open(&directory, memory(), "client"),
            Err(PairingError::Store { .. })
        ));
    }

    /// Holds a directory open through a handle that shares no writing with any other.
    ///
    /// A name can still be created in the directory while it is held, since that opens the name
    /// rather than the directory, but nothing can open the directory itself with a right to add to
    /// it, which is what a flush of it has to do on Windows.
    #[cfg(windows)]
    fn hold_without_shared_writing(directory: &Path) -> File {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// The right to list a directory, which is all the handle holds.
        const FILE_LIST_DIRECTORY: u32 = 0x0001;
        /// Reading is shared with other handles.
        const FILE_SHARE_READ: u32 = 0x0001;
        /// Deleting is shared; writing is not.
        const FILE_SHARE_DELETE: u32 = 0x0004;
        /// What lets a program open a directory at all.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

        OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(directory)
            .expect("the directory is held")
    }

    /// KR-REQ-10.32: opening the budget flushes the directory that names it and the directory
    /// itself, here through a handle on each that may add to it. While a handle that shares no
    /// writing holds either one, the budget does not open, so no charge is recorded in a directory
    /// a crash could take away; once it is let go, the same budget opens and records a charge.
    #[cfg(windows)]
    #[test]
    fn a_budget_whose_directories_cannot_be_flushed_does_not_open() {
        let scratch = Scratch::new("held");
        let secrets = memory();
        let directory = scratch.0.join("budget");
        std::fs::create_dir(&directory).expect("the budget's directory");
        for held in [&directory, &scratch.0] {
            let holding = hold_without_shared_writing(held);
            let opened = DurableClientBudgetStore::open(&directory, Arc::clone(&secrets), "client");
            drop(holding);
            let Err(refused) = opened else {
                panic!(
                    "the budget opened while {} could not be flushed",
                    held.display()
                );
            };
            assert!(matches!(refused, PairingError::Store { .. }), "{refused}");
        }
        let store = DurableClientBudgetStore::open(&directory, secrets, "client")
            .expect("with nothing held, the budget opens");
        assert_eq!(charge(&store, &TestClock::new(), 1), 1);
    }

    /// The flush that makes the lock and the slots durable once the open has created them asks for
    /// a handle on their directory that may add a file to it, so a handle that shares no writing
    /// stops it, and it is made once that handle is let go.
    #[cfg(windows)]
    #[test]
    fn the_names_made_in_the_budget_directory_are_flushed_into_it() {
        let scratch = Scratch::new("slots");
        let holding = hold_without_shared_writing(&scratch.0);
        let refused = sync_directory(&scratch.0, NameKind::File)
            .expect_err("the flush is refused while the directory is held");
        assert!(matches!(refused, PairingError::Store { .. }), "{refused}");
        drop(holding);
        sync_directory(&scratch.0, NameKind::File).expect("and made once it is let go");
    }
}
