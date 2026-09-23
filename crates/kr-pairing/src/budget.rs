//! The candidate's attempt budget, kept on disk.
//!
//! [`crate::client::charge_attempt`] decides what one entered code's record becomes; this is where
//! the records live between one entry and the next, across application restarts and reboots, and
//! how two entries of the same code on one device, in two threads or in two processes, are kept
//! from both seeing four attempts.
//!
//! * The records are one file in an owner-only directory, rewritten whole: a temporary file,
//!   flushed to the device, renamed over the old one, and the directory flushed after it. A reader
//!   sees the old records or the new ones, never a mixture, and a crash loses at most the write
//!   that was under way.
//! * Every operation holds an exclusive lock on a `lock` file in the same directory, which is
//!   created once and never replaced, so the lock two processes take is always on the same file.
//! * The counter's key is a secret of its own, 32 random bytes kept in the secret store the caller
//!   gives (the platform's credential store, or the owner-only directory fallback where section 10
//!   allows one), under `<scope>/pairing-client-budget-key`. It is created under the same lock, so
//!   two first entries agree on one key. It is never a transport or control key.
//! * A records file this store cannot read is an error, never an empty budget: forgetting a
//!   device's attempts is exactly what the budget exists to prevent.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_crypto::secret::SymmetricKey;
use kr_crypto::store::{SecretName, SecretStore};
use kr_protocol::scalars::Mac256;
use serde::{Deserialize, Serialize};

use crate::error::{PairingError, Result};
use crate::platform::{BootIdentity, ClientAttemptRecord, ClientBudgetStore};

/// The file the records live in.
const RECORDS: &str = "records.json";

/// The file a new version of the records is written to before it replaces them.
const STAGING: &str = "records.json.new";

/// The file every operation locks. It is never written, truncated or replaced.
const LOCK: &str = "lock";

/// The largest records file this store reads. A device keeps a record per entered code for at
/// most a day, which is a few hundred bytes each.
const MAX_RECORDS_BYTES: u64 = 4 * 1024 * 1024;

/// The version of the records file this store writes and reads.
const FORMAT_VERSION: u32 = 1;

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
}

impl std::fmt::Debug for DurableClientBudgetStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableClientBudgetStore")
            .field("directory", &self.directory)
            .field("secrets", &self.secrets.describe())
            .field("key_name", &self.key_name)
            .finish()
    }
}

impl DurableClientBudgetStore {
    /// Opens the budget kept in `directory`, creating the directory owner-only, with its key kept
    /// in `secrets` for `scope`.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] when the directory is a link, cannot be created, is open to
    /// anyone but its owner, or its lock file cannot be created.
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
        };
        // The lock file exists from here on, so every later operation opens the same file.
        drop(store.lock()?);
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

    /// Reads every record. A missing file is an empty budget; anything unreadable is an error.
    fn read(&self) -> Result<BTreeMap<[u8; 32], ClientAttemptRecord>> {
        let path = self.directory.join(RECORDS);
        reject_link(&path)?;
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(io_error("open", &path, &error)),
        };
        let mut text = Vec::new();
        file.take(MAX_RECORDS_BYTES + 1)
            .read_to_end(&mut text)
            .map_err(|error| io_error("read", &path, &error))?;
        if text.len() as u64 > MAX_RECORDS_BYTES {
            return Err(PairingError::Store {
                reason: format!(
                    "{} is larger than a budget's records can be",
                    path.display()
                ),
            });
        }
        let stored: StoredBudget =
            serde_json::from_slice(&text).map_err(|error| PairingError::Store {
                reason: format!("{} is not a budget's records: {error}", path.display()),
            })?;
        if stored.version != FORMAT_VERSION {
            return Err(PairingError::Store {
                reason: format!(
                    "{} is version {} of the records, and this store reads version {FORMAT_VERSION}",
                    path.display(),
                    stored.version
                ),
            });
        }
        stored
            .records
            .into_iter()
            .map(|(key, record)| Ok((decode_hex::<32>(&key)?, record.into_record()?)))
            .collect()
    }

    /// Replaces the records with `records`, whole.
    fn write(&self, records: &BTreeMap<[u8; 32], ClientAttemptRecord>) -> Result<()> {
        let stored = StoredBudget {
            version: FORMAT_VERSION,
            records: records
                .iter()
                .map(|(key, record)| (hex::encode(key), StoredRecord::from_record(record)))
                .collect(),
        };
        let text = serde_json::to_vec(&stored).map_err(|error| PairingError::Store {
            reason: format!("the budget's records cannot be written: {error}"),
        })?;
        let staging = self.directory.join(STAGING);
        let path = self.directory.join(RECORDS);
        reject_link(&staging)?;
        reject_link(&path)?;
        let mut file = owner_only_options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&staging)
            .map_err(|error| io_error("create", &staging, &error))?;
        file.write_all(&text)
            .and_then(|()| file.sync_all())
            .map_err(|error| io_error("write", &staging, &error))?;
        drop(file);
        std::fs::rename(&staging, &path).map_err(|error| io_error("replace", &path, &error))?;
        sync_directory(&self.directory)
    }
}

impl ClientBudgetStore for DurableClientBudgetStore {
    fn budget_key(&self) -> Result<SymmetricKey> {
        let _held = self.lock()?;
        if let Some(bytes) = self.secrets.get(&self.key_name).map_err(store)? {
            return SymmetricKey::from_slice("the client budget key", bytes.expose())
                .map_err(store);
        }
        let key = SymmetricKey::random().map_err(store)?;
        self.secrets
            .set(&self.key_name, key.expose())
            .map_err(store)?;
        Ok(key)
    }

    fn update(
        &self,
        code_key: &Mac256,
        decide: &dyn Fn(Option<ClientAttemptRecord>) -> Result<ClientAttemptRecord>,
    ) -> Result<ClientAttemptRecord> {
        let _held = self.lock()?;
        let mut records = self.read()?;
        let updated = decide(records.get(code_key.as_bytes()).cloned())?;
        records.insert(*code_key.as_bytes(), updated.clone());
        self.write(&records)?;
        Ok(updated)
    }

    fn load(&self, code_key: &Mac256) -> Result<Option<ClientAttemptRecord>> {
        let _held = self.lock()?;
        Ok(self.read()?.remove(code_key.as_bytes()))
    }

    fn expire(&self, now_monotonic_ms: u64, boot: BootIdentity, now_wall_ms: u64) -> Result<()> {
        let _held = self.lock()?;
        let records = self.read()?;
        let kept: BTreeMap<[u8; 32], ClientAttemptRecord> = records
            .iter()
            .map(|(key, record)| (*key, record.anchored(now_monotonic_ms, boot)))
            .filter(|(_, record)| !record.is_expired(now_monotonic_ms, boot, now_wall_ms))
            .collect();
        if kept != records {
            self.write(&kept)?;
        }
        Ok(())
    }
}

/// The records file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBudget {
    version: u32,
    /// Each code's record, by its key in lower-case hexadecimal.
    records: BTreeMap<String, StoredRecord>,
}

/// One code's record as the file holds it.
#[derive(Serialize, Deserialize)]
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

    fn into_record(self) -> Result<ClientAttemptRecord> {
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

/// Creates `directory` owner-only, or checks that it already is, without following a link at it.
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
    Ok(())
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
    // created in, which is the caller's to choose.
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

/// Flushes a directory's entries to the device, so a rename in it survives a crash.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| io_error("flush", directory, &error))
}

/// Windows flushes a rename with the file it renames, and has no directory handle to flush.
#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    Ok(())
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
    use crate::client::charge_attempt;
    use crate::code::EnteredCode;
    use crate::platform::TestClock;
    use kr_crypto::store::MemoryStore;
    use kr_protocol::pairing::{MAX_CLIENT_ATTEMPTS, RendezvousOrigin};

    /// Where a child process of the two-process test finds the directory it shares.
    const CHILD_DIRECTORY: &str = "KR_PAIRING_BUDGET_CHILD_DIRECTORY";

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

    /// KR-REQ-10.32: two stores on one directory, charging the same code from two threads each,
    /// spend five attempts between them and no more.
    #[test]
    fn charges_from_four_threads_spend_five_attempts_between_them() {
        let scratch = Scratch::new("threads");
        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
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
        let allowed = charge(
            &open(&directory, &secrets),
            &TestClock::new(),
            MAX_CLIENT_ATTEMPTS,
        );
        // On a line of its own: the harness writes the test's name on the line it starts.
        println!("\nallowed {allowed}");
    }

    /// KR-REQ-10.32: two processes that open one budget at the same time agree on one key, made
    /// by whichever came first, and spend five attempts between them.
    #[test]
    fn a_budget_shared_by_two_processes_spends_five_attempts() {
        let scratch = Scratch::new("processes");
        // The secret store's directory exists before the children start: what they race on is the
        // budget, its directory, its lock and its key.
        kr_crypto::store::open_store_in(&scratch.0.join("secrets")).expect("the shared secrets");
        let program = std::env::current_exe().expect("this test program");
        let children: Vec<_> = (0..2)
            .map(|_| {
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
                    .expect("a child process")
            })
            .collect();
        let outputs: Vec<_> = children
            .into_iter()
            .map(|child| child.wait_with_output().expect("the child ends"))
            .collect();
        let allowed: u32 = outputs
            .iter()
            .map(|output| {
                let text = String::from_utf8_lossy(&output.stdout);
                assert!(output.status.success(), "the child succeeded: {text}");
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
        let store = open(&scratch.0, &secrets);
        let key = crate::client::budget_key(&store, &origin(), &code()).expect("a key");
        let record = store.load(&key).expect("readable").expect("one record");
        assert_eq!(
            record.attempts, MAX_CLIENT_ATTEMPTS,
            "both charged one record"
        );
    }

    /// KR-REQ-10.32: the count survives the application going away and coming back, with the same
    /// key.
    #[test]
    fn the_budget_survives_a_restart() {
        let scratch = Scratch::new("restart");
        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
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
        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let clock = TestClock::new();
        assert_eq!(charge(&open(&scratch.0, &secrets), &clock, 1), 1);

        clock.reboot(7);
        let after = open(&scratch.0, &secrets);
        assert!(matches!(
            charge_attempt(&after, &clock, &origin(), &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
        let key = crate::client::budget_key(&after, &origin(), &code()).expect("a key");
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

    /// Records this store cannot read are an error, never an empty budget that would let the code
    /// be tried again.
    #[test]
    fn records_this_store_cannot_read_are_an_error() {
        let scratch = Scratch::new("unreadable");
        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let store = open(&scratch.0, &secrets);
        std::fs::write(
            store.directory().join(RECORDS),
            b"{\"version\":1,\"records\":7}",
        )
        .expect("written");
        assert!(matches!(
            charge_attempt(&store, &TestClock::new(), &origin(), &code()),
            Err(PairingError::Store { .. })
        ));
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
        let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        assert!(matches!(
            DurableClientBudgetStore::open(&directory, secrets, "client"),
            Err(PairingError::Store { .. })
        ));
    }
}
