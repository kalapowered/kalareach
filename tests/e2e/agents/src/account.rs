//! What the parts that need the person's vendor login add to a part: the budget their turns are
//! charged to, where a key a part carried in its session's environment was found, the person's
//! login keychain a run's own home searches, and what a part changed in the person's own agent
//! directories.
//!
//! None of it reads a credential into this process except the one variable a login is, whose value
//! the harness hands over on a pipe ([`key_from_descriptor`]); it is given to the agent's session
//! only, and never written or printed here: where it ended up is found by searching the run's own
//! files for its bytes, and only the paths are recorded.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kr_e2e_m1b::LIVENESS;
use kr_e2e_m1b::run::output_within;
use serde::Serialize;
use serde_json::{Value, json};

/// The variable naming the ledger file the harness keeps across runs.
pub const TURNS_VARIABLE: &str = "KR_AGENTS_TURNS";

/// The variable naming the file where a part records where a key it carried was found.
pub const KEY_SCAN_VARIABLE: &str = "KR_AGENTS_KEY_SCAN";

/// How long a part waits for the ledger's lock.
const LOCK_WAIT: Duration = Duration::from_secs(20);

/// The turns charged to one budget, kept in a file across runs, so retries, controls and runs that
/// stopped part way all count. Parts run one at a time; a lock file keeps two charges apart all
/// the same.
#[derive(Clone, Debug)]
pub struct Ledger {
    path: PathBuf,
    budget: String,
    limit: u64,
}

impl Ledger {
    /// The ledger the harness named, for `budget`, which allows `limit` turns.
    ///
    /// # Panics
    ///
    /// Panics when [`TURNS_VARIABLE`] names no file: a part that spends turns does not run without a
    /// ledger to charge them to.
    #[must_use]
    pub fn from_environment(budget: &str, limit: u64) -> Self {
        let path = std::env::var_os(TURNS_VARIABLE)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                panic!("{TURNS_VARIABLE} names no ledger, and a part that spends turns needs one")
            });
        Self {
            path,
            budget: budget.to_owned(),
            limit,
        }
    }

    /// The turns charged to the budget so far.
    ///
    /// # Errors
    ///
    /// Returns why the ledger could not be read: an unreadable ledger is not an empty one.
    pub fn spent(&self) -> Result<u64, String> {
        let ledger = read_ledger(&self.path)?;
        let entries = ledger["budgets"][&self.budget]
            .as_array()
            .map_or(0, Vec::len);
        Ok(u64::try_from(entries).unwrap_or(u64::MAX))
    }

    /// The most turns the budget allows.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Charges one turn, before the submission that makes the agent call its model, and returns
    /// the budget's total.
    ///
    /// # Errors
    ///
    /// Returns why nothing may be submitted: the budget would pass its limit, or the ledger could
    /// not be written.
    pub fn charge(&self, part: &str, what: &str) -> Result<u64, String> {
        let _lock = LedgerLock::take(&self.path)?;
        let mut ledger = read_ledger(&self.path)?;
        let entries = ledger["budgets"][&self.budget]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let spent = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        if spent >= self.limit {
            return Err(format!(
                "the {} budget has {spent} of its {} turns spent, so part {part} submits nothing \
                 more",
                self.budget, self.limit
            ));
        }
        let mut entries = entries;
        entries.push(json!({ "at_ms": now_ms(), "part": part, "what": what }));
        ledger["budgets"][&self.budget] = Value::Array(entries);
        let next = self.path.with_extension("next");
        std::fs::write(
            &next,
            serde_json::to_vec_pretty(&ledger).expect("the ledger is JSON"),
        )
        .and_then(|()| std::fs::rename(&next, &self.path))
        .map_err(|error| format!("the ledger {}: {error}", self.path.display()))?;
        Ok(spent + 1)
    }
}

/// Reads the ledger, or an empty one where there is no file yet.
fn read_ledger(path: &Path) -> Result<Value, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| format!("the ledger {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({ "budgets": {} })),
        Err(error) => Err(format!("the ledger {}: {error}", path.display())),
    }
}

/// The ledger's lock: a file created exclusively beside it, removed when this is dropped.
struct LedgerLock(PathBuf);

impl LedgerLock {
    fn take(ledger: &Path) -> Result<Self, String> {
        let path = ledger.with_extension("lock");
        let started = std::time::Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if started.elapsed() >= LOCK_WAIT {
                        return Err(format!(
                            "the ledger's lock {} is held after {LOCK_WAIT:?}",
                            path.display()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
        }
    }
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Milliseconds since the epoch, now.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Milliseconds since the epoch of a file time, where the system gives one.
fn ms_of(time: std::io::Result<SystemTime>) -> Option<u64> {
    time.ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

/// One file of a run that held a key's bytes.
#[derive(Clone, Debug, Serialize)]
pub struct KeyHolder {
    /// The file, relative to the run's directory.
    pub path: String,
    /// Its size when it was read.
    pub bytes: u64,
    /// When it was created, where the file system says.
    pub created_ms: Option<u64>,
    /// When it was last written.
    pub modified_ms: Option<u64>,
}

/// What a search of a run's directory for a key's bytes found: every regular file that held them,
/// by path relative to the directory, and every entry the search could not read, which leaves the
/// search incomplete. Nothing of the value is kept.
#[derive(Clone, Debug, Default, Serialize)]
pub struct KeyScan {
    /// The files that held the value.
    pub held_by: Vec<KeyHolder>,
    /// The entries that could not be read, with why.
    pub unread: Vec<String>,
}

impl KeyScan {
    /// Whether every entry was read.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.unread.is_empty()
    }
}

/// Searches every regular file under `root` for `value`, and returns where it was and what could
/// not be read. Nothing of the value is returned or printed.
///
/// # Panics
///
/// Panics when `value` is shorter than eight bytes, which would find anything.
#[must_use]
pub fn files_holding(root: &Path, value: &[u8]) -> KeyScan {
    assert!(
        value.len() >= 8,
        "a key shorter than eight bytes cannot be searched for"
    );
    let relative = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string()
    };
    let mut scan = KeyScan::default();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                scan.unread
                    .push(format!("{}: {error}", relative(&directory)));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    scan.unread
                        .push(format!("{}: {error}", relative(&directory)));
                    continue;
                }
            };
            let path = entry.path();
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(error) => {
                    scan.unread.push(format!("{}: {error}", relative(&path)));
                    continue;
                }
            };
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            // A link, a socket or a pipe holds no bytes of its own to search.
            if !kind.is_file() {
                continue;
            }
            let mut bytes = Vec::new();
            if let Err(error) =
                std::fs::File::open(&path).and_then(|mut file| file.read_to_end(&mut bytes))
            {
                scan.unread.push(format!("{}: {error}", relative(&path)));
                continue;
            }
            if bytes.windows(value.len()).any(|window| window == value) {
                let metadata = entry.metadata().ok();
                scan.held_by.push(KeyHolder {
                    path: relative(&path),
                    bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    created_ms: metadata.as_ref().and_then(|meta| ms_of(meta.created())),
                    modified_ms: metadata.as_ref().and_then(|meta| ms_of(meta.modified())),
                });
            }
        }
    }
    scan.held_by
        .sort_by(|left, right| left.path.cmp(&right.path));
    scan
}

/// Appends one line to the key-scan file the harness named: the part, the variable by its name,
/// every file of the run that held its value and what could not be read, when the run's directory
/// was removed, and whether it is gone. Nothing of the value is written.
///
/// # Panics
///
/// Panics when the harness named a file that cannot be written.
pub fn record_key_scan(part: &str, variable: &str, scan: &KeyScan, removed_ms: u64, gone: bool) {
    let Some(path) = std::env::var_os(KEY_SCAN_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    else {
        return;
    };
    let mut line = serde_json::to_vec(&json!({
        "part": part,
        "variable": variable,
        "held_by": scan.held_by,
        "unread": scan.unread,
        "complete": scan.complete(),
        "run_removed_ms": removed_ms,
        "run_gone": gone,
    }))
    .expect("a scan is JSON");
    line.push(b'\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(&line))
        .unwrap_or_else(|error| panic!("the key-scan file {}: {error}", path.display()));
}

/// One file of the person's home that a part must leave as it found it, as it was at one moment:
/// its path relative to the home, and its SHA-256, or none where it did not exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guarded {
    /// The path relative to the person's home.
    pub relative: String,
    /// The file's SHA-256, where it exists.
    pub sha256: Option<[u8; 32]>,
}

/// Reads each of `files`, relative to `home`, for [`Guarded`]: a file that cannot be read, other
/// than one that does not exist, is an error, since nothing about it could be compared.
///
/// # Errors
///
/// Returns the file that could not be read, and why.
pub fn guarded_files(home: &Path, files: &[String]) -> Result<Vec<Guarded>, String> {
    files
        .iter()
        .map(|relative| {
            let path = home.join(relative);
            match std::fs::read(&path) {
                Ok(bytes) => Ok(Guarded {
                    relative: relative.clone(),
                    sha256: Some(kr_cbor::sha256(&bytes)),
                }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Guarded {
                    relative: relative.clone(),
                    sha256: None,
                }),
                Err(error) => Err(format!("~/{relative}: {error}")),
            }
        })
        .collect()
}

/// Appends one line to the file beside the key-scan file the harness named: the part, and each
/// guarded file's SHA-256 before and after, in hexadecimal, so the comparison can be checked
/// without the files; the record itself says only whether each changed.
///
/// # Panics
///
/// Panics when the harness named a file that cannot be written.
pub fn record_guarded(part: &str, before: &[Guarded], after: &[Guarded]) {
    let Some(path) = std::env::var_os(KEY_SCAN_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).with_file_name("guarded-files.jsonl"))
    else {
        return;
    };
    let hex = |digest: &Option<[u8; 32]>| {
        digest.map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
    };
    let files: Vec<Value> = before
        .iter()
        .zip(after)
        .map(|(first, second)| {
            json!({ "file": format!("~/{}", first.relative), "before": hex(&first.sha256), "after": hex(&second.sha256) })
        })
        .collect();
    let mut line = serde_json::to_vec(&json!({ "part": part, "files": files }))
        .expect("the guarded files are JSON");
    line.push(b'\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(&line))
        .unwrap_or_else(|error| panic!("the guarded-files file {}: {error}", path.display()));
}

/// When the person's login keychain says the item `service`, for the account `USER` names, was
/// last modified: its attributes only, read with the person's home, never its value. `None` when
/// the item or its time cannot be read.
#[must_use]
pub fn keychain_item_modified(home: &Path, service: &str) -> Option<String> {
    let account = std::env::var("USER").ok()?;
    let mut command = Command::new("/usr/bin/security");
    command
        .args(["find-generic-password", "-s", service, "-a", &account])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin");
    let output = output_within(command, LIVENESS).ok()?;
    if !output.status.success() {
        return None;
    }
    // The attribute line reads `"mdat"<timedate>=0x... "20260927120000Z\000"`; only its date is
    // kept, and every other line, the account's name among them, is dropped here.
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.trim_start().starts_with("\"mdat\""))
        .and_then(|line| line.split('"').nth(3).map(str::to_owned))
}

/// The variable naming the file descriptor the harness passes a login's value on: a pipe, so the
/// value is in no file and in no process's environment until the agent's session is given it.
pub const KEY_DESCRIPTOR_VARIABLE: &str = "KR_AGENTS_KEY_FD";

/// Reads a login's value from the descriptor [`KEY_DESCRIPTOR_VARIABLE`] names, to its end, trimmed
/// of its line end. The pipe is empty afterwards, so a program that inherits the descriptor reads
/// nothing from it.
///
/// # Errors
///
/// Returns why there is no value: no descriptor named, or nothing on it.
pub fn key_from_descriptor() -> Result<String, String> {
    let named = std::env::var(KEY_DESCRIPTOR_VARIABLE)
        .map_err(|_| format!("{KEY_DESCRIPTOR_VARIABLE} names no descriptor"))?;
    let descriptor: u32 = named
        .parse()
        .map_err(|_| format!("{KEY_DESCRIPTOR_VARIABLE} is not a descriptor"))?;
    let mut value = String::new();
    std::fs::File::open(format!("/dev/fd/{descriptor}"))
        .and_then(|mut file| file.read_to_string(&mut value))
        .map_err(|error| format!("descriptor {descriptor}: {error}"))?;
    let value = value.trim_end_matches(['\n', '\r']).to_owned();
    if value.len() < 8 {
        return Err(format!(
            "descriptor {descriptor} carried {} bytes, too few for a key",
            value.len()
        ));
    }
    Ok(value)
}

/// Makes a run's home search the person's login keychain and name it its default: the same list
/// and default the person's own home has, which [`person_keychains`] reads first. No keychain is
/// created or deleted; the run's home only names this one, and its preferences go with the run.
///
/// # Errors
///
/// Returns what did not hold: the person's list is not the login keychain alone, a step failed,
/// or the run's home names anything else afterwards.
pub fn borrow_login_keychain(run_home: &Path, person_home: &Path) -> Result<(), String> {
    let login = person_home
        .join("Library")
        .join("Keychains")
        .join("login.keychain-db");
    let (list, default) = person_keychains(person_home)?;
    let wanted = login.display().to_string();
    if list != [wanted.clone()] || default != wanted {
        return Err(format!(
            "the person's home searches {list:?} with {default} as its default, not the login \
             keychain alone, so a run's home cannot be given the same"
        ));
    }
    let preferences = run_home.join("Library").join("Preferences");
    std::fs::create_dir_all(&preferences)
        .map_err(|error| format!("{}: {error}", preferences.display()))?;
    security(run_home, &["list-keychains", "-d", "user", "-s", &wanted])?;
    security(run_home, &["default-keychain", "-d", "user", "-s", &wanted])?;
    let (run_list, run_default) = person_keychains(run_home)?;
    if run_list != [wanted.clone()] || run_default != wanted {
        return Err(format!(
            "the run's home searches {run_list:?} with {run_default} as its default after it was \
             given the login keychain"
        ));
    }
    Ok(())
}

/// The keychains a home searches, and its default, as `security` reads them with that home.
///
/// # Errors
///
/// Returns why `security` could not say.
pub fn person_keychains(home: &Path) -> Result<(Vec<String>, String), String> {
    let list = security(home, &["list-keychains", "-d", "user"])?;
    let default = security(home, &["default-keychain", "-d", "user"])?;
    let unquote = |line: &str| line.trim().trim_matches('"').to_owned();
    Ok((
        list.lines()
            .map(unquote)
            .filter(|line| !line.is_empty())
            .collect(),
        unquote(&default),
    ))
}

/// Runs one `security` step with `home` as the only home it names.
fn security(home: &Path, arguments: &[&str]) -> Result<String, String> {
    let mut command = Command::new("/usr/bin/security");
    command
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin");
    let output = output_within(command, LIVENESS).map_err(|why| format!("security {why}"))?;
    if !output.status.success() {
        return Err(format!(
            "security {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// One file of the person's agent directories: its size, its modification time and inode, and the
/// SHA-256 of its bytes where it is small enough to read at each look.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    bytes: u64,
    modified_ns: i128,
    inode: u64,
    digest: Option<[u8; 32]>,
}

/// The person's agent directories at one moment.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    roots: Vec<PathBuf>,
    files: BTreeMap<PathBuf, Entry>,
    directories: std::collections::BTreeSet<PathBuf>,
    hash_limit: u64,
    /// Every entry that could not be read, with why.
    unread: Vec<String>,
}

impl Snapshot {
    /// Whether every entry under the roots was read: a snapshot that is not whole says nothing
    /// about what it missed, which could later be taken for something new.
    #[must_use]
    pub const fn whole(&self) -> bool {
        self.unread.is_empty()
    }

    /// The entries that could not be read, with why.
    #[must_use]
    pub fn unread(&self) -> &[String] {
        &self.unread
    }
}

/// Reads every file under each of `directories`, relative to `home`: size, modification time and
/// inode for all, and the SHA-256 of each no larger than `hash_limit` bytes. A root that does not
/// exist, and an entry gone between its directory's listing and its own read, are not there; any
/// other entry that cannot be read, a file that cannot be hashed whole included, is recorded, and
/// the snapshot is then not whole.
#[must_use]
pub fn snapshot(home: &Path, directories: &[String], hash_limit: u64) -> Snapshot {
    let mut files = BTreeMap::new();
    let mut seen_directories = std::collections::BTreeSet::new();
    let mut unread = Vec::new();
    let roots: Vec<PathBuf> = directories
        .iter()
        .map(|relative| home.join(relative))
        .collect();
    for top in &roots {
        let mut pending = vec![top.clone()];
        while let Some(path) = pending.pop() {
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    unread.push(format!("{}: {error}", path.display()));
                    continue;
                }
            };
            if metadata.is_dir() {
                match std::fs::read_dir(&path) {
                    Ok(entries) => {
                        for entry in entries {
                            match entry {
                                Ok(entry) => pending.push(entry.path()),
                                Err(error) => unread.push(format!("{}: {error}", path.display())),
                            }
                        }
                    }
                    Err(error) => unread.push(format!("{}: {error}", path.display())),
                }
                seen_directories.insert(path);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let digest = if metadata.len() <= hash_limit {
                let digest = digest_of(&path, metadata.len());
                if digest.is_none() {
                    unread.push(format!(
                        "{}: its {} bytes could not be read whole",
                        path.display(),
                        metadata.len()
                    ));
                }
                digest
            } else {
                None
            };
            files.insert(
                path,
                Entry {
                    bytes: metadata.len(),
                    modified_ns: i128::from(metadata.mtime()) * 1_000_000_000
                        + i128::from(metadata.mtime_nsec()),
                    inode: metadata.ino(),
                    digest,
                },
            );
        }
    }
    Snapshot {
        roots,
        files,
        directories: seen_directories,
        hash_limit,
        unread,
    }
}

/// The SHA-256 of a file's first `length` bytes, where it has them.
fn digest_of(path: &Path, length: u64) -> Option<[u8; 32]> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(length)
        .read_to_end(&mut bytes)
        .ok()?;
    (u64::try_from(bytes.len()).ok()? == length).then(|| kr_cbor::sha256(&bytes))
}

/// What changed in the person's agent directories between two snapshots.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Changes {
    /// Files that are new.
    pub created: Vec<PathBuf>,
    /// Files that are gone.
    pub removed: Vec<PathBuf>,
    /// Files whose earlier bytes are unchanged and that grew.
    pub appended: Vec<PathBuf>,
    /// Files whose earlier bytes changed, or that were replaced.
    pub rewritten: Vec<PathBuf>,
    /// Files that changed and were too large to compare.
    pub changed_uncompared: Vec<PathBuf>,
}

/// What changed from `before` to `after`.
#[must_use]
pub fn changes(before: &Snapshot, after: &Snapshot) -> Changes {
    let mut changes = Changes::default();
    for (path, entry) in &after.files {
        match before.files.get(path) {
            None => changes.created.push(path.clone()),
            Some(earlier) if earlier == entry => {}
            Some(earlier)
                if earlier.bytes == entry.bytes
                    && earlier.digest.is_some()
                    && earlier.digest == entry.digest
                    && earlier.inode == entry.inode => {}
            Some(earlier) => match earlier.digest {
                Some(old) if entry.bytes > earlier.bytes && earlier.inode == entry.inode => {
                    if digest_of(path, earlier.bytes) == Some(old) {
                        changes.appended.push(path.clone());
                    } else {
                        changes.rewritten.push(path.clone());
                    }
                }
                Some(_) => changes.rewritten.push(path.clone()),
                None if earlier.bytes > before.hash_limit => {
                    changes.changed_uncompared.push(path.clone());
                }
                None => changes.rewritten.push(path.clone()),
            },
        }
    }
    for path in before.files.keys() {
        if !after.files.contains_key(path) {
            changes.removed.push(path.clone());
        }
    }
    changes
}

/// Removes each file the part created, inside the snapshot's roots, that holds one of `marks`
/// (the part's own marker, or the run's own directory, which the agent writes as the working
/// directory), and then each directory the part created there that is left empty; returns what it
/// removed and what it left. Nothing that existed before the part, a file or a directory, is
/// touched, and nothing at all when `before` is not whole, since what it missed may have existed.
#[must_use]
pub fn remove_created(
    before: &Snapshot,
    changes: &Changes,
    marks: &[&str],
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    if !before.whole() {
        return (Vec::new(), changes.created.clone());
    }
    let inside = |path: &Path| before.roots.iter().any(|root| path.starts_with(root));
    let mut removed = Vec::new();
    let mut left = Vec::new();
    for path in &changes.created {
        let new =
            inside(path) && !before.files.contains_key(path) && !before.directories.contains(path);
        let ours = new
            && std::fs::read(path).is_ok_and(|bytes| {
                marks.iter().any(|mark| {
                    bytes
                        .windows(mark.len())
                        .any(|window| window == mark.as_bytes())
                })
            });
        if ours && std::fs::remove_file(path).is_ok() {
            removed.push(path.clone());
        } else {
            left.push(path.clone());
        }
    }
    // A directory the part created is removed only when nothing is left in it, deepest first.
    let mut directories: Vec<PathBuf> = removed
        .iter()
        .flat_map(|path| {
            path.ancestors()
                .skip(1)
                .map(Path::to_path_buf)
                .collect::<Vec<_>>()
        })
        .filter(|directory| inside(directory) && !before.directories.contains(directory))
        .collect();
    directories.sort();
    directories.dedup();
    directories.sort_by_key(|directory| std::cmp::Reverse(directory.components().count()));
    for directory in directories {
        if std::fs::remove_dir(&directory).is_ok() {
            removed.push(directory);
        }
    }
    (removed, left)
}

/// The identifier of the conversation a file holds: the last identifier shaped like a UUID in its
/// name, or the name without its extension.
#[must_use]
pub fn conversation_id(file: &Path) -> String {
    let stem = file
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let shaped = |candidate: &str| {
        candidate.len() == 36
            && candidate.char_indices().all(|(index, character)| {
                if [8, 13, 18, 23].contains(&index) {
                    character == '-'
                } else {
                    character.is_ascii_hexdigit()
                }
            })
    };
    (0..stem.len().saturating_sub(35))
        .rev()
        .filter_map(|start| stem.get(start..start + 36))
        .find(|candidate| shaped(candidate))
        .map_or(stem.clone(), str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of this test's own, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("kr-account-{name}-{}", kr_ipc::new_uuid()));
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_ledger_charges_up_to_its_limit_across_instances_and_refuses_the_next() {
        let scratch = Scratch::new("ledger");
        let path = scratch.0.join("turns.json");
        let ledger = Ledger {
            path: path.clone(),
            budget: "agent".to_owned(),
            limit: 2,
        };
        assert_eq!(ledger.charge("1", "first"), Ok(1));
        let again = Ledger {
            path,
            budget: "agent".to_owned(),
            limit: 2,
        };
        assert_eq!(again.charge("1", "second"), Ok(2));
        assert!(
            again.charge("1", "third").is_err(),
            "the third passes the limit"
        );
        assert_eq!(again.spent(), Ok(2), "a refused charge is not recorded");
        let other = Ledger {
            budget: "another".to_owned(),
            ..again
        };
        assert_eq!(other.charge("2a", "its own budget"), Ok(1));
    }

    #[test]
    fn an_unreadable_ledger_is_neither_charged_nor_counted_as_empty() {
        let scratch = Scratch::new("unreadable");
        let path = scratch.0.join("turns.json");
        std::fs::write(&path, "{ not a ledger").expect("a broken ledger");
        let ledger = Ledger {
            path: path.clone(),
            budget: "agent".to_owned(),
            limit: 2,
        };
        assert!(ledger.spent().is_err(), "a broken ledger has no count");
        assert!(
            ledger.charge("1", "first").is_err(),
            "a broken ledger takes no charge"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("the ledger"),
            "{ not a ledger",
            "a refused charge leaves the ledger as it was"
        );
    }

    #[test]
    fn changes_tell_a_created_an_appended_a_rewritten_and_an_uncompared_file_apart() {
        let scratch = Scratch::new("changes");
        let home = &scratch.0;
        let agent = home.join(".agent");
        std::fs::create_dir_all(&agent).expect("the agent's directory");
        std::fs::write(agent.join("history"), "one\n").expect("a history");
        std::fs::write(agent.join("settings"), "a").expect("settings");
        std::fs::write(agent.join("large"), vec![0_u8; 32]).expect("a large file");
        let directories = vec![".agent".to_owned()];
        let before = snapshot(home, &directories, 16);
        std::fs::write(agent.join("history"), "one\ntwo\n").expect("an append");
        std::fs::write(agent.join("settings"), "b").expect("a rewrite");
        std::fs::write(agent.join("large"), vec![1_u8; 33]).expect("a large change");
        std::fs::write(agent.join("new"), "made").expect("a new file");
        let after = snapshot(home, &directories, 16);
        let found = changes(&before, &after);
        assert_eq!(found.created, vec![agent.join("new")]);
        assert_eq!(found.appended, vec![agent.join("history")]);
        assert_eq!(found.rewritten, vec![agent.join("settings")]);
        assert_eq!(found.changed_uncompared, vec![agent.join("large")]);
        assert!(found.removed.is_empty());
    }

    #[test]
    fn only_created_files_that_hold_a_mark_are_removed_with_the_directories_they_emptied() {
        let scratch = Scratch::new("remove");
        let home = &scratch.0;
        let agent = home.join(".agent");
        std::fs::create_dir_all(agent.join("kept")).expect("the agent's directory");
        std::fs::create_dir_all(agent.join("empty")).expect("an empty directory");
        std::fs::write(agent.join("kept").join("old"), "the person's").expect("an old file");
        let directories = vec![".agent".to_owned()];
        let before = snapshot(home, &directories, 1 << 20);
        let ours = agent.join("sessions").join("day");
        std::fs::create_dir_all(&ours).expect("a new directory");
        std::fs::write(agent.join("empty").join("ours"), "kr0123")
            .expect("ours in an old directory");
        std::fs::write(ours.join("ours.jsonl"), "prompt kr0123").expect("our conversation");
        std::fs::write(agent.join("kept").join("theirs"), "someone else's").expect("another file");
        let after = snapshot(home, &directories, 1 << 20);
        let found = changes(&before, &after);
        let (removed, left) = remove_created(&before, &found, &["kr0123"]);
        assert!(
            !ours.join("ours.jsonl").exists(),
            "the marked file is removed"
        );
        assert!(
            !agent.join("sessions").exists(),
            "the directories it emptied go with it"
        );
        assert!(
            agent.join("kept").join("theirs").exists(),
            "an unmarked file stays"
        );
        assert!(agent.join("kept").join("old").exists(), "an old file stays");
        assert!(agent.exists(), "the agent's own directory stays");
        assert!(
            agent.join("kept").exists(),
            "a directory that was there stays"
        );
        assert_eq!(left, vec![agent.join("kept").join("theirs")]);
        assert!(removed.contains(&ours.join("ours.jsonl")));
        assert!(
            agent.join("empty").is_dir() && !agent.join("empty").join("ours").exists(),
            "an empty directory that was there stays when the file the part put in it goes"
        );
    }

    #[test]
    fn a_snapshot_that_could_not_read_a_directory_is_not_whole_and_nothing_is_removed_after_it() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new("unread");
        let home = &scratch.0;
        let agent = home.join(".agent");
        let closed = agent.join("closed");
        std::fs::create_dir_all(&closed).expect("the agent's directory");
        std::fs::write(closed.join("history"), "the person's").expect("a file in it");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000))
            .expect("a directory nobody can list");
        let directories = vec![".agent".to_owned(), ".absent".to_owned()];
        let before = snapshot(home, &directories, 1 << 20);
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700))
            .expect("the directory listed again");
        assert!(
            !before.whole(),
            "a directory it could not list leaves it not whole"
        );
        assert_eq!(
            before.unread().len(),
            1,
            "only that directory: {:?}",
            before.unread()
        );
        std::fs::write(closed.join("history"), "the person's kr0123").expect("an edit");
        std::fs::write(agent.join("ours"), "kr0123").expect("a marked file");
        let after = snapshot(home, &directories, 1 << 20);
        assert!(
            after.whole(),
            "a root that does not exist is not an unread entry"
        );
        let found = changes(&before, &after);
        let (removed, left) = remove_created(&before, &found, &["kr0123"]);
        assert!(
            removed.is_empty(),
            "nothing is removed after a snapshot that is not whole"
        );
        assert_eq!(left.len(), found.created.len());
        assert!(closed.join("history").exists() && agent.join("ours").exists());
    }

    #[test]
    fn a_conversation_is_named_by_the_last_uuid_in_its_file_name_or_by_the_name() {
        let uuid = "0b6e283a-e886-42b0-a27e-8ef85a608ab7";
        assert_eq!(
            conversation_id(Path::new(&format!("/p/{uuid}.jsonl"))),
            uuid
        );
        assert_eq!(
            conversation_id(Path::new(&format!(
                "/p/rollout-2026-09-27T10-00-00-{uuid}.jsonl"
            ))),
            uuid
        );
        assert_eq!(
            conversation_id(Path::new("/p/session-42.json")),
            "session-42"
        );
    }
}
