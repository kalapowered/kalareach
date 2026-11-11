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
///
/// The file is the operator's, made on purpose and never by a charge: a JSON object whose
/// `budgets` member is an object holding, for the budget, an array of the turns charged to it. The
/// first, empty ledger is `{"budgets": {"<budget>": []}}` written to the file `KR_AGENTS_TURNS`
/// names. A file that is not there, or is not of that shape, is refused before anything is
/// submitted, since a ledger read as empty gives back the whole allowance.
#[derive(Clone, Debug)]
pub struct Ledger {
    path: PathBuf,
    budget: String,
    limit: u64,
    /// How many turns this process has charged, however many clones of the ledger charged them.
    charged: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Ledger {
    /// The ledger the harness named, for `budget`, which allows `limit` turns.
    ///
    /// # Panics
    ///
    /// Panics when [`TURNS_VARIABLE`] names no file, or the file is not there or is not a ledger
    /// that holds an array for `budget` ([`Ledger::at`]): a part that spends turns does not run
    /// without a ledger to charge them to, and nothing is submitted.
    #[must_use]
    pub fn from_environment(budget: &str, limit: u64) -> Self {
        let path = std::env::var_os(TURNS_VARIABLE)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                panic!("{TURNS_VARIABLE} names no ledger, and a part that spends turns needs one")
            });
        Self::at(path, budget, limit).unwrap_or_else(|why| panic!("{why}"))
    }

    /// The ledger in the file at `path`, for `budget`, which allows `limit` turns.
    ///
    /// # Errors
    ///
    /// Returns why the ledger is refused: the file is not there, cannot be read, is not JSON, or does
    /// not hold an array for the budget. The text says how the first, empty ledger is made.
    pub fn at(path: PathBuf, budget: &str, limit: u64) -> Result<Self, String> {
        let ledger = Self {
            path,
            budget: budget.to_owned(),
            limit,
            charged: std::sync::Arc::default(),
        };
        let _ = ledger.entries(&read_ledger(&ledger.path, budget)?)?;
        Ok(ledger)
    }

    /// The turns the budget holds in `ledger`, as an array of charge records: a ledger whose
    /// array holds anything else is refused, since an entry that is not a charge cannot be counted
    /// as one.
    fn entries(&self, ledger: &Value) -> Result<Vec<Value>, String> {
        let entries = ledger
            .get("budgets")
            .and_then(|budgets| budgets.get(&self.budget))
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "the ledger {} holds no array of turns for the {} budget, so what is left of \
                     it is not known; {}",
                    self.path.display(),
                    self.budget,
                    how_to_make_a_ledger(&self.budget)
                )
            })?;
        if let Some(place) = entries.iter().position(|entry| !is_charge(entry)) {
            return Err(format!(
                "entry {place} of the {} budget's array in the ledger {} is not a charge, so what \
                 is left of the budget is not known: {CHARGE_FORM}",
                self.budget,
                self.path.display()
            ));
        }
        Ok(entries)
    }

    /// How many turns this run has charged so far.
    #[must_use]
    pub fn charged_here(&self) -> u64 {
        self.charged.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Charges `count` turns that were found to have been spent without a charge, beyond the limit
    /// where need be: the ledger then says what was spent.
    ///
    /// # Errors
    ///
    /// Returns why the ledger could not be written.
    pub fn charge_found(&self, part: &str, what: &str, count: u64) -> Result<u64, String> {
        let _lock = LedgerLock::take(&self.path)?;
        let mut ledger = read_ledger(&self.path, &self.budget)?;
        let mut entries = self.entries(&ledger)?;
        for _ in 0..count {
            entries.push(json!({ "at_ms": now_ms(), "part": part, "what": what }));
        }
        let total = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        ledger["budgets"][&self.budget] = Value::Array(entries);
        write_ledger(&self.path, &ledger)?;
        Ok(total)
    }

    /// The turns charged to the budget so far.
    ///
    /// # Errors
    ///
    /// Returns why the ledger could not be read: an unreadable ledger is not an empty one.
    pub fn spent(&self) -> Result<u64, String> {
        let ledger = read_ledger(&self.path, &self.budget)?;
        let entries = self.entries(&ledger)?.len();
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
        let mut ledger = read_ledger(&self.path, &self.budget)?;
        let entries = self.entries(&ledger)?;
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
        write_ledger(&self.path, &ledger)?;
        self.charged
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(spent + 1)
    }
}

/// What an entry of a budget's array is, in the words of a refusal.
const CHARGE_FORM: &str = "a valid entry is an object that holds at_ms (a whole number of \
     milliseconds), part (text) and what (text), as a charge writes it";

/// Whether `entry` is a charge record, as [`Ledger::charge`] writes one.
fn is_charge(entry: &Value) -> bool {
    entry.as_object().is_some_and(|record| {
        record.get("at_ms").is_some_and(Value::is_u64)
            && record.get("part").is_some_and(Value::is_string)
            && record.get("what").is_some_and(Value::is_string)
    })
}

/// A file this process made exclusively beside the ledger, removed when this is dropped unless it
/// was renamed into the ledger's place: its name is the run's own, so what is removed is only what
/// this run made.
struct Temporary {
    path: PathBuf,
    kept: bool,
}

impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.kept {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Writes the ledger so that it is on disk when this returns: the new file is created exclusively
/// under a name of this run's own (never one that was there, never through a link, never opened
/// with truncation), written and synchronised, renamed over the old one, and the directory that
/// holds the name is synchronised too. A charge is made before a prompt is sent, so a crash after
/// the prompt must not leave the older ledger to be read next. A file left behind by a failure is
/// removed, as far as it can be.
fn write_ledger(path: &Path, ledger: &Value) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let failed = |error: std::io::Error| format!("the ledger {}: {error}", path.display());
    let name = path
        .file_name()
        .ok_or_else(|| format!("the ledger {} names no file", path.display()))?;
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let unique = kr_ipc::new_uuid().to_string();
    let next = directory.join(format!(
        "{}.{}-{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        &unique[..8]
    ));
    // `create_new` is `O_CREAT | O_EXCL`: a name that is taken, a link included, is refused and
    // left alone.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&next)
        .map_err(failed)?;
    let mut temporary = Temporary {
        path: next.clone(),
        kept: false,
    };
    file.write_all(&serde_json::to_vec_pretty(ledger).expect("the ledger is JSON"))
        .and_then(|()| file.sync_all())
        .map_err(failed)?;
    drop(file);
    std::fs::rename(&next, path).map_err(failed)?;
    temporary.kept = true;
    std::fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(failed)
}

/// How the operator makes the first, empty ledger for `budget`, on purpose.
fn how_to_make_a_ledger(budget: &str) -> String {
    format!(
        "make the first, empty ledger on purpose, a file holding exactly \
         {{\"budgets\": {{\"{budget}\": []}}}}, and name it in {TURNS_VARIABLE}"
    )
}

/// Reads the ledger, opened with no link followed and checked to be a regular file: a ledger that
/// is a symbolic link is refused, since a charge replaces the name and the link's target would keep
/// the old count. A file that is not there is not an empty ledger: it is an error, which says how
/// the first one is made.
fn read_ledger(path: &Path, budget: &str) -> Result<Value, String> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::io::Read as _;
    let handle = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(handle) => handle,
        Err(rustix::io::Errno::NOENT) => {
            return Err(format!(
                "the ledger {} is not there, and a charge makes no ledger of its own; {}",
                path.display(),
                how_to_make_a_ledger(budget)
            ));
        }
        // What `O_NOFOLLOW` says of a name that is a symbolic link.
        Err(rustix::io::Errno::LOOP) => {
            return Err(format!(
                "the ledger {} is a symbolic link, which is refused: a charge would replace the \
                 link and leave its target with the old count; name the ledger file itself",
                path.display()
            ));
        }
        Err(error) => return Err(format!("the ledger {}: {error}", path.display())),
    };
    let stat = rustix::fs::fstat(&handle)
        .map_err(|error| format!("the ledger {}: {error}", path.display()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(format!(
            "the ledger {} is not a regular file",
            path.display()
        ));
    }
    // A second name for the ledger is as a link is: a charge replaces this name and leaves the
    // count under the other name as it was.
    if stat.st_nlink != 1 {
        return Err(format!(
            "the ledger {} has more than one name, which is refused: a charge would replace this \
             name and leave the old count under the other; name a ledger file that has one name",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(handle)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("the ledger {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("the ledger {}: {error}", path.display()))
}

/// The ledger's lock: a file created exclusively beside it, removed when this is dropped.
struct LedgerLock(PathBuf);

impl LedgerLock {
    fn take(ledger: &Path) -> Result<Self, String> {
        // The ledger's own file name and `.lock`: never the ledger's own name, whatever it ends in.
        let path = ledger.with_file_name(format!(
            "{}.lock",
            ledger
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
        ));
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

/// The most lines that one list of a key scan keeps; the rest are counted.
const TOLD_LINES_AT_MOST: usize = 10_000;

/// The most bytes that one list of a key scan keeps, over all its lines: a line holds a path that
/// can be 16 kilobytes long in a deep tree, and a tree of a million links leaves a line for each,
/// which no bound on the bytes read or the entries listed holds back.
const TOLD_BYTES_AT_MOST: usize = 4 << 20;

/// What one line of a [`Told`] list holds in memory, at least.
pub trait Weighs {
    /// The bytes the line keeps.
    fn weight(&self) -> usize;
}

impl Weighs for String {
    fn weight(&self) -> usize {
        self.len()
    }
}

impl Weighs for KeyHolder {
    fn weight(&self) -> usize {
        self.path.len() + 64
    }
}

/// One list of what a key scan tells: it keeps the first lines up to a number of lines and of bytes
/// in all, and counts every line past either, so the run's end can always write what it holds. A
/// list that has counted a line is not empty.
#[derive(Clone, Debug)]
pub struct Told<T> {
    kept: Vec<T>,
    bytes: usize,
    more: u64,
    lines_at_most: usize,
    bytes_at_most: usize,
}

impl<T> Default for Told<T> {
    fn default() -> Self {
        Self::within(TOLD_LINES_AT_MOST, TOLD_BYTES_AT_MOST)
    }
}

impl<T> Told<T> {
    /// An empty list that keeps at most `lines` lines and `bytes` bytes.
    #[must_use]
    pub const fn within(lines: usize, bytes: usize) -> Self {
        Self {
            kept: Vec::new(),
            bytes: 0,
            more: 0,
            lines_at_most: lines,
            bytes_at_most: bytes,
        }
    }
}

impl<T: Weighs> Told<T> {
    /// Keeps `line` where the list has room for it, and counts it otherwise.
    pub fn push(&mut self, line: T) {
        let weight = line.weight();
        if self.kept.len() < self.lines_at_most
            && self.bytes.saturating_add(weight) <= self.bytes_at_most
        {
            self.bytes += weight;
            self.kept.push(line);
        } else {
            self.more += 1;
        }
    }

    /// The lines kept, in the order they were told.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.kept.iter()
    }

    /// How many lines were told, those counted and not kept included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.kept
            .len()
            .saturating_add(usize::try_from(self.more).unwrap_or(usize::MAX))
    }

    /// Whether no line was told.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kept.is_empty() && self.more == 0
    }

    /// How many lines were counted and not kept.
    #[must_use]
    pub const fn not_listed(&self) -> u64 {
        self.more
    }

    /// Orders the lines kept.
    pub fn sort_by(&mut self, order: impl FnMut(&T, &T) -> std::cmp::Ordering) {
        self.kept.sort_by(order);
    }
}

impl<T: Serialize> Serialize for Told<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.kept.serialize(serializer)
    }
}

/// What a search of a run's directory for a key's bytes found: every regular file that held them,
/// by path relative to the directory, and every entry the search could not read, which leaves the
/// search incomplete. Nothing of the value is kept. Each list keeps a set number of lines and of
/// bytes and counts the rest ([`Told::not_listed`]).
#[derive(Clone, Debug, Default, Serialize)]
pub struct KeyScan {
    /// The files that held the value.
    pub held_by: Told<KeyHolder>,
    /// The entries that could not be read, with why.
    pub unread: Told<String>,
    /// The scan met an entry on another file system than its root's, as a mounted volume is: the
    /// run's directory is then left where it is.
    #[serde(skip)]
    pub crossed_a_mount: bool,
    /// The root of a run's scan is not the directory the run made.
    #[serde(skip)]
    pub root_changed: bool,
    /// How many entries the scan has looked at, and what it reads at most.
    #[serde(skip)]
    entries: usize,
    #[serde(skip)]
    limits: ScanLimits,
    /// The bytes the scans that share this budget have read in all.
    #[serde(skip)]
    bytes: std::sync::Arc<ScanBytes>,
}

/// The most bytes of one file that the key scan reads: a file above it is told as not scanned.
const SCAN_FILE_AT_MOST: u64 = 1 << 30;

/// The most entries that the key scan lists, in all, counted when each is listed: the names of one
/// listing are held until its directory is done, so the count bounds what the walk holds. It stops
/// there and says so.
const SCAN_ENTRIES_AT_MOST: usize = 1_000_000;

/// The most bytes that the key scans of one run read in all, both scans together: a run's own
/// directory is under a gigabyte, so this is several times what a real run holds, and many files
/// that each fit the per-file bound (clones cost no disk) cannot keep the scan reading for days
/// while the run's directory, and the login's file in it, stays on disk.
const SCAN_BYTES_AT_MOST: u64 = 8 << 30;

/// The bytes read in all by the key scans that share it, counted when a file is about to be read.
#[derive(Debug)]
pub struct ScanBytes {
    read: std::sync::atomic::AtomicU64,
    at_most: u64,
}

impl ScanBytes {
    /// A budget of `at_most` bytes.
    #[must_use]
    pub const fn new(at_most: u64) -> Self {
        Self {
            read: std::sync::atomic::AtomicU64::new(0),
            at_most,
        }
    }

    /// Takes `size` bytes from the budget and says whether they were within it. A file that is
    /// refused still takes its size, so that no later file is read past the bound.
    fn takes(&self, size: u64) -> bool {
        let before = self
            .read
            .fetch_add(size, std::sync::atomic::Ordering::Relaxed);
        before.saturating_add(size) <= self.at_most
    }
}

impl Default for ScanBytes {
    fn default() -> Self {
        Self::new(SCAN_BYTES_AT_MOST)
    }
}

/// What a key scan reads at most.
#[derive(Clone, Copy, Debug)]
struct ScanLimits {
    /// The most bytes of one file.
    file: u64,
    /// The most entries listed, in all.
    entries: usize,
    /// The most bytes read in all by the scans that share a budget.
    bytes: u64,
    /// The most lines, and the most bytes of lines, that each of a scan's two lists keeps.
    told: (usize, usize),
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            file: SCAN_FILE_AT_MOST,
            entries: SCAN_ENTRIES_AT_MOST,
            bytes: SCAN_BYTES_AT_MOST,
            told: (TOLD_LINES_AT_MOST, TOLD_BYTES_AT_MOST),
        }
    }
}

impl KeyScan {
    /// Whether every entry was read.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.unread.is_empty()
    }
}

/// Searches every regular file under `root`, or `root` itself where it is one, for `value`, and
/// returns where it was and what could not be read. Nothing of the value is returned or printed.
/// The walk is made through directory handles with no link followed below `root` (a link, a socket
/// or a pipe holds no bytes of its own to search and is read through by nothing; a name that became
/// a link while the scan ran is told as not scanned). A root that is a file is read through the
/// handle that was checked. The walk stays on the file system of `root`:
/// an entry on another one (a volume attached below it) is told as not scanned and nothing on it is
/// opened. A place of the person's own may hold files with several names, and they are read; a
/// run's own directory is searched by [`run_files_holding`].
///
/// # Panics
///
/// Panics when `value` is shorter than eight bytes, which would find anything.
#[must_use]
pub fn files_holding(root: &Path, value: &[u8]) -> KeyScan {
    files_holding_any(root, &[value])
}

/// [`files_holding`] for several values at once, each file read once: a file is listed when it holds
/// any of them.
///
/// # Panics
///
/// Panics when a value is shorter than eight bytes, which would find anything.
#[must_use]
pub fn files_holding_any(root: &Path, values: &[&[u8]]) -> KeyScan {
    scan_files(root, values, None)
}

/// [`files_holding`] for a run's own directory, which holds no file with a second name: a file whose
/// link count is not one is the same file under another name, possibly one of the person's, and is
/// told as not scanned (which leaves the scan incomplete) and never read. The root is opened with no
/// link followed at its last component, as a run's directory is; below it the links the harness
/// makes ([`crate::stage::is_an_installation_link`]) are skipped, and any other link is told as not
/// scanned.
///
/// # Panics
///
/// Panics when `value` is shorter than eight bytes, which would find anything.
#[must_use]
pub fn run_files_holding(root: &Path, rules: &RunRules, value: &[u8]) -> KeyScan {
    run_files_holding_any(root, rules, &[value])
}

/// [`files_holding_any`] for a run's own directory ([`run_files_holding`]).
///
/// # Panics
///
/// Panics when a value is shorter than eight bytes, which would find anything.
#[must_use]
pub fn run_files_holding_any(root: &Path, rules: &RunRules, values: &[&[u8]]) -> KeyScan {
    scan_files(root, values, Some(rules))
}

/// [`run_files_holding`] sharing the budget of bytes `bytes` with the other scans of the run.
///
/// # Panics
///
/// Panics when `value` is shorter than eight bytes, which would find anything.
#[must_use]
pub fn run_files_holding_sharing(
    root: &Path,
    rules: &RunRules,
    value: &[u8],
    bytes: &std::sync::Arc<ScanBytes>,
) -> KeyScan {
    run_files_holding_any_sharing(root, rules, &[value], bytes)
}

/// [`run_files_holding_any`] sharing the budget of bytes `bytes` with the other scans of the run.
///
/// # Panics
///
/// Panics when a value is shorter than eight bytes, which would find anything.
#[must_use]
pub fn run_files_holding_any_sharing(
    root: &Path,
    rules: &RunRules,
    values: &[&[u8]],
    bytes: &std::sync::Arc<ScanBytes>,
) -> KeyScan {
    scan_files_sharing(
        root,
        values,
        Some(rules),
        ScanLimits::default(),
        std::sync::Arc::clone(bytes),
    )
}

/// What a scan of a run's own directory holds to besides reading: the directory the run made, which
/// the root must be and everything read must lie beneath; and the links that may be there, which are
/// the harness's own (the places it made them at) and nothing else.
#[derive(Clone, Debug)]
pub struct RunRules {
    pin: kr_e2e_m1b::run::RootPin,
    links: Vec<String>,
    agent: Option<AgentLinks>,
}

/// The names of the links the pinned build makes in its own home when it starts, each to its own
/// executable (the helpers of its patch tool and of its command wrapper).
const AGENT_HELPERS: [&str; 3] = ["apply_patch", "applypatch", "codex-execve-wrapper"];

/// Where the agent makes links in its own home, and what they may name.
#[derive(Clone, Debug)]
struct AgentLinks {
    /// The agent's home, relative to the run's directory.
    home: String,
    /// What a link may say: the pinned executable in the run's own installation, by the path the
    /// run starts it by and by its resolved path.
    executables: Vec<PathBuf>,
}

impl RunRules {
    /// The rules for the run whose directory is `pin`, in which the harness made links at exactly
    /// the places `links` names, relative to the run's directory and joined by `/`.
    #[must_use]
    pub fn new(pin: &kr_e2e_m1b::run::RootPin, links: Vec<String>) -> Self {
        Self {
            pin: pin.clone(),
            links,
            agent: None,
        }
    }

    /// Adds the links the pinned build makes in its own home, `home` relative to the run's
    /// directory: `home/tmp/arg0/codex-arg0<random>/<helper>` for the helpers it is known to make
    /// ([`AGENT_HELPERS`]), when the link's own text is one of `executables`, the pinned executable
    /// in the run's own installation, and nothing else. A link of any other name, in any other
    /// place, or saying anything else is counted.
    #[must_use]
    pub fn with_agent_links(mut self, home: &str, executables: Vec<PathBuf>) -> Self {
        self.agent = Some(AgentLinks {
            home: home.to_owned(),
            executables,
        });
        self
    }

    /// The directory the run made.
    #[must_use]
    pub const fn pin(&self) -> &kr_e2e_m1b::run::RootPin {
        &self.pin
    }

    /// Whether the link `name` in `directory`, at `place` below the run's directory, is one the
    /// harness made, or one the pinned build makes in its home and that says nothing but the
    /// pinned executable: its text is read and never followed.
    fn allows(&self, directory: &std::os::fd::OwnedFd, name: &std::ffi::CStr, place: &str) -> bool {
        if self.links.iter().any(|link| link == place) {
            return true;
        }
        let Some(agent) = &self.agent else {
            return false;
        };
        let names: Vec<&str> = place.split('/').collect();
        let [home, "tmp", "arg0", helper_directory, helper] = names.as_slice() else {
            return false;
        };
        if *home != agent.home
            || !helper_directory.starts_with("codex-arg0")
            || !AGENT_HELPERS.contains(helper)
        {
            return false;
        }
        rustix::fs::readlinkat(directory, name, Vec::new()).is_ok_and(|text| {
            use std::os::unix::ffi::OsStrExt as _;
            agent
                .executables
                .iter()
                .any(|executable| executable.as_os_str().as_bytes() == text.to_bytes())
        })
    }
}

/// What the scan tells of an entry it did not read.
fn not_scanned(why: &str) -> String {
    format!("not scanned: {why}")
}

/// One directory of the scan, through its handle: every entry is looked at with `fstatat` and no
/// link followed, an entry on another file system than `root`, the look at the scan's root, is not
/// opened, a directory is opened with the same handle and no link followed and checked to be
/// the one that was looked at, and a file is opened with no link followed, nonblocking, checked to
/// be the regular file that was looked at (and, in a `strict` scan, to have one name, before and
/// after it is opened), and only then read. What cannot be read is told in `scan.unread` and the
/// walk goes on.
fn scan_directory(
    directory: &std::os::fd::OwnedFd,
    root: &rustix::fs::Stat,
    relative: &str,
    depth: usize,
    rules: Option<&RunRules>,
    holds: &dyn Fn(&[u8]) -> bool,
    scan: &mut KeyScan,
) {
    use crate::held::{DEEPEST, opened_directory};
    use rustix::fs::{AtFlags, FileType};
    let place = |name: &str| {
        if relative.is_empty() {
            name.to_owned()
        } else {
            format!("{relative}/{name}")
        }
    };
    if depth > DEEPEST {
        scan.unread.push(format!(
            "{relative}: {}",
            not_scanned("the tree is too deep")
        ));
        return;
    }
    let names: Vec<std::ffi::CString> = {
        let listing = match rustix::fs::Dir::read_from(directory) {
            Ok(listing) => listing,
            Err(error) => {
                scan.unread.push(format!("{relative}: {error}"));
                return;
            }
        };
        let mut names = Vec::new();
        for entry in listing {
            match entry {
                Ok(entry) => {
                    let name = entry.file_name();
                    if name.to_bytes() != b"." && name.to_bytes() != b".." {
                        // An entry is counted when it is listed, across the whole scan. Told once,
                        // by the entry that went past the bound; the entries after it only stop.
                        scan.entries = scan.entries.saturating_add(1);
                        if scan.entries > scan.limits.entries {
                            if scan.entries == scan.limits.entries.saturating_add(1) {
                                scan.unread.push(format!(
                                    "{relative}: {}",
                                    not_scanned("more entries than the scan reads")
                                ));
                            }
                            return;
                        }
                        names.push(name.to_owned());
                    }
                }
                Err(error) => scan.unread.push(format!("{relative}: {error}")),
            }
        }
        names
    };
    for name in names {
        // A scan that went past its bound in a directory below this one goes no further.
        if scan.entries > scan.limits.entries {
            return;
        }
        let shown = place(&name.to_string_lossy());
        let looked = match rustix::fs::statat(directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
        {
            Ok(looked) => looked,
            Err(error) => {
                scan.unread.push(format!("{shown}: {error}"));
                continue;
            }
        };
        // A volume attached below the root is no link and its files have one name: only the
        // device tells it from the root's own file system, and nothing on it is opened.
        // The check is for mounts only: the system's own volumes share one device number.
        if looked.st_dev != root.st_dev {
            scan.crossed_a_mount = true;
            scan.unread
                .push(format!("{shown}: {}", not_scanned("another file system")));
            continue;
        }
        match FileType::from_raw_mode(looked.st_mode) {
            FileType::Directory => match opened_directory(directory, name.as_c_str(), &looked, 0) {
                Ok(child) if rules.is_some_and(|rules| !rules.pin.contains(&child)) => {
                    scan.unread.push(format!(
                        "{shown}: {}",
                        not_scanned("it was moved out of the run while the scan ran")
                    ));
                }
                Ok(child) => scan_directory(&child, root, &shown, depth + 1, rules, holds, scan),
                Err(unlooked) => scan
                    .unread
                    .push(format!("{shown}: {}", not_scanned(&unlooked.to_string()))),
            },
            FileType::RegularFile => {
                scan_file(
                    directory,
                    name.as_c_str(),
                    &looked,
                    &shown,
                    rules,
                    holds,
                    scan,
                );
            }
            // A run holds the links the harness itself makes (the one to the installed build and
            // the ones to its runtimes), which nothing is read through; any other link is counted.
            FileType::Symlink
                if rules.is_some_and(|rules| !rules.allows(directory, name.as_c_str(), &shown)) =>
            {
                scan.unread.push(format!(
                    "{shown}: {}",
                    not_scanned("a link the harness did not make")
                ));
            }
            // The harness's own links, a link in a place of the person's own, a socket or a pipe
            // hold no bytes of their own to search, and nothing is read through them.
            _ => {}
        }
    }
}

/// One regular file of the scan, which `looked` described: opened through `directory` with no link
/// followed and nonblocking, checked to be the regular file that was looked at (and, in a `strict`
/// scan, to have one name, before and after it is opened), and only then read, through that
/// handle. What cannot be read is told in `scan.unread`.
fn scan_file(
    directory: impl rustix::fd::AsFd,
    name: impl rustix::path::Arg,
    looked: &rustix::fs::Stat,
    shown: &str,
    rules: Option<&RunRules>,
    holds: &dyn Fn(&[u8]) -> bool,
    scan: &mut KeyScan,
) {
    use crate::held::{Class, opening_failed};
    use rustix::fs::{FileType, Mode, OFlags};
    let strict = rules.is_some();
    if strict && looked.st_nlink != 1 {
        scan.unread.push(format!(
            "{shown}: {}",
            not_scanned("a file with more than one name")
        ));
        return;
    }
    let handle = match rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(handle) => handle,
        Err(error) => {
            let why = match opening_failed(error) {
                Class::Replaced => "it became a link while the scan ran".to_owned(),
                _ => error.to_string(),
            };
            scan.unread.push(format!("{shown}: {}", not_scanned(&why)));
            return;
        }
    };
    let opened = match rustix::fs::fstat(&handle) {
        Ok(opened) => opened,
        Err(error) => {
            scan.unread.push(format!("{shown}: {error}"));
            return;
        }
    };
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || (opened.st_dev, opened.st_ino) != (looked.st_dev, looked.st_ino)
    {
        scan.unread.push(format!(
            "{shown}: {}",
            not_scanned("it was replaced while the scan ran")
        ));
        return;
    }
    if strict && opened.st_nlink != 1 {
        scan.unread.push(format!(
            "{shown}: {}",
            not_scanned("a file with more than one name")
        ));
        return;
    }
    // A file moved into a directory that was moved out of the run is not the run's.
    if rules.is_some_and(|rules| !rules.pin.contains(&handle)) {
        scan.unread.push(format!(
            "{shown}: {}",
            not_scanned("it is no longer beneath the run's directory")
        ));
        return;
    }
    // The size comes from the handle that will be read, and no more than the bound is read
    // through it: a file above it, sparse or not, is not read into memory.
    let too_large = || {
        format!(
            "{shown}: {}",
            not_scanned("it is larger than the scan reads")
        )
    };
    let Some(size) = u64::try_from(opened.st_size)
        .ok()
        .filter(|size| *size <= scan.limits.file)
    else {
        scan.unread.push(too_large());
        return;
    };
    // And no more than the bound in all, by the scans that share the budget: a file that would
    // take it past the bound is told as unread and not read.
    if !scan.bytes.takes(size) {
        scan.unread.push(format!(
            "{shown}: {}",
            not_scanned("the scan has read the bytes it reads in all")
        ));
        return;
    }
    let mut file = std::fs::File::from(handle);
    let mut bytes = Vec::new();
    if let Err(error) =
        Read::take(&mut file, scan.limits.file.saturating_add(1)).read_to_end(&mut bytes)
    {
        scan.unread.push(format!("{shown}: {error}"));
        return;
    }
    // A file that grew past the bound since its size was read is not searched.
    if u64::try_from(bytes.len()).map_or(true, |read| read > scan.limits.file) {
        scan.unread.push(too_large());
        return;
    }
    if holds(&bytes) {
        let metadata = file.metadata().ok();
        scan.held_by.push(KeyHolder {
            path: shown.to_owned(),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            created_ms: metadata.as_ref().and_then(|meta| ms_of(meta.created())),
            modified_ms: metadata.as_ref().and_then(|meta| ms_of(meta.modified())),
        });
    }
}

/// The root of a scan, looked at and opened like what lies below it: in a `strict` scan, a run's, no
/// link is followed at its last component (a root that is a link is told as not scanned), as the
/// record's root is opened; a place of the person's own may be a link they made, and a directory
/// root that is one is followed. A directory is opened and checked to be the one that was looked at,
/// and walked on its file system; a file is read as any file of the scan is, through the handle that
/// was checked.
fn scan_root(
    root: &Path,
    rules: Option<&RunRules>,
    holds: &dyn Fn(&[u8]) -> bool,
    scan: &mut KeyScan,
) {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    let (look, open) = if rules.is_some() {
        (AtFlags::SYMLINK_NOFOLLOW, OFlags::NOFOLLOW)
    } else {
        (AtFlags::empty(), OFlags::empty())
    };
    let name = root
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let looked = match rustix::fs::statat(rustix::fs::CWD, root, look) {
        Ok(looked) => looked,
        Err(error) => {
            scan.unread.push(format!(": {error}"));
            return;
        }
    };
    match FileType::from_raw_mode(looked.st_mode) {
        FileType::Directory => {
            let directory = match rustix::fs::open(
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | open,
                Mode::empty(),
            ) {
                Ok(directory) => directory,
                Err(error) => {
                    scan.unread.push(format!(": {error}"));
                    return;
                }
            };
            match rustix::fs::fstat(&directory) {
                Ok(_) if rules.is_some_and(|rules| !rules.pin.holds(&directory)) => {
                    scan.root_changed = true;
                    scan.unread.push(format!(
                        ": {}",
                        not_scanned("the run's directory is not the one the run made")
                    ));
                }
                Ok(opened) if (opened.st_dev, opened.st_ino) == (looked.st_dev, looked.st_ino) => {
                    scan_directory(&directory, &opened, "", 1, rules, holds, scan);
                }
                Ok(_) => scan.unread.push(format!(
                    ": {}",
                    not_scanned("it was replaced while the scan ran")
                )),
                Err(error) => scan.unread.push(format!(": {error}")),
            }
        }
        // The root of a run's scan is the directory the run made, which no file is: a file there
        // is another entry put in its place, and it is not read.
        FileType::RegularFile if rules.is_some() => {
            scan.root_changed = true;
            scan.unread.push(format!(
                ": {}",
                not_scanned("the run's directory is not the one the run made")
            ));
        }
        // A root of a place of the person's own that is a link to a file is looked at through the
        // link, and the no-follow open then refuses it and tells it with the wrong text, "it became
        // a link while the scan ran": it was one from the start. It is still refused and still
        // incomplete; only the wording is off, and only the parts that scan such a place meet it.
        FileType::RegularFile => {
            scan_file(rustix::fs::CWD, root, &looked, &name, rules, holds, scan)
        }
        _ => scan.unread.push(format!(
            "{name}: {}",
            not_scanned("the root is a link, or is neither a file nor a directory")
        )),
    }
}

/// [`files_holding_any`] and [`run_files_holding_any`]: with `rules`, a run's scan refuses a file
/// with more than one name, a root that is a link or is not the directory the run made, and a link
/// the harness did not make.
fn scan_files(root: &Path, values: &[&[u8]], rules: Option<&RunRules>) -> KeyScan {
    scan_files_within(root, values, rules, ScanLimits::default())
}

/// [`scan_files`] within `limits`, with a budget of bytes of its own.
fn scan_files_within(
    root: &Path,
    values: &[&[u8]],
    rules: Option<&RunRules>,
    limits: ScanLimits,
) -> KeyScan {
    let bytes = std::sync::Arc::new(ScanBytes::new(limits.bytes));
    scan_files_sharing(root, values, rules, limits, bytes)
}

/// [`scan_files_within`] with the budget of bytes `bytes`, which other scans may share.
fn scan_files_sharing(
    root: &Path,
    values: &[&[u8]],
    rules: Option<&RunRules>,
    limits: ScanLimits,
    bytes: std::sync::Arc<ScanBytes>,
) -> KeyScan {
    assert!(
        values.iter().all(|value| value.len() >= 8),
        "a key shorter than eight bytes cannot be searched for"
    );
    // Each value's searcher is made once: a run's directory holds binaries of tens of megabytes, which
    // a search window by window would take minutes over for a dozen values.
    let finders: Vec<memchr::memmem::Finder<'_>> =
        values.iter().map(memchr::memmem::Finder::new).collect();
    let holds = |bytes: &[u8]| finders.iter().any(|finder| finder.find(bytes).is_some());
    let mut scan = KeyScan {
        limits,
        bytes,
        held_by: Told::within(limits.told.0, limits.told.1),
        unread: Told::within(limits.told.0, limits.told.1),
        ..KeyScan::default()
    };
    scan_root(root, rules, &holds, &mut scan);
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
        "held_by_not_listed": scan.held_by.not_listed(),
        "unread": scan.unread,
        "unread_not_listed": scan.unread.not_listed(),
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
/// its path relative to the home, its SHA-256, or none where it did not exist, and whether those
/// same bytes held one of the needles it was read for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guarded {
    /// The path relative to the person's home.
    pub relative: String,
    /// The file's SHA-256, where it exists.
    pub sha256: Option<[u8; 32]>,
    /// Whether the bytes hashed held one of the needles.
    pub holds: bool,
    /// The file's length, where it exists.
    pub bytes: Option<u64>,
    /// When it was last modified, in nanoseconds since the epoch, where it exists.
    pub modified_ns: Option<i128>,
}

/// Reads each of `files`, relative to `home`, once, for [`Guarded`]: its digest and whether it
/// holds one of `needles` come from the same read. A file that cannot be read, other than one that
/// does not exist, is an error, since nothing about it could be compared.
///
/// # Errors
///
/// Returns the file that could not be read, and why.
pub fn guarded_files(
    home: &Path,
    files: &[String],
    needles: &[&str],
) -> Result<Vec<Guarded>, String> {
    files
        .iter()
        .map(|relative| {
            let path = home.join(relative);
            match std::fs::read(&path) {
                Ok(bytes) => Ok(Guarded {
                    relative: relative.clone(),
                    sha256: Some(kr_cbor::sha256(&bytes)),
                    holds: holds_any(&bytes, needles),
                    bytes: Some(bytes.len() as u64),
                    modified_ns: std::fs::metadata(&path).ok().map(|metadata| {
                        i128::from(metadata.mtime()) * 1_000_000_000
                            + i128::from(metadata.mtime_nsec())
                    }),
                }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Guarded {
                    relative: relative.clone(),
                    sha256: None,
                    holds: false,
                    bytes: None,
                    modified_ns: None,
                }),
                Err(error) => Err(format!("~/{relative}: {error}")),
            }
        })
        .collect()
}

/// Appends one line to the file beside the key-scan file the harness named: the part, and each
/// guarded file's SHA-256, size and modification time before and after, so the comparison can be
/// checked without the files; the record itself says only whether each changed.
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
            let millis = |nanoseconds: Option<i128>| {
                nanoseconds.and_then(|ns| i64::try_from(ns / 1_000_000).ok())
            };
            json!({
                "file": format!("~/{}", first.relative),
                "before": hex(&first.sha256),
                "after": hex(&second.sha256),
                "bytes_before": first.bytes,
                "bytes_after": second.bytes,
                "modified_ms_before": millis(first.modified_ns),
                "modified_ms_after": millis(second.modified_ns),
            })
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

/// A file of the person's home that the agent and the person's other programs only append lines
/// to, as a part found it before it started: its path relative to the home, and its bytes, none
/// where it did not exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendOnly {
    /// The path relative to the person's home.
    pub relative: String,
    /// The file's bytes, where it existed.
    pub before: Option<Vec<u8>>,
}

/// Reads each of `files`, relative to `home`, whole, for [`AppendOnly`]. A file that cannot be read,
/// other than one that does not exist, is an error, since nothing about it could be compared.
///
/// # Errors
///
/// Returns the file that could not be read, and why.
pub fn append_only_files(home: &Path, files: &[String]) -> Result<Vec<AppendOnly>, String> {
    files
        .iter()
        .map(|relative| {
            Ok(AppendOnly {
                relative: relative.clone(),
                before: read_if_there(&home.join(relative))
                    .map_err(|error| format!("~/{relative}: {error}"))?,
            })
        })
        .collect()
}

/// A file's bytes, or `None` where it does not exist.
///
/// # Errors
///
/// Returns why a file that exists could not be read.
pub fn read_if_there(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The lines appended to a file since its bytes were `before`, where its bytes `now` still begin
/// with every earlier byte, in place: whole lines, from the first line boundary at or after the
/// earlier end, so a line the earlier bytes ended part way through stays an earlier line; the last
/// may still lack its line end. `None` when an earlier byte changed or went, or the file went.
#[must_use]
pub fn appended_since<'a>(before: Option<&[u8]>, now: Option<&'a [u8]>) -> Option<Vec<&'a [u8]>> {
    let now = match (before, now) {
        (Some(_), None) => return None,
        (None, None) => return Some(Vec::new()),
        (_, Some(now)) => now,
    };
    let earlier = before.unwrap_or_default();
    if !now.starts_with(earlier) {
        return None;
    }
    let start = if earlier.is_empty() || earlier.ends_with(b"\n") {
        earlier.len()
    } else {
        now[earlier.len()..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(now.len(), |at| earlier.len() + at + 1)
    };
    Some(
        now[start..]
            .split_inclusive(|byte| *byte == b'\n')
            .collect(),
    )
}

/// What a line appended to a file only appended to says of itself, where it is a JSON object: the
/// conversation it names (its `id`, or its `session_id` as an agent's history line names it) and
/// its time (its `updated_at`, or its `ts`), the first of each pair the line has. Each is kept only
/// in the shape an identifier or a time has, so no other text of the line can come through: an
/// identifier of at most 64 letters, digits and `.`, `_`, `:` or `-`; a time that is a number, or
/// text of at most 40 letters, digits and `.`, `:`, `+` or `-`. Nothing else of the line is read.
#[must_use]
pub fn line_identity(line: &[u8]) -> (Option<String>, Option<Value>) {
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(line) else {
        return (None, None);
    };
    let shaped = |text: &str, longest: usize, marks: &[char]| {
        !text.is_empty()
            && text.len() <= longest
            && text
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || marks.contains(&character))
    };
    let id = ["id", "session_id", "sessionId"]
        .iter()
        .find_map(|key| fields.get(*key))
        .and_then(Value::as_str)
        .filter(|id| shaped(id, 64, &['.', '_', ':', '-']))
        .map(str::to_owned);
    let time = ["updated_at", "ts"]
        .iter()
        .find_map(|key| fields.get(*key))
        .filter(|time| match time {
            Value::Number(_) => true,
            Value::String(text) => shaped(text, 40, &['.', ':', '+', '-']),
            _ => false,
        })
        .cloned();
    (id, time)
}

/// Whether `bytes` hold one of `needles`.
#[must_use]
pub fn holds_any(bytes: &[u8], needles: &[&str]) -> bool {
    needles.iter().any(|needle| {
        !needle.is_empty()
            && bytes
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
    })
}

/// Removes from the line file `path`, whose bytes were `before` when the part started, each line
/// appended since that holds one of `needles` (the part's mark or the run's directory: the part's
/// own), and returns how many it removed: under an exclusive lock on the file, which every writer
/// of such a file takes for each line, the file is read, every earlier byte must still be there in
/// place, and only when an appended line is the part's is the file written again, in place, with
/// the earlier bytes and the other appended lines as they were. A file that is not there, and was
/// not, has no lines to remove.
///
/// # Errors
///
/// Returns why the file could not be read, locked or written, or that an earlier line changed or
/// went.
pub fn remove_appended_lines(
    path: &Path,
    before: Option<&[u8]>,
    needles: &[&str],
) -> Result<usize, String> {
    use std::io::Seek;
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && before.is_none() => {
            return Ok(0);
        }
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let result = (|| {
        let mut now = Vec::new();
        file.read_to_end(&mut now)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let appended = appended_since(before, Some(&now)).ok_or_else(|| {
            format!(
                "{}: a line that was there before the part changed or went",
                path.display()
            )
        })?;
        let start = now.len() - appended.iter().map(|line| line.len()).sum::<usize>();
        let kept: Vec<&[u8]> = appended
            .iter()
            .copied()
            .filter(|line| !holds_any(line, needles))
            .collect();
        let removed = appended.len() - kept.len();
        if removed > 0 {
            let mut rest = now[..start].to_vec();
            rest.extend(kept.concat());
            file.seek(std::io::SeekFrom::Start(0))
                .and_then(|_| file.write_all(&rest))
                .and_then(|()| file.set_len(u64::try_from(rest.len()).unwrap_or(u64::MAX)))
                .map_err(|error| format!("{}: {error}", path.display()))?;
        }
        Ok(removed)
    })();
    let _ = rustix::fs::flock(&file, rustix::fs::FlockOperation::Unlock);
    result
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
    /// The roots listed for the files directly in them only.
    shallow: Vec<PathBuf>,
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

    /// Whether `path` was in the snapshot and its bytes were read whole for a digest.
    #[must_use]
    pub fn is_hashed(&self, path: &Path) -> bool {
        self.files
            .get(path)
            .is_some_and(|entry| entry.digest.is_some())
    }

    /// The entries that could not be read, with why.
    #[must_use]
    pub fn unread(&self) -> &[String] {
        &self.unread
    }

    /// How many entries could not be read under each root, for each root that has any, in the
    /// order of the roots, as [`Snapshot::count_by_root`] counts them. Unlike
    /// [`Snapshot::unread`], it names no entry, so it can be said where the person's own file
    /// names must not be.
    #[must_use]
    pub fn unread_by_root(&self) -> Vec<(PathBuf, usize)> {
        self.count_by_root(self.unread.iter().map(String::as_str))
    }

    /// How many of `texts`, each an absolute path, alone or followed by ": " and why, lie under
    /// each root, for each root that has any, in the order of the roots: a text counts under the
    /// longest root that is its path or holds it, and one under none is not counted. It names no
    /// path, so it can be said where the person's own file names must not be.
    #[must_use]
    pub fn count_by_root<'a>(
        &self,
        texts: impl IntoIterator<Item = &'a str>,
    ) -> Vec<(PathBuf, usize)> {
        let mut counts: Vec<(PathBuf, usize)> =
            self.roots.iter().map(|root| (root.clone(), 0)).collect();
        for text in texts {
            let holder = counts
                .iter_mut()
                .filter(|(root, _)| {
                    let root = root.display().to_string();
                    text == root
                        || text.starts_with(&format!("{root}/"))
                        || text.starts_with(&format!("{root}: "))
                })
                .max_by_key(|(root, _)| root.as_os_str().len());
            if let Some((_, count)) = holder {
                *count += 1;
            }
        }
        counts.retain(|(_, count)| *count > 0);
        counts
    }

    /// How many of `paths` lie under each root, for each root that has any, in the order of the
    /// roots, compared as paths, whatever bytes their names hold: a path counts under the longest
    /// root that is it or holds it, and one under none under `None`, last.
    #[must_use]
    pub fn count_paths_by_root<'a>(
        &self,
        paths: impl IntoIterator<Item = &'a Path>,
    ) -> Vec<(Option<PathBuf>, usize)> {
        let mut counts: Vec<(Option<PathBuf>, usize)> = self
            .roots
            .iter()
            .map(|root| (Some(root.clone()), 0))
            .chain(std::iter::once((None, 0)))
            .collect();
        for path in paths {
            let holder = self
                .roots
                .iter()
                .filter(|root| path.starts_with(root))
                .max_by_key(|root| root.as_os_str().len())
                .cloned();
            if let Some((_, count)) = counts.iter_mut().find(|(root, _)| *root == holder) {
                *count += 1;
            }
        }
        counts.retain(|(_, count)| *count > 0);
        counts
    }
}

/// Reads every file under each of `directories`, relative to `home`: size, modification time and
/// inode for all, and the SHA-256 of each no larger than `hash_limit` bytes. A directory named with
/// a trailing `/*` is read for the files directly in it, and the directories in it are recorded as
/// there but not read. A root that does not exist, and an entry gone between its directory's
/// listing and its own read, are not there; any other entry that cannot be read, a file that cannot
/// be hashed whole included, is recorded, and the snapshot is then not whole.
#[must_use]
pub fn snapshot(home: &Path, directories: &[String], hash_limit: u64) -> Snapshot {
    let mut files = BTreeMap::new();
    let mut seen_directories = std::collections::BTreeSet::new();
    let mut unread = Vec::new();
    let mut roots = Vec::new();
    let mut shallow = Vec::new();
    for relative in directories {
        match relative.strip_suffix("/*") {
            Some(directory) => {
                roots.push(home.join(directory));
                shallow.push(home.join(directory));
            }
            None => roots.push(home.join(relative)),
        }
    }
    for top in &roots {
        let only_its_files = shallow.contains(top);
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
                if only_its_files && &path != top {
                    seen_directories.insert(path);
                    continue;
                }
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
        shallow,
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

/// What the agent's own upkeep rewrote, by listed path: for each of `listed` (files or directories,
/// relative to `data`, the person's data directory), how many of its files the part found rewritten
/// and created, the rewritten files' sizes together, the latest time one was modified, and a
/// SHA-256 over the rewritten files' names and digests, so a rewrite shows without a name or a
/// byte of what it holds. The second list has one entry for each rewritten file, with its size,
/// time and digest before and after, for the part's private evidence. A file whose bytes were too
/// many to hash whole is not one of the rewrites this lists: the part stops on it (see
/// [`Snapshot::is_hashed`]).
#[must_use]
pub fn reported_rewrites(
    data: &Path,
    listed: &[String],
    (before, after): (&Snapshot, &Snapshot),
    found: &Changes,
) -> (Vec<Value>, Vec<Value>) {
    let hex = |digest: Option<[u8; 32]>| {
        digest.map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
    };
    let millis = |nanoseconds: i128| i64::try_from(nanoseconds / 1_000_000).ok();
    let mut private = Vec::new();
    let published = listed
        .iter()
        .map(|member| {
            let root = data.join(member);
            let mut rewritten: Vec<&PathBuf> = found
                .rewritten
                .iter()
                .filter(|path| path.starts_with(&root))
                .collect();
            rewritten.sort();
            let created = found
                .created
                .iter()
                .filter(|path| path.starts_with(&root))
                .count();
            let mut bytes = 0_u64;
            let mut latest: Option<i128> = None;
            let mut names = String::new();
            for path in &rewritten {
                let (Some(old), Some(new)) = (before.files.get(*path), after.files.get(*path))
                else {
                    continue;
                };
                bytes += new.bytes;
                latest = latest.max(Some(new.modified_ns));
                let relative = path.strip_prefix(data).unwrap_or(path).display().to_string();
                names.push_str(&format!(
                    "{relative}\t{}\n",
                    hex(new.digest).unwrap_or_else(|| "unhashed".to_owned())
                ));
                private.push(json!({
                    "file": relative,
                    "bytes_before": old.bytes,
                    "bytes_after": new.bytes,
                    "modified_ms_before": millis(old.modified_ns),
                    "modified_ms_after": millis(new.modified_ns),
                    "sha256_before": hex(old.digest),
                    "sha256_after": hex(new.digest),
                }));
            }
            json!({
                "path": member,
                "rewritten": rewritten.len(),
                "created": created,
                "bytes": bytes,
                "modified_ms": latest.and_then(millis),
                "sha256": (!rewritten.is_empty()).then(|| hex(Some(kr_cbor::sha256(names.as_bytes())))),
            })
        })
        .collect();
    (published, private)
}

/// Appends one line to the file beside the key-scan file the harness named: the part and what the
/// agent's own upkeep rewrote, each file with its size, time and digest before and after. It names
/// the person's files, so it stays with the run's private evidence and is never published.
///
/// # Panics
///
/// Panics when the harness named a file that cannot be written.
pub fn record_rewrites(part: &str, files: &[Value]) {
    let Some(path) = std::env::var_os(KEY_SCAN_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).with_file_name("rewritten-upkeep.jsonl"))
    else {
        return;
    };
    let mut line = serde_json::to_vec(&json!({ "part": part, "files": files }))
        .expect("the rewritten files are JSON");
    line.push(b'\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(&line))
        .unwrap_or_else(|error| panic!("the rewritten-files file {}: {error}", path.display()));
}

/// Removes each file the part created inside one of `removable`, the directories whose files
/// belong to one conversation or run each, that holds one of `marks` (the part's own marker, or the
/// run's own directory, which the agent writes as the working directory), and then each directory
/// the part created there that is left empty; returns what it removed and what it left. A file the
/// part created anywhere else is left and reported, since a file there, such as a database, can
/// hold the part's text beside the person's own. Nothing that existed before the part, a file or a
/// directory, is touched, and nothing at all when `before` is not whole, since what it missed may
/// have existed. A directory is removed only inside a root that was read whole: in one read for its
/// own files alone, a directory's earlier contents were not seen.
#[must_use]
pub fn remove_created(
    before: &Snapshot,
    changes: &Changes,
    marks: &[&str],
    removable: &[PathBuf],
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    if !before.whole() {
        return (Vec::new(), changes.created.clone());
    }
    let inside = |path: &Path| {
        before.roots.iter().any(|root| path.starts_with(root))
            && removable.iter().any(|root| path.starts_with(root))
    };
    let inside_a_whole_root = |path: &Path| {
        before
            .roots
            .iter()
            .filter(|root| !before.shallow.contains(root))
            .any(|root| path.starts_with(root))
            && removable.iter().any(|root| path.starts_with(root))
    };
    let mut removed = Vec::new();
    let mut left = Vec::new();
    for path in &changes.created {
        let new =
            inside(path) && !before.files.contains_key(path) && !before.directories.contains(path);
        let ours = new
            && which_hold(std::slice::from_ref(path), marks)
                .0
                .contains(path);
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
        .filter(|directory| {
            inside_a_whole_root(directory) && !before.directories.contains(directory)
        })
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

/// Which of `paths` hold one of `needles`, read a piece at a time so a file of any size can be
/// searched; and each that could not be read, with why. A file that is gone is not listed.
#[must_use]
pub fn which_hold(paths: &[PathBuf], needles: &[&str]) -> (Vec<PathBuf>, Vec<String>) {
    const PIECE: usize = 1 << 20;
    let needles: Vec<&[u8]> = needles
        .iter()
        .filter(|needle| !needle.is_empty())
        .map(|needle| needle.as_bytes())
        .collect();
    let overlap = needles.iter().map(|needle| needle.len()).max().unwrap_or(1) - 1;
    let mut holding = Vec::new();
    let mut unread = Vec::new();
    for path in paths {
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                unread.push(format!("{}: {error}", path.display()));
                continue;
            }
        };
        let mut window: Vec<u8> = Vec::with_capacity(PIECE + overlap);
        let mut piece = vec![0; PIECE];
        let found = loop {
            match file.read(&mut piece) {
                Ok(0) => break Ok(false),
                Ok(read) => {
                    window.extend_from_slice(&piece[..read]);
                    if needles.iter().any(|needle| {
                        window
                            .windows(needle.len())
                            .any(|candidate| candidate == *needle)
                    }) {
                        break Ok(true);
                    }
                    let keep = window.len().min(overlap);
                    window.drain(..window.len() - keep);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => break Err(error),
            }
        };
        match found {
            Ok(true) => holding.push(path.clone()),
            Ok(false) => {}
            Err(error) => unread.push(format!("{}: {error}", path.display())),
        }
    }
    (holding, unread)
}

/// Whether `candidate` is shaped like a UUID: 36 characters, hexadecimal digits and four dashes.
fn uuid_shaped(candidate: &str) -> bool {
    candidate.len() == 36
        && candidate.char_indices().all(|(index, character)| {
            if [8, 13, 18, 23].contains(&index) {
                character == '-'
            } else {
                character.is_ascii_hexdigit()
            }
        })
}

/// The identifier of the conversation a file holds: the name of the session directory that holds it
/// (`session_<uuid>`), where the agent keeps each conversation in a directory of its own; else the
/// last identifier shaped like a UUID in its name, or the name without its extension.
#[must_use]
pub fn conversation_id(file: &Path) -> String {
    if let Some(session) = file
        .ancestors()
        .skip(1)
        .filter_map(|directory| directory.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .find(|name| name.strip_prefix("session_").is_some_and(uuid_shaped))
    {
        return session;
    }
    let stem = file
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let shaped = uuid_shaped;
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

    /// The rules for the scan of `root` as a run's directory (a root that is no directory is
    /// given its parent as the run's directory), with the harness's links at `links`.
    fn rules_for(root: &Path, links: &[&str]) -> RunRules {
        let pin = kr_e2e_m1b::run::RootPin::of(root)
            .or_else(|_| kr_e2e_m1b::run::RootPin::of(root.parent().expect("a parent")))
            .expect("a directory to pin");
        RunRules::new(&pin, links.iter().map(|link| (*link).to_owned()).collect())
    }

    /// The ledger at `path` for `budget`, in a file made as the operator makes the first one: with
    /// an explicit empty array for each of `budgets`.
    fn made(path: &Path, budgets: &[&str], budget: &str, limit: u64) -> Ledger {
        let empty: serde_json::Map<String, Value> = budgets
            .iter()
            .map(|name| ((*name).to_owned(), json!([])))
            .collect();
        std::fs::write(path, json!({ "budgets": empty }).to_string()).expect("a first ledger");
        Ledger::at(path.to_path_buf(), budget, limit).expect("a ledger")
    }

    /// A second process reads the ledger the moment a charge returns, and finds the charge.
    #[test]
    fn a_charge_is_in_the_file_another_process_reads_when_the_charge_returns() {
        let scratch = Scratch::new("durable");
        let path = scratch.0.join("turns.json");
        let ledger = made(&path, &["agent"], "agent", 3);
        for expected in 1..=2_u64 {
            assert_eq!(ledger.charge("1", "a prompt"), Ok(expected));
            let read = std::process::Command::new("/bin/cat")
                .arg(&path)
                .output()
                .expect("cat starts");
            assert!(read.status.success());
            let seen: Value = serde_json::from_slice(&read.stdout).expect("a ledger");
            assert_eq!(
                seen["budgets"]["agent"].as_array().map(Vec::len),
                Some(usize::try_from(expected).expect("a count")),
                "the second process sees every charge made"
            );
            assert!(
                !path.with_extension("next").exists(),
                "no half-written file is left beside it"
            );
        }
        assert_eq!(ledger.charge_found("1", "found", 1), Ok(3));
    }

    #[test]
    fn a_ledger_charges_up_to_its_limit_across_instances_and_refuses_the_next() {
        let scratch = Scratch::new("ledger");
        let path = scratch.0.join("turns.json");
        let ledger = made(&path, &["agent", "another"], "agent", 2);
        assert_eq!(ledger.charge("1", "first"), Ok(1));
        let again = Ledger::at(path, "agent", 2).expect("the same ledger");
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
    fn the_turns_a_run_charged_are_counted_and_those_found_spent_are_charged_beyond_the_limit() {
        let scratch = Scratch::new("found");
        let ledger = made(&scratch.0.join("turns.json"), &["agent"], "agent", 2);
        let clone = ledger.clone();
        assert_eq!(ledger.charged_here(), 0);
        assert_eq!(clone.charge("1", "first"), Ok(1));
        assert!(ledger.charge("1", "second").is_ok());
        assert!(ledger.charge("1", "third").is_err());
        assert_eq!(
            ledger.charged_here(),
            2,
            "clones share one count; a refusal is none"
        );
        assert_eq!(ledger.charge_found("1", "found in the record", 2), Ok(4));
        assert_eq!(
            ledger.spent(),
            Ok(4),
            "the ledger says what was spent, over the limit"
        );
        assert_eq!(
            ledger.charged_here(),
            2,
            "what was found was not charged by the run"
        );
    }

    /// A ledger that is not there, or whose budget is not an array, gives back no allowance: it is
    /// refused before anything is submitted, and a charge never overwrites what it refused.
    #[test]
    fn a_ledger_that_is_missing_or_of_the_wrong_shape_is_refused_and_never_overwritten() {
        let scratch = Scratch::new("shape");
        let path = scratch.0.join("turns.json");
        // Not there: no ledger is made by asking for one, and the text says how to make one.
        let why = Ledger::at(path.clone(), "agent", 3).expect_err("a missing ledger");
        assert!(
            why.contains(r#"{"budgets": {"agent": []}}"#) && why.contains(TURNS_VARIABLE),
            "{why}"
        );
        assert!(!path.exists(), "asking for a ledger makes none");
        for wrong in [
            "{}",
            r#"{"budgets": []}"#,
            r#"{"budgets": {"agent": 21}}"#,
            r#"{"budgets": {"agent": {"spent": 0}}}"#,
            r#"{"budgets": {"another": []}}"#,
            "[]",
            "{ not json",
            // An array whose entries are not charges: nothing counts them as turns.
            r#"{"budgets": {"agent": [null]}}"#,
            r#"{"budgets": {"agent": [{"spent": 21}]}}"#,
            r#"{"budgets": {"agent": [{"at_ms": 1, "part": "1"}]}}"#,
            r#"{"budgets": {"agent": [{"at_ms": -1, "part": "1", "what": "w"}]}}"#,
            r#"{"budgets": {"agent": [{"at_ms": 1.5, "part": "1", "what": "w"}]}}"#,
            r#"{"budgets": {"agent": [{"at_ms": 1, "part": 1, "what": "w"}]}}"#,
            r#"{"budgets": {"agent": [{"at_ms": 1, "part": "1", "what": "w"}, 7]}}"#,
        ] {
            std::fs::write(&path, wrong).expect("a wrong ledger");
            assert!(
                Ledger::at(path.clone(), "agent", 3).is_err(),
                "{wrong} is refused"
            );
            // A ledger that became wrong after it was accepted takes no charge and is left alone.
            let ledger = made(&scratch.0.join("good.json"), &["agent"], "agent", 3);
            let ledger = Ledger {
                path: path.clone(),
                ..ledger
            };
            assert!(
                ledger.charge("1", "first").is_err(),
                "{wrong} takes no charge"
            );
            assert!(ledger.charge_found("1", "found", 1).is_err());
            assert!(ledger.spent().is_err());
            assert_eq!(
                std::fs::read_to_string(&path).expect("the ledger"),
                wrong,
                "a refused charge leaves the ledger as it was"
            );
            assert_eq!(ledger.charged_here(), 0);
        }
        // The explicit empty ledger is accepted and charges; an entry a charge wrote is a charge.
        let ledger = made(&path, &["agent"], "agent", 3);
        assert_eq!(ledger.spent(), Ok(0));
        assert_eq!(ledger.charge("1", "first"), Ok(1));
        assert_eq!(ledger.charge_found("1", "found", 1), Ok(2));
        assert_eq!(
            Ledger::at(path.clone(), "agent", 3).map(|l| l.limit()),
            Ok(3)
        );
        // The refusal says what a valid entry is.
        std::fs::write(&path, r#"{"budgets": {"agent": [null]}}"#).expect("a wrong ledger");
        let why = Ledger::at(path, "agent", 3).expect_err("a null entry");
        assert!(
            why.contains("at_ms")
                && why.contains("part")
                && why.contains("what")
                && why.contains("entry 0"),
            "{why}"
        );
    }

    /// A ledger that is a symbolic link is refused; a charge never replaces the link and leaves its
    /// target with the old count; and the temporary file is a name of the run's own, created
    /// exclusively, never the fixed name beside the ledger, and gone after a failure.
    #[test]
    fn a_linked_ledger_is_refused_and_the_temporary_file_is_the_runs_own() {
        let scratch = Scratch::new("files");
        let real = scratch.0.join("real.json");
        let link = scratch.0.join("linked.json");
        let ledger = made(&real, &["agent"], "agent", 3);
        std::os::unix::fs::symlink(&real, &link).expect("a link");
        let why = Ledger::at(link.clone(), "agent", 3).expect_err("a linked ledger");
        assert!(why.contains("symbolic link"), "{why}");
        // A ledger that became a link after it was accepted takes no charge, and the link stays.
        let linked = Ledger {
            path: link.clone(),
            ..ledger.clone()
        };
        assert!(linked.charge("1", "first").is_err());
        assert!(linked.charge_found("1", "found", 1).is_err());
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("the link")
                .file_type()
                .is_symlink(),
            "a refused charge leaves the link as it was"
        );
        assert_eq!(ledger.spent(), Ok(0), "the target keeps its count");
        // A file that is not a regular file is refused too.
        assert!(Ledger::at(scratch.0.clone(), "agent", 3).is_err());
        // A second name for the ledger (a hard link) is refused as a link is, and what a charge
        // would have replaced is left alone.
        let alias = scratch.0.join("alias.json");
        std::fs::hard_link(&real, &alias).expect("a second name");
        let why = Ledger::at(alias.clone(), "agent", 3).expect_err("a ledger with two names");
        assert!(why.contains("more than one name"), "{why}");
        assert!(
            Ledger::at(real.clone(), "agent", 3).is_err(),
            "either name is refused"
        );
        assert!(
            ledger.charge("1", "first").is_err(),
            "no charge on a ledger with two names"
        );
        assert_eq!(
            std::fs::read(&real).expect("the ledger"),
            std::fs::read(&alias).expect("the other name"),
            "both names still say the same"
        );
        std::fs::remove_file(&alias).expect("removed");
        assert_eq!(ledger.spent(), Ok(0), "with one name it is read again");

        // The predictable names beside the ledger are not used: files there are left alone.
        let fixed = real.with_extension("next");
        let appended = scratch.0.join("real.json.next");
        std::fs::write(&fixed, "keep one").expect("a file");
        std::fs::write(&appended, "keep two").expect("a file");
        assert_eq!(ledger.charge("1", "first"), Ok(1));
        assert_eq!(std::fs::read_to_string(&fixed).expect("kept"), "keep one");
        assert_eq!(
            std::fs::read_to_string(&appended).expect("kept"),
            "keep two"
        );
        let left: Vec<String> = std::fs::read_dir(&scratch.0)
            .expect("a listing")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.ends_with(".tmp") || name.ends_with(".lock"))
            .collect();
        assert!(
            left.is_empty(),
            "no temporary file or lock is left: {left:?}"
        );
        // A ledger whose own name ends in `.next` or `.lock` is not its own temporary file or lock.
        for name in ["turns.next", "turns.lock", "turns.tmp"] {
            let odd = made(&scratch.0.join(name), &["agent"], "agent", 3);
            assert_eq!(odd.charge("1", "first"), Ok(1), "{name}");
            assert_eq!(odd.spent(), Ok(1), "{name}");
        }
        // A failure after the file was made leaves none behind: the rename onto a directory fails.
        let directory = scratch.0.join("a-directory");
        std::fs::create_dir(&directory).expect("a directory");
        assert!(write_ledger(&directory, &json!({ "budgets": {} })).is_err());
        let left: Vec<String> = std::fs::read_dir(&scratch.0)
            .expect("a listing")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            // `turns.tmp` is a ledger of this test's own.
            .filter(|name| name.ends_with(".tmp") && name != "turns.tmp")
            .collect();
        assert!(
            left.is_empty(),
            "a failed write leaves no temporary file: {left:?}"
        );
    }

    /// A file above the scan's bound is told as unread and none of it is read into memory, and a
    /// scan stops at its count of entries and says so; the files within the bounds are searched.
    #[test]
    fn a_file_above_the_scans_bound_is_unread_and_a_scan_stops_at_its_count_of_entries() {
        let scratch = Scratch::new("scan-bounds");
        let run = scratch.0.join("run");
        std::fs::create_dir_all(run.join("a")).expect("a run");
        let key = b"the-key-value-0123456789";
        std::fs::write(run.join("a/holds-it"), key).expect("a file that holds the key");
        // A sparse file far over the bound, with a bound of one kilobyte.
        let sparse = std::fs::File::create(run.join("a/sparse")).expect("a file");
        sparse.set_len(256 << 20).expect("a sparse file");
        let limits = ScanLimits {
            file: 1 << 10,
            entries: 100,
            ..ScanLimits::default()
        };
        let scan = scan_files_within(&run, &[key], Some(&rules_for(&run, &[])), limits);
        assert!(!scan.complete());
        assert!(
            scan.unread
                .iter()
                .any(|entry| entry.starts_with("a/sparse:")
                    && entry.contains("not scanned: it is larger than the scan reads")),
            "{:?}",
            scan.unread
        );
        assert_eq!(
            scan.held_by
                .iter()
                .map(|holder| holder.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a/holds-it"],
            "the file within the bound was searched"
        );
        // More entries than the scan walks, in one directory and below it: it stops at the count,
        // says so once, and goes on to nothing after it.
        std::fs::remove_file(run.join("a/sparse")).expect("removed");
        for index in 0..8 {
            std::fs::write(run.join(format!("a/more-{index}")), b"nothing to find")
                .expect("a file");
        }
        let few = ScanLimits {
            file: 1 << 10,
            entries: 4,
            ..ScanLimits::default()
        };
        let scan = scan_files_within(&run, &[key], Some(&rules_for(&run, &[])), few);
        assert!(!scan.complete());
        assert_eq!(
            scan.unread
                .iter()
                .filter(|entry| entry.contains("more entries than the scan reads"))
                .count(),
            1,
            "{:?}",
            scan.unread
        );
        // Within the bounds the same tree is searched whole.
        let whole = scan_files_within(&run, &[key], Some(&rules_for(&run, &[])), limits);
        assert!(whole.complete(), "{:?}", whole.unread);
    }

    /// A deep tree that holds many links, and many copies of the key, leaves each of the scan's two
    /// lists within its bound of lines and of bytes: the lines past it are counted and not kept, the
    /// scan is not complete, and what the scan file would hold stays within the bound.
    #[test]
    fn a_tree_of_many_links_and_copies_leaves_the_scans_lists_within_their_bounds() {
        let scratch = Scratch::new("scan-lists");
        let key = b"the-key-value-0123456789";
        let mut deep = scratch.0.join("run");
        for level in 0..20 {
            deep = deep.join(format!("{level:0>40}"));
        }
        std::fs::create_dir_all(&deep).expect("a deep run");
        let run = scratch.0.join("run");
        for index in 0..60 {
            std::os::unix::fs::symlink("/nowhere", deep.join(format!("link-{index:0>60}")))
                .expect("a link");
            std::fs::write(deep.join(format!("copy-{index:0>60}")), key)
                .expect("a copy of the key");
        }
        let limits = ScanLimits {
            told: (7, 3000),
            ..ScanLimits::default()
        };
        let scan = scan_files_within(&run, &[key], Some(&rules_for(&run, &[])), limits);
        assert!(!scan.complete());
        for (kept, bytes, told, more, what) in [
            (
                scan.unread.iter().count(),
                scan.unread.iter().map(String::len).sum::<usize>(),
                scan.unread.len(),
                scan.unread.not_listed(),
                "unread",
            ),
            (
                scan.held_by.iter().count(),
                scan.held_by
                    .iter()
                    .map(|holder| holder.path.len())
                    .sum::<usize>(),
                scan.held_by.len(),
                scan.held_by.not_listed(),
                "held_by",
            ),
        ] {
            assert!(kept <= 7, "{what} kept {kept} lines");
            assert!(bytes <= 3000, "{what} kept {bytes} bytes");
            assert!(kept > 0, "{what} kept none of its lines");
            assert_eq!(told, 60, "{what} counts every line it was told");
            assert_eq!(
                more,
                u64::try_from(60 - kept).expect("a count"),
                "{what} counts each line it did not keep"
            );
        }
        // Where the bytes allow more than the lines do, the lines bound the list.
        let few = ScanLimits {
            told: (4, 1 << 20),
            ..ScanLimits::default()
        };
        let four = scan_files_within(&run, &[key], Some(&rules_for(&run, &[])), few);
        assert_eq!(four.unread.iter().count(), 4);
        assert_eq!(four.unread.not_listed(), 56);
        assert_eq!(four.held_by.iter().count(), 4);
        // Where no line fits the bytes, none is kept and the scan is still not complete.
        let narrow = ScanLimits {
            told: (7, 10),
            ..ScanLimits::default()
        };
        let none = scan_files_within(&run, &[key], Some(&rules_for(&run, &[])), narrow);
        assert!(!none.complete());
        assert_eq!(none.unread.iter().count(), 0);
        assert_eq!(none.unread.len(), 60);
        assert_eq!(none.held_by.iter().count(), 0);
        assert_eq!(none.held_by.not_listed(), 60);
        let written = serde_json::to_vec(&scan).expect("a scan is JSON");
        assert!(
            written.len() < 2 * 3000 + 2000,
            "{} bytes written",
            written.len()
        );
    }

    /// Two scans that share a budget of bytes read no more in all than it holds, and the entries of
    /// a scan are counted when they are listed, across all its levels.
    #[test]
    fn the_scans_of_a_run_share_a_budget_of_bytes_and_count_entries_when_listed() {
        let scratch = Scratch::new("scan-totals");
        let run = scratch.0.join("run");
        std::fs::create_dir_all(run.join("a")).expect("a run");
        for index in 0..6 {
            std::fs::write(run.join(format!("a/f{index}")), "x".repeat(1000)).expect("a file");
        }
        let key = b"the-key-value-0123456789";
        let limits = ScanLimits {
            file: 2 << 10,
            bytes: 3 << 10,
            ..ScanLimits::default()
        };
        let rules = rules_for(&run, &[]);
        let bytes = std::sync::Arc::new(ScanBytes::new(limits.bytes));
        let first = scan_files_sharing(&run, &[key], Some(&rules), limits, bytes.clone());
        let unread = |scan: &KeyScan| {
            scan.unread
                .iter()
                .filter(|entry| entry.contains("the scan has read the bytes it reads in all"))
                .count()
        };
        assert_eq!(unread(&first), 3, "{:?}", first.unread);
        // The second scan finds the budget spent: every file is told as unread and none is read.
        let second = scan_files_sharing(&run, &[key], Some(&rules), limits, bytes);
        assert_eq!(unread(&second), 6, "{:?}", second.unread);
        // Entries in all: four levels that each list five entries, and a bound of twelve.
        let deep = scratch.0.join("deep");
        let mut place = deep.clone();
        for _ in 0..4 {
            std::fs::create_dir_all(&place).expect("a level");
            for file in 0..4 {
                std::fs::write(place.join(format!("f{file}")), "x").expect("a file");
            }
            place = place.join("next");
        }
        let few = ScanLimits {
            entries: 12,
            ..ScanLimits::default()
        };
        let scan = scan_files_within(&deep, &[key], Some(&rules_for(&deep, &[])), few);
        assert_eq!(
            scan.unread
                .iter()
                .filter(|entry| entry.contains("more entries than the scan reads"))
                .count(),
            1,
            "{:?}",
            scan.unread
        );
    }

    /// The scan of a run's directory reads through handles and refuses what it must not read: a
    /// file with a second name is told as not scanned and is not read, and a link is read through by
    /// nothing; a place of the person's own is read though its files have several names.
    #[test]
    fn the_scan_of_a_run_reads_no_file_with_a_second_name_and_follows_no_link() {
        let scratch = Scratch::new("scan");
        let run = scratch.0.join("run");
        let elsewhere = scratch.0.join("elsewhere");
        std::fs::create_dir_all(run.join("a/b")).expect("a run");
        std::fs::create_dir_all(&elsewhere).expect("outside");
        let key = b"the-key-value-0123456789";
        std::fs::write(run.join("a/b/holds-it"), key).expect("a file that holds the key");
        std::fs::write(run.join("a/clean"), b"nothing to find here").expect("a clean file");
        // A clean run: the key is found where it is, and every entry was read.
        let scan = run_files_holding(&run, &rules_for(&run, &[]), key);
        assert!(scan.complete(), "{:?}", scan.unread);
        assert_eq!(
            scan.held_by
                .iter()
                .map(|holder| holder.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a/b/holds-it"]
        );
        // A file of the person's, one of whose names is in the run: not read in a run's scan, so
        // the scan is incomplete and nothing of the file is searched.
        std::fs::write(elsewhere.join("theirs"), key).expect("a file of the person's");
        std::fs::hard_link(elsewhere.join("theirs"), run.join("a/second-name")).expect("a link");
        let scan = run_files_holding(&run, &rules_for(&run, &[]), key);
        assert!(!scan.complete());
        assert!(
            scan.unread
                .iter()
                .any(|entry| entry.contains("not scanned: a file with more than one name")),
            "{:?}",
            scan.unread
        );
        assert!(
            scan.held_by
                .iter()
                .all(|holder| holder.path == "a/b/holds-it"),
            "the file with a second name was not read: {:?}",
            scan.held_by
        );
        // A place of the person's own is read as it was.
        let lenient = files_holding(&run, key);
        assert!(lenient.complete(), "{:?}", lenient.unread);
        assert_eq!(lenient.held_by.len(), 2);
        std::fs::remove_file(run.join("a/second-name")).expect("removed");
        // A symbolic link, to a file and to a directory that hold the key, is read through by
        // nothing; a run's scan counts it as a link the harness did not make, and a place of the
        // person's own, which may hold links, skips it.
        std::os::unix::fs::symlink(elsewhere.join("theirs"), run.join("a/linked-file"))
            .expect("a link");
        std::os::unix::fs::symlink(&elsewhere, run.join("a/linked-directory")).expect("a link");
        let scan = run_files_holding(&run, &rules_for(&run, &[]), key);
        assert!(!scan.complete());
        assert_eq!(
            scan.unread
                .iter()
                .filter(|entry| entry.contains("not scanned: a link the harness did not make"))
                .count(),
            2,
            "{:?}",
            scan.unread
        );
        assert_eq!(scan.held_by.len(), 1, "{:?}", scan.held_by);
        let lenient = files_holding(&run, key);
        assert!(lenient.complete(), "{:?}", lenient.unread);
        assert_eq!(lenient.held_by.len(), 1, "{:?}", lenient.held_by);
    }

    /// The links the harness makes in a run, the one to the installed build and the ones to its
    /// runtimes, are skipped by name and place; a link anywhere else, or a link named like one of
    /// them in another place, is counted as a link the harness did not make.
    #[test]
    fn a_run_s_scan_skips_the_links_the_harness_makes_and_counts_every_other_link() {
        let scratch = Scratch::new("scan-links");
        let run = scratch.0.join("run");
        let elsewhere = scratch.0.join("elsewhere");
        std::fs::create_dir_all(run.join("agent/runtime")).expect("a run");
        std::fs::create_dir_all(run.join("other/agent")).expect("a run");
        std::fs::create_dir_all(elsewhere.join("build")).expect("outside");
        let key = b"the-key-value-0123456789";
        std::fs::write(elsewhere.join("build/theirs"), key).expect("a file that holds the key");
        std::fs::write(run.join("own"), b"nothing to find here").expect("a clean file");
        let link = |target: &Path, place: &str| {
            std::os::unix::fs::symlink(target, run.join(place)).expect("a link");
        };
        link(&elsewhere.join("build"), "agent/current");
        link(&elsewhere.join("build/theirs"), "agent/runtime/node");
        // What the harness makes: the scan is whole and reads through neither.
        let rules = rules_for(&run, &["agent/current", "agent/runtime/node"]);
        let scan = run_files_holding(&run, &rules, key);
        assert!(scan.complete(), "{:?}", scan.unread);
        assert!(scan.held_by.is_empty(), "{:?}", scan.held_by);
        // Every other link is counted, whatever it points at and whatever it is called.
        for place in [
            "agent/other",
            "agent/runtime/unlisted",
            "agent/current-next",
            "agent/runtime/inner/deeper",
            "other/agent/current",
            "linked",
        ] {
            if let Some(parent) = Path::new(place).parent() {
                std::fs::create_dir_all(run.join(parent)).expect("a directory");
            }
            link(&elsewhere.join("build"), place);
            let scan = run_files_holding(&run, &rules, key);
            assert!(!scan.complete(), "{place}");
            assert_eq!(
                scan.unread
                    .iter()
                    .filter(|entry| entry.contains("not scanned: a link the harness did not make"))
                    .count(),
                1,
                "{place}: {:?}",
                scan.unread
            );
            assert!(scan.held_by.is_empty(), "{place}: {:?}", scan.held_by);
            std::fs::remove_file(run.join(place)).expect("removed");
        }
    }

    /// The root of a run's scan is opened as the record's root is, with no link followed at its last
    /// component, and a root that is a file is read through the handle that was checked, with its
    /// link count; a place of the person's own is read as it was.
    #[test]
    fn a_run_s_scan_follows_no_link_at_its_root_and_reads_a_file_root_with_one_name() {
        let scratch = Scratch::new("scan-root");
        let elsewhere = scratch.0.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("inner")).expect("outside");
        let key = b"the-key-value-0123456789";
        std::fs::write(elsewhere.join("inner/theirs"), key).expect("a file that holds the key");
        // The root is a link to a directory that holds the key.
        let linked = scratch.0.join("linked-run");
        std::os::unix::fs::symlink(&elsewhere, &linked).expect("a link");
        let scan = run_files_holding(&linked, &rules_for(&linked, &[]), key);
        assert!(!scan.complete());
        assert!(scan.held_by.is_empty(), "{:?}", scan.held_by);
        let lenient = files_holding(&linked, key);
        assert!(lenient.complete(), "{:?}", lenient.unread);
        assert_eq!(lenient.held_by.len(), 1);
        // The root is a link to a file that holds the key.
        let linked_file = scratch.0.join("linked-file");
        std::os::unix::fs::symlink(elsewhere.join("inner/theirs"), &linked_file).expect("a link");
        let scan = run_files_holding(&linked_file, &rules_for(&linked_file, &[]), key);
        assert!(!scan.complete());
        assert!(scan.held_by.is_empty(), "{:?}", scan.held_by);
        // The root is a file of any kind: in a run's scan it is no directory the run made, so it is
        // refused as a changed root and not read, whatever its name count; in the scan of a place of
        // the person's own it is read through its checked handle, a second name included, and named
        // by its own name.
        let own = scratch.0.join("own-file");
        std::fs::write(&own, key).expect("a file");
        let second = scratch.0.join("second-name");
        std::fs::hard_link(elsewhere.join("inner/theirs"), &second).expect("a hard link");
        for file in [&own, &second] {
            let scan = run_files_holding(file, &rules_for(file, &[]), key);
            assert!(scan.root_changed && !scan.complete(), "{:?}", scan.unread);
            assert!(scan.held_by.is_empty(), "{:?}", scan.held_by);
        }
        let lenient = files_holding(&own, key);
        assert!(lenient.complete(), "{:?}", lenient.unread);
        assert_eq!(
            lenient
                .held_by
                .iter()
                .map(|holder| holder.path.as_str())
                .collect::<Vec<_>>(),
            vec!["own-file"]
        );
        let lenient = files_holding(&second, key);
        assert!(lenient.complete(), "{:?}", lenient.unread);
        assert_eq!(lenient.held_by.len(), 1);
    }

    /// The helper links the pinned build makes in its own home are skipped only when they are in
    /// the place and under the names it makes them, and say the pinned executable in the run's own
    /// installation; every other link is counted.
    #[test]
    fn a_run_s_scan_skips_only_the_helper_links_the_pinned_build_makes_in_its_home_to_itself() {
        let scratch = Scratch::new("scan-agent-links");
        let run = scratch.0.join("run");
        let pinned = scratch.0.join("pinned-codex");
        let other = scratch.0.join("other-file");
        std::fs::write(&pinned, b"the pinned executable").expect("a file");
        std::fs::write(&other, b"another file").expect("a file");
        let current = run.join("agent/current/bin/codex");
        let key = b"the-key-value-0123456789";
        let rules = |run: &Path| {
            rules_for(run, &[])
                .with_agent_links("agent-config", vec![current.clone(), pinned.clone()])
        };
        let link = |target: &Path, place: &str| {
            let path = run.join(place);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            std::os::unix::fs::symlink(target, path).expect("a link");
        };
        std::fs::create_dir_all(&run).expect("a run");
        // What the build makes, naming itself by the path the run starts it by and by its own.
        for (name, target) in [
            ("apply_patch", &pinned),
            ("applypatch", &current),
            ("codex-execve-wrapper", &pinned),
        ] {
            link(
                target,
                &format!("agent-config/tmp/arg0/codex-arg0abc123/{name}"),
            );
        }
        let scan = run_files_holding(&run, &rules(&run), key);
        assert!(scan.complete(), "{:?}", scan.unread);
        // Anything else is counted: another name, another text, another place, another folder name,
        // another depth, another home.
        for (place, target) in [
            (
                "agent-config/tmp/arg0/codex-arg0abc123/other-helper",
                &pinned,
            ),
            ("agent-config/tmp/arg0/codex-arg0def456/apply_patch", &other),
            (
                "agent-config/tmp/other/codex-arg0abc123/apply_patch",
                &pinned,
            ),
            ("agent-config/tmp/arg0/not-arg0/apply_patch", &pinned),
            (
                "agent-config/tmp/arg0/codex-arg0abc123/inner/apply_patch",
                &pinned,
            ),
            ("other-home/tmp/arg0/codex-arg0abc123/apply_patch", &pinned),
        ] {
            link(target, place);
            let scan = run_files_holding(&run, &rules(&run), key);
            assert_eq!(
                scan.unread
                    .iter()
                    .filter(|entry| entry.contains("not scanned: a link the harness did not make"))
                    .count(),
                1,
                "{place}: {:?}",
                scan.unread
            );
            std::fs::remove_file(run.join(place)).expect("removed");
        }
    }

    /// A file, or a directory with files in it, that is not beneath the run's directory (it was moved
    /// out, or into a directory that was) is not read, whatever the walk was given.
    #[test]
    fn the_scan_reads_nothing_that_is_no_longer_beneath_the_run() {
        use rustix::fs::{AtFlags, Mode, OFlags};
        let scratch = Scratch::new("scan-beneath");
        let run = scratch.0.join("run");
        let outside = scratch.0.join("outside");
        std::fs::create_dir_all(&run).expect("a run");
        std::fs::create_dir_all(outside.join("inner")).expect("outside");
        let key = b"the-key-value-0123456789";
        std::fs::write(outside.join("theirs"), key).expect("a file");
        std::fs::write(outside.join("inner/theirs"), key).expect("a file");
        let rules = rules_for(&run, &[]);
        let finders = [memchr::memmem::Finder::new(key.as_slice())];
        let holds = |bytes: &[u8]| finders.iter().any(|finder| finder.find(bytes).is_some());
        let mut scan = KeyScan::default();
        let path = outside.join("theirs");
        let looked =
            rustix::fs::statat(rustix::fs::CWD, &path, AtFlags::SYMLINK_NOFOLLOW).expect("a look");
        scan_file(
            rustix::fs::CWD,
            path.as_path(),
            &looked,
            "theirs",
            Some(&rules),
            &holds,
            &mut scan,
        );
        let directory = rustix::fs::open(
            &outside,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("a directory outside the run");
        let stat = rustix::fs::fstat(&directory).expect("a look");
        scan_directory(&directory, &stat, "", 1, Some(&rules), &holds, &mut scan);
        assert!(scan.held_by.is_empty(), "{:?}", scan.held_by);
        // The subdirectory is refused as itself, before anything in it is looked at, and each file
        // met directly in the outside directory is refused.
        assert_eq!(scan.unread.len(), 3, "{:?}", scan.unread);
        assert!(
            scan.unread
                .iter()
                .any(|entry| entry.starts_with("inner:") && entry.contains("moved out")),
            "{:?}",
            scan.unread
        );
    }

    /// A volume attached below the scan's root (a disk image, a network view) is another file
    /// system, and the files on it have one name: it is told as not scanned and nothing on it is
    /// read, in a run's scan and in the scan of a place of the person's own.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_scan_does_not_cross_into_a_file_system_mounted_below_its_root() {
        use kr_ipc::testing::volumes::{Volume, not_attachable};
        let scratch = Scratch::new("scan-mounted");
        let run = scratch.0.join("run");
        let images = scratch.0.join("images");
        std::fs::create_dir_all(run.join("a/mounted")).expect("a run");
        std::fs::create_dir_all(&images).expect("images");
        let key = b"the-key-value-0123456789";
        std::fs::write(run.join("a/own"), key).expect("a file of the run's own that holds the key");
        let volume = Volume::attach(&run.join("a/mounted"), &images, "scan")
            .unwrap_or_else(|| not_attachable());
        std::fs::write(run.join("a/mounted/theirs"), key)
            .expect("a file with one name, on the volume, that holds the key");
        let scans = [
            run_files_holding(&run, &rules_for(&run, &[]), key),
            files_holding(&run, key),
        ];
        volume.detach();
        for scan in scans {
            assert!(!scan.complete());
            assert!(
                scan.unread
                    .iter()
                    .any(|entry| entry.contains("not scanned: another file system")),
                "{:?}",
                scan.unread
            );
            assert_eq!(
                scan.held_by
                    .iter()
                    .map(|holder| holder.path.as_str())
                    .collect::<Vec<_>>(),
                vec!["a/own"],
                "nothing on the volume was read"
            );
        }
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
            charged: std::sync::Arc::default(),
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
    fn what_the_upkeep_rewrote_is_listed_by_path_with_size_time_and_digest_and_no_content() {
        let scratch = Scratch::new("upkeep");
        let home = &scratch.0;
        let data = home.join(".agent");
        std::fs::create_dir_all(data.join("cache")).expect("the cache");
        std::fs::create_dir_all(data.join("index")).expect("the index");
        std::fs::write(data.join("list.json"), "{\"a\":1}").expect("the list");
        std::fs::write(data.join("cache").join("one"), "first").expect("a cache file");
        std::fs::write(data.join("cache").join("two"), "second").expect("a cache file");
        let directories = vec![".agent".to_owned()];
        let before = snapshot(home, &directories, 1 << 20);
        std::fs::write(data.join("list.json"), "{\"a\":1,\"b\":2}").expect("a rewrite");
        std::fs::write(data.join("cache").join("one"), "FIRST!").expect("a rewrite");
        std::fs::write(data.join("cache").join("three"), "third").expect("a new file");
        let after = snapshot(home, &directories, 1 << 20);
        let found = changes(&before, &after);
        let listed = ["list.json", "cache", "index"].map(str::to_owned);
        let (published, private) = reported_rewrites(&data, &listed, (&before, &after), &found);
        assert_eq!(published.len(), 3, "each listed path has an entry");
        assert_eq!(published[0]["path"], "list.json");
        assert_eq!(published[0]["rewritten"], 1);
        assert_eq!(published[0]["bytes"], 13);
        assert!(published[0]["modified_ms"].is_i64());
        assert_eq!(published[0]["sha256"].as_str().map(str::len), Some(64));
        assert_eq!(published[1]["path"], "cache");
        assert_eq!(published[1]["rewritten"], 1);
        assert_eq!(published[1]["created"], 1);
        assert_eq!(published[2]["rewritten"], 0);
        assert!(published[2]["sha256"].is_null() && published[2]["modified_ms"].is_null());
        assert_eq!(private.len(), 2);
        let text = serde_json::to_string(&published).expect("JSON");
        assert!(
            !text.contains("FIRST") && !text.contains("\"b\""),
            "no content in what is published"
        );
        assert_eq!(private[0]["file"], "list.json");
        assert_eq!(private[1]["file"], "cache/one");
        assert_eq!(private[1]["bytes_before"], 5);
        assert_eq!(private[1]["bytes_after"], 6);
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
        let (removed, left) =
            remove_created(&before, &found, &["kr0123"], std::slice::from_ref(&agent));
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
        assert_eq!(
            before.unread_by_root(),
            vec![(agent.clone(), 1)],
            "counted under the root that holds it, which names no entry"
        );
        let text = |path: &Path| path.display().to_string();
        assert_eq!(
            before.count_by_root([
                text(&agent).as_str(),
                text(&agent.join("a")).as_str(),
                format!("{}: why", text(&agent)).as_str(),
                text(&home.join(".agentx").join("b")).as_str(),
                text(&home.join(".absent").join("c")).as_str(),
            ]),
            vec![(agent.clone(), 3), (home.join(".absent"), 1)],
            "a root itself, what it holds and a root followed by why count under it; a sibling \
             whose name only begins like it does not"
        );
        let unnamed = {
            use std::os::unix::ffi::OsStrExt;
            agent.join(std::ffi::OsStr::from_bytes(b"not \xff utf-8"))
        };
        assert_eq!(
            before.count_paths_by_root([
                agent.as_path(),
                unnamed.as_path(),
                home.join(".agentx").join("b").as_path(),
            ]),
            vec![(Some(agent.clone()), 2), (None, 1)],
            "paths count whatever bytes their names hold, and one under no root is counted too"
        );
        std::fs::write(closed.join("history"), "the person's kr0123").expect("an edit");
        std::fs::write(agent.join("ours"), "kr0123").expect("a marked file");
        let after = snapshot(home, &directories, 1 << 20);
        assert!(
            after.whole(),
            "a root that does not exist is not an unread entry"
        );
        let found = changes(&before, &after);
        let (removed, left) =
            remove_created(&before, &found, &["kr0123"], std::slice::from_ref(&agent));
        assert!(
            removed.is_empty(),
            "nothing is removed after a snapshot that is not whole"
        );
        assert_eq!(left.len(), found.created.len());
        assert!(closed.join("history").exists() && agent.join("ours").exists());
    }

    #[test]
    fn a_directory_read_for_its_own_files_lists_them_and_prunes_nothing_beneath_it() {
        let scratch = Scratch::new("shallow");
        let home = &scratch.0;
        let agent = home.join(".agent");
        let day = agent.join("sessions").join("2026").join("09").join("27");
        std::fs::create_dir_all(&day).expect("a day's directory");
        std::fs::write(agent.join("history.jsonl"), "old\n").expect("a history");
        std::fs::write(day.join("old.jsonl"), "old").expect("an old conversation");
        let earlier = agent.join("sessions").join("2026").join("09").join("26");
        std::fs::create_dir_all(&earlier).expect("an earlier day's directory");
        std::fs::write(earlier.join("older.jsonl"), "older").expect("an older conversation");
        let directories = vec![
            ".agent/*".to_owned(),
            ".agent/sessions/2026/09/27".to_owned(),
            ".agent/sessions/2026/09/28".to_owned(),
        ];
        let before = snapshot(home, &directories, 1 << 20);
        assert!(before.whole());
        assert!(
            before.files.contains_key(&agent.join("history.jsonl"))
                && before.files.contains_key(&day.join("old.jsonl"))
                && !before.files.contains_key(&earlier.join("older.jsonl")),
            "a directory read for its own files lists them and not what lies beneath it, which a root \
             of its own lists"
        );
        let next = agent.join("sessions").join("2026").join("09").join("28");
        std::fs::create_dir_all(&next).expect("the next day's directory");
        std::fs::write(next.join("ours.jsonl"), "prompt kr0123").expect("ours after midnight");
        std::fs::write(day.join("ours.jsonl"), "prompt kr0123").expect("ours");
        std::fs::write(agent.join("state.sqlite"), "kr0123 and theirs").expect("a new database");
        std::fs::write(agent.join("history.jsonl"), "old\nkr0123\n").expect("an appended line");
        let beneath = agent.join("cache").join("fresh");
        std::fs::create_dir_all(&beneath).expect("a directory the listing does not read");
        std::fs::write(beneath.join("x"), "kr0123").expect("a file it does not see");
        let after = snapshot(home, &directories, 1 << 20);
        let found = changes(&before, &after);
        assert_eq!(found.appended, vec![agent.join("history.jsonl")]);
        let (removed, left) =
            remove_created(&before, &found, &["kr0123"], &[day.clone(), next.clone()]);
        assert!(!day.join("ours.jsonl").exists() && day.join("old.jsonl").exists());
        assert!(
            !next.exists(),
            "the next day's directory, which the part made, goes once empty"
        );
        assert!(
            agent.join("sessions").join("2026").join("09").is_dir(),
            "a directory beneath the one read for its own files stays"
        );
        assert!(
            agent.join("state.sqlite").exists() && !removed.contains(&agent.join("state.sqlite")),
            "a file the part made outside the directories whose files are its own stays, marked \
             or not, since it can hold the person's own data beside the part's"
        );
        assert_eq!(left, vec![agent.join("state.sqlite")]);
        assert!(
            beneath.join("x").exists(),
            "what the listing did not see is not touched"
        );
    }

    #[test]
    fn appended_lines_are_those_after_every_earlier_byte_and_none_where_one_changed_or_went() {
        let lines = |before: Option<&str>, now: Option<&str>| {
            appended_since(before.map(str::as_bytes), now.map(str::as_bytes)).map(|lines| {
                lines
                    .iter()
                    .map(|line| String::from_utf8_lossy(line).into_owned())
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(lines(None, None), Some(vec![]));
        assert_eq!(
            lines(None, Some("a\nb\n")),
            Some(vec!["a\n".to_owned(), "b\n".to_owned()]),
            "a file that was not there holds only appended lines"
        );
        assert_eq!(lines(Some("a\n"), None), None, "a file that went");
        assert_eq!(lines(Some("a\nb\n"), Some("a\nb\n")), Some(vec![]));
        assert_eq!(
            lines(Some("a\nb\n"), Some("a\nb\nc\nd")),
            Some(vec!["c\n".to_owned(), "d".to_owned()]),
            "the last appended line may still lack its end"
        );
        assert_eq!(
            lines(Some("a\nb"), Some("a\nb more\nc\n")),
            Some(vec!["c\n".to_owned()]),
            "a line the earlier bytes ended part way through stays an earlier line"
        );
        assert_eq!(
            lines(Some("a\nb\n"), Some("a\nB\nc\n")),
            None,
            "an earlier line changed"
        );
        assert_eq!(
            lines(Some("a\nb\n"), Some("b\nc\n")),
            None,
            "an earlier line went"
        );
        assert_eq!(lines(Some("a\nb\n"), Some("a\n")), None, "the file shrank");
    }

    #[test]
    fn an_appended_line_names_its_conversation_and_time_as_an_index_or_a_history_line_does() {
        assert_eq!(
            line_identity(
                br#"{"id":"01a0e3de-f28d-78b3-a902-158410b19f5b","thread_name":"x","updated_at":"2026-09-27T17:17:55Z"}"#
            ),
            (
                Some("01a0e3de-f28d-78b3-a902-158410b19f5b".to_owned()),
                Some(json!("2026-09-27T17:17:55Z"))
            )
        );
        assert_eq!(
            line_identity(b"{\"session_id\":\"s1\",\"ts\":1790529467,\"text\":\"kr0123\"}\n"),
            (Some("s1".to_owned()), Some(json!(1_790_529_467)))
        );
        assert_eq!(line_identity(b"not json\n"), (None, None));
        assert_eq!(line_identity(b"[1,2]\n"), (None, None));
        assert_eq!(
            line_identity(
                br#"{"id":"c1","updated_at":{"text":"something private"},"ts":["more"]}"#
            ),
            (Some("c1".to_owned()), None),
            "a time that is an object or a list is not kept, nor a later key in its place"
        );
        assert_eq!(
            line_identity(
                br#"{"id":"private words here","updated_at":"2026-09-27 and more words"}"#
            ),
            (None, None),
            "text in the place of an identifier or a time that is not shaped as one is not kept"
        );
        assert_eq!(
            line_identity(br#"{"session_id":"s3","ts":["something private"]}"#),
            (Some("s3".to_owned()), None),
            "a time that is a list is not kept"
        );
        assert_eq!(
            line_identity(br#"{"session_id":"s4","ts":true}"#),
            (Some("s4".to_owned()), None),
            "a time that is neither a number nor text is not kept"
        );
        assert_eq!(
            line_identity(br#"{"id":{"a":1},"session_id":"s2","ts":1.5}"#),
            (None, Some(json!(1.5))),
            "an identifier that is not text is not kept, nor a later key in its place"
        );
    }

    #[test]
    fn only_the_part_s_own_appended_lines_are_removed_in_place_and_earlier_lines_must_hold() {
        let scratch = Scratch::new("lines");
        let path = scratch.0.join("history.jsonl");
        let before = "one kr0123\ntwo\n";
        std::fs::write(
            &path,
            format!("{before}kr0123 three\nfour\n/run/x five\nkr0123 six"),
        )
        .expect("a line file");
        let inode = std::fs::metadata(&path).expect("its metadata").ino();
        assert_eq!(
            remove_appended_lines(&path, Some(before.as_bytes()), &["kr0123", "/run/x"]),
            Ok(3)
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("the file"),
            "one kr0123\ntwo\nfour\n",
            "an earlier line stays even where it holds the mark, and someone else's appended line stays"
        );
        assert_eq!(
            std::fs::metadata(&path).expect("its metadata").ino(),
            inode,
            "the file is written in place"
        );
        let modified = std::fs::metadata(&path)
            .expect("its metadata")
            .modified()
            .ok();
        let now = std::fs::read(&path).expect("the file");
        assert_eq!(remove_appended_lines(&path, Some(&now), &["kr0123"]), Ok(0));
        assert_eq!(
            std::fs::metadata(&path)
                .expect("its metadata")
                .modified()
                .ok(),
            modified,
            "a file without the part's lines is not written"
        );
        assert!(
            remove_appended_lines(&path, Some(b"one kr0123\nTWO\n"), &["kr0123"])
                .is_err_and(|why| why.contains("changed or went")),
            "an earlier line that changed is an error, and nothing is written"
        );
        assert_eq!(std::fs::read(&path).expect("the file"), now);
        assert_eq!(
            remove_appended_lines(&scratch.0.join("none"), None, &["kr0123"]),
            Ok(0)
        );
        assert!(
            remove_appended_lines(&scratch.0.join("none"), Some(b"x\n"), &["kr0123"]).is_err(),
            "a file that went is an error"
        );
    }

    #[test]
    fn a_search_in_pieces_finds_a_needle_across_a_piece_boundary() {
        let scratch = Scratch::new("hold");
        let across = scratch.0.join("across");
        let mut bytes = vec![b'x'; (1 << 20) - 3];
        bytes.extend_from_slice(b"kr0123");
        bytes.extend_from_slice(&[b'y'; 10]);
        std::fs::write(&across, &bytes).expect("a large file");
        let without = scratch.0.join("without");
        std::fs::write(&without, vec![b'z'; 3 << 20]).expect("a file without it");
        let (holding, unread) = which_hold(
            &[across.clone(), without, scratch.0.join("gone")],
            &["kr0123", "/run/root"],
        );
        assert_eq!(holding, vec![across]);
        assert!(unread.is_empty(), "{unread:?}");
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
        assert_eq!(
            conversation_id(Path::new(&format!(
                "/p/sessions/wd_w_0123456789ab/session_{uuid}/agents/main/wire.jsonl"
            ))),
            format!("session_{uuid}"),
            "a conversation kept in a session directory of its own is named by the directory"
        );
    }
}
