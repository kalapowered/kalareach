//! H's watch on the clock floor. When the agent starts the host maps the floor, keeps the mapping
//! to ask whether the floor's name still names the file it mapped, and keeps a descriptor of the
//! file. At each kill the words are compared with those at the start, and before the attempt with
//! those at the kill. Every byte is read through the descriptor and none through the mapping,
//! which a truncation by the agent would end in a signal: a file shorter than the floor is refused
//! first, and each moving word is read by an aligned read of eight bytes, in the order owed,
//! recorded, floor, twice, and accepted when the two reads are equal. Two equal reads show no
//! tear; a write between them that restores the value, or a tear that repeats, is not seen. The
//! check refuses and never passes: a word moved forward inside the limit is not seen, which is the
//! stated residual.
//!
//! The floor's open once more, before the attempt, maps no file in this program: the floor's bytes
//! are read through the descriptor, written to a file in a directory of the harness's own, and the
//! product's open runs on that file in a program of its own, `kr-e2e-m1b-floor-open`, whose end is
//! read. The host places that program in the run's `b/` with the others before it records the
//! run's tree, and starts it with an empty environment, only while it is the file that was placed.
//! An agent that finds the file can cut it, which ends that program with a signal that the
//! harness reads as a refusal, or replace it after the directory is checked, which can make the
//! product open another regular file that the agent names, of the floor's length, of the account
//! and closed to others; the open writes nothing. The program is not bounded in time, because its
//! open ends for every file the agent can put there: it opens with `O_NONBLOCK` before it looks at
//! the file's type (`crates/kr-ipc/src/floor.rs:607`), refuses a file that is not a regular one
//! (`:626`), and maps a file of the floor's length (`:641`, `:653`). A regular file on a filesystem
//! that has stopped answering is not covered.

use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use kr_ipc::clock::{SharedClock as _, SystemSharedClock};
use kr_ipc::floor::{FLOOR_FILE_LEN, SharedFloor};
use kr_protocol::ids::{BootEpoch, EnvironmentId};

use rustix::fs::{AtFlags, Mode, OFlags};

use crate::run::{
    Removal, RootPin, make_root, open_directory, open_file_below, remove_run_directory, run_base,
};

/// How far above what H's own readings allow a floor word that rose may stand, in milliseconds.
pub const ALLOWANCE_MS: u64 = 60_000;

/// Where the floor word stands in the file.
const FLOOR_AT: u64 = 64;

/// Where the owed word stands in the file.
const OWED_AT: u64 = 72;

/// Where the recorded word stands in the file.
const RECORDED_AT: u64 = 80;

/// How many times a word is read again while two reads differ, before the look says that the word
/// does not stand still.
const READ_TRIES: usize = 5;

/// Where the floor's words begin: the header and the bytes up to here are fixed.
const WORDS_FROM: usize = 64;

/// Where the floor's words end: every byte from here on is fixed.
const WORDS_TO: usize = 104;

/// The two establishment words, which the live daemon writes.
const ESTABLISHMENT: std::ops::Range<usize> = 88..104;

/// The most bytes of the floor's file H reads: the file is 4,096 bytes, so a larger one is read
/// only as far as to say that it changed.
const READ_AT_MOST: u64 = 1 << 20;

/// The wall clock and the continuous clock, read together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Readings {
    /// The wall clock, in milliseconds since the epoch.
    pub wall_ms: u64,
    /// The continuous clock, in milliseconds.
    pub boot_ms: u64,
}

impl Readings {
    /// The two clocks now: the wall clock and the system's continuous clock.
    #[must_use]
    pub fn now() -> Self {
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        Self {
            wall_ms,
            boot_ms: SystemSharedClock.boot_elapsed_ms(),
        }
    }
}

/// What a look at the floor found.
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    owed: u64,
    recorded: u64,
    floor: u64,
    /// The header, the bytes up to the first word and every byte after the words.
    fixed: Vec<u8>,
    /// The two establishment words as they stand in the file.
    establishment: Vec<u8>,
}

/// Where the floor is: the run's directory and its pin, the floor's place below the directory, and
/// its path.
#[derive(Clone, Copy, Debug)]
pub struct Opening<'a> {
    /// The run's directory.
    pub root: &'a Path,
    /// The directory `root` was pinned as.
    pub pin: &'a RootPin,
    /// The floor's place below `root`.
    pub relative: &'a Path,
    /// The floor's path.
    pub path: &'a Path,
}

/// H's watch on the floor of one run.
#[derive(Debug)]
pub struct Watch {
    mapping: SharedFloor,
    file: File,
    at_the_start: State,
    start: Readings,
    anchor: Readings,
    greatest_wall: u64,
    at_the_kill: Option<State>,
    scratch: Scratch,
}

/// The directory of the harness's own in which the floor's bytes are written for the product's open
/// once more: made before the agent starts, pinned, owner-only and empty, and removed with the watch.
#[derive(Debug)]
struct Scratch {
    root: PathBuf,
    pin: RootPin,
}

impl Scratch {
    /// The file in the directory that holds `bytes`, made by exclusive creation through the
    /// directory's handle, for `open` to open by its path; it is removed after, whatever `open`
    /// returns.
    fn with<T>(
        &self,
        bytes: &[u8],
        open: impl FnOnce(&Path) -> Result<T, String>,
    ) -> Result<T, String> {
        let directory = open_directory(&self.root)
            .map_err(|why| format!("the directory of the floor's copy cannot be opened: {why}"))?;
        if !self.pin.holds(&directory) {
            return Err(
                "the directory of the floor's copy is not the directory the harness made"
                    .to_owned(),
            );
        }
        let made = rustix::fs::openat(
            &directory,
            COPY,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|why| format!("the floor's copy is not made: {why}"))?;
        let opened = File::from(made)
            .write_all(bytes)
            .map_err(|why| format!("the floor's copy is not written: {why}"))
            .and_then(|()| open(&self.root.join(COPY)));
        let removed = rustix::fs::unlinkat(&directory, COPY, AtFlags::empty())
            .map_err(|why| format!("the floor's copy is not removed: {why}"));
        opened.and_then(|opened| removed.map(|()| opened))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Removal::Left(why) = remove_run_directory(&self.root, &self.pin) {
            eprintln!("the directory of the floor's copy is left in place: {why}");
        }
    }
}

/// The name of the floor's copy in its directory.
const COPY: &str = "floor";

impl Watch {
    /// Opens the floor at `path` as the daemon does and keeps the mapping, opens the file at
    /// `relative` below the run's directory `root` through the run's handles, and reads what the
    /// floor holds. `anchor` is H's own pair of readings taken before the daemon's first start,
    /// `now` the pair read with this look.
    ///
    /// # Errors
    ///
    /// Returns why the floor cannot be read, or holds a word above its floor word, saying so.
    pub fn at_the_start(
        opening: Opening<'_>,
        environment: EnvironmentId,
        boot: BootEpoch,
        anchor: Readings,
        now: Readings,
    ) -> Result<Self, String> {
        let Opening {
            root,
            pin,
            relative,
            path,
        } = opening;
        let said = |why: &dyn std::fmt::Display| {
            format!("the clock floor cannot be read at the start: {why}")
        };
        let mapping = SharedFloor::open(path, environment, boot).map_err(|why| said(&why))?;
        let file = open_file_below(root, pin, relative)
            .map_err(|why| said(&why))?
            .map(File::from)
            .ok_or_else(|| said(&"it is not there"))?;
        let at_the_start = look(&file).map_err(|why| said(&why))?;
        let (scratch_root, scratch_pin) = make_root(
            &run_base(),
            &mut || kr_ipc::new_uuid().to_string(),
            &mut |_| {},
        )
        .map_err(|why| said(&format_args!("the directory for the floor's copy: {why}")))?;
        let scratch = Scratch {
            root: scratch_root,
            pin: scratch_pin,
        };
        for (word, value) in [
            ("owed", at_the_start.owed),
            ("recorded", at_the_start.recorded),
        ] {
            if value > at_the_start.floor {
                return Err(format!(
                    "the clock floor holds {word} {value}, above its floor word {}, at the start",
                    at_the_start.floor
                ));
            }
        }
        Ok(Self {
            mapping,
            file,
            at_the_start,
            start: now,
            anchor,
            greatest_wall: anchor.wall_ms.max(now.wall_ms),
            at_the_kill: None,
            scratch,
        })
    }

    /// At a kill: the floor now against what it held at the start. The daemon ran until the kill, so
    /// its words may have moved, and the establishment words are not looked at; they are read as the
    /// record the attempt compares with.
    pub fn at_the_kill(&mut self, now: Readings) -> Vec<String> {
        let before = self.at_the_start.clone();
        let (refused, found) = self.compare(now, &before, false);
        self.at_the_kill = found;
        refused
    }

    /// Before the attempt: the floor now against what it held at the kill. No daemon runs, so only
    /// the worker's words, owed and the floor, may have risen.
    pub fn before_the_attempt(&mut self, now: Readings) -> Vec<String> {
        let Some(before) = self.at_the_kill.clone() else {
            return vec!["the clock floor cannot be read: it was not read at the kill".to_owned()];
        };
        self.compare(now, &before, true).0
    }

    /// Opens the floor once more as the daemon does, and requires that its name still names the
    /// file held since the start. The file held is read through its descriptor, shown to be a
    /// regular file of the account that no other user can read or write, of the floor's length, and
    /// the product's open runs on a copy of its bytes in the harness's own directory, in the
    /// program at `program`, which the caller has shown to be the file that was placed: this
    /// program maps no file.
    ///
    /// # Errors
    ///
    /// Returns why the open fails, including that the program that ran it was ended by a signal,
    /// or that the name no longer names the file held.
    pub fn open_again(&self, program: &Path, environment: EnvironmentId) -> Result<(), String> {
        let said = |why: &dyn std::fmt::Display| {
            format!("the clock floor cannot be opened again before the attempt: {why}")
        };
        if !self.mapping.named() {
            return Err(said(
                &"its name no longer names the file held since the start",
            ));
        }
        let bytes = held_bytes(&self.file).map_err(|why| said(&why))?;
        self.scratch
            .with(&bytes, |copy| product_opens(program, copy, environment))
            .map_err(|why| said(&why))
    }

    /// The limit on a floor word that rose: the greatest of H's greatest wall reading, the anchor's
    /// wall reading with the continuous time since the anchor, and the floor at the start with the
    /// continuous time since the start, and the allowance above it.
    #[must_use]
    pub fn limit(&self, now: Readings) -> u64 {
        let since = |from: Readings| now.boot_ms.saturating_sub(from.boot_ms);
        self.greatest_wall
            .max(self.anchor.wall_ms.saturating_add(since(self.anchor)))
            .max(self.at_the_start.floor.saturating_add(since(self.start)))
            .saturating_add(ALLOWANCE_MS)
    }

    fn compare(
        &mut self,
        now: Readings,
        before: &State,
        attempt: bool,
    ) -> (Vec<String>, Option<State>) {
        self.greatest_wall = self.greatest_wall.max(now.wall_ms);
        let found = match look(&self.file) {
            Ok(found) => found,
            Err(why) => return (vec![format!("the clock floor cannot be read: {why}")], None),
        };
        let mut refused = Vec::new();
        if !self.mapping.named() {
            refused.push(
                "the clock floor's name no longer names the file that was mapped when the agent \
                 started"
                    .to_owned(),
            );
        }
        if found.fixed != before.fixed {
            refused.push("the clock floor's bytes outside its words changed".to_owned());
        }
        let mut words = vec![
            ("owed", before.owed, found.owed),
            ("floor", before.floor, found.floor),
        ];
        if !attempt {
            words.push(("recorded", before.recorded, found.recorded));
        }
        for (word, was, is) in words {
            if is < was {
                refused.push(format!(
                    "the clock floor's {word} word went down, from {was} to {is}"
                ));
            }
        }
        for (word, value) in [("owed", found.owed), ("recorded", found.recorded)] {
            if value > found.floor {
                refused.push(format!(
                    "the clock floor's {word} word is {value}, above its floor word {}",
                    found.floor
                ));
            }
        }
        if found.floor > before.floor {
            let limit = self.limit(now);
            if found.floor > limit {
                refused.push(format!(
                    "the clock floor's floor word is {}, {} ms above the limit {limit}",
                    found.floor,
                    found.floor - limit
                ));
            }
        }
        if attempt {
            if found.recorded != before.recorded {
                refused.push(format!(
                    "the clock floor's recorded word changed between the kill and the attempt, \
                     from {} to {}",
                    before.recorded, found.recorded
                ));
            }
            if found.establishment != before.establishment {
                refused.push(
                    "the clock floor's establishment words changed between the kill and the attempt"
                        .to_owned(),
                );
            }
        }
        (refused, Some(found))
    }
}

/// The name of the program that runs the product's open of the floor, as the host places it in the
/// run's `b/`.
pub(crate) const FLOOR_OPEN: &str = "kr-e2e-m1b-floor-open";

/// Runs `program` with an empty environment on the floor's copy at `copy` for `environment`, and
/// reads how it ended: the open when it exits 0, a refusal with its text when it exits 2, and a
/// refusal that names the signal when a signal ends it, as the cut of the copy by an agent does.
fn product_opens(program: &Path, copy: &Path, environment: EnvironmentId) -> Result<(), String> {
    use std::os::unix::process::ExitStatusExt as _;
    if !program.is_file() {
        return Err(format!(
            "the program that opens the floor is not at {}; build it with `cargo build -p \
             kr-e2e-m1b --features legs --bins`",
            program.display()
        ));
    }
    let output = std::process::Command::new(program)
        .env_clear()
        .arg(copy)
        .arg(environment.to_string())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|why| format!("the program that opens the floor does not start: {why}"))?;
    let said = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    match (output.status.code(), output.status.signal()) {
        (Some(0), _) => Ok(()),
        (Some(2), _) => Err(said),
        (Some(code), _) => Err(format!(
            "the program that opens the floor ended with the code {code}: {said}"
        )),
        (None, Some(signal)) => Err(format!(
            "the product's open of the floor's copy was ended by the signal {signal}, which an \
             agent that cuts the copy while the product maps it can cause"
        )),
        (None, None) => {
            Err("the program that opens the floor ended with no code and no signal".to_owned())
        }
    }
}

/// The bytes of the floor, read through the descriptor of the file held since the start once the
/// file is shown to be what the daemon opens: a regular file of the account, with no permission for
/// any other user, of the floor's length.
fn held_bytes(file: &File) -> Result<Vec<u8>, String> {
    let metadata = file.metadata().map_err(|why| why.to_string())?;
    if !metadata.is_file() {
        return Err("the clock floor file must be a regular file".to_owned());
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err("the clock floor file belongs to another user".to_owned());
    }
    if metadata.mode() & 0o077 != 0 {
        return Err("the clock floor file may be read or written by another user".to_owned());
    }
    if metadata.len() != FLOOR_FILE_LEN as u64 {
        return Err("the clock floor file is not the length this build writes".to_owned());
    }
    let mut bytes = vec![0_u8; FLOOR_FILE_LEN];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|why| format!("the clock floor file cannot be read whole: {why}"))?;
    Ok(bytes)
}

/// Reads the floor through the descriptor and loads nothing from the mapping, so that a truncation
/// while the floor is read ends in an error and not in a signal: the length first, which must be
/// the floor's at least, then the moving words in the order owed, recorded, floor, then the whole
/// file.
fn look(file: &File) -> Result<State, String> {
    let length = file.metadata().map_err(|why| why.to_string())?.len();
    if length < FLOOR_FILE_LEN as u64 {
        return Err(format!(
            "the file is {length} bytes, shorter than the floor's {FLOOR_FILE_LEN}"
        ));
    }
    let owed = word(file, OWED_AT)?;
    let recorded = word(file, RECORDED_AT)?;
    let floor = word(file, FLOOR_AT)?;
    let mut bytes = vec![0_u8; usize::try_from(length.min(READ_AT_MOST)).unwrap_or(0)];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|why| why.to_string())?;
    if length > READ_AT_MOST {
        bytes.extend_from_slice(&length.to_be_bytes());
    }
    let mut fixed = bytes[..WORDS_FROM].to_vec();
    fixed.extend_from_slice(&bytes[WORDS_TO..]);
    Ok(State {
        owed,
        recorded,
        floor,
        fixed,
        establishment: bytes[ESTABLISHMENT].to_vec(),
    })
}

/// One word of the floor, by reads of eight bytes at the aligned offset `at`.
fn word(file: &File, at: u64) -> Result<u64, String> {
    settled(at, || {
        let mut bytes = [0_u8; 8];
        file.read_exact_at(&mut bytes, at)
            .map_err(|why| why.to_string())?;
        Ok(u64::from_ne_bytes(bytes))
    })
}

/// The value that two successive calls of `read` give, at the offset `at`, tried again while they
/// differ, up to [`READ_TRIES`] times.
fn settled(at: u64, mut read: impl FnMut() -> Result<u64, String>) -> Result<u64, String> {
    let mut before = read()?;
    for _ in 0..READ_TRIES {
        let after = read()?;
        if after == before {
            return Ok(after);
        }
        before = after;
    }
    Err(format!(
        "the word at byte {at} did not stand still over {READ_TRIES} reads"
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use kr_ipc::paths::HostPaths;

    use super::*;
    use crate::run::built_directory;

    const ESTABLISHED_AT: u64 = 88;

    /// The floor's opener as this build made it, beside the test program: the cases that have no
    /// run to place it in start it from here.
    fn opener() -> PathBuf {
        built_directory().join(FLOOR_OPEN)
    }

    /// The readings the watch is anchored at, and the same readings a moment later.
    const START: Readings = Readings {
        wall_ms: 1_000_000,
        boot_ms: 5_000,
    };

    fn later(ms: u64) -> Readings {
        Readings {
            wall_ms: START.wall_ms + ms,
            boot_ms: START.boot_ms + ms,
        }
    }

    /// A run's directory with a floor in it, and a second mapping of the floor: the worker's and
    /// the daemon's.
    struct World {
        root: PathBuf,
        pin: RootPin,
        path: PathBuf,
        environment: EnvironmentId,
        boot: BootEpoch,
        other: SharedFloor,
    }

    /// The directory the cases make their runs' directories in.
    fn base() -> PathBuf {
        if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::fs::canonicalize(std::env::temp_dir()).expect("the temporary directory")
        }
    }

    fn world(name: &str, floor_ms: u64) -> World {
        world_at(
            base().join(format!(
                "kf-{name}-{}",
                &kr_ipc::new_uuid().to_string()[..8]
            )),
            floor_ms,
        )
    }

    /// A world whose run's directory is `root`.
    fn world_at(root: PathBuf, floor_ms: u64) -> World {
        for directory in ["r", "s"] {
            std::fs::create_dir_all(root.join(directory)).expect("a root");
            std::fs::set_permissions(root.join(directory), std::fs::Permissions::from_mode(0o700))
                .expect("owner only");
        }
        let paths = HostPaths::new(root.join("r"), root.join("s")).expect("host roots");
        let environment = paths.environment(paths.open_environment_id().expect("an identity"));
        environment.create().expect("the environment's directories");
        let boot = kr_ipc::identity::boot_epoch(
            &kr_ipc::identity::boot_identity().expect("a boot identity"),
        )
        .expect("a boot epoch");
        let path = environment.utc_floor_file();
        SharedFloor::create(&path, environment.environment_id(), boot, floor_ms).expect("a floor");
        let other = SharedFloor::open(&path, environment.environment_id(), boot).expect("a floor");
        World {
            pin: RootPin::of(&root).expect("a pin"),
            root,
            path,
            environment: environment.environment_id(),
            boot,
            other,
        }
    }

    impl World {
        fn watch(&self) -> Watch {
            self.watch_anchored(START, START)
        }

        /// The watch with the anchor and the start's own readings given.
        fn watch_anchored(&self, anchor: Readings, start: Readings) -> Watch {
            Watch::at_the_start(
                Opening {
                    root: &self.root,
                    pin: &self.pin,
                    relative: self.path.strip_prefix(&self.root).expect("below the run"),
                    path: &self.path,
                },
                self.environment,
                self.boot,
                anchor,
                start,
            )
            .expect("a watch")
        }

        /// Writes `bytes` into the floor's file where it is, as a process of the account could.
        fn write_at(&self, at: u64, bytes: &[u8]) {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&self.path)
                .expect("the floor")
                .write_all_at(bytes, at)
                .expect("written in place");
        }

        fn clean(self) {
            drop(self.other);
            std::fs::remove_dir_all(&self.root).expect("clean up");
        }
    }

    /// The environment variable that tells the test program, started again by the case below, that
    /// it is the child and where its directory is.
    const TRUNCATION_CHILD: &str = "KR_FLOOR_TRUNCATION_CHILD";

    /// The child of the case below: it keeps a watch on a floor, truncates the floor's file to
    /// nothing from another thread, and looks at the floor until a look refuses. It says the
    /// refusal, looks once more at the floor, which is truncated by then, says that refusal too,
    /// and removes its directory.
    fn look_while_the_floor_is_truncated(root: PathBuf) {
        let world = world_at(root, 1_000_000);
        let watch = world.watch();
        let path = world.path.clone();
        let refusal = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(30));
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .and_then(|file| file.set_len(0))
                    .expect("the floor is truncated");
            });
            let started = Instant::now();
            loop {
                if let Err(why) = look(&watch.file) {
                    break why;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(20),
                    "no look refused within 20 s of the truncation"
                );
            }
        });
        println!("the look refused: {refusal}");
        let after = look(&watch.file).expect_err("a look at the truncated floor");
        println!("a look after the truncation refused: {after}");
        drop(watch);
        world.clean();
    }

    /// A floor that the agent truncates while H reads it gives a refusal, and the test program
    /// that reads it ends and cleans up as it would otherwise: a load from a mapping of the
    /// truncated file would end it with a signal, and so would a look at a floor that is already
    /// truncated. The case runs itself again as a child to see the end of the program.
    #[test]
    fn a_floor_that_is_truncated_while_it_is_read_gives_a_refusal_and_not_a_signal() {
        if let Ok(root) = std::env::var(TRUNCATION_CHILD) {
            look_while_the_floor_is_truncated(PathBuf::from(root));
            return;
        }
        let root = base().join(format!(
            "kf-truncated-{}",
            &kr_ipc::new_uuid().to_string()[..8]
        ));
        let output = std::process::Command::new(std::env::current_exe().expect("this program"))
            .args([
                "--exact",
                "floor::tests::a_floor_that_is_truncated_while_it_is_read_gives_a_refusal_and_not_a_signal",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(TRUNCATION_CHILD, &root)
            .output()
            .expect("the child ran");
        let said = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the child ended with {:?}, signal {:?}: {said} {}",
            output.status,
            std::os::unix::process::ExitStatusExt::signal(&output.status),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            said.contains("the look refused: "),
            "the child said a refusal: {said}"
        );
        assert!(
            said.contains("a look after the truncation refused: "),
            "the child said the refusal of the look after the truncation: {said}"
        );
        assert!(!root.exists(), "the child removed its directory");
    }

    /// The environment variable that tells the test program, started again by the case below, that
    /// it is the child and where its directory is.
    const OPEN_CHILD: &str = "KR_FLOOR_OPEN_AGAIN_CHILD";

    /// The child of the case below: it keeps a watch on a floor, and a thread truncates the floor's
    /// file to nothing and extends it again, over and over, while the main thread opens the floor
    /// once more over and over for three seconds. It says how often the open passed and how often it
    /// was refused, and removes its directory.
    fn open_again_while_the_floor_is_truncated(root: PathBuf) {
        let world = world_at(root, 1_000_000);
        let watch = world.watch();
        let stop = AtomicBool::new(false);
        let (opened, refused) = std::thread::scope(|scope| {
            scope.spawn(|| {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&world.path)
                    .expect("the floor");
                while !stop.load(Ordering::Relaxed) {
                    file.set_len(0).expect("the floor is truncated");
                    file.set_len(FLOOR_FILE_LEN as u64)
                        .expect("the floor is extended");
                }
            });
            let started = Instant::now();
            let (mut opened, mut refused) = (0_u32, 0_u32);
            while started.elapsed() < Duration::from_secs(3) {
                match watch.open_again(&opener(), world.environment) {
                    Ok(()) => opened += 1,
                    Err(_) => refused += 1,
                }
            }
            stop.store(true, Ordering::Relaxed);
            (opened, refused)
        });
        println!("the floor was opened again {opened} times and refused {refused} times");
        assert!(refused > 0, "the truncation made no open refuse");
        drop(watch);
        world.clean();
    }

    /// A floor that the agent truncates while H opens it once more gives a refusal, and the test
    /// program that opens it ends and cleans up as it would otherwise: a map of the truncated file
    /// that the product reads its header through would end it with a signal. The case runs itself
    /// again as a child to see the end of the program.
    #[test]
    fn a_floor_that_is_truncated_while_it_is_opened_again_gives_a_refusal_and_not_a_signal() {
        if let Ok(root) = std::env::var(OPEN_CHILD) {
            open_again_while_the_floor_is_truncated(PathBuf::from(root));
            return;
        }
        let root = base().join(format!("kf-open-{}", &kr_ipc::new_uuid().to_string()[..8]));
        let output = std::process::Command::new(std::env::current_exe().expect("this program"))
            .args([
                "--exact",
                "floor::tests::a_floor_that_is_truncated_while_it_is_opened_again_gives_a_refusal_and_not_a_signal",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(OPEN_CHILD, &root)
            .output()
            .expect("the child ran");
        let said = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the child ended with {:?}, signal {:?}: {said} {}",
            output.status,
            std::os::unix::process::ExitStatusExt::signal(&output.status),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            said.contains("the floor was opened again "),
            "the child said how often the open passed and was refused: {said}"
        );
        assert!(!root.exists(), "the child removed its directory");
    }

    /// The environment variable that tells the test program, started again by the case below, that
    /// it is the child and where its directory is.
    const COPY_CHILD: &str = "KR_FLOOR_COPY_CHILD";

    /// The child of the case below: a thread cuts the floor's copy to nothing and extends it again,
    /// over and over, wherever the copy stands, while the main thread opens the floor once more
    /// over and over for five seconds. It says how often the open passed, how often it was refused
    /// and how often a signal ended the program that ran the product's open, and removes its
    /// directory.
    fn open_again_while_the_copy_is_cut(root: PathBuf) {
        let world = world_at(root, 1_000_000);
        let watch = world.watch();
        let copy = watch.scratch.root.join(COPY);
        let stop = AtomicBool::new(false);
        let (opened, refused, signalled) = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&copy) {
                        let _ = file.set_len(0);
                        let _ = file.set_len(FLOOR_FILE_LEN as u64);
                    }
                }
            });
            let started = Instant::now();
            let (mut opened, mut refused, mut signalled) = (0_u32, 0_u32, 0_u32);
            while started.elapsed() < Duration::from_secs(5) {
                match watch.open_again(&opener(), world.environment) {
                    Ok(()) => opened += 1,
                    Err(why) if why.contains("was ended by the signal") => signalled += 1,
                    Err(_) => refused += 1,
                }
            }
            stop.store(true, Ordering::Relaxed);
            (opened, refused, signalled)
        });
        println!(
            "the floor was opened again {opened} times, refused {refused} times and refused for a \
             signal {signalled} times"
        );
        drop(watch);
        world.clean();
    }

    /// A copy that the agent cuts to nothing and extends again, over and over, while the product
    /// opens it ends the product's open, which the harness reads as a refusal; it does not end the
    /// test program that asks, which cleans up as it would otherwise. The case runs itself again as
    /// a child to see the end of the program.
    #[test]
    fn a_copy_that_is_cut_while_the_product_opens_it_ends_the_open_and_not_this_program() {
        if let Ok(root) = std::env::var(COPY_CHILD) {
            open_again_while_the_copy_is_cut(PathBuf::from(root));
            return;
        }
        let root = base().join(format!("kf-copy-{}", &kr_ipc::new_uuid().to_string()[..8]));
        let output = std::process::Command::new(std::env::current_exe().expect("this program"))
            .args([
                "--exact",
                "floor::tests::a_copy_that_is_cut_while_the_product_opens_it_ends_the_open_and_not_this_program",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(COPY_CHILD, &root)
            .output()
            .expect("the child ran");
        let said = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the child ended with {:?}, signal {:?}: {said} {}",
            output.status,
            std::os::unix::process::ExitStatusExt::signal(&output.status),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            said.contains("the floor was opened again "),
            "the child said how often the open passed and was refused: {said}"
        );
        assert!(!root.exists(), "the child removed its directory");
    }

    /// The end of the program that runs the product's open is read: an open where it exits 0, its
    /// text where it exits 2, its code where it exits with another, the signal where a signal ends
    /// it, and where the program is not there, how to build it. The program is started with an
    /// empty environment.
    #[test]
    fn the_end_of_the_program_that_opens_the_floor_is_read_as_an_open_or_a_refusal() {
        let world = world("open-ends", 1_000_000);
        let script = |name: &str, body: &str| {
            let path = world.root.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("a script");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("a program");
            path
        };
        // A program written a moment ago is busy while a child that another test starts holds the
        // descriptor it was written through, until that child runs its own program: asked again.
        let ends = |path: &Path| {
            let mut ended = product_opens(path, &world.path, world.environment);
            for _ in 0..100 {
                if !ended
                    .as_ref()
                    .is_err_and(|why| why.contains("Text file busy"))
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
                ended = product_opens(path, &world.path, world.environment);
            }
            ended
        };
        assert_eq!(ends(&script("exits-0", "exit 0")), Ok(()), "exit 0");
        assert_eq!(
            ends(&script(
                "exits-2",
                "echo 'the floor belongs to another boot' >&2; exit 2"
            )),
            Err("the floor belongs to another boot".to_owned()),
            "exit 2"
        );
        let why = ends(&script("exits-3", "echo odd >&2; exit 3")).expect_err("another code");
        assert!(why.contains("ended with the code 3: odd"), "{why}");
        let why = ends(&script("ended-by-a-signal", "kill -BUS $$")).expect_err("a signal");
        assert!(why.contains("was ended by the signal "), "{why}");
        assert_eq!(
            ends(&script(
                "empty-environment",
                "if [ -n \"${HOME:-}\" ]; then echo 'HOME reached the program' >&2; exit 2; fi"
            )),
            Ok(()),
            "the program is started with an empty environment"
        );
        let why = ends(&world.root.join("absent")).expect_err("no program");
        assert!(
            why.contains("is not at") && why.contains("--features legs --bins"),
            "{why}"
        );
        world.clean();
    }

    /// The floor's opener ends at once, with nothing said, when its only argument is `--version`,
    /// which is how the host starts it once, where nothing is timed, when it places the program in
    /// the run; with another argument beside `--version` it is not that start.
    #[test]
    fn the_floor_opener_ends_at_once_when_its_only_argument_is_version() {
        let program = opener();
        let started = |arguments: &[&str]| {
            std::process::Command::new(&program)
                .args(arguments)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("the floor's opener starts")
        };
        let alone = started(&["--version"]);
        assert!(
            alone.status.success() && alone.stderr.is_empty(),
            "--version alone ends the opener with exit 0 and nothing said: {:?} {}",
            alone.status,
            String::from_utf8_lossy(&alone.stderr)
        );
        let beside = started(&["--version", "another"]);
        assert_eq!(
            beside.status.code(),
            Some(2),
            "--version beside another argument is not the start that ends at once"
        );
    }

    /// The floor opened again is opened by the program it is given, which the host has shown to be
    /// the file that was placed: that program's refusal is the refusal.
    #[test]
    fn the_floor_opened_again_is_opened_by_the_program_it_is_given() {
        let world = world("open-again-program", 1_000_000);
        let watch = world.watch();
        let program = world.root.join("the-given-program");
        std::fs::write(
            &program,
            "#!/bin/sh\necho 'the given program ran' >&2\nexit 2\n",
        )
        .expect("a program");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
            .expect("runnable");
        // A program written a moment ago is busy while a child that another test starts holds the
        // descriptor it was written through, until that child runs its own program: asked again.
        let mut why = watch
            .open_again(&program, world.environment)
            .expect_err("the given program refuses");
        for _ in 0..100 {
            if !why.contains("Text file busy") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
            why = watch
                .open_again(&program, world.environment)
                .expect_err("the given program refuses");
        }
        assert!(why.ends_with("the given program ran"), "{why}");
        drop(watch);
        world.clean();
    }

    /// A copy that the agent cuts, replaces by a link, replaces by a pipe or replaces by a second
    /// name of the floor after the directory is checked is read by the product's open as the file
    /// it is: a cut copy and a link and a pipe are refused with the product's reason, and a pipe
    /// does not hold the open; a second name of the floor is opened, which is the stated residual.
    #[test]
    fn a_copy_replaced_after_the_directory_check_is_refused_and_a_pipe_does_not_hold_the_open() {
        let world = world("copy-replaced", 1_000_000);
        let watch = world.watch();
        let program = opener();
        let bytes = held_bytes(&watch.file).expect("the floor's bytes");
        let attacked = |what: &str, attack: &dyn Fn(&Path)| {
            let started = Instant::now();
            let said = watch.scratch.with(&bytes, |copy| {
                attack(copy);
                product_opens(&program, copy, world.environment)
            });
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "{what}: the open ended in time"
            );
            said
        };
        let why = attacked("cut", &|copy| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(copy)
                .and_then(|file| file.set_len(0))
                .expect("the copy is cut");
        })
        .expect_err("a cut copy");
        assert!(why.contains("not the length this build writes"), "{why}");
        let why = attacked("link", &|copy| {
            std::fs::remove_file(copy).expect("the copy is removed");
            std::os::unix::fs::symlink(&world.path, copy).expect("a link in its place");
        })
        .expect_err("a link in the place of the copy");
        assert!(why.contains("must not be a symbolic link"), "{why}");
        let why = attacked("pipe", &|copy| {
            std::fs::remove_file(copy).expect("the copy is removed");
            let made = std::process::Command::new("mkfifo")
                .arg(copy)
                .status()
                .expect("mkfifo runs");
            assert!(made.success(), "mkfifo made a pipe in the copy's place");
        })
        .expect_err("a pipe in the place of the copy");
        assert!(why.contains("must be a regular file"), "{why}");
        assert_eq!(
            attacked("second name", &|copy| {
                std::fs::remove_file(copy).expect("the copy is removed");
                std::fs::hard_link(&world.path, copy).expect("a second name of the floor");
            }),
            Ok(()),
            "a second name of the floor is opened"
        );
        drop(watch);
        world.clean();
    }

    /// The floor opened once more is refused where the directory of its copy is not the one the
    /// harness made, where its file may be read or written by another user, and where it is not the
    /// floor's length, each with the reason.
    #[test]
    fn the_floor_opened_again_is_refused_for_a_replaced_directory_a_mode_and_a_length() {
        let world = world("open-again-checks", 1_000_000);
        let watch = world.watch();
        assert_eq!(watch.open_again(&opener(), world.environment), Ok(()));
        let moved = watch.scratch.root.with_extension("moved");
        std::fs::rename(&watch.scratch.root, &moved).expect("moved away");
        std::fs::create_dir(&watch.scratch.root).expect("another directory");
        std::fs::set_permissions(&watch.scratch.root, std::fs::Permissions::from_mode(0o700))
            .expect("owner only");
        let why = watch
            .open_again(&opener(), world.environment)
            .expect_err("another directory in the place of the copy's");
        assert!(
            why.ends_with(
                "the directory of the floor's copy is not the directory the harness made"
            ),
            "{why}"
        );
        std::fs::remove_dir(&watch.scratch.root).expect("the other directory goes");
        std::fs::rename(&moved, &watch.scratch.root).expect("moved back");
        std::fs::set_permissions(&world.path, std::fs::Permissions::from_mode(0o644))
            .expect("readable by others");
        let why = watch
            .open_again(&opener(), world.environment)
            .expect_err("a floor that others can read");
        assert!(
            why.ends_with("the clock floor file may be read or written by another user"),
            "{why}"
        );
        std::fs::set_permissions(&world.path, std::fs::Permissions::from_mode(0o600))
            .expect("owner only");
        assert_eq!(watch.open_again(&opener(), world.environment), Ok(()));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&world.path)
            .and_then(|file| file.set_len(100))
            .expect("a short floor");
        let why = watch
            .open_again(&opener(), world.environment)
            .expect_err("a floor of another length");
        assert!(
            why.ends_with("the clock floor file is not the length this build writes"),
            "{why}"
        );
        drop(watch);
        world.clean();
    }

    /// A file shorter than the floor is refused before any word is read, and a word that does not
    /// stand still over the tries is refused, while a word that settles is accepted.
    #[test]
    fn a_short_floor_and_a_word_that_does_not_stand_still_are_refused() {
        let world = world("short", 1_000_000);
        let file = File::open(&world.path).expect("the floor");
        assert!(look(&file).is_ok(), "the floor as made");
        let short = world.root.join("short");
        std::fs::write(&short, vec![0_u8; 200]).expect("a short file");
        let why = look(&File::open(&short).expect("a file")).expect_err("a short file");
        assert_eq!(
            why,
            format!("the file is 200 bytes, shorter than the floor's {FLOOR_FILE_LEN}")
        );
        let mut reads = [1_u64, 2, 2].into_iter();
        assert_eq!(
            settled(72, || Ok(reads.next().expect("a read"))),
            Ok(2),
            "a word that moved between the first two reads and then stood still"
        );
        let mut moving = 0_u64;
        let why = settled(72, || {
            moving += 1;
            Ok(moving)
        })
        .expect_err("a word that always moves");
        assert_eq!(
            why,
            format!("the word at byte 72 did not stand still over {READ_TRIES} reads")
        );
        world.clean();
    }

    /// A floor that cannot be opened as the daemon opens it, and one that holds a word above its
    /// floor word, give no watch and say why.
    #[test]
    fn a_floor_that_cannot_be_read_or_holds_a_word_above_the_floor_gives_no_watch() {
        let world = world("start", 1_000_000);
        let watch = |world: &World| {
            Watch::at_the_start(
                Opening {
                    root: &world.root,
                    pin: &world.pin,
                    relative: world.path.strip_prefix(&world.root).expect("below the run"),
                    path: &world.path,
                },
                world.environment,
                world.boot,
                START,
                START,
            )
        };
        world.other.owe(1_000_001);
        let why = watch(&world).expect_err("owed above the floor");
        assert_eq!(
            why,
            "the clock floor holds owed 1000001, above its floor word 1000000, at the start"
        );
        std::fs::remove_file(&world.path).expect("removed");
        let why = watch(&world).expect_err("no floor");
        assert!(
            why.starts_with("the clock floor cannot be read at the start: "),
            "{why}"
        );
        world.clean();
    }

    /// The worker's raise and owe, and the daemon's record and establishment words, are not
    /// refused at the kill; before the attempt the worker's raise and owe still are not.
    #[test]
    fn the_workers_raise_and_owe_are_not_refused_at_either_compare() {
        let world = world("controls", 1_000_000);
        let mut watch = world.watch();
        world.other.raise(1_020_000);
        world.other.owe(1_020_000);
        world.other.record(1_010_000);
        world.other.establish(1_000_500, 5_500);
        assert_eq!(watch.at_the_kill(later(10_000)), Vec::<String>::new());
        world.other.raise(1_030_000);
        world.other.owe(1_025_000);
        assert_eq!(
            watch.before_the_attempt(later(20_000)),
            Vec::<String>::new()
        );
        // The second kill is against the start again, and the same words are fine.
        assert_eq!(watch.at_the_kill(later(30_000)), Vec::<String>::new());
        world.clean();
    }

    /// A floor word that rose past the limit is refused, at the kill and before the attempt: the
    /// limit is the greatest of the three terms and the allowance above it.
    #[test]
    fn a_floor_word_past_the_limit_is_refused() {
        let world = world("limit", 1_000_000);
        let mut watch = world.watch();
        // 1,000 ms after the start every term gives 1,001,000 at most, and the allowance is 60 s.
        world.other.raise(1_061_000);
        assert_eq!(watch.at_the_kill(later(1_000)), Vec::<String>::new());
        world.other.raise(1_061_001);
        let refused = watch.at_the_kill(later(1_000));
        assert_eq!(
            refused,
            ["the clock floor's floor word is 1061001, 1 ms above the limit 1061000"]
        );
        world.clean();
        // Before the attempt the same limit applies to what rose since the kill.
        let later_world = self::world("limit-attempt", 1_000_000);
        let mut watch = later_world.watch();
        later_world.other.raise(1_061_000);
        assert_eq!(watch.at_the_kill(later(1_000)), Vec::<String>::new());
        later_world.other.raise(1_100_000);
        let refused = watch.before_the_attempt(later(1_500));
        assert_eq!(
            refused,
            ["the clock floor's floor word is 1100000, 38500 ms above the limit 1061500"]
        );
        later_world.clean();
    }

    /// The limit follows the greatest wall reading: a later check at a higher wall time allows a
    /// higher word, and the wall clock stepping back does not lower it.
    #[test]
    fn the_limit_follows_the_greatest_wall_reading_and_not_a_later_lower_one() {
        let world = world("wall", 1_000_000);
        let mut watch = world.watch();
        let ahead = Readings {
            wall_ms: START.wall_ms + 600_000,
            boot_ms: START.boot_ms + 1_000,
        };
        world.other.raise(1_650_000);
        assert_eq!(watch.at_the_kill(ahead), Vec::<String>::new());
        let back = Readings {
            wall_ms: START.wall_ms,
            boot_ms: START.boot_ms + 2_000,
        };
        assert_eq!(watch.at_the_kill(back), Vec::<String>::new());
        world.clean();
    }

    /// Each term of the limit counts where the others stand lower: the anchor's reading with the
    /// continuous time since it, when the floor at the start stands behind the wall clock; the
    /// floor at the start with the time since, when the floor stands ahead of the wall clock. The
    /// wall clock reads low at the check in both, as after a step back.
    #[test]
    fn the_anchor_and_the_floor_at_the_start_each_set_the_limit_where_the_wall_clock_reads_low() {
        // The floor stands 100,000 behind the anchor's wall reading.
        let world = world("behind", 900_000);
        let anchor = Readings {
            wall_ms: 1_000_000,
            boot_ms: 5_000,
        };
        let start = Readings {
            wall_ms: 900_000,
            boot_ms: 5_000,
        };
        let check = Readings {
            wall_ms: 100_000,
            boot_ms: 15_000,
        };
        let mut watch = world.watch_anchored(anchor, start);
        world.other.raise(1_070_000);
        assert_eq!(watch.at_the_kill(check), Vec::<String>::new());
        world.other.raise(1_070_001);
        assert_eq!(
            watch.at_the_kill(check),
            ["the clock floor's floor word is 1070001, 1 ms above the limit 1070000"]
        );
        world.clean();
        // The floor stands 100,000 ahead of the anchor's wall reading.
        let ahead_world = self::world("ahead", 1_100_000);
        let start = Readings {
            wall_ms: 100_000,
            boot_ms: 5_000,
        };
        let mut watch = ahead_world.watch_anchored(anchor, start);
        ahead_world.other.raise(1_170_000);
        assert_eq!(watch.at_the_kill(check), Vec::<String>::new());
        ahead_world.other.raise(1_170_001);
        assert_eq!(
            watch.at_the_kill(check),
            ["the clock floor's floor word is 1170001, 1 ms above the limit 1170000"]
        );
        ahead_world.clean();
    }

    /// `owed` or `recorded` written above the floor is refused at the kill and before the attempt.
    #[test]
    fn owed_or_recorded_above_the_floor_is_refused_at_both_compares() {
        for (word, at) in [("owed", OWED_AT), ("recorded", RECORDED_AT)] {
            let world = world("relation", 1_000_000);
            let mut watch = world.watch();
            world.write_at(at, &1_000_001_u64.to_ne_bytes());
            let said =
                format!("the clock floor's {word} word is 1000001, above its floor word 1000000");
            let refused = watch.at_the_kill(later(1_000));
            assert!(refused.contains(&said), "{word}: {refused:?}");
            let refused = watch.before_the_attempt(later(2_000));
            assert!(refused.contains(&said), "{word}: {refused:?}");
            world.clean();
        }
    }

    /// A word that went down is refused, with both values.
    #[test]
    fn a_word_that_went_down_is_refused() {
        let world = world("down", 1_000_000);
        let mut watch = world.watch();
        world.write_at(FLOOR_AT, &999_000_u64.to_ne_bytes());
        let refused = watch.at_the_kill(later(1_000));
        // The recorded word stands above the lowered floor word, which is the second relation.
        assert_eq!(
            refused,
            [
                "the clock floor's floor word went down, from 1000000 to 999000",
                "the clock floor's recorded word is 1000000, above its floor word 999000"
            ]
        );
        world.clean();
    }

    /// A header byte, a byte between the header and the words, a byte after the words and a byte
    /// appended are each a change of the bytes outside the words.
    #[test]
    fn a_changed_header_byte_and_an_appended_byte_are_refused() {
        let said = ["the clock floor's bytes outside its words changed"];
        for at in [3_u64, 50, 200, 4_095] {
            let world = world("fixed", 1_000_000);
            let mut watch = world.watch();
            world.write_at(at, &[0xAA]);
            assert_eq!(watch.at_the_kill(later(1_000)), said, "byte {at}");
            world.clean();
        }
        let world = world("appended", 1_000_000);
        let mut watch = world.watch();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&world.path)
            .expect("the floor")
            .write_all(b"x")
            .expect("appended");
        assert_eq!(watch.at_the_kill(later(1_000)), said);
        world.clean();
    }

    /// A copy with the same header on a new inode is not the file that was mapped.
    #[test]
    fn a_copy_on_a_new_inode_is_not_the_file_that_was_mapped() {
        let world = world("copy", 1_000_000);
        let mut watch = world.watch();
        let staging = world.path.with_extension("copy");
        std::fs::copy(&world.path, &staging).expect("a copy");
        std::fs::rename(&staging, &world.path).expect("renamed over");
        let refused = watch.at_the_kill(later(1_000));
        assert_eq!(
            refused,
            [
                "the clock floor's name no longer names the file that was mapped when the agent started"
            ]
        );
        world.clean();
    }

    /// Between the kill and the attempt `recorded` and the establishment words must be as they were
    /// at the kill; before the kill they are the daemon's to write. A raw change that decodes the
    /// same as the old word is a change.
    #[test]
    fn recorded_and_the_establishment_words_may_not_change_between_the_kill_and_the_attempt() {
        let world = world("daemon-words", 1_000_000);
        let mut watch = world.watch();
        world.other.record(1_000_000);
        world.write_at(ESTABLISHED_AT, &5_u64.to_ne_bytes());
        assert_eq!(watch.at_the_kill(later(1_000)), Vec::<String>::new());
        assert_eq!(watch.before_the_attempt(later(2_000)), Vec::<String>::new());
        // `recorded` up to the floor, and an establishment word whose count stays zero, so that
        // `established()` reads `None` for both values.
        world.write_at(RECORDED_AT, &500_u64.to_ne_bytes());
        let refused = watch.before_the_attempt(later(2_000));
        assert_eq!(
            refused,
            [
                "the clock floor's recorded word changed between the kill and the attempt, from 1000000 to 500"
            ]
        );
        world.write_at(RECORDED_AT, &1_000_000_u64.to_ne_bytes());
        assert!(world.other.established().is_none());
        world.write_at(ESTABLISHED_AT, &6_u64.to_ne_bytes());
        assert!(world.other.established().is_none());
        let refused = watch.before_the_attempt(later(2_000));
        assert_eq!(
            refused,
            ["the clock floor's establishment words changed between the kill and the attempt"]
        );
        world.clean();
    }

    /// The floor opens again as the daemon opens it while its name still names the file held. A name
    /// that names another file, and a floor that the daemon would not open, each fail the open again
    /// and say which.
    #[test]
    fn the_floor_opens_again_while_its_name_names_the_file_held_and_says_why_it_cannot() {
        let world = world("open-again", 1_000_000);
        let watch = world.watch();
        assert_eq!(watch.open_again(&opener(), world.environment), Ok(()));
        // The file held is still at the name, and the daemon would refuse it: another environment's.
        let another = EnvironmentId::new(kr_ipc::new_uuid());
        assert_eq!(
            watch.open_again(&opener(), another),
            Err(
                "the clock floor cannot be opened again before the attempt: the clock floor file \
                 belongs to another environment"
                    .to_owned()
            )
        );
        // A copy on a new inode opens as the floor of this environment, so only the name tells it
        // from the file held.
        let staging = world.path.with_extension("copy");
        std::fs::copy(&world.path, &staging).expect("a copy");
        std::fs::rename(&staging, &world.path).expect("renamed over");
        assert_eq!(
            watch.open_again(&opener(), world.environment),
            Err(
                "the clock floor cannot be opened again before the attempt: its name no longer \
                 names the file held since the start"
                    .to_owned()
            )
        );
        world.clean();
    }
}
