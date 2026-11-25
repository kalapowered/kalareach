//! H's watch on the clock floor. When the agent starts the host maps the floor and keeps the
//! mapping and a descriptor of the file. At each kill the words are compared with those at the
//! start, and before the attempt with those at the kill: the moving words through the mapping's
//! atomic loads in the order owed, recorded, floor, everything else through the descriptor. The
//! check refuses and never passes: a word moved forward inside the limit is not seen, which is the
//! stated residual.

use std::fs::File;
use std::os::unix::fs::FileExt as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use kr_ipc::clock::{SharedClock as _, SystemSharedClock};
use kr_ipc::floor::SharedFloor;
use kr_protocol::ids::{BootEpoch, EnvironmentId};

use crate::run::{RootPin, open_file_below};

/// How far above what H's own readings allow a floor word that rose may stand, in milliseconds.
pub const ALLOWANCE_MS: u64 = 60_000;

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
}

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
        let at_the_start = look(&mapping, &file).map_err(|why| said(&why))?;
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
        let found = match look(&self.mapping, &self.file) {
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

/// Reads the floor: the moving words by the mapping's atomic loads in the order owed, recorded,
/// floor, then the file through the descriptor.
fn look(mapping: &SharedFloor, file: &File) -> Result<State, String> {
    let owed = mapping.owed();
    let recorded = mapping.recorded();
    let floor = mapping.load();
    let length = file.metadata().map_err(|why| why.to_string())?.len();
    let mut bytes = vec![0_u8; usize::try_from(length.min(READ_AT_MOST)).unwrap_or(0)];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|why| why.to_string())?;
    if length > READ_AT_MOST {
        bytes.extend_from_slice(&length.to_be_bytes());
    }
    if bytes.len() < WORDS_TO {
        return Err("the file is shorter than the floor's words".to_owned());
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use kr_ipc::paths::HostPaths;

    use super::*;

    const FLOOR_AT: u64 = 64;
    const OWED_AT: u64 = 72;
    const RECORDED_AT: u64 = 80;
    const ESTABLISHED_AT: u64 = 88;

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

    fn world(name: &str, floor_ms: u64) -> World {
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::fs::canonicalize(std::env::temp_dir()).expect("the temporary directory")
        };
        let root = base.join(format!(
            "kf-{name}-{}",
            &kr_ipc::new_uuid().to_string()[..8]
        ));
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
}
