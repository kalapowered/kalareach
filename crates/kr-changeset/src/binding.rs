//! Binding a result to the run it describes.
//!
//! A result must not attest that the unmodified version passed when the tested source was changed
//! or cannot be established. Reading the copy when it is made and again when the result is
//! recorded cannot show that: a run that changed a file, tested the change and put the file back
//! leaves a copy that reads as it did. This module closes that, by recording what the platform
//! knows about every file and directory of the copy before the command starts and comparing it
//! with the same record after the command has ended.
//!
//! # What is recorded
//!
//! For every file and directory beneath the copy, and the copy itself: what kind of object it is,
//! the device and inode it is, its length, the time it was last modified and **the time its inode
//! last changed**. The last is what binds a result to the run. A write, a truncation, a rename, a
//! change of mode and a change of time all move it to the instant they happen, and no call a
//! process can make sets it back, as `utimensat` sets the modification time. A run that restores
//! a file's bytes and its modification time still leaves the change time later than it was.
//!
//! Three things are done so that equal records mean what they say:
//!
//! * the filesystem has to be one whose change times this host knows to be kept; on any other the
//!   result is indeterminate;
//! * before the command starts, the host waits until the filesystem's own clock has passed the
//!   newest change time it recorded, with a file of its own written beside the copy, so that a
//!   change made in the same tick as the record still shows;
//! * the record of the copy is one reading of every entry, taken by name without following a
//!   link, and the second reading is taken the same way.
//!
//! # Declared outputs
//!
//! A suite may declare paths it writes ([`Outputs`]). Nothing at or beneath a declared path is
//! recorded, and the host makes the directories above a declared path before it takes the record,
//! so that writing the output changes no recorded entry except the directory the output is in,
//! the **parent**. A parent's own record cannot tell the output from anything else written beside
//! it, so a parent is watched by name instead, from before the command starts to after it has
//! ended: the platform reports each name created, removed, renamed, written or changed in it, and
//! a name other than a declared output makes the result indeterminate, however briefly it
//! existed. A watcher the host cannot start, or whose reports it cannot be sure it has all of,
//! makes the result indeterminate too.
//!
//! # What this does not establish
//!
//! It shows that nothing in the copy was written while the command ran, outside the declared
//! outputs. It does not show what the command read: the copy holds the version, and a command can
//! read anything else on the machine. It does not show a write through a shared mapping that the
//! platform has not yet recorded when the result is recorded, a write by a process that outlives
//! the session after the record is taken, a root account that sets the system clock back, or a
//! filesystem that does not keep what it reports.

use kr_protocol::ids::MaterialisationId;

use crate::materialise::Outputs;
use crate::service::ChangeSetService;

/// What a binding found when a result was recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bound {
    /// Nothing outside the declared outputs was written while the command ran.
    Undisturbed,
    /// Something was written, and this says what.
    Disturbed(String),
    /// This host could not establish whether anything was, and this says why.
    Unestablished(String),
}

/// What a run is bound by: the record of its copy, taken before the command started.
///
/// It lives in memory, with the dispatch that waits for the command. A daemon that stops while
/// the command runs has no binding to settle with, and records no result.
#[derive(Debug)]
pub struct RunBinding {
    reading: std::result::Result<unix::Reading, String>,
}

/// Records the copy `materialisation_id` before the command that is about to run in it starts.
///
/// This never fails: a record this host cannot take is a binding that says so when the result is
/// recorded, and the result is then indeterminate. The directories above each declared output
/// are made here, and a platform watcher is started where a declared output needs one.
#[must_use]
pub fn bind_run(
    service: &ChangeSetService,
    materialisation_id: MaterialisationId,
    outputs: &Outputs,
) -> RunBinding {
    RunBinding {
        reading: unix::Reading::take(service, materialisation_id, outputs),
    }
}

impl RunBinding {
    /// Compares the copy now with the record taken before the command started.
    #[must_use]
    pub fn settle(
        &self,
        service: &ChangeSetService,
        materialisation_id: MaterialisationId,
    ) -> Bound {
        match &self.reading {
            Ok(reading) => reading.settle(service, materialisation_id),
            Err(why) => Bound::Unestablished(why.clone()),
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    use cap_std::fs::MetadataExt as _;
    use kr_protocol::ids::MaterialisationId;
    use kr_transfer::{AuthorisedDirectory, RelativeName};

    use super::Bound;
    use crate::materialise::Outputs;
    use crate::service::{ChangeSetService, MATERIALISATIONS_DIRECTORY};

    /// The parents of the declared outputs, and the output names each holds.
    ///
    /// A parent is a relative path of the directory an output is directly in, the copy's root being
    /// the empty path.
    fn parents_of(outputs: &Outputs) -> BTreeMap<String, BTreeSet<String>> {
        let mut parents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for path in outputs.declared() {
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            parents
                .entry(parent.to_owned())
                .or_default()
                .insert(name.to_owned());
        }
        parents
    }

    /// How many paths a description of what was written names before it counts the rest.
    const NAMED: usize = 3;

    /// Says which paths were written, naming a few.
    fn describe(mut written: Vec<String>) -> String {
        written.sort();
        written.dedup();
        let more = written.len().saturating_sub(NAMED);
        let named: Vec<String> = written
            .iter()
            .take(NAMED)
            .map(|path| {
                if path.is_empty() {
                    "the copy's own directory".to_owned()
                } else {
                    kr_project::git::redact(path)
                }
            })
            .collect();
        if more == 0 {
            named.join(", ")
        } else {
            format!("{} and {more} more", named.join(", "))
        }
    }

    /// How long the host waits for the filesystem's clock to pass the newest change time it
    /// recorded. A tick is milliseconds on a filesystem that stamps finely and a second or two on
    /// one that does not; a clock that has not moved in this long is not one to trust.
    const TICK_WAIT: Duration = Duration::from_secs(3);

    /// What kind of object an entry is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Kind {
        Directory,
        File,
        Other,
    }

    /// What the platform says about one entry, of which the change time is the part a run cannot
    /// put back.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Stamp {
        kind: Kind,
        device: u64,
        inode: u64,
        len: u64,
        modified: (i64, i64),
        changed: (i64, i64),
    }

    impl Stamp {
        fn of(metadata: &cap_std::fs::Metadata, kind: Kind) -> Self {
            Self {
                kind,
                device: metadata.dev(),
                inode: metadata.ino(),
                len: if kind == Kind::File {
                    metadata.size()
                } else {
                    0
                },
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            }
        }
    }

    /// The record of one copy, and what it needs to be compared with a second one.
    #[derive(Debug)]
    pub struct Reading {
        stamps: BTreeMap<String, Stamp>,
        /// The directories an output is directly in, whose own stamp is not recorded.
        parents: BTreeMap<String, BTreeSet<String>>,
        declared: BTreeSet<String>,
        names: Option<names::NameWatch>,
    }

    impl Reading {
        pub fn take(
            service: &ChangeSetService,
            id: MaterialisationId,
            outputs: &Outputs,
        ) -> Result<Self, String> {
            let (parent, copy) = open_copy(service, id)?;
            keeps_change_times(&copy)?;
            let parents = parents_of(outputs);
            let declared = outputs.declared().clone();
            make_the_directories_above(&copy, &declared)?;
            let skipped: BTreeSet<String> = parents.keys().cloned().collect();
            let names = names::NameWatch::start(&copy, &parent, &parents)?;
            let stamps = stamp_tree(&copy, &skipped, &declared)?;
            let newest = stamps
                .values()
                .map(|stamp| stamp.changed)
                .max()
                .unwrap_or_default();
            wait_for_the_clock(&parent, newest)?;
            Ok(Self {
                stamps,
                parents,
                declared,
                names,
            })
        }

        pub fn settle(&self, service: &ChangeSetService, id: MaterialisationId) -> Bound {
            let skipped: BTreeSet<String> = self.parents.keys().cloned().collect();
            let end = match open_copy(service, id)
                .and_then(|(_, copy)| stamp_tree(&copy, &skipped, &self.declared))
            {
                Ok(end) => end,
                Err(why) => return Bound::Unestablished(why),
            };
            let mut written = Vec::new();
            for path in self.stamps.keys().chain(end.keys()) {
                if self.stamps.get(path) != end.get(path) {
                    written.push(path.clone());
                }
            }
            let reported = match &self.names {
                Some(names) => names.drain(),
                None => Ok(Vec::new()),
            };
            match reported {
                Ok(names) => written.extend(names),
                Err(why) if written.is_empty() => return Bound::Unestablished(why),
                Err(_) => {}
            }
            if written.is_empty() {
                Bound::Undisturbed
            } else {
                Bound::Disturbed(describe(written))
            }
        }
    }

    /// Opens the directory the materialisation lives in and the materialisation itself.
    fn open_copy(
        service: &ChangeSetService,
        id: MaterialisationId,
    ) -> Result<(AuthorisedDirectory, AuthorisedDirectory), String> {
        let row = service
            .locked()
            .and_then(|store| store.materialisation(id))
            .map_err(|error| format!("the materialisation could not be looked up: {error}"))?
            .ok_or_else(|| format!("there is no materialisation {id}"))?;
        let opened = || -> Result<_, kr_transfer::Escape> {
            let parent = service
                .root()
                .subdirectory(&RelativeName::parse(MATERIALISATIONS_DIRECTORY)?)?;
            let copy = parent
                .subdirectory(&RelativeName::parse(&row.directory_name)?)
                .and_then(AuthorisedDirectory::confined_to_one_mount)?;
            Ok((parent, copy))
        };
        opened().map_err(|error| format!("the materialisation could not be opened: {error}"))
    }

    /// Whether this host knows the filesystem to keep the change times it reports.
    ///
    /// A list of the filesystems this host knows, not of the ones that are known to fail: a
    /// filesystem reached over a network, through a user-space driver or in a format that keeps
    /// no change time of its own reports a time that says nothing about when the file changed.
    fn keeps_change_times(copy: &AuthorisedDirectory) -> Result<(), String> {
        let stat = rustix::fs::fstatfs(copy.handle())
            .map_err(|error| format!("the filesystem could not be asked what it is: {error}"))?;
        known_filesystem(&stat)
    }

    #[cfg(target_os = "linux")]
    fn known_filesystem(stat: &rustix::fs::StatFs) -> Result<(), String> {
        /// ext2, ext3 and ext4, XFS, Btrfs, tmpfs, overlayfs, F2FS and ZFS.
        const KNOWN: [u64; 7] = [
            0xEF53,
            0x5846_5342,
            0x9123_683E,
            0x0102_1994,
            0x794C_7630,
            0xF2F5_2010,
            0x2FC1_2FC1,
        ];
        const NFS: u64 = 0x6969;
        let kind = u64::try_from(stat.f_type).unwrap_or(0) & 0xFFFF_FFFF;
        if KNOWN.contains(&kind) {
            Ok(())
        } else if kind == NFS {
            Err(
                "the copy is on a network filesystem, whose change times this host does not \
                 trust"
                    .to_owned(),
            )
        } else {
            Err(format!(
                "the copy is on a filesystem of type {kind:#x}, whose change times this host \
                 does not know to be kept"
            ))
        }
    }

    #[cfg(target_os = "macos")]
    fn known_filesystem(stat: &rustix::fs::StatFs) -> Result<(), String> {
        let name: String = stat
            .f_fstypename
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| char::from(u8::try_from(*byte).unwrap_or(b'?')))
            .collect();
        if name == "apfs" || name == "hfs" {
            Ok(())
        } else {
            Err(format!(
                "the copy is on a {name} filesystem, whose change times this host does not know \
                 to be kept"
            ))
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn known_filesystem(_stat: &rustix::fs::StatFs) -> Result<(), String> {
        Err("this platform has no record of a copy's change times".to_owned())
    }

    /// Makes the directories above each declared output, so that writing the output changes
    /// nothing above its parent.
    ///
    /// A directory that is already there is the one a suite's earlier stage made or one the
    /// version holds, and is left as it is. A name taken by anything but a directory is a version
    /// file the suite's output would have to replace, and is refused.
    fn make_the_directories_above(
        copy: &AuthorisedDirectory,
        declared: &BTreeSet<String>,
    ) -> Result<(), String> {
        use cap_std::fs::DirBuilderExt as _;

        let mut builder = cap_std::fs::DirBuilder::new();
        builder.mode(0o700);
        for path in declared {
            let mut components: Vec<&str> = path.split('/').collect();
            components.pop();
            let refused = |error: &dyn std::fmt::Display| {
                format!(
                    "the directory above the declared output {} could not be made: {error}",
                    kr_project::git::redact(path)
                )
            };
            let mut here = copy
                .try_clone()
                .map_err(|error| format!("the copy could not be reopened: {error}"))?;
            for component in components {
                match here.handle().create_dir_with(component, &builder) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(refused(&error)),
                }
                let name = RelativeName::parse(component).map_err(|error| refused(&error))?;
                here = here.subdirectory(&name).map_err(|error| refused(&error))?;
            }
        }
        Ok(())
    }

    /// Records every entry beneath the copy, and the copy, except what is declared output and
    /// the stamp of each directory an output is in.
    fn stamp_tree(
        copy: &AuthorisedDirectory,
        skipped: &BTreeSet<String>,
        declared: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, Stamp>, String> {
        let mut stamps = BTreeMap::new();
        let mut left = crate::capture::MAX_WALK_ENTRIES;
        stamp_directory(copy, "", skipped, declared, &mut stamps, &mut left, 0)?;
        Ok(stamps)
    }

    fn stamp_directory(
        directory: &AuthorisedDirectory,
        prefix: &str,
        skipped: &BTreeSet<String>,
        declared: &BTreeSet<String>,
        stamps: &mut BTreeMap<String, Stamp>,
        left: &mut usize,
        depth: usize,
    ) -> Result<(), String> {
        if depth >= crate::capture::MAX_WALK_DEPTH {
            return Err(format!(
                "the copy is more than {} levels deep, which is deeper than this host records",
                crate::capture::MAX_WALK_DEPTH
            ));
        }
        if !skipped.contains(prefix) {
            let metadata = directory
                .handle()
                .dir_metadata()
                .map_err(|error| format!("a directory could not be examined: {error}"))?;
            stamps.insert(prefix.to_owned(), Stamp::of(&metadata, Kind::Directory));
        }
        let entries = directory
            .handle()
            .entries()
            .map_err(|error| format!("a directory could not be listed: {error}"))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("a directory entry could not be read: {error}"))?;
            let Ok(component) = entry.file_name().into_string() else {
                return Err("a name beneath the copy is not readable as text".to_owned());
            };
            let path = if prefix.is_empty() {
                component.clone()
            } else {
                format!("{prefix}/{component}")
            };
            if declared.contains(&path) {
                continue;
            }
            if *left == 0 {
                return Err(format!(
                    "the copy holds more than {} entries, which is more than this host records",
                    crate::capture::MAX_WALK_ENTRIES
                ));
            }
            *left -= 1;
            let name = RelativeName::parse(&component).map_err(|_| {
                format!(
                    "a name beneath the copy is one this host cannot carry: {}",
                    kr_project::git::redact(&component)
                )
            })?;
            let metadata = directory
                .handle()
                .symlink_metadata(&component)
                .map_err(|error| format!("an entry could not be examined: {error}"))?;
            let kind = metadata.file_type();
            if kind.is_dir() {
                let child = directory.subdirectory(&name).map_err(|error| {
                    format!(
                        "a directory beneath the copy could not be opened: {} ({error})",
                        kr_project::git::redact(&path)
                    )
                })?;
                stamp_directory(&child, &path, skipped, declared, stamps, left, depth + 1)?;
            } else {
                let kind = if kind.is_file() {
                    Kind::File
                } else {
                    Kind::Other
                };
                stamps.insert(path, Stamp::of(&metadata, kind));
            }
        }
        Ok(())
    }

    /// Waits until the filesystem's clock has passed `newest`, with a file of the host's own
    /// written beside the copy: a change made in the tick the record was taken in would otherwise
    /// carry the same time as the record.
    fn wait_for_the_clock(parent: &AuthorisedDirectory, newest: (i64, i64)) -> Result<(), String> {
        let name = RelativeName::parse(&format!(".tick-{}", kr_ipc::new_uuid()))
            .map_err(|error| format!("a file to read the filesystem's clock from: {error}"))?;
        let mut file = parent
            .create_new(&name)
            .map_err(|error| format!("a file to read the filesystem's clock from: {error}"))?;
        let deadline = Instant::now() + TICK_WAIT;
        let passed = loop {
            let written = file
                .handle_mut()
                .write_all(b"x")
                .and_then(|()| file.handle().metadata());
            match written {
                Ok(metadata) if (metadata.ctime(), metadata.ctime_nsec()) > newest => break Ok(()),
                Ok(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                Ok(_) => {
                    break Err(
                        "the filesystem's clock did not pass the newest change time of the copy"
                            .to_owned(),
                    );
                }
                Err(error) => {
                    break Err(format!("the filesystem's clock could not be read: {error}"));
                }
            }
        };
        drop(file);
        let _ = parent.remove(&name);
        passed
    }

    #[cfg(target_os = "linux")]
    mod names {
        use std::collections::{BTreeMap, BTreeSet};
        use std::mem::MaybeUninit;
        use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};

        use rustix::fs::inotify::{self, CreateFlags, ReadFlags, WatchFlags};
        use rustix::io::Errno;

        use kr_transfer::{AuthorisedDirectory, RelativeName};

        /// A watch on the directories declared outputs are in, which reports each name created,
        /// removed, renamed, written or changed there.
        #[derive(Debug)]
        pub struct NameWatch {
            inotify: OwnedFd,
            watched: BTreeMap<i32, String>,
            allowed: BTreeMap<String, BTreeSet<String>>,
        }

        impl NameWatch {
            /// Starts watching the parents of declared outputs, before the command does.
            ///
            /// A copy with no declared output needs no watcher, and the answer is none.
            pub fn start(
                copy: &AuthorisedDirectory,
                _beside: &AuthorisedDirectory,
                parents: &BTreeMap<String, BTreeSet<String>>,
            ) -> Result<Option<Self>, String> {
                if parents.is_empty() {
                    return Ok(None);
                }
                let inotify = inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)
                    .map_err(|error| format!("no watcher could be started: {error}"))?;
                let mut watched = BTreeMap::new();
                for parent in parents.keys() {
                    let directory = if parent.is_empty() {
                        copy.try_clone()
                    } else {
                        RelativeName::parse(parent).and_then(|name| copy.subdirectory(&name))
                    }
                    .map_err(|error| {
                        format!("a directory to watch could not be opened: {error}")
                    })?;
                    // Through the open handle, so the directory watched is the one that was opened
                    // and not whatever a path names by now.
                    let through =
                        format!("/proc/self/fd/{}", directory.handle().as_fd().as_raw_fd());
                    let wd = inotify::add_watch(
                        &inotify,
                        through,
                        WatchFlags::ONLYDIR
                            | WatchFlags::CREATE
                            | WatchFlags::DELETE
                            | WatchFlags::DELETE_SELF
                            | WatchFlags::MODIFY
                            | WatchFlags::MOVE_SELF
                            | WatchFlags::MOVED_FROM
                            | WatchFlags::MOVED_TO
                            | WatchFlags::ATTRIB
                            | WatchFlags::CLOSE_WRITE,
                    )
                    .map_err(|error| format!("a directory could not be watched: {error}"))?;
                    watched.insert(wd, parent.clone());
                }
                Ok(Some(Self {
                    inotify,
                    watched,
                    allowed: parents.clone(),
                }))
            }

            /// The paths written since the watch started, other than declared outputs.
            ///
            /// The kernel queues each report as the change happens, so every change made before
            /// this call is in the queue; a queue that overflowed lost some, and then nothing is
            /// established.
            pub fn drain(&self) -> Result<Vec<String>, String> {
                let mut buffer = [MaybeUninit::<u8>::uninit(); 4096];
                let mut reader = inotify::Reader::new(&self.inotify, &mut buffer);
                let mut written = Vec::new();
                loop {
                    let event = match reader.next() {
                        Ok(event) => event,
                        Err(Errno::AGAIN) => return Ok(written),
                        Err(error) => {
                            return Err(format!("the watcher could not be read: {error}"));
                        }
                    };
                    if event.events().contains(ReadFlags::QUEUE_OVERFLOW) {
                        return Err("the watcher lost reports of changes to the copy".to_owned());
                    }
                    let Some(parent) = self.watched.get(&event.wd()) else {
                        continue;
                    };
                    match event.file_name() {
                        Some(name) => {
                            let name = name.to_string_lossy();
                            if self
                                .allowed
                                .get(parent)
                                .is_some_and(|outputs| outputs.contains(name.as_ref()))
                            {
                                continue;
                            }
                            written.push(if parent.is_empty() {
                                name.into_owned()
                            } else {
                                format!("{parent}/{name}")
                            });
                        }
                        None => written.push(parent.clone()),
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    mod names {
        use std::collections::{BTreeMap, BTreeSet};
        use std::path::{Path, PathBuf};
        use std::sync::{Mutex, mpsc};
        use std::time::{Duration, Instant};

        use notify::{Event, RecursiveMode, Watcher as _};

        use kr_transfer::{AuthorisedDirectory, RelativeName};

        /// How long the host waits for the watcher to report a file the host wrote itself.
        ///
        /// FSEvents delivers reports in order and on its own schedule, so the only way to know it
        /// has delivered every report up to a moment is to make a change at that moment and wait
        /// for it to be reported.
        const REPORT_WAIT: Duration = Duration::from_secs(10);

        /// The start of the name of a file the host writes to find out whether the watcher is
        /// up to date.
        const MARK: &str = ".mark-";

        /// A watch on the copy, which reports each name written in the directories declared
        /// outputs are in.
        pub struct NameWatch {
            /// Held so that the stream is.
            _watcher: notify::RecommendedWatcher,
            reports: Mutex<mpsc::Receiver<notify::Result<Event>>>,
            /// The directory the copy is in, where the host writes the files it marks time with.
            beside: AuthorisedDirectory,
            beside_path: PathBuf,
            copy_path: PathBuf,
            parents: BTreeMap<String, BTreeSet<String>>,
        }

        impl std::fmt::Debug for NameWatch {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter
                    .debug_struct("NameWatch")
                    .field("copy", &self.copy_path)
                    .finish_non_exhaustive()
            }
        }

        /// What `path` is beneath `root`, as a relative path of names, or none when it is not
        /// beneath it.
        fn beneath(root: &Path, path: &Path) -> Option<String> {
            path.strip_prefix(root).ok().map(|rest| {
                rest.components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/")
            })
        }

        impl NameWatch {
            /// Starts watching the copy, before the command does.
            ///
            /// A copy with no declared output needs no watcher, and the answer is none. The watch
            /// is up when a file the host writes has been reported; whatever FSEvents reported
            /// before that, of changes the host made itself, is discarded.
            pub fn start(
                copy: &AuthorisedDirectory,
                beside: &AuthorisedDirectory,
                parents: &BTreeMap<String, BTreeSet<String>>,
            ) -> Result<Option<Self>, String> {
                if parents.is_empty() {
                    return Ok(None);
                }
                let resolve = |directory: &AuthorisedDirectory| {
                    std::fs::canonicalize(directory.display_path())
                        .map_err(|error| format!("the copy's place could not be resolved: {error}"))
                };
                let (copy_path, beside_path) = (resolve(copy)?, resolve(beside)?);
                // The path names the directory that was opened and not another one put there.
                let (named, opened) = (
                    std::fs::metadata(&copy_path)
                        .map_err(|error| format!("the copy could not be examined: {error}"))?,
                    copy.handle()
                        .dir_metadata()
                        .map_err(|error| format!("the copy could not be examined: {error}"))?,
                );
                {
                    use cap_std::fs::MetadataExt as _;
                    use std::os::unix::fs::MetadataExt as _;
                    if (named.dev(), named.ino()) != (opened.dev(), opened.ino()) {
                        return Err("the copy is no longer where it was opened".to_owned());
                    }
                }
                let (sender, reports) = mpsc::channel();
                let mut watcher = notify::recommended_watcher(sender)
                    .map_err(|error| format!("no watcher could be started: {error}"))?;
                watcher
                    .watch(&copy_path, RecursiveMode::Recursive)
                    .and_then(|()| watcher.watch(&beside_path, RecursiveMode::NonRecursive))
                    .map_err(|error| format!("the copy could not be watched: {error}"))?;
                let watch = Self {
                    _watcher: watcher,
                    reports: Mutex::new(reports),
                    beside: beside.try_clone().map_err(|error| {
                        format!("the copy's place could not be reopened: {error}")
                    })?,
                    beside_path,
                    copy_path,
                    parents: parents.clone(),
                };
                watch.up_to_date()?;
                Ok(Some(watch))
            }

            /// Writes a file beside the copy and waits until the watcher has reported it, and so
            /// every change made before it, handing back what was reported in the meantime.
            fn up_to_date(&self) -> Result<Vec<Event>, String> {
                let mark = format!("{MARK}{}", kr_ipc::new_uuid());
                let name = RelativeName::parse(&mark)
                    .map_err(|error| format!("a file to mark time with: {error}"))?;
                self.beside
                    .create_new(&name)
                    .map_err(|error| format!("a file to mark time with: {error}"))?;
                let marked = self.beside_path.join(&mark);
                let outcome = self.until_reported(&marked);
                let _ = self.beside.remove(&name);
                outcome
            }

            fn until_reported(&self, marked: &Path) -> Result<Vec<Event>, String> {
                let reports = self
                    .reports
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let deadline = Instant::now() + REPORT_WAIT;
                let mut heard = Vec::new();
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    match reports.recv_timeout(left) {
                        Ok(Ok(event)) => {
                            if event.paths.iter().any(|path| path == marked) {
                                return Ok(heard);
                            }
                            heard.push(event);
                        }
                        Ok(Err(error)) => return Err(format!("the watcher failed: {error}")),
                        Err(_) => {
                            return Err("the watcher did not report a change the host made \
                                        itself, so it cannot be trusted to have reported the \
                                        run's"
                                .to_owned());
                        }
                    }
                }
            }

            /// The paths written beside a declared output since the watch started.
            pub fn drain(&self) -> Result<Vec<String>, String> {
                let mut written = Vec::new();
                for event in self.up_to_date()? {
                    if event.need_rescan() {
                        return Err("the watcher lost reports of changes to the copy".to_owned());
                    }
                    for path in &event.paths {
                        let Some(relative) = beneath(&self.copy_path, path) else {
                            continue;
                        };
                        let (parent, name) = relative.rsplit_once('/').unwrap_or(("", &relative));
                        // The copy itself, and the directory a name is written in, say nothing
                        // about the name; only a name beside a declared output is judged here.
                        let Some(outputs) = self.parents.get(parent) else {
                            continue;
                        };
                        if !name.is_empty() && !outputs.contains(name) {
                            written.push(relative.clone());
                        }
                    }
                }
                Ok(written)
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    mod names {
        use std::collections::{BTreeMap, BTreeSet};

        use kr_transfer::AuthorisedDirectory;

        /// This platform has no watcher: a declared output makes the result indeterminate.
        #[derive(Debug)]
        pub struct NameWatch;

        impl NameWatch {
            pub fn start(
                _copy: &AuthorisedDirectory,
                _beside: &AuthorisedDirectory,
                parents: &BTreeMap<String, BTreeSet<String>>,
            ) -> Result<Option<Self>, String> {
                if parents.is_empty() {
                    Ok(None)
                } else {
                    Err(
                        "this platform has no watcher of the names written beside a declared \
                         output"
                            .to_owned(),
                    )
                }
            }

            pub fn drain(&self) -> Result<Vec<String>, String> {
                Ok(Vec::new())
            }
        }
    }
}

#[cfg(not(unix))]
mod unix {
    use super::{Bound, MaterialisationId, Outputs};
    use crate::service::ChangeSetService;

    /// This platform records no change times of a copy.
    #[derive(Debug)]
    pub struct Reading;

    impl Reading {
        pub fn take(
            _service: &ChangeSetService,
            _id: MaterialisationId,
            _outputs: &Outputs,
        ) -> Result<Self, String> {
            Err("this platform has no record of a copy's change times".to_owned())
        }

        pub fn settle(&self, _service: &ChangeSetService, _id: MaterialisationId) -> Bound {
            Bound::Unestablished("this platform has no record of a copy's change times".to_owned())
        }
    }
}
