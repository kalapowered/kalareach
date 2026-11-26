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
//! last changed**. The last is what binds a result to the run. A write, a truncation, a change of
//! mode and a change of time all move it to the instant they happen, a rename moves it for the
//! directories it changes (and on some filesystems for the renamed entry too), and no call a
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
//! ended: the platform reports each name created, removed, renamed or changed in it, and a name
//! other than a declared output makes the result indeterminate, however briefly it existed. The
//! parent itself is watched too, and so is the copy: a report that the directory was renamed,
//! removed or changed (its mode, its owner, or any of its metadata but its extended attributes) is
//! a write, because the record of a parent is the one thing the comparison leaves out. On macOS a
//! report of a parent can come after the host's own file or not at all, and the file-event service
//! can report the host's own set-up of the copy a second time, after the watcher is up to date. So
//! the host also records the device, the inode and the extended attributes (names and values) of
//! each parent before the command starts, and reads them again at the end, once the watcher has
//! reported the host's own file. A parent that is gone, is no longer a directory, has another
//! device or inode, or has an extended attribute added, removed or changed in value is a write
//! whatever was reported of it. A report that a folder was created at a parent's path, or that
//! its extended attributes changed, is no write by itself, because what the host read at the
//! start decides both: a directory that has the inode it had was not made in the run, and
//! attributes equal to the ones read at the start were not left changed. Every other report of a
//! parent is a write: a removal, a rename, a change of its mode or owner, any other change of its
//! metadata, a change of its content, or a creation of another kind, a mount among them. A parent
//! keeps its device and inode when a suite changes its mode or owner,
//! whether it puts them back or not, and when a suite moves it away and back, so only the
//! watcher's reports show such a change; an extended attribute that a suite changes and puts back
//! is not seen at all. The record of the directory above a parent shows a move away and back too,
//! except for the copy itself and for a parent in a directory that is also a parent. A parent
//! whose full path is longer than the 1,024 bytes that macOS allows for a path cannot be read, nor
//! can a parent with more than 64 extended attributes, names that take more than 8,192 bytes or a
//! value of more than 4,096 bytes, and every result of that suite is indeterminate. A watcher the
//! host cannot start, or whose reports it cannot be sure it has all of, makes the result
//! indeterminate too.
//!
//! # What this does not establish
//!
//! It shows that nothing in the copy was written while the command ran, outside the declared
//! outputs. It does not show what the command read: the copy holds the version, and a command can
//! read anything else on the machine. It does not show a write through a shared mapping that the
//! platform has not yet recorded when the result is recorded. Linux records a store through a
//! mapping when the store faults: on a filesystem that tracks writes to a mapping (ext4, measured)
//! at the first store to a clean page, and on tmpfs only when that store is the page's first
//! access through the mapping. A page made writable before the record can take later stores with
//! no new fault and no change of time, so a mapping made before the record is not shown. macOS
//! records a store when the mapping is released, so a mapping released before the session ends is
//! shown; a writable mapping released without a store counts as a write there, and the result
//! attests no version. It does not show a write by a process that outlives the session after the
//! record is taken, a root account that sets the system clock back, or a filesystem that does not
//! keep what it reports.

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
    materialisation_id: MaterialisationId,
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
        materialisation_id,
        reading: unix::Reading::take(service, materialisation_id, outputs),
    }
}

impl RunBinding {
    /// Compares the copy now with the record taken before the command started.
    ///
    /// A binding speaks only for the copy it was taken of: asked about another, it establishes
    /// nothing.
    #[must_use]
    pub fn settle(
        &self,
        service: &ChangeSetService,
        materialisation_id: MaterialisationId,
    ) -> Bound {
        if materialisation_id != self.materialisation_id {
            return Bound::Unestablished(
                "the record was taken of another copy than the one the result is about".to_owned(),
            );
        }
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
        known_type(u64::try_from(stat.f_type).unwrap_or(0) & 0xFFFF_FFFF)
    }

    /// Whether `kind`, a Linux filesystem's magic number, is one of the kept ones: ext2, ext3 and
    /// ext4, XFS, Btrfs, tmpfs, overlayfs, F2FS and ZFS.
    #[cfg(target_os = "linux")]
    fn known_type(kind: u64) -> Result<(), String> {
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
        known_name(&name)
    }

    /// Whether `name`, a macOS filesystem's type name, is the kept one: APFS.
    #[cfg(target_os = "macos")]
    fn known_name(name: &str) -> Result<(), String> {
        if name == "apfs" {
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
        /// removed, renamed or changed there, and each change to the directories themselves.
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
                            | WatchFlags::MOVE_SELF
                            | WatchFlags::MOVED_FROM
                            | WatchFlags::MOVED_TO
                            | WatchFlags::ATTRIB,
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

    /// What the host makes of the reports a platform's watcher sends, whichever platform sends them.
    ///
    /// A report is the paths it names and whether it says that reports were lost. Judging a
    /// report needs nothing of the platform's, so every Unix test target runs these cases.
    #[cfg(any(target_os = "macos", test))]
    mod judged {
        use std::collections::{BTreeMap, BTreeSet};
        use std::path::{Path, PathBuf};

        /// How many written paths the watcher keeps. A run that has written this many beside its
        /// outputs has been told enough for a result to name a few of them.
        const KEPT: usize = 64;

        /// What the platform said of the run, judged as each report arrived.
        #[derive(Debug, Default)]
        pub(super) struct Heard {
            /// Paths written beside a declared output, relative to the copy; the copy's own path
            /// is the empty one.
            pub(super) written: BTreeSet<String>,
            /// Why the reports cannot be taken as all there were, when they cannot.
            pub(super) lost: Option<String>,
        }

        /// What a report says was done to the paths it names, as far as judging a parent needs it.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum Done {
            /// A folder was created.
            CreatedFolder,
            /// Extended attributes were changed.
            Attributes,
            /// Anything else: a creation of another kind (a file, a link, a mount, a kind the
            /// platform does not say), a removal, a rename, a change of mode, owner or other
            /// metadata, a change of content.
            Other,
        }

        /// Where the watched places are, and what a report about each means.
        #[derive(Debug)]
        pub(super) struct Places {
            copy: PathBuf,
            parents: BTreeMap<String, BTreeSet<String>>,
        }

        impl Places {
            pub(super) fn new(copy: PathBuf, parents: BTreeMap<String, BTreeSet<String>>) -> Self {
                Self { copy, parents }
            }

            /// The path of the copy that a report about `path` shows to have been written, if it
            /// does.
            ///
            /// A directory a declared output is in, and the copy itself, are judged by what is
            /// reported about the directory: FSEvents says nothing of a directory when a name is
            /// made in it, so a report that names the directory is a rename, a removal or a change
            /// of its mode, owner or metadata, whichever name the command gave it meanwhile. The
            /// creation of a folder at such a directory's path and a change of its extended
            /// attributes are no write by themselves: what the host read of the directory at the
            /// start decides both. Every other creation, a mount among them, is a write. A name
            /// in such a directory is judged by whether it is a declared output.
            fn written(&self, path: &Path, done: Done) -> Option<String> {
                let relative = path.strip_prefix(&self.copy).ok().map(|rest| {
                    rest.components()
                        .map(|part| part.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                })?;
                if self.parents.contains_key(&relative) {
                    return (done == Done::Other).then_some(relative);
                }
                if relative.is_empty() {
                    return Some(relative);
                }
                let (parent, name) = relative.rsplit_once('/').unwrap_or(("", &relative));
                let outputs = self.parents.get(parent)?;
                (!outputs.contains(name)).then_some(relative)
            }

            /// Takes one report into `heard`: `rescan` is whether it says that reports were lost,
            /// `done` is what it says was done, and `paths` are the paths it names.
            ///
            /// A report that says reports were lost is a loss whatever paths it names, and when it
            /// names none. FSEvents sends such a report at the path where it lost reports, which
            /// is often a directory above the copy or the root of the volume. The watcher passes
            /// it on with that path, so a path outside the copy is no reason to leave it out.
            pub(super) fn hear(
                &self,
                heard: &mut Heard,
                rescan: bool,
                done: Done,
                paths: &[PathBuf],
            ) {
                // The loss comes first. A path the report names in the copy is kept like any
                // other, though a result that holds a loss names no written path.
                if rescan {
                    heard.lost.get_or_insert_with(|| {
                        "the watcher lost reports of changes to the copy".to_owned()
                    });
                }
                for path in paths {
                    if heard.written.len() < KEPT
                        && let Some(relative) = self.written(path, done)
                    {
                        heard.written.insert(relative);
                    }
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use std::collections::{BTreeMap, BTreeSet};
            use std::path::PathBuf;

            use super::{Done, Heard, Places};

            /// A copy at `/work/run/copy`, in the directory `/work/run`, with a declared output
            /// `out` at its root and another, `gen`, in its directory `sub`.
            fn places() -> Places {
                Places::new(
                    PathBuf::from("/work/run/copy"),
                    BTreeMap::from([
                        (String::new(), BTreeSet::from(["out".to_owned()])),
                        ("sub".to_owned(), BTreeSet::from(["gen".to_owned()])),
                    ]),
                )
            }

            /// What is heard of one report of `done` that names `paths`.
            fn heard_done(rescan: bool, done: Done, paths: &[&str]) -> Heard {
                let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
                let mut heard = Heard::default();
                places().hear(&mut heard, rescan, done, &paths);
                heard
            }

            /// What is heard of one report that names `paths` and says nothing more than that.
            fn heard_of(rescan: bool, paths: &[&str]) -> Heard {
                heard_done(rescan, Done::Other, paths)
            }

            /// KR-REQ-14.34: a notice that reports were lost is a loss at whatever path it names.
            /// FSEvents names the root of the volume, a directory above the copy, or the directory
            /// the copy is in, and none of them is a path written in the copy.
            #[test]
            fn a_loss_notice_at_a_path_outside_the_copy_is_a_loss() {
                for outside in ["/", "/work", "/work/run", "/elsewhere/file"] {
                    let heard = heard_of(true, &[outside]);
                    assert!(heard.lost.is_some(), "{outside} is a loss");
                    assert!(heard.written.is_empty(), "{outside} is no write");
                }
            }

            /// KR-REQ-14.34: a notice that names no path is a loss.
            #[test]
            fn a_loss_notice_that_names_no_path_is_a_loss() {
                let heard = heard_of(true, &[]);
                assert!(heard.lost.is_some());
                assert!(heard.written.is_empty());
            }

            /// KR-REQ-14.34: a notice at a path in the copy is a loss, and the path is kept like
            /// any other that was reported.
            #[test]
            fn a_loss_notice_in_the_copy_is_a_loss_and_keeps_the_path() {
                let heard = heard_of(true, &["/work/run/copy/sub/file"]);
                assert!(heard.lost.is_some());
                assert_eq!(heard.written, BTreeSet::from(["sub/file".to_owned()]));
            }

            /// A report that does not say that reports were lost is judged by its path alone,
            /// and a path outside the copy is no write.
            #[test]
            fn a_report_outside_the_copy_that_loses_nothing_is_no_loss_and_no_write() {
                let heard = heard_of(
                    false,
                    &[
                        "/",
                        "/work",
                        "/work/run",
                        "/work/run/other",
                        "/elsewhere/file",
                    ],
                );
                assert!(heard.lost.is_none());
                assert!(heard.written.is_empty());
            }

            /// A name beside a declared output is a write and the output is not, and the copy
            /// itself is written when a report names it.
            #[test]
            fn a_name_beside_a_declared_output_is_a_write_and_the_output_is_not() {
                let heard = heard_of(false, &["/work/run/copy/out", "/work/run/copy/sub/gen"]);
                assert!(heard.written.is_empty());
                let heard = heard_of(
                    false,
                    &[
                        "/work/run/copy/other",
                        "/work/run/copy/sub/x",
                        "/work/run/copy",
                    ],
                );
                assert!(heard.lost.is_none());
                assert_eq!(
                    heard.written,
                    BTreeSet::from(["".to_owned(), "other".to_owned(), "sub/x".to_owned()])
                );
            }

            /// KR-REQ-14.34: the creation of a folder at the path of a directory an output is in,
            /// and a change of its extended attributes, are no write by themselves, the copy's own
            /// directory among them when an output is at its root; every other report that names
            /// it is a write.
            #[test]
            fn a_creation_or_attribute_report_of_a_parent_is_no_write_and_any_other_is() {
                for parent in ["/work/run/copy", "/work/run/copy/sub"] {
                    for done in [Done::CreatedFolder, Done::Attributes] {
                        let heard = heard_done(false, done, &[parent]);
                        assert!(heard.written.is_empty(), "{parent} {done:?} is no write");
                    }
                    let heard = heard_done(false, Done::Other, &[parent]);
                    assert_eq!(heard.written.len(), 1, "{parent} is a write");
                }
            }

            /// KR-REQ-14.34: a creation of a name beside a declared output, or in a directory
            /// that no output is in, is a write all the same: what the host read at the start
            /// decides only the directories an output is in.
            #[test]
            fn a_creation_of_a_name_that_is_no_parent_is_a_write() {
                let heard = heard_done(
                    false,
                    Done::CreatedFolder,
                    &["/work/run/copy/other", "/work/run/copy/sub/x"],
                );
                assert_eq!(
                    heard.written,
                    BTreeSet::from(["other".to_owned(), "sub/x".to_owned()])
                );
            }
        }
    }

    /// What the watches of one process may hold of its open files.
    ///
    /// FSEvents holds one open file for each component of each path it is given and eight more
    /// for each watch of a copy and the directory beside it. That was measured on macOS 27.2.1
    /// (build 26B131) with notify 9.0.0: 29 for a copy 11 components deep, 31 at 12 and 39 at 16,
    /// with the soft limit of open files at 256 and at 2560, and nothing else was measured. At 11
    /// components a process whose limit started at 256, which its first stream raised to 2560,
    /// held 88 such watches before a watch could not start, and past that the library can end
    /// the process. So the host refuses first: a watch is admitted only while the cost of the
    /// watches the process holds, with its own, is no more than half of the process's soft limit
    /// of open files, read when the watch starts, and half of 2560 where that limit is higher or
    /// there is none, since nothing was measured past it. The other half is an allowance for the
    /// rest of the process and not a reservation: the host does not count the process's other
    /// open files, nor the one directory that each watch reopens beside its copy, so a process
    /// that holds more than that half for other reasons can still reach the edge. Until the
    /// first stream has raised the limit, and for good where a hard limit of 256 does not allow
    /// the raise, the budget admits at most 4 watches of 29. A limit below twice the cost of one
    /// watch, 58 at 11 components, refuses every watch with the same words.
    #[cfg(any(target_os = "macos", test))]
    mod budget {
        use std::path::{Component, Path};
        use std::sync::atomic::{AtomicU64, Ordering};

        /// The soft limit of open files under which the cost and the ceiling of a watch were
        /// measured.
        const MEASURED: u64 = 2560;

        /// What a watch holds of its own, apart from a file for each component of its two paths.
        const OWN: u64 = 8;

        /// Why a watch was not made when the budget did not admit it.
        pub(super) const REFUSED: &str = "the copy could not be watched: too many copies are \
                                          watched at once";

        /// What the live watches of a process cost, in open files.
        pub(super) struct Budget {
            live: AtomicU64,
        }

        /// What one watch has taken of the budget, given back when it is dropped.
        struct Cost<'a> {
            budget: &'a Budget,
            cost: u64,
        }

        impl Drop for Cost<'_> {
            fn drop(&mut self) {
                self.budget.live.fetch_sub(self.cost, Ordering::AcqRel);
            }
        }

        /// A watch and its cost, held for as long as the watch lives. The watch is dropped first
        /// and the cost goes back after it, on every path of the host's own code, so that the
        /// budget never admits another watch while the stream of this one still holds its files.
        /// The library's own panic is outside that: it can leave the stream open before the cost
        /// goes back.
        pub(super) struct Held<'a, T> {
            _watch: T,
            _cost: Cost<'a>,
        }

        impl Budget {
            /// A budget with no live watch.
            pub(super) const fn new() -> Self {
                Self {
                    live: AtomicU64::new(0),
                }
            }

            /// Makes the watch with `start` when the process's watches, with this one, would cost
            /// no more than half of `soft`, the soft limit of open files, taken as 2560 where it
            /// is higher or none, and makes none otherwise: the library is not asked. A watch
            /// that could not be started holds nothing.
            pub(super) fn admit<T>(
                &self,
                cost: u64,
                soft: Option<u64>,
                start: impl FnOnce() -> Result<T, String>,
            ) -> Result<Held<'_, T>, String> {
                let half = soft.map_or(MEASURED, |soft| soft.min(MEASURED)) / 2;
                self.live
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                        live.checked_add(cost).filter(|total| *total <= half)
                    })
                    .map_err(|_| REFUSED.to_owned())?;
                let cost = Cost { budget: self, cost };
                let watch = start()?;
                Ok(Held {
                    _watch: watch,
                    _cost: cost,
                })
            }
        }

        /// What a watch of the copy and the directory beside it holds of the process's open
        /// files: one for each component of each of the two paths and eight of its own.
        pub(super) fn cost_of(copy: &Path, beside: &Path) -> u64 {
            let components = |path: &Path| {
                path.components()
                    .filter(|component| matches!(component, Component::Normal(_)))
                    .count()
            };
            u64::try_from(components(copy) + components(beside))
                .map_or(u64::MAX, |n| n.saturating_add(OWN))
        }

        #[cfg(test)]
        mod tests {
            use std::cell::Cell;
            use std::path::Path;
            use std::sync::atomic::Ordering;

            use super::{Budget, Held, cost_of};

            /// A watch of `cost` made with nothing to start, held or refused.
            fn admitted(budget: &Budget, cost: u64, soft: Option<u64>) -> Option<Held<'_, ()>> {
                budget.admit(cost, soft, || Ok(())).ok()
            }

            /// How many watches of `cost` the budget admits, one after the other, under `soft`,
            /// and whether the next is refused.
            fn admits(cost: u64, soft: Option<u64>) -> (usize, bool) {
                let budget = Budget::new();
                let mut held = Vec::new();
                while let Some(watch) = admitted(&budget, cost, soft) {
                    held.push(watch);
                    if held.len() > 1000 {
                        return (held.len(), false);
                    }
                }
                (held.len(), true)
            }

            /// The store's copy under a home directory is 11 components deep.
            const STORE: &str = "/Users/someone/Library/Application Support/KalaReach/host/environments/\
                                 0a1b2c3d/changesets/materialisations/id";

            /// The same place with five more components, 16 deep.
            const DEEPER: &str = "/Users/someone/Library/Application Support/KalaReach/host/environments/\
                                  0a1b2c3d/changesets/materialisations/a/b/c/d/e/id";

            /// What a watch of the copy at `copy` and the directory it is in costs.
            fn cost_at(copy: &str) -> u64 {
                let copy = Path::new(copy);
                cost_of(copy, copy.parent().unwrap_or(Path::new("/")))
            }

            fn store_cost() -> u64 {
                cost_at(STORE)
            }

            /// A watch holds a file for each component of its two paths and eight of its own.
            #[test]
            fn a_watch_costs_one_for_each_component_of_both_paths_and_eight_more() {
                assert_eq!(cost_of(Path::new("/a/b/c"), Path::new("/a/b")), 13);
                assert_eq!(store_cost(), 29);
                assert_eq!(
                    cost_of(Path::new("/x/a/b/c"), Path::new("/x/a/b")),
                    13 + 2,
                    "a deeper path costs two more for each component"
                );
            }

            /// The last watch that stays within half of the limit is admitted and the next is
            /// refused without the library being asked.
            #[test]
            fn the_last_watch_within_half_the_limit_is_admitted_and_the_next_is_refused() {
                let budget = Budget::new();
                let held: Vec<_> = (0..3).map(|_| admitted(&budget, 29, Some(174))).collect();
                assert!(held.iter().all(Option::is_some), "29 x 3 is half of 174");
                let asked = Cell::new(false);
                let fourth = budget.admit(29, Some(174), || {
                    asked.set(true);
                    Ok(())
                });
                assert!(fourth.is_err(), "the fourth is past half of 174");
                assert!(!asked.get(), "a refused watch does not ask the library");
            }

            /// A watch that passes half of the limit by one is refused.
            #[test]
            fn a_watch_that_would_pass_half_the_limit_by_one_is_refused() {
                let budget = Budget::new();
                let first = admitted(&budget, 29, Some(172));
                let second = admitted(&budget, 29, Some(172));
                assert!(first.is_some() && second.is_some());
                assert!(admitted(&budget, 29, Some(172)).is_none(), "87 is past 86");
            }

            /// A dropped watch gives its cost back, so a watch the budget refused is admitted.
            #[test]
            fn a_dropped_watch_gives_its_cost_back() {
                let budget = Budget::new();
                let mut held: Vec<_> = (0..3).map(|_| admitted(&budget, 29, Some(174))).collect();
                assert!(admitted(&budget, 29, Some(174)).is_none());
                held.pop();
                assert!(admitted(&budget, 29, Some(174)).is_some());
            }

            /// A watch that could not be started holds nothing: its error comes back as it is,
            /// and the budget is whole again.
            #[test]
            fn a_watch_that_could_not_be_started_gives_its_cost_back() {
                let budget = Budget::new();
                let failed = budget.admit(29, Some(58), || Err::<(), _>("no stream".to_owned()));
                assert_eq!(failed.err().as_deref(), Some("no stream"));
                let held: Vec<_> = (0..2).map(|_| admitted(&budget, 29, Some(116))).collect();
                assert!(
                    held.iter().all(Option::is_some),
                    "nothing was held by the failure"
                );
            }

            /// What the budget counted when this was dropped.
            struct Probe<'a> {
                budget: &'a Budget,
                counted: &'a Cell<Option<u64>>,
            }

            impl Drop for Probe<'_> {
                fn drop(&mut self) {
                    self.counted
                        .set(Some(self.budget.live.load(Ordering::Acquire)));
                }
            }

            /// A dropped watch is dropped before its cost goes back: while it is, the budget still
            /// counts the cost, so no other watch is admitted while its stream holds its files.
            #[test]
            fn a_dropped_watch_is_dropped_before_its_cost_goes_back() {
                let budget = Budget::new();
                let counted = Cell::new(None);
                let held = budget.admit(29, Some(256), || {
                    Ok(Probe {
                        budget: &budget,
                        counted: &counted,
                    })
                });
                assert!(held.is_ok(), "the watch is admitted");
                assert_eq!(counted.get(), None, "the watch is held");
                drop(held);
                assert_eq!(
                    counted.get(),
                    Some(29),
                    "the cost was still counted when the watch was dropped"
                );
                assert!(
                    admitted(&budget, 29, Some(256)).is_some(),
                    "and it went back after"
                );
            }

            /// A deeper path costs more, so fewer watches are admitted under the same limit.
            #[test]
            fn a_deeper_path_costs_more_and_so_fewer_are_admitted() {
                assert_eq!(cost_at(DEEPER), 39);
                assert_eq!(admits(cost_at(STORE), Some(256)), (4, true));
                assert_eq!(admits(cost_at(DEEPER), Some(256)), (3, true));
            }

            /// A soft limit of 256 admits what half of it allows.
            #[test]
            fn a_limit_of_256_admits_what_half_of_it_allows() {
                assert_eq!(
                    admits(29, Some(256)),
                    (4, true),
                    "116 is within 128, 145 is not"
                );
            }

            /// Nothing was measured past a limit of 2560: a higher limit, and none, admit what
            /// half of 2560 allows and refuse the next.
            #[test]
            fn a_limit_above_2560_or_none_admits_what_half_of_2560_allows() {
                assert_eq!(admits(29, Some(2560)), (44, true), "1276 is within 1280");
                assert_eq!(admits(29, Some(1_048_576)), (44, true));
                assert_eq!(admits(29, None), (44, true));
            }

            /// A cost that overflows the count is refused.
            #[test]
            fn a_cost_that_overflows_the_count_is_refused() {
                let budget = Budget::new();
                let first = admitted(&budget, 29, Some(2560));
                assert!(first.is_some());
                assert!(admitted(&budget, u64::MAX, Some(2560)).is_none());
            }
        }
    }

    /// What a directory an output is in was before the command started, to be read again at the
    /// end.
    ///
    /// The stamp of such a directory is not recorded, because making the output changes it. Its
    /// device and inode, that it is a directory, and its extended attributes do not change when a
    /// name is made in it. The first three are another when the directory was removed and made
    /// again, and the attributes are another when one is added, removed or given another value.
    #[cfg(any(target_os = "macos", test))]
    mod record {
        use std::collections::BTreeMap;
        #[cfg(target_os = "macos")]
        use std::path::Path;

        /// The most extended attributes of a directory that the host reads.
        #[cfg(target_os = "macos")]
        const MOST_ATTRIBUTES: usize = 64;

        /// The most bytes that the names of those attributes take, each with its end.
        #[cfg(target_os = "macos")]
        const MOST_NAME_BYTES: usize = 8192;

        /// The most bytes of one value.
        #[cfg(target_os = "macos")]
        const MOST_VALUE_BYTES: usize = 4096;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) struct Identity {
            device: u64,
            inode: u64,
            directory: bool,
        }

        impl Identity {
            /// What is at `path` now, a link not followed.
            #[cfg(target_os = "macos")]
            pub(super) fn of(path: &Path) -> std::io::Result<Self> {
                use std::os::unix::fs::MetadataExt as _;

                let metadata = std::fs::symlink_metadata(path)?;
                Ok(Self {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    directory: metadata.is_dir(),
                })
            }

            /// Whether `now` is another place than this one: on another device, with another
            /// inode, or no longer a directory.
            pub(super) fn is_another(self, now: Self) -> bool {
                self.device != now.device
                    || self.inode != now.inode
                    || self.directory != now.directory
            }
        }

        /// The extended attributes of a directory, each name with its value.
        type Attributes = BTreeMap<Vec<u8>, Vec<u8>>;

        /// What a directory is and what extended attributes it holds.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(super) struct Record {
            identity: Identity,
            attributes: Attributes,
        }

        impl Record {
            /// What is at `path` now, a link not followed. A directory with more extended
            /// attributes than the host reads, or larger ones, is an error, and so is an
            /// attribute that is gone before it is read.
            #[cfg(target_os = "macos")]
            pub(super) fn of(path: &Path) -> std::io::Result<Self> {
                Ok(Self {
                    identity: Identity::of(path)?,
                    attributes: attributes_of(path)?,
                })
            }

            /// Whether `now` is another place than this one, or holds other extended attributes:
            /// one added, one removed, or one with another value.
            pub(super) fn is_another(&self, now: &Self) -> bool {
                self.identity.is_another(now.identity) || self.attributes != now.attributes
            }
        }

        /// The extended attributes at `path`, a link not followed.
        #[cfg(target_os = "macos")]
        fn attributes_of(path: &Path) -> std::io::Result<Attributes> {
            use rustix::io::Errno;

            let too_many = || {
                std::io::Error::other(
                    "it has more extended attributes, or larger ones, than the host reads",
                )
            };
            let read = |error: Errno| {
                if error == Errno::RANGE {
                    too_many()
                } else {
                    error.into()
                }
            };
            let mut listed = vec![0u8; MOST_NAME_BYTES];
            let length = rustix::fs::llistxattr(path, &mut listed[..]).map_err(read)?;
            let names: Vec<&[u8]> = listed[..length]
                .split(|byte| *byte == 0)
                .filter(|name| !name.is_empty())
                .collect();
            if names.len() > MOST_ATTRIBUTES {
                return Err(too_many());
            }
            let mut attributes = Attributes::new();
            for name in names {
                let mut value = vec![0u8; MOST_VALUE_BYTES];
                let length = rustix::fs::lgetxattr(path, name, &mut value[..]).map_err(read)?;
                value.truncate(length);
                attributes.insert(name.to_vec(), value);
            }
            Ok(attributes)
        }

        #[cfg(test)]
        mod tests {
            use std::collections::BTreeMap;

            use super::{Identity, Record};

            fn directory(device: u64, inode: u64) -> Identity {
                Identity {
                    device,
                    inode,
                    directory: true,
                }
            }

            /// A directory with the device and the inode it had is the place it was.
            #[test]
            fn a_directory_with_the_device_and_inode_it_had_is_the_same_place() {
                assert!(!directory(1, 2).is_another(directory(1, 2)));
            }

            /// KR-REQ-14.34: a directory on another device is another place.
            #[test]
            fn a_directory_on_another_device_is_another_place() {
                assert!(
                    directory(1, 2).is_another(directory(3, 2)),
                    "the device is not the one the directory was on"
                );
            }

            /// KR-REQ-14.34: a directory with another inode is another place.
            #[test]
            fn a_directory_with_another_inode_is_another_place() {
                assert!(
                    directory(1, 2).is_another(directory(1, 3)),
                    "the inode is not the one the directory had"
                );
            }

            /// KR-REQ-14.34: what is no longer a directory is another place.
            #[test]
            fn what_is_no_longer_a_directory_is_another_place() {
                let file = Identity {
                    device: 1,
                    inode: 2,
                    directory: false,
                };
                assert!(
                    directory(1, 2).is_another(file),
                    "what was a directory is not one now"
                );
            }

            /// A directory holding the attributes of the same names and values is as it was.
            fn record(attributes: &[(&str, &str)]) -> Record {
                Record {
                    identity: directory(1, 2),
                    attributes: attributes
                        .iter()
                        .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
                        .collect::<BTreeMap<_, _>>(),
                }
            }

            #[test]
            fn a_directory_holding_the_attributes_it_held_is_as_it_was() {
                assert!(
                    !record(&[("a", "1"), ("b", "2")])
                        .is_another(&record(&[("a", "1"), ("b", "2")]))
                );
            }

            /// KR-REQ-14.34: a directory with an attribute more is not as it was.
            #[test]
            fn a_directory_with_an_attribute_added_is_another() {
                assert!(record(&[("a", "1")]).is_another(&record(&[("a", "1"), ("b", "2")])));
            }

            /// KR-REQ-14.34: a directory with an attribute less is not as it was.
            #[test]
            fn a_directory_with_an_attribute_removed_is_another() {
                assert!(record(&[("a", "1"), ("b", "2")]).is_another(&record(&[("a", "1")])));
            }

            /// KR-REQ-14.34: a directory with an attribute of another value is not as it was.
            #[test]
            fn a_directory_with_an_attribute_of_another_value_is_another() {
                assert!(record(&[("a", "1")]).is_another(&record(&[("a", "2")])));
            }
        }
    }

    #[cfg(target_os = "macos")]
    mod names {
        use std::collections::{BTreeMap, BTreeSet};
        use std::path::{Path, PathBuf};
        use std::sync::{Arc, Mutex, PoisonError, mpsc};
        use std::time::{Duration, Instant};

        use notify::event::{CreateKind, EventKind, MetadataKind, ModifyKind};
        use notify::{Event, RecursiveMode, Watcher as _};

        use kr_transfer::{AuthorisedDirectory, RelativeName};

        use super::budget::{self, Budget, Held};
        use super::judged::{Done, Heard, Places};
        use super::record::Record;

        /// What the watches of this process cost, in open files.
        static WATCHES: Budget = Budget::new();

        /// The process's soft limit of open files, none when it has none.
        fn soft_limit() -> Option<u64> {
            rustix::process::getrlimit(rustix::process::Resource::Nofile).current
        }

        /// How long the host waits for the watcher to report a file the host wrote itself.
        ///
        /// FSEvents delivers reports on its own schedule, so the host makes a change of its own at
        /// the moment it asks and waits for that change to be reported. The report shows how far
        /// the watcher has come in its stream, and not that every earlier change was reported.
        const REPORT_WAIT: Duration = Duration::from_secs(10);

        /// The start of the name of a file the host writes to find out whether the watcher is
        /// up to date.
        const MARK: &str = ".mark-";

        /// What the watcher's handler and the host both hold.
        #[derive(Debug, Default)]
        struct Shared {
            heard: Heard,
            /// The file the host is waiting to hear of.
            awaited: Option<PathBuf>,
        }

        /// What a report of the watcher says was done to the paths it names. Only the creation of
        /// a folder has a variant of its own: the library reports a mount as a creation of kind
        /// other, and that is a write.
        fn done_by(kind: &EventKind) -> Done {
            match kind {
                EventKind::Create(CreateKind::Folder) => Done::CreatedFolder,
                EventKind::Modify(ModifyKind::Metadata(MetadataKind::Extended)) => Done::Attributes,
                _ => Done::Other,
            }
        }

        /// Takes one report from the watcher into `shared`, and gives back the file the host is
        /// waiting to hear of when the report names it.
        fn take(
            places: &Places,
            shared: &mut Shared,
            report: notify::Result<Event>,
        ) -> Option<PathBuf> {
            match report {
                Ok(event) => {
                    places.hear(
                        &mut shared.heard,
                        event.need_rescan(),
                        done_by(&event.kind),
                        &event.paths,
                    );
                    let awaited = shared.awaited.as_ref();
                    event.paths.into_iter().find(|path| Some(path) == awaited)
                }
                Err(error) => {
                    shared
                        .heard
                        .lost
                        .get_or_insert_with(|| format!("the watcher failed: {error}"));
                    None
                }
            }
        }

        /// A watch on the copy, which reports each name written in the directories declared
        /// outputs are in, and each change to those directories themselves.
        pub struct NameWatch {
            /// The watcher, held with what its stream costs the process: the cost goes back after
            /// the stream has stopped, on every path of the host's own code.
            _watcher: Held<'static, notify::RecommendedWatcher>,
            shared: Arc<Mutex<Shared>>,
            reported: Mutex<mpsc::Receiver<PathBuf>>,
            site: Site,
        }

        /// Where a watch is, and what each directory an output is in was when the watch started.
        struct Site {
            /// The directory the copy is in, where the host writes the files it marks time with.
            beside: AuthorisedDirectory,
            beside_path: PathBuf,
            copy_path: PathBuf,
            /// What each directory an output is in was, by its path in the copy.
            records: BTreeMap<String, Record>,
        }

        /// The place of a directory in the copy, the empty path being the copy itself.
        fn place_in(copy_path: &Path, relative: &str) -> PathBuf {
            if relative.is_empty() {
                copy_path.to_path_buf()
            } else {
                copy_path.join(relative)
            }
        }

        /// What each directory an output is in is now, by its path in the copy.
        fn records_of(
            copy_path: &Path,
            parents: &BTreeMap<String, BTreeSet<String>>,
        ) -> Result<BTreeMap<String, Record>, String> {
            parents
                .keys()
                .map(|relative| {
                    Record::of(&place_in(copy_path, relative))
                        .map(|record| (relative.clone(), record))
                        .map_err(|error| {
                            format!("a directory an output is in could not be examined: {error}")
                        })
                })
                .collect()
        }

        impl Site {
            /// Reads where `copy` is, with `beside` the directory it is in, and what each
            /// directory an output is in is, its identity and its extended attributes, before the
            /// command starts, to be read again when it has ended. A failure is the host's own and
            /// comes before the budget is asked.
            fn of(
                copy: &AuthorisedDirectory,
                beside: &AuthorisedDirectory,
                parents: &BTreeMap<String, BTreeSet<String>>,
            ) -> Result<Self, String> {
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
                let reopened = beside
                    .try_clone()
                    .map_err(|error| format!("the copy's place could not be reopened: {error}"))?;
                let records = records_of(&copy_path, parents)?;
                Ok(Self {
                    beside: reopened,
                    beside_path,
                    copy_path,
                    records,
                })
            }
        }

        impl std::fmt::Debug for NameWatch {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter
                    .debug_struct("NameWatch")
                    .field("copy", &self.site.copy_path)
                    .finish_non_exhaustive()
            }
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
                // Every step that can fail without the library is made before the admission, so
                // that after it only the library's own calls and the host's own marker file can
                // fail.
                let site = Site::of(copy, beside, parents)?;
                let places = Arc::new(Places::new(site.copy_path.clone(), parents.clone()));
                let shared = Arc::new(Mutex::new(Shared::default()));
                let (tell, reported) = mpsc::channel();
                // Each report is judged here, as it arrives, so the host keeps what it needs of a
                // run's reports and not the reports.
                let handler = {
                    let (places, shared) = (Arc::clone(&places), Arc::clone(&shared));
                    move |report: notify::Result<Event>| {
                        let mut shared = shared.lock().unwrap_or_else(PoisonError::into_inner);
                        if let Some(path) = take(&places, &mut shared, report) {
                            let _ = tell.send(path);
                        }
                    }
                };
                // FSEvents sends a notice that it lost reports at the path where it lost them,
                // often a directory above the copy or the root of the volume. The backend passes
                // every notice it receives on this stream to the handler whatever path it names,
                // and the handler takes each as a loss of the copy's reports too. The host cannot
                // see a loss that FSEvents does not announce: its own marker file, reported in
                // time, shows only that the watcher has not fallen behind, and nothing more.
                //
                // FSEvents holds open files for each stream root, and a start that fails for want
                // of them can end the process, so the host asks only for a watch that the budget
                // admits.
                let watcher = WATCHES.admit(
                    budget::cost_of(&site.copy_path, &site.beside_path),
                    soft_limit(),
                    || {
                        let mut watcher = notify::recommended_watcher(handler)
                            .map_err(|error| format!("no watcher could be started: {error}"))?;
                        watcher
                            .watch(&site.copy_path, RecursiveMode::Recursive)
                            .and_then(|()| {
                                watcher.watch(&site.beside_path, RecursiveMode::NonRecursive)
                            })
                            .map_err(|error| format!("the copy could not be watched: {error}"))?;
                        Ok(watcher)
                    },
                )?;
                let watch = Self {
                    _watcher: watcher,
                    shared,
                    reported: Mutex::new(reported),
                    site,
                };
                watch.up_to_date()?;
                watch
                    .shared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .heard = Heard::default();
                Ok(Some(watch))
            }

            /// Writes a file beside the copy and waits until the watcher has reported it. That
            /// shows how far the watcher has come in its stream, and not that every earlier change
            /// was reported.
            fn up_to_date(&self) -> Result<(), String> {
                let mark = format!("{MARK}{}", kr_ipc::new_uuid());
                let name = RelativeName::parse(&mark)
                    .map_err(|error| format!("a file to mark time with: {error}"))?;
                let marked = self.site.beside_path.join(&mark);
                self.shared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .awaited = Some(marked.clone());
                let outcome = self
                    .site
                    .beside
                    .create_new(&name)
                    .map_err(|error| format!("a file to mark time with: {error}"))
                    .and_then(|_| self.until_reported(&marked));
                self.shared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .awaited = None;
                let _ = self.site.beside.remove(&name);
                outcome
            }

            fn until_reported(&self, marked: &Path) -> Result<(), String> {
                let reported = self.reported.lock().unwrap_or_else(PoisonError::into_inner);
                let deadline = Instant::now() + REPORT_WAIT;
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    match reported.recv_timeout(left) {
                        Ok(path) if path == marked => return Ok(()),
                        // A report of an earlier file of the host's own.
                        Ok(_) => {}
                        Err(_) => {
                            return Err("the watcher did not report a change the host made \
                                        itself, so it cannot be trusted to have reported the \
                                        run's"
                                .to_owned());
                        }
                    }
                }
            }

            /// The directories an output is in that are not what they were when the watch
            /// started: gone, no longer a directory, on another device or with another inode, or
            /// with an extended attribute added, removed or changed in value. This reads the copy
            /// and not the watcher's reports, which come on the platform's schedule.
            fn changed(&self) -> Result<BTreeSet<String>, String> {
                let mut changed = BTreeSet::new();
                for (relative, before) in &self.site.records {
                    match Record::of(&place_in(&self.site.copy_path, relative)) {
                        Ok(now) if !before.is_another(&now) => {}
                        Ok(_) => {
                            changed.insert(relative.clone());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            changed.insert(relative.clone());
                        }
                        Err(error) => {
                            return Err(format!(
                                "a directory an output is in could not be examined: {error}"
                            ));
                        }
                    }
                }
                Ok(changed)
            }

            /// The paths written beside a declared output since the watch started, and the
            /// directories themselves when something was done to them or when one is not what it
            /// was, whether the watcher reported it or not.
            pub fn drain(&self) -> Result<Vec<String>, String> {
                self.up_to_date()?;
                let changed = self.changed()?;
                let shared = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
                match &shared.heard.lost {
                    Some(why) => Err(why.clone()),
                    None => Ok(shared
                        .heard
                        .written
                        .iter()
                        .chain(&changed)
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect()),
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use std::collections::{BTreeMap, BTreeSet};
            use std::path::{Path, PathBuf};
            use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};

            use notify::Event;
            use notify::event::{
                CreateKind, DataChange, EventKind, Flag, MetadataKind, ModifyKind, RemoveKind,
                RenameMode,
            };

            use super::{
                AuthorisedDirectory, Budget, Duration, Held, Instant, MARK, NameWatch, Places,
                Shared, Site, WATCHES, budget, take,
            };

            /// A copy at `/work/run/copy`, in the directory `/work/run`, with a declared output
            /// `out` at its root.
            fn places() -> Places {
                Places::new(
                    PathBuf::from("/work/run/copy"),
                    BTreeMap::from([(String::new(), BTreeSet::from(["out".to_owned()]))]),
                )
            }

            /// A notice that reports were lost, as notify 9.0.0 sends it when FSEvents says
            /// "must scan subdirectories": an event of no particular kind with the rescan flag,
            /// the reason FSEvents gave when it gave one, and the path FSEvents named.
            fn notice(reason: Option<&str>, path: Option<&str>) -> Event {
                let mut event = Event::new(EventKind::Other).set_flag(Flag::Rescan);
                if let Some(reason) = reason {
                    event = event.set_info(reason);
                }
                if let Some(path) = path {
                    event = event.add_path(PathBuf::from(path));
                }
                event
            }

            /// KR-REQ-14.34: the notices notify 9.0.0 sends for a loss at a path the watcher does
            /// not watch are a loss, with each reason FSEvents gives and with none.
            #[test]
            fn the_notices_notify_sends_for_a_loss_outside_the_copy_are_a_loss() {
                for (reason, path) in [
                    (Some("rescan: user dropped"), "/"),
                    (Some("rescan: kernel dropped"), "/work"),
                    (None, "/work/run"),
                ] {
                    let mut shared = Shared::default();
                    let seen = take(&places(), &mut shared, Ok(notice(reason, Some(path))));
                    assert_eq!(seen, None, "{path}");
                    assert!(shared.heard.lost.is_some(), "{path} is a loss");
                    assert!(shared.heard.written.is_empty(), "{path} is no write");
                }
            }

            /// KR-REQ-14.34: a notice with no path is a loss.
            #[test]
            fn a_notice_notify_sends_with_no_path_is_a_loss() {
                let mut shared = Shared::default();
                take(&places(), &mut shared, Ok(notice(None, None)));
                assert!(shared.heard.lost.is_some());
            }

            /// A failure the watcher reports instead of an event is a loss, and says so.
            #[test]
            fn a_failure_the_watcher_reports_is_a_loss() {
                let mut shared = Shared::default();
                take(
                    &places(),
                    &mut shared,
                    Err(notify::Error::generic("the stream stopped")),
                );
                assert!(shared.heard.lost.is_some(), "the failure is a loss");
                let lost = shared.heard.lost.unwrap_or_default();
                assert!(lost.contains("the watcher failed"), "{lost}");
            }

            /// The file the host is waiting to hear of is given back when a report names it, and
            /// no other path is.
            #[test]
            fn the_file_the_host_waits_for_is_given_back_when_a_report_names_it() {
                let awaited = PathBuf::from("/work/run/.mark-1");
                let mut shared = Shared {
                    awaited: Some(awaited.clone()),
                    ..Shared::default()
                };
                let other = Event::new(EventKind::Create(CreateKind::File))
                    .add_path(PathBuf::from("/work/run/.mark-0"));
                assert_eq!(take(&places(), &mut shared, Ok(other)), None);
                let marked =
                    Event::new(EventKind::Create(CreateKind::File)).add_path(awaited.clone());
                assert_eq!(take(&places(), &mut shared, Ok(marked)), Some(awaited));
                assert!(shared.heard.lost.is_none());
            }

            /// Since 9.0.0 the watcher also says when a place it watches is renamed or removed, at
            /// that place's own path. A report at the copy's own path is a write to the copy. A
            /// report at the directory beside the copy is not, as nothing in the copy changed.
            #[test]
            fn a_change_of_root_at_the_copy_is_a_write_and_beside_it_is_not() {
                let changed = |path: &str| {
                    Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::From)))
                        .set_info("root changed")
                        .add_path(PathBuf::from(path))
                };
                let mut shared = Shared::default();
                take(&places(), &mut shared, Ok(changed("/work/run")));
                assert!(shared.heard.written.is_empty());
                take(&places(), &mut shared, Ok(changed("/work/run/copy")));
                assert_eq!(shared.heard.written, BTreeSet::from([String::new()]));
                assert!(shared.heard.lost.is_none());
            }

            /// The whole budget of this process, held for as long as this lives, so that a start
            /// made meanwhile is refused at any limit. The cases that hold it run one at a time,
            /// and no other case of this program starts a watch.
            struct WholeBudget {
                _held: Held<'static, ()>,
                _turn: MutexGuard<'static, ()>,
            }

            fn the_whole_budget() -> WholeBudget {
                static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
                let turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
                // Half of 2560, the most that any limit admits.
                let held = WATCHES
                    .admit(1280, Some(2560), || Ok(()))
                    .expect("the budget is free");
                WholeBudget {
                    _held: held,
                    _turn: turn,
                }
            }

            /// A copy in a folder of its own, with the directory beside it, both opened, and one
            /// declared output at its root.
            struct Copy {
                _root: tempfile::TempDir,
                copy_path: PathBuf,
                copy: AuthorisedDirectory,
                beside: AuthorisedDirectory,
                parents: BTreeMap<String, BTreeSet<String>>,
            }

            fn a_copy() -> Copy {
                let root = tempfile::TempDir::new().expect("a folder to work in");
                let beside_path = std::fs::canonicalize(root.path())
                    .expect("the folder resolves")
                    .join("materialisations");
                let copy_path = beside_path.join("copy");
                std::fs::create_dir_all(&copy_path).expect("the copy");
                let open = |path: &PathBuf| {
                    AuthorisedDirectory::open_root(
                        kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
                        path,
                    )
                    .expect("the directory opens")
                };
                Copy {
                    copy: open(&copy_path),
                    beside: open(&beside_path),
                    _root: root,
                    copy_path,
                    parents: BTreeMap::from([(String::new(), BTreeSet::from(["out".to_owned()]))]),
                }
            }

            /// KR-REQ-14.34: a start that the budget does not admit is refused, with the words
            /// that make the result indeterminate, and the library is not asked: with the whole
            /// budget held, a start for a copy returns the refusal and makes no stream.
            #[test]
            fn a_start_past_the_budget_is_refused_without_a_stream() {
                let made = a_copy();
                let _whole = the_whole_budget();
                let started = NameWatch::start(&made.copy, &made.beside, &made.parents);
                assert_eq!(
                    started.err().as_deref(),
                    Some(budget::REFUSED),
                    "the start was not refused"
                );
            }

            /// What the host does itself comes before the budget is asked: with the whole budget
            /// held, a start for a copy that is no longer where it was opened says that, and not
            /// that too many copies are watched.
            #[test]
            fn a_step_of_the_host_that_fails_is_reported_before_the_budget_is_asked() {
                let made = a_copy();
                std::fs::rename(&made.copy_path, made.copy_path.with_file_name("moved"))
                    .expect("the copy is moved away");
                std::fs::create_dir(&made.copy_path).expect("another directory is at its place");
                let _whole = the_whole_budget();
                let started = NameWatch::start(&made.copy, &made.beside, &made.parents);
                assert_eq!(
                    started.err().as_deref(),
                    Some("the copy is no longer where it was opened"),
                    "the host's own step did not come first"
                );
            }

            /// The directories above the declared outputs `out` at the copy's root and
            /// `target/debug`.
            fn parents_of_outputs() -> BTreeMap<String, BTreeSet<String>> {
                BTreeMap::from([
                    (String::new(), BTreeSet::from(["out".to_owned()])),
                    ("target".to_owned(), BTreeSet::from(["debug".to_owned()])),
                ])
            }

            /// A copy with the directories above its declared outputs, the directory beside it
            /// where the host writes its markers, and a watch with no stream: what a stream would
            /// report is delivered by the case, through `take`, the way the watcher's handler
            /// delivers it.
            struct Place {
                _root: tempfile::TempDir,
                copy: PathBuf,
                watch: NameWatch,
                places: Arc<Places>,
                shared: Arc<Mutex<Shared>>,
                tell: mpsc::Sender<PathBuf>,
            }

            /// A watcher that holds no stream, held with a cost of nothing from a budget of its own.
            fn no_stream() -> Held<'static, notify::RecommendedWatcher> {
                static NO_STREAM: Budget = Budget::new();
                let started = NO_STREAM.admit(0, None, || {
                    notify::recommended_watcher(|_: notify::Result<Event>| {})
                        .map_err(|error| format!("a watcher with no stream: {error}"))
                });
                match started {
                    Ok(held) => held,
                    Err(why) => panic!("a watch that costs nothing is admitted: {why}"),
                }
            }

            /// The attribute that the cases put on the directory `target` before the host reads
            /// it, so that what the host records holds an attribute that the cases control.
            const KEPT: &str = "kr.test";

            fn set_attribute(path: &Path, name: &str, value: &[u8]) {
                rustix::fs::lsetxattr(path, name, value, rustix::fs::XattrFlags::empty())
                    .expect("the attribute is set");
            }

            /// A folder of its own with the copy and the directory beside it, both opened. The
            /// copy holds the directories above its declared outputs, `target` with the attribute
            /// that the cases control.
            struct Layout {
                _root: tempfile::TempDir,
                copy: PathBuf,
                copy_directory: AuthorisedDirectory,
                beside: AuthorisedDirectory,
            }

            fn a_layout() -> Layout {
                let root = tempfile::TempDir::new().expect("a directory to work in");
                let root_path = std::fs::canonicalize(root.path()).expect("the directory resolves");
                let beside_path = root_path.join("materialisations");
                let copy = beside_path.join("copy");
                std::fs::create_dir_all(copy.join("target/debug")).expect("the directories above");
                set_attribute(&copy.join("target"), KEPT, b"one");
                let open = |path: &Path| {
                    AuthorisedDirectory::open_root(
                        kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
                        path,
                    )
                    .expect("the directory opens")
                };
                let (copy_directory, beside) = (open(&copy), open(&beside_path));
                Layout {
                    _root: root,
                    copy,
                    copy_directory,
                    beside,
                }
            }

            fn a_place() -> Place {
                let layout = a_layout();
                let places = Arc::new(Places::new(layout.copy.clone(), parents_of_outputs()));
                let shared = Arc::new(Mutex::new(Shared::default()));
                let (tell, reported) = mpsc::channel();
                let watch = NameWatch {
                    _watcher: no_stream(),
                    shared: Arc::clone(&shared),
                    reported: Mutex::new(reported),
                    site: Site::of(
                        &layout.copy_directory,
                        &layout.beside,
                        &parents_of_outputs(),
                    )
                    .expect("the directories above are examined"),
                };
                Place {
                    _root: layout._root,
                    copy: layout.copy,
                    watch,
                    places,
                    shared,
                    tell,
                }
            }

            fn report(kind: EventKind, path: &Path) -> Event {
                Event::new(kind).add_path(path.to_path_buf())
            }

            /// What the run does: removes the directory an output is in and makes it again, with
            /// the output in it again.
            fn replace_the_parent(copy: &Path) {
                std::fs::remove_dir_all(copy.join("target")).expect("the run removes the parent");
                std::fs::create_dir_all(copy.join("target/debug")).expect("and makes it again");
                std::fs::write(copy.join("target/debug/artefact"), "built again\n")
                    .expect("and the output with it");
            }

            /// Delivers `before`, waits for the host's marker to be written and runs `at_marker`,
            /// delivers the report of the marker, and delivers `after` once the host has decided,
            /// which the returned sender says.
            fn deliver(
                place: &Place,
                before: Vec<Event>,
                at_marker: impl FnOnce() + Send + 'static,
                after: Vec<Event>,
            ) -> (std::thread::JoinHandle<()>, mpsc::Sender<()>) {
                let (places, shared, tell) = (
                    Arc::clone(&place.places),
                    Arc::clone(&place.shared),
                    place.tell.clone(),
                );
                let beside = place.watch.site.beside_path.clone();
                let (decided, decision) = mpsc::channel::<()>();
                let tell_of = move |event: Event| {
                    let mut shared = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Some(path) = take(&places, &mut shared, Ok(event)) {
                        let _ = tell.send(path);
                    }
                };
                let thread = std::thread::spawn(move || {
                    for event in before {
                        tell_of(event);
                    }
                    let deadline = Instant::now() + Duration::from_secs(10);
                    let marker = loop {
                        let found = std::fs::read_dir(&beside)
                            .expect("the directory beside the copy reads")
                            .filter_map(Result::ok)
                            .map(|entry| entry.path())
                            .find(|path| {
                                path.file_name()
                                    .is_some_and(|name| name.to_string_lossy().starts_with(MARK))
                            });
                        if let Some(path) = found {
                            break path;
                        }
                        assert!(Instant::now() < deadline, "the host wrote no marker");
                        std::thread::sleep(Duration::from_millis(1));
                    };
                    at_marker();
                    tell_of(report(EventKind::Create(CreateKind::File), &marker));
                    let _ = decision.recv_timeout(Duration::from_secs(10));
                    for event in after {
                        tell_of(event);
                    }
                });
                (thread, decided)
            }

            /// The paths the watch says were written, when the stream reports `before` ahead of
            /// the host's marker and `after` once the host has decided, and `at_marker` runs as the
            /// marker is reported.
            fn written_with(
                place: &Place,
                before: Vec<Event>,
                at_marker: impl FnOnce() + Send + 'static,
                after: Vec<Event>,
            ) -> Vec<String> {
                let (platform, decided) = deliver(place, before, at_marker, after);
                let written = place.watch.drain().expect("the watch is up to date");
                decided.send(()).expect("the platform waits");
                platform.join().expect("the platform ends");
                written
            }

            /// Control: a directory an output is in that is removed and made again, which the
            /// stream reports at the directory's own path ahead of the marker, is a write.
            #[test]
            fn a_parent_replaced_and_reported_before_the_marker_is_a_write() {
                let place = a_place();
                replace_the_parent(&place.copy);
                let parent = place.copy.join("target");
                let before = vec![
                    report(EventKind::Create(CreateKind::Folder), &parent),
                    report(EventKind::Remove(RemoveKind::Folder), &parent),
                ];
                let written = written_with(&place, before, || {}, Vec::new());
                assert_eq!(written, vec!["target".to_owned()]);
            }

            /// Control: an output that is removed and made again in its directory is the run's to
            /// write, and the directory is not written by it.
            #[test]
            fn an_output_made_again_in_its_parent_is_no_write() {
                let place = a_place();
                std::fs::remove_dir_all(place.copy.join("target/debug"))
                    .expect("the run removes it");
                std::fs::create_dir_all(place.copy.join("target/debug"))
                    .expect("and makes it again");
                let output = place.copy.join("target/debug");
                let before = vec![
                    report(EventKind::Remove(RemoveKind::Folder), &output),
                    report(EventKind::Create(CreateKind::Folder), &output),
                ];
                let written = written_with(&place, before, || {}, Vec::new());
                assert!(
                    written.is_empty(),
                    "only the output was made again, and the watch says it wrote {written:?}"
                );
            }

            /// KR-REQ-14.34: a directory an output is in that is removed and made again is a
            /// write, also when the stream reports it only after the marker the host waits for: the
            /// host decides when the marker is reported, and the copy shows the directory is
            /// another.
            #[test]
            fn a_parent_replaced_and_reported_after_the_marker_is_a_write() {
                let place = a_place();
                replace_the_parent(&place.copy);
                let parent = place.copy.join("target");
                let after = vec![
                    report(EventKind::Create(CreateKind::Folder), &parent),
                    report(EventKind::Remove(RemoveKind::Folder), &parent),
                ];
                let written = written_with(&place, Vec::new(), || {}, after);
                assert!(
                    written.iter().any(|path| path == "target"),
                    "the directory was removed and made again, and the watch says it wrote {written:?}"
                );
            }

            /// KR-REQ-14.34: a directory an output is in that is removed and made again is a
            /// write, also when the stream reports only what is beneath it: the output, which is
            /// the run's to write, and the file in it.
            #[test]
            fn a_parent_replaced_and_reported_only_by_what_is_beneath_it_is_a_write() {
                let place = a_place();
                replace_the_parent(&place.copy);
                let output = place.copy.join("target/debug");
                let before = vec![
                    report(EventKind::Create(CreateKind::Folder), &output),
                    report(EventKind::Remove(RemoveKind::Folder), &output),
                    report(EventKind::Create(CreateKind::Folder), &output),
                    report(
                        EventKind::Create(CreateKind::File),
                        &output.join("artefact"),
                    ),
                ];
                let written = written_with(&place, before, || {}, Vec::new());
                assert!(
                    written.iter().any(|path| path == "target"),
                    "the directory was removed and made again, and the watch says it wrote {written:?}"
                );
            }

            /// KR-REQ-14.34: a directory an output is in that is removed and made again while the
            /// host waits for its marker is a write, though the stream reports nothing of it.
            #[test]
            fn a_parent_replaced_while_the_host_waits_for_its_marker_is_a_write() {
                let place = a_place();
                let copy = place.copy.clone();
                let written = written_with(
                    &place,
                    Vec::new(),
                    move || replace_the_parent(&copy),
                    Vec::new(),
                );
                assert!(
                    written.iter().any(|path| path == "target"),
                    "the directory was removed and made again, and the watch says it wrote {written:?}"
                );
            }

            /// KR-REQ-14.34: a directory an output is in that is gone is a write, though the
            /// stream reports nothing of it: the host reads the copy and not the reports.
            #[test]
            fn a_parent_that_is_gone_is_a_write_though_nothing_was_reported() {
                let place = a_place();
                std::fs::remove_dir_all(place.copy.join("target")).expect("the run removes it");
                let written = written_with(&place, Vec::new(), || {}, Vec::new());
                assert_eq!(
                    written,
                    vec!["target".to_owned()],
                    "the directory is gone, and the watch says it wrote {written:?}"
                );
            }

            /// Gives a directory its mode back when it is dropped.
            struct Shut(PathBuf);

            impl Shut {
                /// Takes every right to the directory away, so that nothing in it can be reached.
                fn the_directory(path: &Path) -> Self {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))
                        .expect("the directory is shut");
                    Self(path.to_path_buf())
                }
            }

            impl Drop for Shut {
                fn drop(&mut self) {
                    use std::os::unix::fs::PermissionsExt as _;
                    let _ =
                        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
                }
            }

            /// A directory an output is in that cannot be examined at the end is no answer: the
            /// drain fails, so the result is not established, and it is neither a write nor none.
            #[test]
            fn a_parent_that_cannot_be_examined_makes_the_drain_fail() {
                let place = a_place();
                let _shut = Shut::the_directory(&place.copy);
                let (platform, decided) = deliver(&place, Vec::new(), || {}, Vec::new());
                let drained = place.watch.drain();
                decided.send(()).expect("the platform waits");
                platform.join().expect("the platform ends");
                let why = drained.err().unwrap_or_default();
                assert!(
                    why.contains("could not be examined"),
                    "the drain did not fail as it should: {why:?}"
                );
            }

            /// KR-REQ-14.34: what each directory an output is in is, is read before the budget is
            /// asked: with the whole budget held, a start for a copy that lacks one of those
            /// directories says that it could not be examined, and not that too many copies are
            /// watched.
            #[test]
            fn a_directory_an_output_is_in_is_read_before_the_budget_is_asked() {
                let mut made = a_copy();
                made.parents
                    .insert("target".to_owned(), BTreeSet::from(["debug".to_owned()]));
                let _whole = the_whole_budget();
                let started = NameWatch::start(&made.copy, &made.beside, &made.parents);
                let why = started.err().unwrap_or_default();
                assert!(
                    why.contains("could not be examined"),
                    "the directory was not read before the budget was asked: {why:?}"
                );
            }

            fn created() -> EventKind {
                EventKind::Create(CreateKind::Folder)
            }

            fn attributes_changed() -> EventKind {
                EventKind::Modify(ModifyKind::Metadata(MetadataKind::Extended))
            }

            /// What the watch says was written when the stream reports `kinds` of the directory
            /// `target` ahead of the host's marker, and the directory is as the host recorded it.
            fn written_for(kinds: Vec<EventKind>) -> Vec<String> {
                let place = a_place();
                let parent = place.copy.join("target");
                let before = kinds
                    .into_iter()
                    .map(|kind| report(kind, &parent))
                    .collect();
                written_with(&place, before, || {}, Vec::new())
            }

            /// KR-REQ-14.34: a report that a directory an output is in was created is no write
            /// when the directory is the one the host recorded: the host made it itself, before
            /// the watch, and the service can report that later.
            #[test]
            fn a_creation_report_of_a_parent_with_its_record_held_is_no_write() {
                let written = written_for(vec![created()]);
                assert!(
                    written.is_empty(),
                    "the directory is as recorded, and the watch says it wrote {written:?}"
                );
            }

            /// KR-REQ-14.34: the same for a report that its extended attributes changed, when
            /// they are the ones the host recorded.
            #[test]
            fn an_attribute_report_of_a_parent_with_its_record_held_is_no_write() {
                let written = written_for(vec![attributes_changed()]);
                assert!(
                    written.is_empty(),
                    "the attributes are as recorded, and the watch says it wrote {written:?}"
                );
            }

            /// KR-REQ-14.34: what a failing run heard: the service delivers the host's own making
            /// of the directory as a creation and a change of its extended attributes, and
            /// delivers both again after the watcher is up to date.
            #[test]
            fn the_creation_and_attribute_reports_the_service_delivers_again_are_no_write() {
                let written = written_for(vec![
                    created(),
                    attributes_changed(),
                    created(),
                    attributes_changed(),
                ]);
                assert!(
                    written.is_empty(),
                    "the directory is as recorded, and the watch says it wrote {written:?}"
                );
            }

            /// What the watch says was written when `change` is made to the directory `target`
            /// as the host waits for its marker, without a report of the change and then with a
            /// report that its extended attributes changed.
            fn written_when_changed(change: fn(&Path)) -> [Vec<String>; 2] {
                [false, true].map(|reported| {
                    let place = a_place();
                    let parent = place.copy.join("target");
                    let before = if reported {
                        vec![report(attributes_changed(), &parent)]
                    } else {
                        Vec::new()
                    };
                    written_with(&place, before, move || change(&parent), Vec::new())
                })
            }

            /// KR-REQ-14.34: an extended attribute added to a directory an output is in is a
            /// write, reported or not.
            #[test]
            fn an_attribute_added_to_a_parent_is_a_write() {
                for written in
                    written_when_changed(|parent| set_attribute(parent, "kr.other", b"two"))
                {
                    assert_eq!(
                        written,
                        vec!["target".to_owned()],
                        "an attribute was added, and the watch says it wrote {written:?}"
                    );
                }
            }

            /// KR-REQ-14.34: an extended attribute of a directory an output is in that has
            /// another value is a write, reported or not.
            #[test]
            fn an_attribute_changed_in_value_is_a_write() {
                for written in written_when_changed(|parent| set_attribute(parent, KEPT, b"two")) {
                    assert_eq!(
                        written,
                        vec!["target".to_owned()],
                        "an attribute has another value, and the watch says it wrote {written:?}"
                    );
                }
            }

            /// KR-REQ-14.34: an extended attribute removed from a directory an output is in is a
            /// write, reported or not.
            #[test]
            fn an_attribute_removed_from_a_parent_is_a_write() {
                for written in written_when_changed(|parent| {
                    rustix::fs::lremovexattr(parent, KEPT).expect("the attribute is removed");
                }) {
                    assert_eq!(
                        written,
                        vec!["target".to_owned()],
                        "an attribute was removed, and the watch says it wrote {written:?}"
                    );
                }
            }

            /// What a directory can hold that the host does not read: more than 64 extended
            /// attributes, and a value of more than 4,096 bytes.
            fn more_than_the_host_reads() -> [fn(&Path); 2] {
                [
                    |parent| {
                        for number in 0..65 {
                            set_attribute(parent, &format!("kr.n{number}"), b"x");
                        }
                    },
                    |parent| set_attribute(parent, "kr.big", &[b'x'; 4097]),
                ]
            }

            /// KR-REQ-14.34: a directory an output is in that holds more than the host reads is
            /// not read: the start fails, before the budget is asked.
            #[test]
            fn a_parent_with_more_attributes_than_the_host_reads_is_not_read() {
                for grow in more_than_the_host_reads() {
                    let layout = a_layout();
                    grow(&layout.copy.join("target"));
                    let why = Site::of(
                        &layout.copy_directory,
                        &layout.beside,
                        &parents_of_outputs(),
                    )
                    .err()
                    .unwrap_or_default();
                    assert!(
                        why.contains("could not be examined"),
                        "the directory was read though it holds more than the host reads: {why:?}"
                    );
                }
            }

            /// KR-REQ-14.34: a directory an output is in that comes to hold more than the host
            /// reads cannot be read at the end: the drain fails, and it is neither a write nor
            /// none.
            #[test]
            fn a_parent_that_grows_past_what_the_host_reads_makes_the_drain_fail() {
                for grow in more_than_the_host_reads() {
                    let place = a_place();
                    let parent = place.copy.join("target");
                    let (platform, decided) =
                        deliver(&place, Vec::new(), move || grow(&parent), Vec::new());
                    let drained = place.watch.drain();
                    decided.send(()).expect("the platform waits");
                    platform.join().expect("the platform ends");
                    let why = drained.err().unwrap_or_default();
                    assert!(
                        why.contains("could not be examined"),
                        "the drain did not fail as it should: {why:?}"
                    );
                }
            }

            /// KR-REQ-14.34: a directory removed and made again has another inode, which is a
            /// write whatever was reported of it, also when what was reported is a creation, and
            /// the directory made again holds the attribute that was recorded.
            #[test]
            fn a_creation_report_of_a_parent_with_another_inode_is_a_write() {
                let place = a_place();
                replace_the_parent(&place.copy);
                let parent = place.copy.join("target");
                set_attribute(&parent, KEPT, b"one");
                let before = vec![report(created(), &parent)];
                let written = written_with(&place, before, || {}, Vec::new());
                assert!(
                    written.iter().any(|path| path == "target"),
                    "the directory has another inode, and the watch says it wrote {written:?}"
                );
            }

            /// KR-REQ-14.34: the library reports a mount as a creation of kind other with the
            /// note "mount". A tree mounted over a directory an output is in and unmounted before
            /// the end leaves the record as it was, so the report is the one trace of it: it is a
            /// write, with no report of the unmount.
            #[test]
            fn a_mount_report_of_a_parent_is_a_write_though_its_record_is_held() {
                let place = a_place();
                let parent = place.copy.join("target");
                let mount = report(EventKind::Create(CreateKind::Other), &parent).set_info("mount");
                let written = written_with(&place, vec![mount], || {}, Vec::new());
                assert_eq!(written, vec!["target".to_owned()]);
            }

            /// KR-REQ-14.34: only the creation of a folder is the host's own making of a directory
            /// an output is in. A creation of any other kind at its path is a write: a file, a
            /// kind the library does not say, a kind the platform does not say.
            #[test]
            fn a_creation_report_of_another_kind_than_a_folder_at_a_parent_is_a_write() {
                for kind in [CreateKind::File, CreateKind::Other, CreateKind::Any] {
                    let written = written_for(vec![EventKind::Create(kind)]);
                    assert_eq!(written, vec!["target".to_owned()], "{kind:?}");
                }
            }

            /// KR-REQ-14.34: every report of a directory an output is in but a creation of a
            /// folder or a change of its extended attributes is a write, with the directory as
            /// recorded: a removal.
            #[test]
            fn a_removal_report_of_a_parent_is_a_write() {
                let written = written_for(vec![EventKind::Remove(RemoveKind::Folder)]);
                assert_eq!(written, vec!["target".to_owned()]);
            }

            /// KR-REQ-14.34: a rename.
            #[test]
            fn a_rename_report_of_a_parent_is_a_write() {
                let written =
                    written_for(vec![EventKind::Modify(ModifyKind::Name(RenameMode::Any))]);
                assert_eq!(written, vec!["target".to_owned()]);
            }

            /// KR-REQ-14.34: a change of its owner, and of its mode.
            #[test]
            fn an_owner_or_mode_report_of_a_parent_is_a_write() {
                for kind in [MetadataKind::Ownership, MetadataKind::Permissions] {
                    let written = written_for(vec![EventKind::Modify(ModifyKind::Metadata(kind))]);
                    assert_eq!(written, vec!["target".to_owned()], "{kind:?}");
                }
            }

            /// KR-REQ-14.34: any other metadata, and its content.
            #[test]
            fn any_other_metadata_or_content_report_of_a_parent_is_a_write() {
                for kind in [
                    EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any)),
                    EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
                    EventKind::Modify(ModifyKind::Data(DataChange::Content)),
                ] {
                    let written = written_for(vec![kind]);
                    assert_eq!(written, vec!["target".to_owned()], "{kind:?}");
                }
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

    #[cfg(test)]
    mod tests {
        /// KR-REQ-14.34: a copy on a filesystem this host does not know to keep change times has
        /// no record taken, so its result is indeterminate. Only a privileged mount can put a copy
        /// on such a filesystem, so the list is read directly.
        #[cfg(target_os = "linux")]
        #[test]
        fn only_the_linux_filesystems_known_to_keep_change_times_are_trusted() {
            for kept in [0xEF53, 0x0102_1994, 0x5846_5342, 0x9123_683E] {
                assert!(super::known_type(kept).is_ok(), "{kept:#x}");
            }
            // NFS, FUSE, SMB and FAT.
            for other in [0x6969, 0x6573_5546, 0xFE53_4D42, 0x4D44] {
                assert!(super::known_type(other).is_err(), "{other:#x}");
            }
        }

        /// As on Linux; only APFS is trusted.
        #[cfg(target_os = "macos")]
        #[test]
        fn only_apfs_is_trusted_to_keep_change_times() {
            assert!(super::known_name("apfs").is_ok());
            for other in ["hfs", "nfs", "smbfs", "msdos", "exfat", "autofs"] {
                assert!(super::known_name(other).is_err(), "{other}");
            }
        }
    }
}

#[cfg(not(unix))]
mod unix {
    use super::{Bound, MaterialisationId, Outputs};
    use crate::service::ChangeSetService;

    /// This platform records no change times of a copy, so no record is ever taken.
    #[derive(Debug)]
    pub enum Reading {}

    impl Reading {
        pub fn take(
            _service: &ChangeSetService,
            _id: MaterialisationId,
            _outputs: &Outputs,
        ) -> Result<Self, String> {
            Err("this platform has no record of a copy's change times".to_owned())
        }

        pub fn settle(&self, _service: &ChangeSetService, _id: MaterialisationId) -> Bound {
            match *self {}
        }
    }
}
