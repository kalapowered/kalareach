//! The steps that write and take out the login item's file, and what finishes them after a stop.
//!
//! The core takes explicit paths and bytes and derives nothing: every environment, `HOME` and
//! `XDG_CONFIG_HOME` read is the command's. Each operation is an ordered array of step functions.
//! The command runs the whole array; a case runs it up to a step and stops, and compares the tree
//! with what the record says is under way.
//!
//! At every instant the file, the aside and the staging file are each absent or one of the
//! record's strings (a staging file may hold a prefix of the new bytes), and every one of the
//! three that exists is named by the record or is one name of the same file as the file.

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use kr_client::shown;
use kr_client::shown::Shown;
use kr_flush::NameKind;

use super::record::{Operation, Pending, READ_LIMIT, Record};
use super::render::Kind;

/// The paths one run works with.
pub(super) struct Paths {
    /// The record's file.
    pub record: PathBuf,
    /// The login item's file.
    pub file: PathBuf,
    /// Where the file is moved aside for its check.
    pub aside: PathBuf,
    /// Where new bytes are staged.
    pub staging: PathBuf,
}

/// What kr was doing when a step failed, as the sentence says it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Doing {
    Recording,
    MakingDirectory,
    Staging,
    Linking,
    RemovingStaging,
    RecordingWritten,
    MovingAside,
    PuttingBack,
    RemovingFile,
    RemovingRecord,
}

impl Doing {
    const fn said(self) -> &'static str {
        match self {
            Self::Recording => "recording what it will write",
            Self::MakingDirectory => "making the directory for the file",
            Self::Staging => "staging the file",
            Self::Linking => "giving the file its name",
            Self::RemovingStaging => "removing the staging file",
            Self::RecordingWritten => "recording the file as written",
            Self::MovingAside => "moving the file aside",
            Self::PuttingBack => "putting the file back",
            Self::RemovingFile => "removing the file",
            Self::RemovingRecord => "removing the record",
        }
    }
}

/// Why a step failed.
pub(super) enum Cause {
    Io(std::io::Error),
    Ipc(kr_ipc::IpcError),
    /// Another file holds the name the aside was to go back to.
    Taken,
}

/// A step that failed.
pub(super) struct StepError {
    pub doing: Doing,
    pub cause: Cause,
}

kr_client::debug_as_name!(StepError);

impl StepError {
    /// The failure as a sentence says it.
    pub(super) fn said(&self) -> Shown {
        match &self.cause {
            Cause::Io(error) => shown!(
                "kr stopped while it was {}: {}",
                self.doing.said(),
                Shown::io(error)
            ),
            Cause::Ipc(error) => shown!(
                "kr stopped while it was {}: {}",
                self.doing.said(),
                Shown::ipc(error)
            ),
            Cause::Taken => shown!(
                "kr stopped while it was {}: another file holds the name",
                self.doing.said()
            ),
        }
    }
}

type Result<T> = std::result::Result<T, StepError>;

/// What a run did that a person is told of.
pub(super) enum Event {
    /// A file kr wrote, or left beside it, was removed.
    Removed(PathBuf),
    /// A file was left where it is because it is not what kr wrote.
    Left(PathBuf),
    /// The login item's own file was left because it was changed after kr wrote it.
    LeftFile,
    /// The aside stays, because another file holds the place it was to go back to.
    AsideStays(PathBuf),
}

/// Whether a file was moved aside for its check.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Moved {
    Nothing,
    NotRegular,
    Aside,
}

/// One run of an operation: the paths, the bytes and what it has done so far.
pub(super) struct Run {
    pub paths: Paths,
    pub kind: Kind,
    pub label: String,
    /// The bytes the file holds when the operation is done.
    pub new: String,
    /// The record as it was read before the run.
    pub before: Option<Record>,
    /// What the run did that a person is told of.
    pub events: Vec<Event>,
    moved: Moved,
}

impl Run {
    pub(super) fn new(
        paths: Paths,
        kind: Kind,
        label: &str,
        new: &str,
        before: Option<Record>,
    ) -> Self {
        Self {
            paths,
            kind,
            label: label.to_owned(),
            new: new.to_owned(),
            before,
            events: Vec::new(),
            moved: Moved::Nothing,
        }
    }

    fn clean(&self, contents: &str) -> Record {
        Record::clean(self.kind, &self.label, &self.paths.file, contents)
    }

    fn directory(&self) -> &Path {
        self.paths.file.parent().unwrap_or_else(|| Path::new("."))
    }
}

type Step = fn(&mut Run) -> Result<()>;

/// A fresh file: record first, then every step that makes a path.
pub(super) const PUBLISH: [Step; 6] = [
    write_record_publishing,
    make_directory,
    stage,
    link,
    drop_staging,
    finish_publish,
];

/// A file kr wrote is taken out.
pub(super) const REMOVE: [Step; 5] = [
    write_record_removing,
    move_aside,
    check_and_delete,
    flush_removal,
    drop_record,
];

/// An aside goes back to the file's place.
pub(super) const PUT_BACK: [Step; 2] = [link_back, drop_aside];

/// Runs every step of `steps`.
pub(super) fn run_all(run: &mut Run, steps: &[Step]) -> Result<()> {
    for step in steps {
        step(run)?;
    }
    Ok(())
}

fn io(doing: Doing) -> impl Fn(std::io::Error) -> StepError {
    move |error| StepError {
        doing,
        cause: Cause::Io(error),
    }
}

fn flush(directory: &Path, doing: Doing) -> Result<()> {
    match kr_flush::flush_directory(directory, NameKind::File) {
        // A directory that is not there has no name in it to lose.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other.map_err(io(doing)),
    }
}

fn write_record(run: &Run, record: &Record, doing: Doing) -> Result<()> {
    kr_ipc::paths::write_owner_only_file(&run.paths.record, &record.bytes()).map_err(|error| {
        StepError {
            doing,
            cause: Cause::Ipc(error),
        }
    })
}

fn remove_if_there(path: &Path, doing: Doing) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other.map_err(io(doing)),
    }
}

/// What the disk holds at a name.
pub(super) enum Disk {
    Missing,
    Bytes(Vec<u8>),
    /// Something is there that is not an owner-only regular file of ours.
    Untrusted,
}

pub(super) fn disk(path: &Path) -> Disk {
    // A name under something that is not a directory is not there either.
    if let Err(error) = std::fs::symlink_metadata(path)
        && matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        )
    {
        return Disk::Missing;
    }
    match kr_ipc::paths::read_owner_only_file(path, READ_LIMIT) {
        Ok(None) => Disk::Missing,
        Ok(Some(bytes)) => Disk::Bytes(bytes),
        Err(_) => Disk::Untrusted,
    }
}

fn same_file(first: &Path, second: &Path) -> bool {
    match (
        std::fs::symlink_metadata(first),
        std::fs::symlink_metadata(second),
    ) {
        (Ok(first), Ok(second)) => first.dev() == second.dev() && first.ino() == second.ino(),
        _ => false,
    }
}

/* publish */

fn write_record_publishing(run: &mut Run) -> Result<()> {
    let record = run.clean(&run.new).with(Pending {
        operation: Operation::Publish,
        contents: None,
        aside: None,
        staging: Some(run.paths.staging.clone()),
    });
    write_record(run, &record, Doing::Recording)
}

fn make_directory(run: &mut Run) -> Result<()> {
    std::fs::create_dir_all(run.directory()).map_err(io(Doing::MakingDirectory))
}

fn stage(run: &mut Run) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&run.paths.staging)
        .map_err(io(Doing::Staging))?;
    file.write_all(run.new.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(io(Doing::Staging))
}

fn link(run: &mut Run) -> Result<()> {
    kr_flush::publish_without_replacing(&run.paths.staging, &run.paths.file)
        .map_err(io(Doing::Linking))
}

fn drop_staging(run: &mut Run) -> Result<()> {
    remove_if_there(&run.paths.staging, Doing::RemovingStaging)?;
    flush(run.directory(), Doing::RemovingStaging)
}

fn finish_publish(run: &mut Run) -> Result<()> {
    write_record(run, &run.clean(&run.new), Doing::RecordingWritten)
}

/* remove */

fn write_record_removing(run: &mut Run) -> Result<()> {
    let Some(before) = &run.before else {
        return Ok(());
    };
    let record = before.clone().with(Pending {
        operation: Operation::Remove,
        contents: None,
        aside: Some(run.paths.aside.clone()),
        staging: None,
    });
    write_record(run, &record, Doing::Recording)
}

fn move_aside(run: &mut Run) -> Result<()> {
    match std::fs::symlink_metadata(&run.paths.file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            run.moved = Moved::Nothing;
            Ok(())
        }
        Err(error) => Err(io(Doing::MovingAside)(error)),
        Ok(metadata) if metadata.is_file() => {
            std::fs::rename(&run.paths.file, &run.paths.aside).map_err(io(Doing::MovingAside))?;
            run.moved = Moved::Aside;
            Ok(())
        }
        Ok(_) => {
            run.moved = Moved::NotRegular;
            run.events.push(Event::LeftFile);
            Ok(())
        }
    }
}

fn check_and_delete(run: &mut Run) -> Result<()> {
    if run.moved != Moved::Aside {
        return Ok(());
    }
    let wrote = run.before.as_ref().map(|before| before.contents.as_bytes());
    match disk(&run.paths.aside) {
        Disk::Bytes(bytes) if Some(bytes.as_slice()) == wrote => {
            std::fs::remove_file(&run.paths.aside).map_err(io(Doing::RemovingFile))?;
            run.events.push(Event::Removed(run.paths.file.clone()));
            Ok(())
        }
        Disk::Missing => Ok(()),
        _ => {
            put_back(run)?;
            if !run
                .events
                .iter()
                .any(|event| matches!(event, Event::AsideStays(_)))
            {
                run.events.push(Event::LeftFile);
            }
            Ok(())
        }
    }
}

fn flush_removal(run: &mut Run) -> Result<()> {
    flush(run.directory(), Doing::RemovingFile)
}

fn drop_record(run: &mut Run) -> Result<()> {
    remove_if_there(&run.paths.record, Doing::RemovingRecord)?;
    let state = run.paths.record.parent().unwrap_or_else(|| Path::new("."));
    flush(state, Doing::RemovingRecord)
}

/* put back */

fn link_back(run: &mut Run) -> Result<()> {
    match kr_flush::publish_without_replacing(&run.paths.aside, &run.paths.file) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(StepError {
            doing: Doing::PuttingBack,
            cause: Cause::Taken,
        }),
        other => other.map_err(io(Doing::PuttingBack)),
    }
}

fn drop_aside(run: &mut Run) -> Result<()> {
    remove_if_there(&run.paths.aside, Doing::PuttingBack)?;
    flush(run.directory(), Doing::PuttingBack)
}

/// Puts the aside back where the file was. Where another file holds the place, the aside stays
/// and the run says so.
fn put_back(run: &mut Run) -> Result<()> {
    match run_all(run, &PUT_BACK) {
        Err(StepError {
            cause: Cause::Taken,
            ..
        }) => {
            run.events.push(Event::AsideStays(run.paths.aside.clone()));
            Ok(())
        }
        other => other,
    }
}

/* settle */

/// Who is finishing what an earlier run began.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// `install`: a file that is not vouched for stops it, and nothing changes.
    Install,
    /// `remove`: the leftovers go by their own rules and the file is left as it is.
    Remove,
}

/// What finishing an earlier run came to.
#[derive(PartialEq, Eq)]
pub(super) enum Settled {
    /// The record has nothing under way now.
    Done,
    /// The file is not vouched for: nothing was changed, and the record keeps what is under way.
    Changed,
}

enum Place {
    Missing,
    Vouched,
    Unvouched,
}

fn place(run: &Run, record: &Record) -> Place {
    match disk(&run.paths.file) {
        Disk::Missing => Place::Missing,
        Disk::Bytes(bytes) if record.vouches_for(&bytes) => Place::Vouched,
        _ => Place::Unvouched,
    }
}

/// Settles the paths `record` names as under way, then writes the record without them.
///
/// `run.paths.file` is the record's path. Nothing is dropped from the record before the directory
/// is flushed, and a flush that fails stops the settling with the record as it was, so a run again
/// finishes it.
pub(super) fn settle(run: &mut Run, record: &Record, mode: Mode) -> Result<Settled> {
    let Some(pending) = &record.pending else {
        return Ok(Settled::Done);
    };
    if mode == Mode::Install && matches!(place(run, record), Place::Unvouched) {
        return Ok(Settled::Changed);
    }
    if let Some(staging) = &pending.staging {
        run.paths.staging.clone_from(staging);
        leftover(run, record, Leftover::Staging)?;
    }
    if let Some(aside) = &pending.aside {
        run.paths.aside.clone_from(aside);
        leftover(run, record, Leftover::Aside)?;
    }
    let after = place(run, record);
    if mode == Mode::Install && matches!(after, Place::Unvouched) {
        return Ok(Settled::Changed);
    }
    flush(run.directory(), Doing::RemovingStaging)?;
    let new = match disk(&run.paths.file) {
        Disk::Bytes(bytes) if bytes == record.new_bytes().as_bytes() => record.new_bytes(),
        _ => &record.contents,
    };
    write_record(run, &run.clean(new), Doing::RecordingWritten)?;
    Ok(Settled::Done)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Leftover {
    Staging,
    Aside,
}

/// One path an earlier run may have left, by the first rule that fits: missing, nothing; not an
/// owner-only regular file of ours, left and named; one file with the login item's file, removed;
/// a staging file that holds a prefix of the new bytes, removed; an aside put back where the file
/// is missing, removed where the file is there and the aside holds vouched bytes, otherwise left.
fn leftover(run: &mut Run, record: &Record, which: Leftover) -> Result<()> {
    let path = match which {
        Leftover::Staging => run.paths.staging.clone(),
        Leftover::Aside => run.paths.aside.clone(),
    };
    let bytes = match disk(&path) {
        Disk::Missing => return Ok(()),
        Disk::Untrusted => {
            run.events.push(Event::Left(path));
            return Ok(());
        }
        Disk::Bytes(bytes) => bytes,
    };
    let remove = |run: &mut Run| -> Result<()> {
        std::fs::remove_file(&path).map_err(io(Doing::RemovingStaging))?;
        flush(run.directory(), Doing::RemovingStaging)?;
        run.events.push(Event::Removed(path.clone()));
        Ok(())
    };
    if same_file(&path, &run.paths.file) {
        return remove(run);
    }
    match which {
        Leftover::Staging if record.new_bytes().as_bytes().starts_with(&bytes) => remove(run),
        Leftover::Staging => {
            run.events.push(Event::Left(path));
            Ok(())
        }
        Leftover::Aside => match place(run, record) {
            Place::Missing => put_back(run),
            Place::Vouched | Place::Unvouched if record.vouches_for(&bytes) => remove(run),
            _ => {
                run.events.push(Event::Left(path));
                Ok(())
            }
        },
    }
}

/* failure */

/// What a failed run says after its own error.
pub(super) enum Tail {
    /// The record was taken back and no file was written.
    TookBack,
    /// The new file is in place; the record keeps what is under way.
    InPlace,
    /// A path that is not what kr wrote stays, and the record keeps naming it.
    KeptNamed(PathBuf),
    /// The record keeps what is under way, and a run again finishes it.
    Unfinished,
}

/// A failed run.
pub(super) struct Failure {
    pub error: StepError,
    pub tail: Tail,
}

/// Reads the disk after a step failed, because an error from a link or a flush can come after the
/// name exists: a publication that happened is finished by the next run, not undone, and one that
/// did not is rolled back. A removal is never rolled back.
pub(super) fn fail(run: &mut Run, operation: Operation, error: StepError) -> Failure {
    let unfinished = |error| Failure {
        error,
        tail: Tail::Unfinished,
    };
    if operation == Operation::Remove {
        return unfinished(error);
    }
    if let Disk::Bytes(bytes) = disk(&run.paths.file)
        && bytes == run.new.as_bytes()
    {
        return Failure {
            error,
            tail: Tail::InPlace,
        };
    }
    let pending = run.clean(&run.new).with(Pending {
        operation,
        contents: None,
        aside: None,
        staging: Some(run.paths.staging.clone()),
    });
    let before = run.events.len();
    if let Err(next) = leftover(run, &pending, Leftover::Staging) {
        return unfinished(next);
    }
    if let Some(Event::Left(path)) = run.events.get(before..).and_then(<[Event]>::last) {
        let path = path.clone();
        return Failure {
            error,
            tail: Tail::KeptNamed(path),
        };
    }
    if let Err(next) = flush(run.directory(), Doing::RemovingStaging) {
        return unfinished(next);
    }
    let held = match disk(&run.paths.record) {
        Disk::Bytes(bytes) => serde_json::from_slice::<Record>(&bytes).ok(),
        _ => None,
    };
    let state = run.paths.record.parent().unwrap_or_else(|| Path::new("."));
    let restored = match (&run.before, &held) {
        (Some(before), Some(held)) if before == held => Ok(()),
        (Some(before), _) => write_record(run, before, Doing::Recording),
        (None, None) if !run.paths.record.exists() => Ok(()),
        (None, _) => remove_if_there(&run.paths.record, Doing::RemovingRecord)
            .and_then(|()| flush(state, Doing::RemovingRecord)),
    };
    match restored {
        Ok(()) => Failure {
            error,
            tail: Tail::TookBack,
        },
        Err(next) => unfinished(next),
    }
}
