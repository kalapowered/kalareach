//! An invocation's private root: its creation and its removal.
//!
//! The root is one directory under the broker's `run` directory, with a random name, made by a
//! single create call, relative to the held `run` handle, that carries its descriptor, so that it
//! never inherits an entry from the folder above. Under it are `tmp` and `home`, made the same
//! way. The handle the create call returns is the one the broker keeps. Git runs as a boundary
//! account and may fill the root with anything its group can write: links to outside names,
//! junctions, long and case-sensitive names, names that end in a dot or a space, read-only files,
//! files with open handles, objects whose own permission list refuses the system. The removal is
//! written for exactly that and writes no permission list and no attribute on anything.
//!
//! The removal works from the bottom up, from handles, on the walk's primitives. Every object,
//! a link and a file with several names included, is opened once by its listed name relative to
//! the held directory, with the right to delete it and the backup and restore privileges that the
//! guard on this thread holds, and without delete sharing. Its whole key is compared with the
//! listing's on that handle, and the same handle is then deleted with the platform's POSIX
//! semantics, which ignore the read-only attribute. A name is never opened a second time, so what
//! is deleted is the object that was checked, and nothing that a sibling swapped in or renamed
//! out can be reached. A link's target is never opened, and a hard link's other names stay. An
//! object that cannot be opened or read, that is not the listed one, or that stays in use past
//! the waits of [`ROOT_LIMITS`] is a leftover: its reason and path are returned, and nothing on it
//! is changed.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DISPOSITION_DELETE, FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_INFORMATION_EX, FILE_DISPOSITION_POSIX_SEMANTICS,
    FileDispositionInformationEx, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_OPERATION_ABORTED,
    ERROR_SHARING_VIOLATION, HANDLE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
};
use windows_sys::Win32::System::IO::{CancelSynchronousIo, IO_STATUS_BLOCK};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::ffi::{Handle, Sid, error, last};
use super::privilege::PrivGuard;
use super::sd::{self, Principals, SdKind};
use super::walk::{Bounds, Child, DELETE, DirHandle, Kind, LIST, Lost, ROOT_BOUNDS};
use crate::filekey::FileKey;
use crate::journal::rows::RootName;

const READ_CONTROL: u32 = 0x0002_0000;
const RETRY_EVERY: Duration = Duration::from_millis(100);
/// A delete call that takes no longer than this is an ordinary one and costs the root's waits
/// nothing: a delete is a metadata change that takes well under a millisecond, a few milliseconds
/// beside a scanner that reads the file, so 50 ms is ten times what a busy disk and a scanner give
/// and still short enough that no lock holder answering at its limit goes uncounted. Counting every
/// ordinary delete would spend the total on a tree of thousands of files.
const DELETE_GRACE: Duration = Duration::from_millis(50);
/// What a delete call is given at least, once the waits for the whole root are spent: one such
/// call is made, and the removal stops when it ends by its bound.
const DELETE_FLOOR: Duration = Duration::from_millis(500);
/// How long the removal waits for a delete call after it has asked the system to cancel it. A
/// call that has not ended by then is given up.
const CANCEL_GRACE: Duration = Duration::from_secs(2);

/// The figures a removal works within, stated once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most objects a root may hold and the deepest it may be nested. More is one
    /// `too large` leftover for the root.
    pub bounds: Bounds,
    /// How long the removal waits for one object that another process has open, and how long a
    /// delete call on an opened object may take before the system is asked to cancel it.
    pub wait_each: Duration,
    /// How long the removal waits for objects in use in all, for one root: the waits to open
    /// them, and the time of every delete call that takes longer than a few milliseconds
    /// whatever its result. Past it, an object in use is a leftover at once, a delete call is
    /// given [`DELETE_FLOOR`], and a delete call that ends by its bound stops the removal's
    /// delete calls for the root.
    pub wait_total: Duration,
}

/// The limits of a private root's removal.
pub const ROOT_LIMITS: Limits = Limits {
    bounds: ROOT_BOUNDS,
    wait_each: Duration::from_secs(5),
    wait_total: Duration::from_secs(60),
};

/// Draws a name for a private root from the system's random source.
fn random_name() -> Result<RootName, RootError> {
    let mut bytes = [0_u8; 16];
    // SAFETY: the buffer is 16 bytes, which is the length passed; no algorithm handle is used.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(error(status as u32, "drawing a random name for the private root").into());
    }
    Ok(RootName::from_bytes(bytes))
}

/// A name as the units a name relative to a held directory is given in.
fn units(name: &RootName) -> Vec<u16> {
    name.as_str().encode_utf16().collect()
}

/// The rows the root writes about itself, each durable before the step it protects. A root is
/// named by its [`RootName`] alone: the journal records no path.
pub trait RootRows {
    /// The root is about to be made under this name.
    ///
    /// # Errors
    ///
    /// Returns an error when the row is not durable; nothing is made then.
    fn intent(&mut self, name: &RootName) -> Result<(), RootError>;
    /// The root was made under this name, and this is its identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    fn made(&mut self, name: &RootName, key: &FileKey) -> Result<(), RootError>;
    /// The root was removed.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be written.
    fn removed(&mut self) -> Result<(), RootError>;
}

/// A failure of the root's creation or removal.
#[derive(Debug, thiserror::Error)]
pub enum RootError {
    /// The platform refused a call.
    #[error("{0}")]
    Os(#[from] super::ffi::Error),
    /// A row could not be written.
    #[error("the journal could not take the row: {0}")]
    Journal(String),
    /// What was made is not what was asked for.
    #[error("{0}")]
    Refused(String),
}

/// An object the removal could not remove. Nothing on it was changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leftover {
    /// Where it is, below the root, with the root's name left out.
    pub path: String,
    /// Why it stayed.
    pub reason: String,
}

impl std::fmt::Display for Leftover {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "leftover: {} {}", self.reason, self.path)
    }
}

/// A private root that was made and is held open.
#[derive(Debug)]
pub struct PrivateRoot {
    dir: DirHandle,
    name: RootName,
    path: PathBuf,
}

impl PrivateRoot {
    /// The root's path as the invocation's environment names it. Nothing is opened through it.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The root's name beneath `run`, which is what the journal records.
    #[must_use]
    pub fn name(&self) -> &RootName {
        &self.name
    }

    /// The root's `tmp` directory.
    #[must_use]
    pub fn tmp(&self) -> PathBuf {
        self.path.join("tmp")
    }

    /// The root's `home` directory.
    #[must_use]
    pub fn home(&self) -> PathBuf {
        self.path.join("home")
    }

    /// The root's identity, for the journal.
    #[must_use]
    pub fn key(&self) -> FileKey {
        self.dir.key()
    }

    /// The held directory, which stays open without delete sharing until the root is removed.
    #[must_use]
    pub fn dir(&self) -> &DirHandle {
        &self.dir
    }
}

/// Makes the private root for an invocation under `run`, the held directory whose path is
/// `run_path`.
///
/// The row `intent` is durable before the directory is made and `made` after it is made and
/// checked. The directory and its `tmp` and `home` are each made by one create call relative to
/// the handle above them, so nothing is opened through a path: `run_path` only tells the
/// invocation's environment where the root is. The handle the call returns is the one kept. The
/// check requires a directory that is not a reparse point and directly beneath `run`, and reads
/// the descriptor back and compares it with the one sent; `tmp` and `home` are compared with the
/// same whole descriptor.
///
/// A failure after the intent may leave the directory behind; the recovery of an intent without
/// its `made` row looks for it by its name and removes it.
///
/// # Errors
///
/// Returns an error when a row cannot be written, the name exists, the platform refuses a call,
/// or what was made is not what was asked for.
pub fn create_root(
    run: &DirHandle,
    run_path: &Path,
    group: &Sid,
    rows: &mut dyn RootRows,
) -> Result<PrivateRoot, RootError> {
    make_root(run, run_path, random_name()?, group, rows)
}

/// As [`create_root`], under a name the case chooses, so that a name that already exists can be
/// tried.
///
/// # Errors
///
/// See [`create_root`].
#[cfg(feature = "testing")]
pub fn create_root_named(
    run: &DirHandle,
    run_path: &Path,
    name: RootName,
    group: &Sid,
    rows: &mut dyn RootRows,
) -> Result<PrivateRoot, RootError> {
    make_root(run, run_path, name, group, rows)
}

fn make_root(
    run: &DirHandle,
    run_path: &Path,
    name: RootName,
    group: &Sid,
    rows: &mut dyn RootRows,
) -> Result<PrivateRoot, RootError> {
    let principals = Principals {
        group: Some(group.clone()),
        ..Principals::default()
    };
    let descriptor = sd::descriptor(SdKind::PrivateRoot, &principals)?;
    rows.intent(&name)?;
    let held = run
        .create_directory_named(&units(&name), &descriptor, LIST | DELETE | READ_CONTROL)?
        .map_err(|lost| RootError::Refused(format!("the new private root: {lost}")))?;
    let wanted = descriptor.summary()?;
    if sd::summary_of_handle(held.handle())? != wanted {
        return Err(RootError::Refused(
            "the private root's descriptor is not the one that was sent".to_owned(),
        ));
    }
    rows.made(&name, &held.key())?;
    for part in ["tmp", "home"] {
        let units: Vec<u16> = part.encode_utf16().collect();
        let inner = held
            .create_directory_named(&units, &descriptor, LIST | READ_CONTROL)?
            .map_err(|lost| RootError::Refused(format!("the root's {part} directory: {lost}")))?;
        if sd::summary_of_handle(inner.handle())? != wanted {
            return Err(RootError::Refused(format!(
                "the root's {part} directory has another descriptor than the root"
            )));
        }
    }
    let path = run_path.join(name.as_str());
    Ok(PrivateRoot {
        dir: held,
        name,
        path,
    })
}

/// Removes the private root and everything under it. The privileged thread's guard is the proof
/// that the call runs inside a walk.
///
/// Returns what could not be removed. When nothing is left over the root itself is gone and the
/// `removed` row is written; otherwise the root stays, and so does everything the removal could
/// not take.
///
/// # Errors
///
/// Returns an error when a row cannot be written.
pub fn remove_root(
    root: &PrivateRoot,
    guard: &PrivGuard,
    rows: &mut dyn RootRows,
) -> Result<Vec<Leftover>, RootError> {
    remove_root_within(root, guard, ROOT_LIMITS, rows)
}

/// As [`remove_root`], within the limits a case chooses.
///
/// # Errors
///
/// See [`remove_root`].
pub fn remove_root_within(
    root: &PrivateRoot,
    _guard: &PrivGuard,
    limits: Limits,
    rows: &mut dyn RootRows,
) -> Result<Vec<Leftover>, RootError> {
    let mut state = Removal {
        limits,
        listed: 0,
        waited: Duration::ZERO,
        too_large: false,
        stopped: false,
        leftovers: Vec::new(),
        deleter: Deleter::start(root.name.as_str())?,
        #[cfg(feature = "testing")]
        root: root.name.as_str().to_owned(),
    };
    state.empty(&root.dir, "", 1);
    if state.leftovers.is_empty() {
        // The root's own delete is made on the same thread and within the same bound, through a
        // copy of its handle, which the caller keeps.
        state.remove(duplicate(root.dir.handle())?, "");
        if state.leftovers.is_empty() {
            rows.removed()?;
        }
    }
    Ok(state.leftovers)
}

/// A second handle to the same object, with the same access.
fn duplicate(handle: &Handle) -> Result<Handle, super::ffi::Error> {
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: the handle is open in this process, and the call writes one handle to the local.
    let done = unsafe {
        let me = GetCurrentProcess();
        DuplicateHandle(
            me,
            handle.raw(),
            me,
            &raw mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if done == 0 {
        return Err(last("duplicating a handle"));
    }
    Handle::new(copy, "duplicating a handle")
}

/// One object to delete through, which the thread that deletes owns until its call returns.
struct Job {
    handle: Handle,
    #[cfg(feature = "testing")]
    root: String,
}

/// How a delete call ended.
enum Call {
    /// It returned inside its limit.
    Ended(Result<(), super::ffi::Error>),
    /// It returned after the system was asked to cancel it.
    Cancelled(Result<(), super::ffi::Error>),
    /// It did not return, even after the cancel and a wait.
    DidNotEnd,
}

/// The one thread that makes a removal's delete calls, so that the removal's own thread never
/// waits in one. An object that another process holds by a lock it does not give up makes the
/// call wait for an answer that never comes, and no wait of the caller counts inside it. The
/// removal waits for the call's limit, asks the system to cancel it, waits a short while more, and
/// then gives the call up: the thread keeps the handle and closes it when its call returns, and
/// the removal makes no further call, so at most one such thread stays for a root.
struct Deleter {
    jobs: Sender<Job>,
    answers: Receiver<Result<(), super::ffi::Error>>,
    thread: JoinHandle<()>,
    #[cfg(feature = "testing")]
    root: String,
}

impl Deleter {
    fn start(root: &str) -> Result<Deleter, RootError> {
        let (jobs, work) = std::sync::mpsc::channel::<Job>();
        let (reply, answers) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("private-root-delete".to_owned())
            .spawn(move || {
                // A delete through an open handle needs no privilege and no impersonation. The
                // loop ends when the removal lets go of its end, and a closed answer ends it too.
                while let Ok(job) = work.recv() {
                    #[cfg(feature = "testing")]
                    testing::wait_while_held(&job.root);
                    let result = delete(&job.handle);
                    drop(job.handle);
                    if reply.send(result).is_err() {
                        break;
                    }
                }
            })
            .map_err(|failure| {
                error(
                    failure.raw_os_error().map_or(0, |code| code as u32),
                    "starting the thread that deletes",
                )
            })?;
        let _ = root;
        Ok(Deleter {
            jobs,
            answers,
            thread,
            #[cfg(feature = "testing")]
            root: root.to_owned(),
        })
    }

    fn call(&self, handle: Handle, limit: Duration) -> Call {
        let job = Job {
            handle,
            #[cfg(feature = "testing")]
            root: self.root.clone(),
        };
        if self.jobs.send(job).is_err() {
            return Call::DidNotEnd;
        }
        match self.answers.recv_timeout(limit) {
            Ok(result) => return Call::Ended(result),
            Err(RecvTimeoutError::Disconnected) => return Call::DidNotEnd,
            Err(RecvTimeoutError::Timeout) => {}
        }
        #[cfg(feature = "testing")]
        testing::note_cancel(&self.root);
        // SAFETY: the thread's handle is open while its join handle lives, and the call only asks
        // the system to cancel the synchronous request that thread has pending, if it has one.
        unsafe { CancelSynchronousIo(self.thread.as_raw_handle()) };
        match self.answers.recv_timeout(CANCEL_GRACE) {
            Ok(result) => Call::Cancelled(result),
            Err(_) => Call::DidNotEnd,
        }
    }
}

/// What the cases may watch and use during a removal: the points between a listing and the open
/// of what it named, and between that open and the deletion, where a sibling's change would land.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::{Arc, Condvar, Mutex};

    use crate::journal::rows::RootName;

    /// A point of the removal.
    #[derive(Debug)]
    pub enum Event<'a> {
        /// A directory was listed and none of its children is opened yet.
        Listed {
            /// The directory, below the root; empty for the root.
            directory: &'a str,
            /// The names the listing returned, in order.
            names: Vec<String>,
            /// Whether the directory has more children than the listing returned.
            more: bool,
        },
        /// A child was opened and checked and is about to be removed or entered.
        Opened {
            /// The child, below the root.
            path: &'a str,
        },
    }

    type Hook = Arc<dyn Fn(&Event<'_>) + Send + Sync>;

    static HOOKS: Mutex<Vec<(String, Hook)>> = Mutex::new(Vec::new());

    /// Sets the function called at each point of the removal of the root named `root`, until
    /// [`clear`]. The removal of another root does not call it, so cases that run side by side do
    /// not meet each other's function.
    pub fn set(root: &RootName, hook: impl Fn(&Event<'_>) + Send + Sync + 'static) {
        let mut hooks = HOOKS.lock().unwrap();
        hooks.retain(|(name, _)| name != root.as_str());
        hooks.push((root.as_str().to_owned(), Arc::new(hook)));
    }

    /// Removes the function of the root named `root`.
    pub fn clear(root: &RootName) {
        HOOKS
            .lock()
            .unwrap()
            .retain(|(name, _)| name != root.as_str());
    }

    pub(super) fn fire(root: &str, event: &Event<'_>) {
        let hook = HOOKS
            .lock()
            .unwrap()
            .iter()
            .find(|(name, _)| name == root)
            .map(|(_, hook)| hook.clone());
        if let Some(hook) = hook {
            hook(event);
        }
    }

    type Gate = Arc<(Mutex<bool>, Condvar)>;

    static HOLDS: Mutex<Vec<(String, Gate)>> = Mutex::new(Vec::new());
    static CANCELS: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

    /// Holds the thread that makes the delete calls of the removal of the root named `root`
    /// before each call, until the guard is dropped. A held thread has no request pending in the
    /// system, so a cancel does not reach it: it stands for a delete call that cannot be
    /// cancelled.
    #[must_use]
    pub fn hold_deletes(root: &RootName) -> DeleteHold {
        let gate: Gate = Arc::new((Mutex::new(true), Condvar::new()));
        let mut holds = HOLDS.lock().unwrap();
        holds.retain(|(name, _)| name != root.as_str());
        holds.push((root.as_str().to_owned(), gate.clone()));
        DeleteHold {
            gate,
            root: root.as_str().to_owned(),
        }
    }

    /// The hold on a root's delete thread, released when it is dropped.
    pub struct DeleteHold {
        gate: Gate,
        root: String,
    }

    impl Drop for DeleteHold {
        fn drop(&mut self) {
            HOLDS.lock().unwrap().retain(|(name, _)| *name != self.root);
            *self.gate.0.lock().unwrap() = false;
            self.gate.1.notify_all();
        }
    }

    static DELAYS: Mutex<Vec<(String, std::time::Duration)>> = Mutex::new(Vec::new());

    /// Makes the thread that makes the delete calls of the removal of the root named `root` wait
    /// `delay` before each call, until the guard is dropped. The wait is no request pending in the
    /// system, so a cancel does not shorten it: it stands for a delete call that ends by itself
    /// after a wait.
    #[must_use]
    pub fn delay_deletes(root: &RootName, delay: std::time::Duration) -> DeleteDelay {
        let mut delays = DELAYS.lock().unwrap();
        delays.retain(|(name, _)| name != root.as_str());
        delays.push((root.as_str().to_owned(), delay));
        DeleteDelay {
            root: root.as_str().to_owned(),
        }
    }

    /// The delay on a root's delete thread, removed when it is dropped.
    pub struct DeleteDelay {
        root: String,
    }

    impl Drop for DeleteDelay {
        fn drop(&mut self) {
            DELAYS
                .lock()
                .unwrap()
                .retain(|(name, _)| *name != self.root);
        }
    }

    pub(super) fn wait_while_held(root: &str) {
        let delay = DELAYS
            .lock()
            .unwrap()
            .iter()
            .find(|(name, _)| name == root)
            .map(|(_, delay)| *delay);
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        let gate = HOLDS
            .lock()
            .unwrap()
            .iter()
            .find(|(name, _)| name == root)
            .map(|(_, gate)| gate.clone());
        if let Some(gate) = gate {
            let mut held = gate.0.lock().unwrap();
            while *held {
                held = gate.1.wait(held).unwrap();
            }
        }
    }

    pub(super) fn note_cancel(root: &str) {
        let mut cancels = CANCELS.lock().unwrap();
        match cancels.iter_mut().find(|(name, _)| name == root) {
            Some((_, count)) => *count += 1,
            None => cancels.push((root.to_owned(), 1)),
        }
    }

    /// How many times the removals of the root named `root` asked the system to cancel a delete
    /// call.
    #[must_use]
    pub fn cancels(root: &RootName) -> usize {
        CANCELS
            .lock()
            .unwrap()
            .iter()
            .find(|(name, _)| name == root.as_str())
            .map_or(0, |(_, count)| *count)
    }
}

struct Removal {
    limits: Limits,
    /// The children listed so far, in every directory: the objects the root has used.
    listed: usize,
    /// The time spent so far waiting for objects in use.
    waited: Duration,
    /// Whether the one `too large` leftover was made.
    too_large: bool,
    /// Whether the removal makes no further delete call: one ended by its bound with the waits
    /// spent, or one that did not end.
    stopped: bool,
    leftovers: Vec<Leftover>,
    /// The thread that makes the delete calls.
    deleter: Deleter,
    /// The root's name, which the cases' functions are set by.
    #[cfg(feature = "testing")]
    root: String,
}

fn joined(at: &str, child: &Child) -> String {
    if at.is_empty() {
        child.display()
    } else {
        format!("{at}\\{}", child.display())
    }
}

impl Removal {
    fn leave(&mut self, path: &str, reason: impl Into<String>) {
        self.leftovers.push(Leftover {
            path: path.to_owned(),
            reason: reason.into(),
        });
    }

    /// The root's tree has more than the limits allow. That is one leftover for the root, made
    /// the first time, whichever directory is the first to show it.
    fn leave_too_large(&mut self) {
        if !self.too_large {
            self.too_large = true;
            self.leave("", "too large");
        }
    }

    /// Removes every child of `dir`, which is held open. The listing stops at the objects the
    /// root has left. A failure to list or to read an object is a leftover for it and the removal
    /// goes on.
    fn empty(&mut self, dir: &DirHandle, at: &str, depth: usize) {
        let room = self.limits.bounds.objects.saturating_sub(self.listed);
        let listing = match dir.children(room) {
            Ok(listing) => listing,
            Err(failure) => {
                self.leave(
                    at,
                    format!("could not be listed (Windows error {})", failure.code),
                );
                return;
            }
        };
        self.listed += listing.children.len();
        #[cfg(feature = "testing")]
        testing::fire(
            &self.root,
            &testing::Event::Listed {
                directory: at,
                names: listing.children.iter().map(Child::display).collect(),
                more: listing.more,
            },
        );
        if listing.more {
            self.leave_too_large();
        }
        for child in &listing.children {
            if self.stopped {
                break;
            }
            let path = joined(at, child);
            self.remove_child(dir, child, &path, depth);
        }
    }

    fn remove_child(&mut self, dir: &DirHandle, child: &Child, path: &str, depth: usize) {
        let listed_directory = child.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && child.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0;
        if listed_directory && depth >= self.limits.bounds.depth {
            self.leave_too_large();
            return;
        }
        // A link is opened as itself, with the right to delete it alone; a directory also with
        // the right to list it.
        let access = DELETE | if listed_directory { LIST } else { 0 };
        let opened = match self.open_waiting(dir, child, access) {
            Ok(opened) => opened,
            Err(Lost::Gone) => return,
            Err(Lost::Refused(code)) if code == ERROR_SHARING_VIOLATION => {
                self.leave(path, "in use");
                return;
            }
            Err(Lost::Refused(code)) if code == ERROR_ACCESS_DENIED => {
                self.leave(path, "access denied");
                return;
            }
            Err(lost) => {
                self.leave(path, lost.to_string());
                return;
            }
        };
        #[cfg(feature = "testing")]
        testing::fire(&self.root, &testing::Event::Opened { path });
        match opened.kind() {
            Kind::File | Kind::ReparsePoint => self.remove(opened.into_handle(), path),
            Kind::Directory if !listed_directory => {
                // The listing said a link and the object now reads as an ordinary directory:
                // it was opened for deletion alone and is not entered.
                self.leave(
                    path,
                    "it is a directory that was not one when it was listed",
                );
            }
            Kind::Directory => {
                let held = match DirHandle::from_opened(opened) {
                    Ok(held) => held,
                    Err(failure) => {
                        self.leave(
                            path,
                            format!(
                                "could not be read after it was opened (Windows error {})",
                                failure.code
                            ),
                        );
                        return;
                    }
                };
                let before = self.leftovers.len();
                self.empty(&held, path, depth + 1);
                if self.stopped {
                    return;
                }
                match held.children(1) {
                    Err(failure) => self.leave(
                        path,
                        format!("could not be listed (Windows error {})", failure.code),
                    ),
                    Ok(rest) if !rest.is_empty() => {
                        // A directory that stays only because of a leftover inside it, or
                        // because the root is too large, is not listed beside it; one that holds
                        // something new is.
                        if self.leftovers.len() == before && !self.too_large {
                            self.leave(path, "not empty after its contents were removed");
                        }
                    }
                    Ok(_) => self.remove(held.into_handle(), path),
                }
            }
        }
    }

    /// Opens a child for removal, waiting for a short while while another process has it open:
    /// at most `wait_each` for this object, and `wait_total` for all of the root's.
    fn open_waiting(
        &mut self,
        dir: &DirHandle,
        child: &Child,
        access: u32,
    ) -> Result<super::walk::Opened, Lost> {
        let mut here = Duration::ZERO;
        loop {
            match dir.open_child(child, access) {
                Ok(Err(Lost::Refused(code))) if code == ERROR_SHARING_VIOLATION => {
                    if here >= self.limits.wait_each || self.waited >= self.limits.wait_total {
                        return Err(Lost::Refused(code));
                    }
                    std::thread::sleep(RETRY_EVERY);
                    here += RETRY_EVERY;
                    self.waited += RETRY_EVERY;
                }
                Ok(other) => return other,
                Err(failure) => return Err(Lost::Refused(failure.code)),
            }
        }
    }

    /// Deletes through `handle`, which was opened and checked, on the delete thread and within
    /// the removal's bound, and makes a leftover of the object at `path` (the root when empty)
    /// when it cannot be. The open of every name completes at once on a lock that is not given
    /// up, so no delete call is reached on a handle that was opened while a break was owed; the
    /// break that the delete itself owes is the one a lock can still make it wait for. The call
    /// has `wait_each` or what is left of the total, and at least [`DELETE_FLOOR`]. The time of a
    /// call that takes longer than [`DELETE_GRACE`] is counted against the total whatever its
    /// result. A call that does not end, or one that takes longer than the grace once the total is
    /// spent, stops the removal's delete calls for this root: what is left stays, under one
    /// leftover for the root.
    fn remove(&mut self, handle: Handle, path: &str) {
        if self.stopped {
            return;
        }
        let remaining = self.limits.wait_total.saturating_sub(self.waited);
        let limit = remaining.min(self.limits.wait_each).max(DELETE_FLOOR);
        let started = Instant::now();
        let call = self.deleter.call(handle, limit);
        let elapsed = started.elapsed();
        if elapsed > DELETE_GRACE {
            self.waited += elapsed;
        }
        match call {
            Call::Ended(Ok(())) | Call::Cancelled(Ok(())) => {}
            Call::Ended(Err(failure)) => self.leave_not_removed(path, failure.code),
            Call::Cancelled(Err(failure)) => {
                if failure.code == ERROR_OPERATION_ABORTED {
                    self.leave(path, "in use");
                } else {
                    self.leave_not_removed(path, failure.code);
                }
            }
            Call::DidNotEnd => {
                self.leave(path, "the delete call did not end");
                self.stop("a delete call did not end");
            }
        }
        if elapsed > DELETE_GRACE && self.waited >= self.limits.wait_total {
            self.stop("the waits for objects in use are spent");
        }
    }

    fn leave_not_removed(&mut self, path: &str, code: u32) {
        if path.is_empty() {
            self.leave(
                path,
                format!("the root itself could not be removed (Windows error {code})"),
            );
        } else {
            self.leave(path, format!("not removed (Windows error {code})"));
        }
    }

    /// Ends the removal's delete calls for this root, with one leftover for the root that says why
    /// (none besides the root's own when the root's delete is the one that ended).
    fn stop(&mut self, reason: &str) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        if self
            .leftovers
            .last()
            .is_none_or(|last| !last.path.is_empty())
        {
            self.leave("", reason);
        }
    }
}

/// Deletes the object behind the handle with POSIX semantics: the name goes at once, whatever
/// else has the object open, and the read-only attribute does not stop it. The handle must be
/// open with the right to delete. On a link or a reparse point it removes that name only.
fn delete(handle: &Handle) -> Result<(), super::ffi::Error> {
    let information = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE
            | FILE_DISPOSITION_POSIX_SEMANTICS
            | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the handle is open with the right to delete, and the buffer is the structure the
    // class takes, of the size given.
    let status = unsafe {
        NtSetInformationFile(
            handle.raw(),
            &raw mut status_block,
            (&raw const information).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        )
    };
    if status < 0 {
        // SAFETY: converts a status code to a Windows error number; it reads nothing else.
        let code = unsafe { windows_sys::Win32::Foundation::RtlNtStatusToDosError(status) };
        return Err(error(code, "deleting an object"));
    }
    Ok(())
}

/// Checks that the disposition call works on this volume, on a scratch file made in `dir`, which
/// only administrators can write: the service refuses to start when it does not.
///
/// # Errors
///
/// Returns an error when the file cannot be made or the call does not delete it.
pub fn check_disposition(dir: &DirHandle) -> Result<(), RootError> {
    let name = format!("disposition-check-{}", random_name()?.as_str());
    let units: Vec<u16> = name.encode_utf16().collect();
    let handle = dir.create_file_named(&units, DELETE)?;
    delete(&handle)?;
    // The name is probed while the handle is still open: with POSIX semantics it is gone at once,
    // and a delete that waited for the last close would still show it.
    let exists = dir.name_exists(&units)?;
    drop(handle);
    if exists {
        return Err(RootError::Refused(
            "the platform's delete with POSIX semantics left the scratch file".to_owned(),
        ));
    }
    Ok(())
}
