//! A disposable host tree for tests.
//!
//! Every host crate needs the same thing from a test: a runtime and state directory that belong to
//! this user, are short enough for a socket address, and disappear afterwards. Building that by
//! hand in each crate invites the two mistakes this type removes — a directory created with the
//! process umask instead of owner-only, and a path long enough that `bind` fails for a reason that
//! has nothing to do with the test.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use kr_protocol::ids::EnvironmentId;

use crate::paths::{EnvironmentPaths, HostPaths};

pub mod created;
#[cfg(target_os = "linux")]
pub mod hung_mount;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod volumes;

/// A descriptor of this process's as far up the table as the system lets one go, left open on
/// exec, and the number it has.
///
/// Placed by asking for the first free number at or above a high one, which takes nothing
/// another case holds, and tried lower until the system accepts one: the highest number it
/// gives is below its own limit on descriptors, which is not always the soft limit.
///
/// # Panics
///
/// Panics when no number can be had at all.
#[cfg(all(unix, not(any(target_os = "ios", target_os = "android"))))]
#[must_use]
pub fn descriptor_far_up(like: &std::fs::File) -> std::os::fd::OwnedFd {
    let mut wanted = 70_000;
    loop {
        match rustix::io::fcntl_dupfd_cloexec(like, wanted) {
            Ok(placed) => {
                rustix::io::fcntl_setfd(&placed, rustix::io::FdFlags::empty())
                    .expect("left open on exec");
                return placed;
            }
            Err(_) if wanted > 64 => wanted /= 2,
            Err(error) => panic!("no descriptor could be placed far up the table: {error}"),
        }
    }
}

/// A loopback address that nothing answers at, whatever else is running beside a test.
///
/// A test that needs a connection refused cannot take the port it frees: another test in the same
/// binary, or another program, can be given that port before the test connects to it, and then
/// something answers. This address is not one a program is handed. The ports a program is given
/// when it asks for any free port begin far above port 1 unless the machine is set up to hand
/// out port 1, so nothing listens here unless a program was put here on purpose, and a connection
/// is refused. A machine where that does not hold fails `nothing_answers_at_the_unanswered_address`
/// in this crate, which names the address.
pub const UNANSWERED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

/// A host tree that removes itself when it is dropped.
///
/// Its root is a [`PrivateTempDir`] with a shorter name, so it is a directory this tree made and
/// nothing else did.
#[derive(Debug)]
pub struct TempHost {
    paths: HostPaths,
    environment_id: EnvironmentId,
    // Declared last: the directory is removed after every field above has let go of its files.
    root: PrivateTempDir,
}

impl TempHost {
    /// Creates a fresh tree under the platform's temporary directory.
    ///
    /// # Panics
    ///
    /// Panics when the directories cannot be created, which in a test means the environment is
    /// unusable rather than that the case under test failed.
    #[must_use]
    pub fn create() -> Self {
        Self::create_in(&std::env::temp_dir())
    }

    /// Creates a fresh tree under `parent`, which is how a test puts the whole host on a
    /// filesystem of its own.
    ///
    /// # Panics
    ///
    /// Panics when the directories cannot be created, which in a test means the environment is
    /// unusable rather than that the case under test failed.
    #[must_use]
    pub fn create_in(parent: &Path) -> Self {
        Self::create_with_state_name(parent, "s")
    }

    /// Creates a fresh tree under `parent` whose state root is the tree's directory `state_name`.
    ///
    /// A test that needs the state root to be the one a default install of a platform gives, which
    /// is a directory of a fixed name inside the directory a variable names, names it here.
    ///
    /// # Panics
    ///
    /// As [`Self::create`].
    #[must_use]
    pub fn create_with_state_name(parent: &Path, state_name: &str) -> Self {
        // Short on purpose: a Unix socket address is 104 bytes on macOS, and a command backend's
        // socket in a test host's runtime directory is the root's length and 39 bytes more. A name
        // this short can be taken, and then another is tried; it is never adopted.
        let root = PrivateTempDir::create_named(parent, || {
            let suffix = crate::new_uuid().to_string();
            format!("kr-{}", &suffix[..8])
        });
        let paths = HostPaths::new(root.path().join("r"), root.path().join(state_name))
            .expect("absolute roots");
        let environment_id = paths.open_environment_id().expect("environment identity");
        paths
            .environment(environment_id)
            .create()
            .expect("environment directories");
        Self {
            root,
            paths,
            environment_id,
        }
    }

    /// Returns the roots.
    #[must_use]
    pub const fn paths(&self) -> &HostPaths {
        &self.paths
    }

    /// Returns the environment identity allocated for this tree.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Returns the directories of this tree's environment.
    #[must_use]
    pub fn environment(&self) -> EnvironmentPaths {
        self.paths.environment(self.environment_id)
    }

    /// Returns the root of the tree.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.path()
    }
}

/// A temporary directory of the kind this host makes its own directories: owner-only, with the
/// same list on every platform, and removed when it is dropped.
///
/// `tempfile::tempdir()` makes a directory that inherits the access list of the temporary
/// directory it is under. Where that list names an account besides its owner, which is so on a
/// machine whose temporary directory carries an entry for another account, the host's owner-only
/// check refuses every directory a test builds below it, and so does the check of a directory a
/// test opens as one of the host's own. A test that hands a directory to code which checks it
/// takes one made here, whose list is protected and so inherits nothing.
///
/// The name is short on purpose: a Unix socket address is 104 bytes on macOS, and a temporary
/// directory there already spends about half of that. The directory is created exclusively: a name
/// that is already taken is somebody else's directory, so another name is tried, and what is
/// removed on drop is only ever what this value made. A [`TempHost`] is rooted in one.
#[derive(Debug)]
pub struct PrivateTempDir {
    root: PathBuf,
}

impl PrivateTempDir {
    /// How many names are tried before the temporary directory is taken to be unusable.
    const ATTEMPTS: usize = 16;

    /// Creates a fresh owner-only directory under the platform's temporary directory.
    ///
    /// # Panics
    ///
    /// Panics when the directory cannot be created, which in a test means the environment is
    /// unusable rather than that the case under test failed.
    #[must_use]
    pub fn create() -> Self {
        Self::create_in(&std::env::temp_dir())
    }

    /// Creates a fresh owner-only directory under `parent`.
    ///
    /// # Panics
    ///
    /// As [`Self::create`].
    #[must_use]
    pub fn create_in(parent: &Path) -> Self {
        Self::create_named(parent, || {
            let suffix = crate::new_uuid().to_string().replace('-', "");
            format!("kr-{}", &suffix[..12])
        })
    }

    /// Creates a fresh owner-only directory under `parent`, named by the names `next_name` gives
    /// in turn, and leaves alone every one of them that is already taken.
    fn create_named(parent: &Path, mut next_name: impl FnMut() -> String) -> Self {
        for _ in 0..Self::ATTEMPTS {
            let root = parent.join(next_name());
            if crate::paths::create_new_private_directory(&root)
                .expect("an owner-only temporary directory")
            {
                return Self { root };
            }
        }
        panic!(
            "no unused name for an owner-only temporary directory under {} in {} tries",
            parent.display(),
            Self::ATTEMPTS
        );
    }

    /// Returns the directory's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }
}

/// How long the removal of a [`PrivateTempDir`] is tried again while it is refused for a reason
/// that time can end.
///
/// That is any refusal on Windows, where a file held open without sharing refuses the removal of
/// the folder it is in until its holder lets go. Elsewhere it is the refusal "directory not
/// empty": another thread made a file in the tree while it was removed, as the drop of a listener
/// makes its lock file again when a task that was aborted is cancelled beside the removal, and the
/// next removal takes that file as well. Elsewhere a permission's refusal is final at once, and on
/// Windows it is tried again like every other refusal. The patience covers a holder that is
/// ending: a task that was aborted and is cancelled at the runtime's next turn, a thread that is
/// joining. A holder that keeps a file longer than this has not let go yet: a fixture that does
/// not end it, or a blocking thread or a shell's teardown that a loaded host is slow to finish.
/// The drop then says so on the error output when the line is written (the process can end
/// before), a line that names the case, and the directory is left to the cleanup of the temporary
/// folder. A case that needs the tree gone, as one that starts a daemon whose own sweep holds a
/// file for up to thirty seconds does, waits for it itself.
pub const REMOVAL_PATIENCE: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the drop of a [`PrivateTempDir`] waits for its own line to be written: a bound on the
/// wait, which a standard error that has stopped draining is the only one to pay.
///
/// A stream that takes the line has it written as soon as the thread that writes it runs, and the
/// drop goes on then. The bound is an expectation and not a guarantee: it is long enough that no
/// case's result depends on it when a new thread runs within five seconds, as the thread of a
/// loaded machine does, so that a process that ends right after the drop keeps its line. A stalled
/// stream holds the drop for the whole of it, once.
const LINE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// What the drop of a [`PrivateTempDir`] knows of the line that it said, as two facts that the
/// drop itself sets: a stall of the dropping thread or of the process that does not keep the
/// receive past `LINE_WAIT` changes neither.
///
/// `wait` is the length of the wait that the drop gave the writer's word: the time that its
/// receive was given, set from the same value, whether or not a word came. It is nothing when no
/// thread could be started, as there was then no wait to give. A wait of no length can still find
/// the word, since a writer that is quicker than the dropping thread has sent it before the
/// receive begins; `wait` is what says that the wait had no length.
///
/// `written` is true only when the writer's word came in that time and said that its write
/// returned without an error. It is false for a word that says the write failed, for a wait that
/// ran out, and for a drop that did not wait for a word.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the cases of this file read the record, and no other code does"
    )
)]
struct LineRecord {
    wait: std::time::Duration,
    written: bool,
}

/// The record of the last drop of a [`PrivateTempDir`] that said a line: both facts are nothing
/// until a drop has said one.
///
/// A process that a case runs again reads it right after the drop to learn how the drop waited and
/// whether its writer wrote, which the line on the standard error cannot say: a process that is
/// stopped for long enough after a drop that did not wait finds the line written all the same.
static LAST_LINE: std::sync::Mutex<LineRecord> = std::sync::Mutex::new(LineRecord {
    wait: std::time::Duration::ZERO,
    written: false,
});

/// Whether the refusal `error` of a removal is one that time can end: any refusal on Windows, and
/// elsewhere "directory not empty", which means that another thread made a file in the tree while
/// it was removed. Elsewhere a permission's refusal stays as it is.
fn time_can_end(error: &std::io::Error) -> bool {
    cfg!(windows) || error.kind() == std::io::ErrorKind::DirectoryNotEmpty
}

/// Removes `root` and what is in it, with `remove` as the removal of the directory so that a case
/// can see each time it is refused. A refusal that time can end is tried again for no longer than
/// `patience`, which is no time at all when it is zero; the refusal that is left at the end is
/// returned. A directory that is not there is removed.
fn remove_tree_by(
    root: &Path,
    patience: std::time::Duration,
    mut remove: impl FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let begun = std::time::Instant::now();
    loop {
        match remove(root) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) if time_can_end(&error) && begun.elapsed() < patience => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Removes `root` as [`remove_tree_by`] does, and gives `say` the line that names the tree when it
/// is not removed at the end. `say` is not called when the tree is gone.
fn remove_tree_or_say(
    root: &Path,
    patience: std::time::Duration,
    remove: impl FnMut(&Path) -> std::io::Result<()>,
    say: impl FnOnce(String),
) {
    let begun = std::time::Instant::now();
    if let Err(error) = remove_tree_by(root, patience, remove) {
        // The thread of a case is named for the case, so this names the case that left the tree.
        let thread = std::thread::current();
        say(format!(
            "{} is not removed {:?} after its removal was first tried, by {}: {error}\n",
            root.display(),
            begun.elapsed(),
            thread.name().unwrap_or("a thread with no name")
        ));
    }
}

impl Drop for PrivateTempDir {
    /// Removes the directory and what is in it.
    ///
    /// The removal is refused when another thread makes a file in the tree while it is removed, as
    /// the drop of a listener does when a task that was aborted is cancelled on another thread
    /// beside the removal, and on Windows when a thread or a process still holds a file open
    /// without sharing. Such a holder is usually something that is ending and lets go soon, so the
    /// removal is tried again while the refusal is one that time can end, and for no longer than
    /// `REMOVAL_PATIENCE` (two seconds); elsewhere than on Windows a permission's refusal is final
    /// at once.
    ///
    /// What is not removed at the end is said on the error output, outside what a test's capture
    /// keeps, by a thread of its own that the drop waits for no longer than `LINE_WAIT`: a standard
    /// error that has stopped draining holds a writer for as long as it stands full, and the case
    /// that stalls one holds nothing else. The line is lost when the stream takes none in that
    /// time and the process ends before it does. The drop does not fail the case: this directory
    /// is made by the suites of every platform, and a case that has a holder to wait for, as a
    /// host that waits for its daemon's lock does, fails on a tree that is left, and one that has a
    /// guard of its own removes the tree again after this.
    fn drop(&mut self) {
        remove_tree_or_say(
            &self.root,
            REMOVAL_PATIENCE,
            |root| std::fs::remove_dir_all(root),
            say_on_the_standard_error,
        );
    }
}

/// Says `line` on the standard error from a thread of its own, and waits for that thread's word
/// about its write for `LINE_WAIT` at most. The drop keeps what it gave and what it got as
/// [`LAST_LINE`].
///
/// A write to a standard error that has stopped draining waits for a reader, and the standard
/// library holds one lock for the whole write, so a thread that writes beside it waits too. A drop
/// that said its line on the thread that drops would hold that thread for as long as the stream
/// stands full, and a process whose standard error is full and read by no one, as the one a case
/// runs to show that a worker goes on, would not end. So the writer is a thread of its own, and
/// the wait for it has a bound: a stream that takes the line keeps it even when the process ends
/// right after, and a stalled one holds the drop for the bound only. The line is lost when the
/// stream takes none by then and the process ends first, or when no thread could be started.
fn say_on_the_standard_error(line: String) {
    use std::io::Write as _;

    let record = say_by(line, LINE_WAIT, |line| {
        std::io::stderr().write_all(line.as_bytes())
    });
    *LAST_LINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = record;
}

/// [`say_on_the_standard_error`] with the write given, and the time to wait for it, so that a case
/// can have a write that is slow, one that stalls or one that fails. The writer sends the result of
/// its write as its word. The answer is the [`LineRecord`] of the wait: `wait` is the time that the
/// receive of the word was given, and `written` says that a word came in that time and that it said
/// the write returned without an error.
fn say_by(
    line: String,
    wait: std::time::Duration,
    write: impl FnOnce(String) -> std::io::Result<()> + Send + 'static,
) -> LineRecord {
    let (word, writing) = std::sync::mpsc::channel::<std::io::Result<()>>();
    let started = std::thread::Builder::new()
        .name("kr-test-support-said".to_owned())
        .spawn(move || {
            let _ = word.send(write(line));
        });
    if started.is_err() {
        return LineRecord {
            wait: std::time::Duration::ZERO,
            written: false,
        };
    }
    let heard = writing.recv_timeout(wait);
    LineRecord {
        wait,
        written: matches!(heard, Ok(Ok(()))),
    }
}

/// A task that serves a fixture and is asked to end when this is dropped.
///
/// A task whose handle is dropped keeps running, with everything it holds, until the test's
/// runtime ends. A fixture that serves a worker service from such a task has the service's files
/// open for as long, and where an open file refuses the removal of the folder it is in, the
/// fixture's directory cannot go. A fixture keeps this as a field declared before its directory, so
/// that the cancellation is asked for before the directory is removed.
///
/// An abort asks for the cancellation and does not wait for it. On a multi-thread runtime a worker
/// thread cancels the task, which drops its future and what that holds, beside the thread that
/// drops this, so a file that the task's drop lets go of or makes (a listener makes its lock file
/// again as it is dropped) can change the directory while it is removed: the removal of a
/// [`PrivateTempDir`] tries a refusal of that kind again. On a current-thread runtime the
/// cancellation runs when the dropping thread next gives the runtime a turn.
#[derive(Debug)]
pub struct Serving(tokio::task::AbortHandle);

impl Serving {
    /// Spawns `task` on the current runtime.
    ///
    /// # Panics
    ///
    /// Panics when no Tokio runtime is running.
    pub fn spawn<F>(task: F) -> Self
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        Self(tokio::spawn(task).abort_handle())
    }
}

impl Serving {
    /// Asks for the cancellation of the task of `handle` when this is dropped, as a fixture that
    /// keeps the handle too needs.
    #[must_use]
    pub fn guarding<T>(handle: &tokio::task::JoinHandle<T>) -> Self {
        Self(handle.abort_handle())
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Holds the process's file-creation mask at 022, the one a login starts with, until it is dropped.
///
/// A directory made without a mode of its own comes out 0755 under it, which is what a daemon that
/// no service definition started makes. A case that must show a directory is owner-only because the
/// host asked for that mode, and not because the mask of whoever runs the suite happens to take the
/// rest away, holds this first. The mask belongs to the whole process, so a second holder waits for
/// the first to drop its own; a case that does not hold one runs under whichever mask is set.
#[cfg(unix)]
pub struct LoginUmask {
    previous: rustix::fs::Mode,
    _turn: std::sync::MutexGuard<'static, ()>,
}

#[cfg(unix)]
impl LoginUmask {
    /// Sets the mask to 022, after any other holder has dropped its own.
    #[must_use]
    pub fn hold() -> Self {
        static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let turn = TURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(0o022));
        Self {
            previous,
            _turn: turn,
        }
    }
}

#[cfg(unix)]
impl Drop for LoginUmask {
    fn drop(&mut self) {
        rustix::process::umask(self.previous);
    }
}

/// Returns the program that copies a file on this system.
///
/// The usual two places first, then the search path, and a clear refusal when there is none. A
/// system without one cannot place a program this way, and saying so here is better than a failure
/// later that reads like the test's own.
///
/// # Panics
///
/// Panics when this system has no copying program.
#[cfg(unix)]
fn copying_program() -> PathBuf {
    // A name on the search path this user cannot run is not the program being looked for, and
    // stopping at it would hide the one further along that can be run. The operating system is
    // asked, against this process's own credentials: a mode bit on its own says whose permission
    // it is rather than whether it is this process's.
    fn runnable(candidate: &Path) -> bool {
        std::fs::metadata(candidate).is_ok_and(|about| about.is_file())
            && rustix::fs::access(candidate, rustix::fs::Access::EXEC_OK).is_ok()
    }

    for usual in ["/bin/cp", "/usr/bin/cp"] {
        let candidate = Path::new(usual);
        if runnable(candidate) {
            return candidate.to_path_buf();
        }
    }
    let searched = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&searched) {
        let candidate = directory.join("cp");
        if runnable(&candidate) {
            return candidate;
        }
    }
    panic!(
        "a program cannot be placed on this system: it has no copying program that can be run, at \
         /bin/cp, at /usr/bin/cp or anywhere on the search path"
    );
}

/// Places a program where a test can start it, and leaves nothing holding it open for writing.
///
/// A test binary runs its cases on several threads. The moment one thread starts a child process,
/// that child is handed a copy of every descriptor the process had open at that instant, including
/// one another thread has open for writing, and it keeps the copy until its own program takes
/// over. No program can be started while any descriptor anywhere holds it open for writing, so a
/// thread that writes a program and then starts it is racing every other thread in the process:
/// the more the machine has to do, the longer a child takes to reach its own program, and the
/// wider the window in which the write is still visible to it.
///
/// So the bytes are not written by this process at all. Writing them from a process that starts
/// nothing keeps a writing descriptor out of this process's hands altogether, and no child of this
/// test can be handed one it was never given. The placed program is the caller's to start from
/// that moment on, however loaded the machine is and whatever else the test is doing beside it.
///
/// # Panics
///
/// Panics when the program cannot be placed, which in a test means the environment is unusable
/// rather than that the case under test failed.
pub fn place_program(source: &Path, destination: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let copier = copying_program();
        let status = std::process::Command::new(&copier)
            .arg(source)
            .arg(destination)
            .status()
            .unwrap_or_else(|error| {
                panic!(
                    "{} could not be started to place the program at {} at {}: {error}",
                    copier.display(),
                    source.display(),
                    destination.display()
                )
            });
        assert!(
            status.success(),
            "{} did not place the program at {} at {}: {status}",
            copier.display(),
            source.display(),
            destination.display()
        );
        // Owner-only and runnable: a test's own copy of a program is nobody else's business, and
        // the mode a copy is given depends on the person's file-creation mask.
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| {
                panic!(
                    "the program placed at {} could not be made runnable: {error}",
                    destination.display()
                )
            });
    }
    #[cfg(windows)]
    {
        // A program here is held open by the handle that started it rather than by one that wrote
        // it, and a write that has been closed leaves nothing behind for a start to trip over.
        std::fs::copy(source, destination).unwrap_or_else(|error| {
            panic!(
                "the program at {} could not be placed at {}: {error}",
                source.display(),
                destination.display()
            )
        });
    }
}

/// Places a program whose text is `text` at `destination`, runnable, and leaves nothing holding it
/// open for writing.
///
/// The same race as [`place_program`] describes holds for a script a test writes: the thread that
/// writes it and then starts it, or has a shell or a daemon start it, is racing every child another
/// thread starts meanwhile. Closing and syncing the file here would not end that race. A child
/// started while the file is open for writing carries its own copy of the open file until its
/// program takes over, and closing this process's descriptor does not take that copy away; the
/// start then fails with "text file busy" for as long as the child has not yet taken over, which
/// is longer the more the machine has to do.
///
/// So on Unix this process never opens the program for writing. The text goes to a file beside it
/// that nothing starts, a separate process copies that file into place as [`place_program`] does,
/// and the file of text is removed. On Windows [`place_program`] copies in this process, which is
/// safe there: a program is held open by the handle that started it, not by one that wrote it.
///
/// # Panics
///
/// Panics when the text cannot be written or removed, or the program cannot be placed.
pub fn place_script(destination: &Path, text: impl AsRef<[u8]>) {
    let mut name = destination
        .file_name()
        .expect("a program has a name")
        .to_owned();
    name.push(".text");
    let text_file = destination.with_file_name(name);
    std::fs::write(&text_file, text).unwrap_or_else(|error| {
        panic!(
            "the text of the program at {} could not be written: {error}",
            destination.display()
        )
    });
    place_program(&text_file, destination);
    std::fs::remove_file(&text_file).unwrap_or_else(|error| {
        panic!(
            "the text of the program at {} could not be removed once the program was placed: \
             {error}",
            destination.display()
        )
    });
}

/// The descriptor numbers a program started by this process holds when it begins, from 3 up.
///
/// A child is handed a copy of every descriptor of this process that is not marked to close when a
/// program takes over. The child asked here is a shell that looks at the numbers one by one, so
/// what it reports is what the operating system let through. Numbers from 1024 up are not looked
/// at.
///
/// # Panics
///
/// Panics when the shell cannot be started or does not answer with numbers.
#[cfg(unix)]
#[must_use]
pub fn descriptors_a_started_program_holds() -> std::collections::BTreeSet<u32> {
    let looked = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(
            "n=3; while [ $n -lt 1024 ]; do [ -e /dev/fd/$n ] && echo $n; n=$((n+1)); done; exit 0",
        )
        .stdin(std::process::Stdio::null())
        .output()
        .expect("a shell to ask which descriptors a started program holds");
    assert!(
        looked.status.success(),
        "the shell ended with {}",
        looked.status
    );
    String::from_utf8_lossy(&looked.stdout)
        .lines()
        .map(|line| line.parse().expect("a descriptor number"))
        .collect()
}

/// How long the first start of a placed program is given to end.
///
/// A bound on what the operating system does before the program runs at all, and a wide one: a
/// start that has not ended in five minutes is a machine that cannot run the test, and the
/// caller's own deadlines are what measure the program.
const FIRST_START_BOUND: std::time::Duration = std::time::Duration::from_secs(300);

/// Places a program as [`place_program`] does, starts the placed copy once with `arguments`, and
/// waits for that start to end before it returns how long the start took.
///
/// The operating system checks an executable the first time it is started from a newly written
/// file. That is paid once per file rather than once per build: every copy pays it, and a copy
/// that has been started once starts in milliseconds afterwards. On macOS a copy of the debug
/// worker takes about a second for it on a quiet machine and several times that on a loaded one,
/// which is enough to spend a deadline the product holds its first real start to, such as a
/// worker's rendezvous. Paid here, where nothing is timed, it stays out of every test's deadline,
/// and the product's deadlines stay what they are.
///
/// `arguments` must make the program end at once and touch nothing, such as `--version`. The start
/// runs in the directory the program was placed in, with nothing to read and nowhere to write.
///
/// # Panics
///
/// Panics when the program cannot be placed or started, or when its first start does not end
/// successfully within five minutes.
pub fn place_and_start_once(
    source: &Path,
    destination: &Path,
    arguments: &[&str],
) -> std::time::Duration {
    place_program(source, destination);
    let started = std::time::Instant::now();
    let mut command = std::process::Command::new(destination);
    command
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(directory) = destination.parent() {
        command.current_dir(directory);
    }
    let mut child = command.spawn().unwrap_or_else(|error| {
        panic!(
            "the program placed at {} could not be started: {error}",
            destination.display()
        )
    });
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(
                    status.success(),
                    "the first start of the program placed at {} ended with {status}",
                    destination.display()
                );
                return started.elapsed();
            }
            Ok(None) if started.elapsed() < FIRST_START_BOUND => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(None) => {
                // This process's own child, which it has not collected, so the number is still its.
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the first start of the program placed at {} did not end within \
                     {FIRST_START_BOUND:?}",
                    destination.display()
                );
            }
            Err(error) => panic!(
                "the first start of the program placed at {} could not be waited for: {error}",
                destination.display()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::net::TcpStream;
    use std::time::Duration;

    use super::{PrivateTempDir, UNANSWERED};

    /// How long the connection is given to end: a watchdog, never a claim. A closed port refuses
    /// at once on Linux and macOS, and on Windows after the system's own retries, about two
    /// seconds.
    const WATCHDOG: Duration = Duration::from_secs(60);

    /// A descriptor reaches a program this process starts when it is not marked to close as the
    /// program takes over, and the check that says so sees both: it is what the cases that ask
    /// whether a descriptor is handed to a child rely on.
    #[cfg(unix)]
    #[test]
    fn a_descriptor_is_held_by_a_started_program_only_when_it_is_not_marked_to_close() {
        let socket = crate::endpoint::stream_socket().expect("a socket");
        let number = u32::try_from(std::os::fd::AsRawFd::as_raw_fd(&socket)).expect("a number");
        assert!(
            !super::descriptors_a_started_program_holds().contains(&number),
            "a socket made to close on execution is not handed to a program"
        );
        rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::empty()).expect("the mark comes off");
        assert!(
            super::descriptors_a_started_program_holds().contains(&number),
            "a socket without the mark is handed to a program"
        );
    }

    /// A private directory is made only where nothing is. A name that is already taken is another
    /// directory's, which two owners would share and either could remove, so the second maker is
    /// told the name was taken, leaves what is there as it is, and takes the next name.
    #[test]
    fn a_private_directory_is_not_made_where_a_name_is_taken() {
        let first = PrivateTempDir::create();
        std::fs::write(first.path().join("kept"), b"the first owner's").expect("writes a file");

        let made =
            crate::paths::create_new_private_directory(first.path()).expect("asks for the name");

        assert!(!made, "a directory that was already there was made again");
        let taken = first
            .path()
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("a name")
            .to_owned();
        let free = format!("kr-free-{}", crate::new_uuid());
        let mut names = [taken, free.clone()].into_iter();
        let second = PrivateTempDir::create_named(&std::env::temp_dir(), || {
            names.next().expect("a name is left")
        });
        assert_eq!(second.path().file_name(), Some(std::ffi::OsStr::new(&free)));
        assert_eq!(
            std::fs::read(first.path().join("kept")).expect("the file is still there"),
            b"the first owner's"
        );
    }

    /// The removal of a private directory that is refused at a file held open without sharing, as a
    /// task that is ending holds one, is tried again, and succeeds once the file is let go of. The
    /// holder lets go of the file when the first removal is refused, which the case sees in the
    /// removal it gives, so nothing here waits for a time: the removal tried again is the one that
    /// finds the folder free.
    #[cfg(windows)]
    #[test]
    fn a_removal_refused_at_a_file_that_is_held_is_tried_again_once_the_file_is_let_go_of() {
        use std::os::windows::fs::OpenOptionsExt as _;

        let directory = PrivateTempDir::create();
        let root = directory.path().to_path_buf();
        std::fs::write(root.join("a-plain"), b"goes at the first removal").expect("a plain file");
        let mut held = Some(
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .share_mode(0)
                .open(root.join("store.db"))
                .expect("a file held open without sharing"),
        );
        let mut refusals = 0;

        let removed = super::remove_tree_by(&root, Duration::from_secs(60), |root| {
            let removal = std::fs::remove_dir_all(root);
            if removal.is_err() {
                refusals += 1;
                held = None;
            }
            removal
        });

        removed.expect("the removal that was tried again succeeds");
        assert_eq!(
            refusals, 1,
            "the removal was refused once, and then tried again"
        );
        assert!(!root.exists(), "{} is left", root.display());
    }

    /// Set in the environment of the process that a case below runs again, to the directory whose
    /// removal that process is refused.
    #[cfg(unix)]
    const REFUSED_DIRECTORY: &str = "KR_TEST_SUPPORT_REFUSED_DIRECTORY";

    /// Fills this process's standard error, a pipe, to the last byte, so that the next write to it
    /// waits for a reader.
    #[cfg(unix)]
    fn fill_standard_error() {
        use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

        let standard_error = std::io::stderr();
        let flags = fcntl_getfl(&standard_error).expect("the flags of the standard error");
        fcntl_setfl(&standard_error, flags | OFlags::NONBLOCK).expect("a write that does not wait");
        for chunk in [1024_usize, 1] {
            let bytes = vec![b'.'; chunk];
            loop {
                match rustix::io::write(&standard_error, &bytes) {
                    Ok(_) => {}
                    Err(rustix::io::Errno::AGAIN) => break,
                    Err(error) => panic!("filling the standard error: {error}"),
                }
            }
        }
        fcntl_setfl(&standard_error, flags).expect("a write that waits again");
    }

    /// A directory whose removal is refused because the parent that holds it is not writable, which
    /// time does not change. The parent is made writable again when this is dropped, so that a case
    /// that fails, or ends the process it runs, leaves no read-only folder behind.
    #[cfg(unix)]
    struct Refused {
        directory: std::path::PathBuf,
        parent: PrivateTempDir,
    }

    #[cfg(unix)]
    impl Refused {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            let parent = PrivateTempDir::create();
            let directory = parent.path().join("refused");
            std::fs::create_dir(&directory).expect("a directory to refuse the removal of");
            std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o555))
                .expect("the parent refuses what is taken out of it");
            Self { directory, parent }
        }
    }

    #[cfg(unix)]
    impl Drop for Refused {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;

            let _ = std::fs::set_permissions(
                self.parent.path(),
                std::fs::Permissions::from_mode(0o700),
            );
        }
    }

    /// Whether this user is one that a mode refuses nothing to, as a privileged user removes what
    /// a mode refuses to anyone else, so that a case that needs a refusal has nothing to show. It
    /// says so on the standard error, around what the test harness captures and shows only for a
    /// case that fails, and names the case by the name of its thread, so that the run names the
    /// case it did not exercise.
    #[cfg(unix)]
    fn a_mode_refuses_nothing_to_this_user() -> bool {
        use std::io::Write as _;

        let privileged = rustix::process::getuid().is_root();
        if privileged {
            let thread = std::thread::current();
            let line = format!(
                "skipped by {}: a mode refuses nothing to a privileged user\n",
                thread.name().unwrap_or("a thread with no name")
            );
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
        privileged
    }

    /// Says on the standard output what a panic of the process that a case runs again is, so that a
    /// failure before the drop names itself in what the case that runs it reads: the default hook
    /// writes to the standard error, which a process with a full one waits on.
    #[cfg(unix)]
    fn report_panics_on_the_standard_output() {
        std::panic::set_hook(Box::new(|failure| {
            println!("the process panicked: {failure}");
        }));
    }

    /// How long the thread of [`hold_the_standard_error`] holds the lock. It makes a drop that
    /// waits really wait: its writer cannot write before the lock is free. It decides nothing. A
    /// dropping thread that is stopped for longer than this finds the lock free, and a wait of no
    /// length finds the writer's word already sent; the record of the wait that the drop gave
    /// ([`LineRecord`]) is what rejects that, and the length that the record must have is this one.
    #[cfg(unix)]
    const STANDARD_ERROR_HELD: Duration = Duration::from_millis(300);

    /// Starts a thread that takes the standard error's lock, holds it for `STANDARD_ERROR_HELD` and
    /// lets go, and returns once the thread has it. No other thread can write through
    /// `std::io::stderr()` in between.
    #[cfg(unix)]
    fn hold_the_standard_error() {
        let (holding, held) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let lock = std::io::stderr().lock();
            let _ = holding.send(());
            std::thread::sleep(STANDARD_ERROR_HELD);
            drop(lock);
        });
        held.recv().expect("the thread holds the standard error");
    }

    /// The status that a process of a line case ends with when the drop gave its wait a length
    /// shorter than `STANDARD_ERROR_HELD`, nothing included.
    #[cfg(unix)]
    const WAIT_TOO_SHORT: i32 = 3;

    /// The status that a process of a line case ends with when the drop's wait had a length and the
    /// writer's word does not say that its write returned without an error.
    #[cfg(unix)]
    const WRITE_NOT_DONE: i32 = 4;

    /// Ends the process of a line case, right after its drop and before it prints anything else,
    /// with the status that the drop's record gives ([`LineRecord`]): `WAIT_TOO_SHORT` when the
    /// wait that the drop gave was shorter than `STANDARD_ERROR_HELD`, else `WRITE_NOT_DONE` when
    /// the writer's word does not say that its write returned without an error, else 0. The two
    /// facts are read from the record and nothing else, so that no schedule of this process or of
    /// the drop changes them. What the drop took and the two facts go to the standard output, which
    /// a failure shows.
    #[cfg(unix)]
    fn end_by_the_record_of_the_drop(took: Duration) -> ! {
        let record = *super::LAST_LINE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        println!(
            "the drop took {took:?}; it gave its wait {:?}; the writer's word that its write \
             returned without an error: {}",
            record.wait, record.written
        );
        std::process::exit(if record.wait < STANDARD_ERROR_HELD {
            WAIT_TOO_SHORT
        } else if !record.written {
            WRITE_NOT_DONE
        } else {
            0
        });
    }

    /// What a process that a case runs again left: how it ended and what it wrote.
    #[cfg(unix)]
    struct Ended {
        status: std::process::ExitStatus,
        standard_output: String,
        standard_error: String,
    }

    /// Runs the case `name` again as a process of its own, with `directory` named for it, and reads
    /// what it wrote when it has ended. The process ends on its own, and it is ended by its pid
    /// when it has not ended in `WATCHDOG`, which is a limit on how long a failure takes to show
    /// and not a claim about how long the process takes. `if_stuck` says what a process that did
    /// not end was waiting for, as the case that runs it knows it. Its standard error is a pipe
    /// that this process reads, or `standard_error` when that is given, which this process then
    /// reads nothing from.
    #[cfg(unix)]
    fn run_again(
        name: &str,
        directory: &std::path::Path,
        standard_error: Option<std::fs::File>,
        if_stuck: &str,
    ) -> Ended {
        use std::io::Read as _;
        use std::process::{Command, Stdio};

        // The name the test program knows the case by: its module path without the crate's name.
        let name = format!(
            "{}::{name}",
            module_path!().split_once("::").expect("a module path").1
        );
        let mut child = Command::new(std::env::current_exe().expect("this test's program"))
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(REFUSED_DIRECTORY, directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(standard_error.map_or_else(Stdio::piped, Stdio::from))
            .spawn()
            .expect("starts the process");
        let pid = child.id();
        let mut standard_output = child.stdout.take().expect("its standard output");
        let mut standard_error = child.stderr.take();
        let (ended, ending) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = ended.send(child.wait());
        });

        let timely = ending.recv_timeout(WATCHDOG);
        if timely.is_err() {
            let pid =
                rustix::process::Pid::from_raw(i32::try_from(pid).expect("a pid")).expect("a pid");
            rustix::process::kill_process(pid, rustix::process::Signal::KILL)
                .expect("ends the process by its pid");
            let _ = ending.recv();
        }
        let mut said = String::new();
        standard_output
            .read_to_string(&mut said)
            .expect("reads its standard output");
        let Ok(status) = timely else {
            panic!("the process did not end in {WATCHDOG:?}: {if_stuck}: {said}");
        };
        let mut written = String::new();
        if let Some(stream) = standard_error.as_mut() {
            stream
                .read_to_string(&mut written)
                .expect("reads its standard error");
        }
        Ended {
            status: status.expect("waits for the process"),
            standard_output: said,
            standard_error: written,
        }
    }

    /// The drop of a directory whose removal is refused does not wait for a reader of the standard
    /// error: with the standard error full and read by no one, its line cannot be written, and the
    /// drop returns when `LINE_WAIT` is up and the process ends. The wait ran out, so the drop has
    /// no word from the writer that its write returned, and its record says so. The removal is
    /// refused because the directory's parent does not let it go, which time does not change.
    ///
    /// The case runs itself again as a process of its own, whose standard error is a pipe that the
    /// first process holds and does not read until that process has ended. A process that has not
    /// ended in `WATCHDOG` is ended by its pid.
    #[cfg(unix)]
    #[test]
    fn a_refused_removal_does_not_wait_for_a_standard_error_that_is_full() {
        const NAME: &str = "a_refused_removal_does_not_wait_for_a_standard_error_that_is_full";

        if let Some(directory) = std::env::var_os(REFUSED_DIRECTORY) {
            report_panics_on_the_standard_output();
            fill_standard_error();
            drop(PrivateTempDir {
                root: directory.into(),
            });
            println!("the drop returned");
            let record = *super::LAST_LINE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                !record.written,
                "the drop had the writer's word that its write returned without an error, which a \
                 full standard error cannot take"
            );
            return;
        }
        if a_mode_refuses_nothing_to_this_user() {
            return;
        }

        let refused = Refused::new();
        let ended = run_again(
            NAME,
            &refused.directory,
            None,
            "its drop waited for a reader of the standard error",
        );

        assert!(
            ended.status.success() && ended.standard_output.contains("the drop returned"),
            "the process ended badly ({}): {}",
            ended.status,
            ended.standard_output
        );
    }

    /// The drop of a directory that is refused waits for the writer of its line, and a process that
    /// ends right after it has said so on its standard error.
    ///
    /// The case runs itself again as a process of its own, and reads how it ended and its standard
    /// error. In that process one more thread takes the standard error's lock before the drop,
    /// says that it has it, holds it for `STANDARD_ERROR_HELD` and lets go. The drop gives its
    /// line to a writer thread, waits for the writer's word, and records two facts
    /// ([`LineRecord`]): the length of the wait that it gave, and whether the word said that the
    /// write returned without an error. The process reads the record right after the drop, before
    /// it prints anything, and ends with `WAIT_TOO_SHORT` when the wait was shorter than the hold
    /// and with `WRITE_NOT_DONE` when the word does not say that the write returned without an
    /// error. The case fails on either status, whatever the standard error holds, and passes only
    /// when both facts hold. A stall of the process or of the dropping thread that does not keep
    /// the receive past `LINE_WAIT` changes neither fact; the case rests only on the time that the
    /// writer takes, which the wait of `LINE_WAIT` bounds. The line alone cannot decide the case,
    /// because a process that is stopped for long enough after a drop that did not wait finds the
    /// line written all the same. The hold makes a drop that waits really wait; it decides
    /// nothing. The process says on its standard output what the drop took and the two facts,
    /// which a failure shows.
    ///
    /// One kind of run is outside what this case can tell. When the writer's word is already in the
    /// channel at the receive's last check (the dropping thread was stopped until the writer had
    /// written, or a short receive woke after the word came), a wait of `LINE_WAIT`, a wait shorter
    /// than the hold and a wait of no length do the same: the receive returns the word at once and
    /// the line is written. A change of the receive's own argument that leaves the recorded wait as
    /// it is passes the case in such a run, and fails it in every run in which the word is not yet
    /// there. A change that shortens the recorded wait to less than `STANDARD_ERROR_HELD` fails the
    /// case in every run, with `WAIT_TOO_SHORT`.
    #[cfg(unix)]
    #[test]
    fn a_process_that_ends_after_a_refused_removal_has_said_so() {
        const NAME: &str = "a_process_that_ends_after_a_refused_removal_has_said_so";

        if let Some(directory) = std::env::var_os(REFUSED_DIRECTORY) {
            report_panics_on_the_standard_output();
            hold_the_standard_error();
            let begun = std::time::Instant::now();
            drop(PrivateTempDir {
                root: directory.into(),
            });
            end_by_the_record_of_the_drop(begun.elapsed());
        }
        if a_mode_refuses_nothing_to_this_user() {
            return;
        }

        let refused = Refused::new();
        let ended = run_again(
            NAME,
            &refused.directory,
            None,
            "what it waited for is not known here, and its output shows whether the drop returned",
        );

        assert_ne!(
            ended.status.code(),
            Some(WAIT_TOO_SHORT),
            "the drop gave its wait a length shorter than the hold: {}",
            ended.standard_output
        );
        assert_ne!(
            ended.status.code(),
            Some(WRITE_NOT_DONE),
            "the writer's word does not say that its write returned without an error: {}",
            ended.standard_output
        );
        assert!(
            ended.status.success(),
            "the process ended badly ({}): {}",
            ended.status,
            ended.standard_output
        );
        assert!(
            ended
                .standard_error
                .contains(&format!("{} is not removed", refused.directory.display())),
            "the process ended without saying that its directory is not removed: {:?}; what it \
             wrote on its standard output: {:?}",
            ended.standard_error,
            ended.standard_output
        );
    }

    /// A drop whose line cannot be written does not record it as written: the standard error of
    /// the process is a pipe that nothing reads, so its write is refused as a broken pipe, and the
    /// record has a wait of full length and no word that the write returned without an error.
    ///
    /// The case runs itself again as a process of its own whose standard error is a named pipe.
    /// This process opens the pipe for reading, opens it for writing and lets go of the reading
    /// end before it starts that process: the end is marked to close when a program is started, so
    /// no process holds it, and the first write of the process to the pipe is refused whatever the
    /// schedule. The process ends with `WRITE_NOT_DONE`, and the case fails on any other status: a
    /// writer that says its write succeeded when it failed makes the drop's record say so, and the
    /// process ends with 0.
    #[cfg(unix)]
    #[test]
    fn a_line_that_cannot_be_written_is_not_recorded_as_written() {
        const NAME: &str = "a_line_that_cannot_be_written_is_not_recorded_as_written";

        if let Some(directory) = std::env::var_os(REFUSED_DIRECTORY) {
            report_panics_on_the_standard_output();
            let begun = std::time::Instant::now();
            drop(PrivateTempDir {
                root: directory.into(),
            });
            end_by_the_record_of_the_drop(begun.elapsed());
        }
        if a_mode_refuses_nothing_to_this_user() {
            return;
        }

        let refused = Refused::new();
        let pipes = PrivateTempDir::create();
        let pipe = pipes.path().join("standard-error");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .expect("starts mkfifo");
        assert!(made.success(), "mkfifo ended badly ({made})");
        let reader = open_a_pipe(&pipe, true);
        let writer = open_a_pipe(&pipe, false);
        drop(reader);

        let ended = run_again(
            NAME,
            &refused.directory,
            Some(writer),
            "what it waited for is not known here, and its output shows whether the drop returned",
        );

        assert_eq!(
            ended.status.code(),
            Some(WRITE_NOT_DONE),
            "the drop's record does not say that its write failed ({}): {}",
            ended.status,
            ended.standard_output
        );
    }

    /// Opens the named pipe at `path` for reading without waiting for a writer, or for writing,
    /// which does not wait when a reader has it open.
    #[cfg(unix)]
    fn open_a_pipe(path: &std::path::Path, to_read: bool) -> std::fs::File {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = std::fs::OpenOptions::new();
        if to_read {
            let no_waiting = i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).expect("a flag");
            options.read(true).custom_flags(no_waiting);
        } else {
            options.write(true);
        }
        options.open(path).expect("opens the named pipe")
    }

    /// The write of a line that is slow is waited for: the drop's word comes when the write is
    /// done, and the record has the wait that was given.
    #[test]
    fn a_line_is_written_when_the_wait_for_it_ends_even_when_its_write_is_slow() {
        let written = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = std::sync::Arc::clone(&written);

        let record = super::say_by("a line\n".to_owned(), WATCHDOG, move |line| {
            std::thread::sleep(Duration::from_millis(50));
            *sink.lock().expect("the sink") = Some(line);
            Ok(())
        });
        assert!(
            record.written,
            "the wait ended without the writer's word that its write returned"
        );
        assert_eq!(
            record.wait, WATCHDOG,
            "the record has another wait than was given"
        );

        assert_eq!(
            written.lock().expect("the sink").as_deref(),
            Some("a line\n"),
            "the wait ended before the line was written"
        );
    }

    /// A removal of `root` that another thread makes a file in while it is removed, as a task that
    /// is cancelled beside the removal does when its listener is dropped: the removal takes what is
    /// in `root`, a thread makes a file, and the system refuses the directory itself as not empty.
    /// Which file comes when is not a matter of timing here, so a case can rely on the refusal.
    #[cfg(unix)]
    fn removal_beside_a_thread_that_makes_a_file(
        root: &std::path::Path,
        made: &mut usize,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(root)? {
            std::fs::remove_file(entry?.path())?;
        }
        let path = root.join(format!("made-{made}"));
        *made += 1;
        std::thread::spawn(move || {
            std::fs::write(path, b"made while the tree is removed").expect("a thread makes a file");
        })
        .join()
        .expect("the thread ended");
        std::fs::remove_dir(root)
    }

    /// A removal that is refused because another thread made a file in the tree is tried again and
    /// takes the file too: the tree is gone when the drop returns, and no line is said.
    #[cfg(unix)]
    #[test]
    fn a_removal_refused_because_a_thread_made_a_file_is_tried_again_and_the_tree_goes() {
        let directory = PrivateTempDir::create();
        let root = directory.path().to_path_buf();
        std::fs::write(root.join("kept"), b"the tree's own file").expect("a file");
        let mut made = 0;
        let mut refusals = Vec::new();
        let mut said = Vec::new();

        super::remove_tree_or_say(
            &root,
            WATCHDOG,
            |root| {
                let removal = if made == 0 {
                    removal_beside_a_thread_that_makes_a_file(root, &mut made)
                } else {
                    std::fs::remove_dir_all(root)
                };
                if let Err(error) = &removal {
                    refusals.push(error.kind());
                }
                removal
            },
            |line| said.push(line),
        );

        assert_eq!(
            refusals,
            [ErrorKind::DirectoryNotEmpty],
            "the first removal was refused as not empty, and only it"
        );
        assert!(!root.exists(), "{} is left", root.display());
        assert!(said.is_empty(), "a line was said for a tree that is gone");
    }

    /// A thread that goes on making files stays ahead of the removal: it gives up at its patience,
    /// leaves the tree, and says one line that names it.
    #[cfg(unix)]
    #[test]
    fn a_removal_beside_a_thread_that_never_stops_gives_up_and_says_so() {
        let directory = PrivateTempDir::create();
        let root = directory.path().to_path_buf();
        let mut made = 0;
        let mut said = Vec::new();

        super::remove_tree_or_say(
            &root,
            Duration::from_millis(50),
            |root| removal_beside_a_thread_that_makes_a_file(root, &mut made),
            |line| said.push(line),
        );

        assert!(root.exists(), "the tree is gone");
        assert_eq!(said.len(), 1, "one line says that the tree is left");
        assert!(
            said[0].contains(&format!("{} is not removed", root.display())),
            "the line does not name the tree: {:?}",
            said[0]
        );
    }

    /// A permission's refusal is final: the removal is not tried again however much patience it
    /// has.
    #[cfg(unix)]
    #[test]
    fn a_removal_refused_for_a_permission_is_not_tried_again() {
        let mut tries = 0;

        let refused = super::remove_tree_by(
            std::path::Path::new("a-tree-that-is-refused"),
            WATCHDOG,
            |_| {
                tries += 1;
                Err(ErrorKind::PermissionDenied.into())
            },
        );

        assert_eq!(
            refused.expect_err("the refusal is returned").kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(tries, 1, "the removal was tried again");
    }

    /// A removal that stays refused ends at its bound and leaves the directory: the drop does not
    /// wait for a holder that is not ending. The holder here lets go when the drop has returned, or
    /// after twenty seconds, which the drop would only reach by waiting for it, and then the
    /// directory would be gone.
    #[cfg(windows)]
    #[test]
    fn a_removal_that_stays_refused_gives_up_and_leaves_the_directory() {
        use std::os::windows::fs::OpenOptionsExt as _;

        let directory = PrivateTempDir::create();
        let root = directory.path().to_path_buf();
        let held = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .share_mode(0)
            .open(root.join("store.db"))
            .expect("a file held open without sharing");
        let (release, released) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _ = released.recv_timeout(Duration::from_secs(20));
            drop(held);
        });

        drop(directory);

        let left = root.exists();
        release.send(()).expect("the holder is waiting");
        holder.join().expect("the holder ended");
        std::fs::remove_dir_all(&root).expect("the directory goes once the file is let go of");
        assert!(
            left,
            "the drop waited for the holder and removed the directory"
        );
    }

    /// The address the tests name as unanswered refuses a connection. A machine that answers there
    /// fails this test, which names the address. A test that relies on the address can then fail
    /// with a less clear message, or pass for the wrong reason.
    #[test]
    fn nothing_answers_at_the_unanswered_address() {
        match TcpStream::connect_timeout(&UNANSWERED, WATCHDOG) {
            Ok(_) => panic!(
                "something answers at {UNANSWERED}, so a test that connects there to be refused \
                 proves nothing on this machine"
            ),
            Err(refused) => assert_eq!(
                refused.kind(),
                ErrorKind::ConnectionRefused,
                "the connection to {UNANSWERED} was not refused: {refused:?}"
            ),
        }
    }
}
