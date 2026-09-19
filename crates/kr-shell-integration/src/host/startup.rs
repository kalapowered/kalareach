//! The marked, guarded entry each shell's startup configuration gets.
//!
//! Section 7 is exact about what setup may and may not do. It locates the *actual* startup files,
//! including a configured `ZDOTDIR`, rather than assuming the home directory. It adds one marked
//! entry per shell and never replaces `.bashrc`, never points the shell at an alternate `ZDOTDIR`,
//! never substitutes a `--rcfile` and never disables an existing profile. Removal deletes the
//! marked entry and nothing else.
//!
//! The entry itself is inert in an ordinary shell. It runs in every interactive shell of that user,
//! including one a session's own commands start, and the first thing it does is
//! [`decide_activation`](crate::contract::transport::decide_activation): without both bootstrap
//! values in the exported environment there is nothing to attempt, and after the root handshake
//! there are none to inherit.

use std::path::{Path, PathBuf};

use crate::contract::qualification::ShellKind;

/// The line that opens a KalaReach entry.
pub const MARKER_BEGIN: &str = "# >>> KalaReach shell integration >>>";

/// The line that closes it.
pub const MARKER_END: &str = "# <<< KalaReach shell integration <<<";

/// The PowerShell form of the opening marker.
pub const MARKER_BEGIN_POWERSHELL: &str = "# >>> KalaReach shell integration >>>";

/// The variable a known auto-wrapper reads to stay out of a shell's way.
pub const NSH_BYPASS_VARIABLE: &str = "NSH_NO_WRAP";

/// Where one shell's guarded entry goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupTarget {
    /// The shell this file belongs to.
    pub kind: ShellKind,
    /// The file the entry is added to.
    pub path: PathBuf,
    /// Why this file rather than another, for the diagnostics setup prints.
    pub reason: &'static str,
    /// Whether shells other than this one read the file.
    ///
    /// `.profile` is the one that is: `sh`, `dash` and `ksh` read it too, so the entry in it is
    /// written in the language they all share and does nothing unless the shell reading it is the
    /// one the entry is for.
    pub shared: bool,
}

/// What a home directory looks like to setup.
///
/// Passed in rather than read from the process, because setup runs for the user it is configuring
/// and a test has to be able to describe a home directory that is not this process's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeLayout {
    /// The user's home directory.
    pub home: PathBuf,
    /// The value of `ZDOTDIR`, when the user has one.
    pub zdotdir: Option<PathBuf>,
    /// The value of `XDG_CONFIG_HOME`, when the user has one.
    pub xdg_config_home: Option<PathBuf>,
    /// The PowerShell this host would launch, when one is installed.
    ///
    /// Asked where its own profile is, rather than having a path derived for it: PowerShell keeps
    /// that file where the platform puts the user's documents, and on Windows a redirection can
    /// move it anywhere. Two editions answer differently, so this has to be the executable a
    /// session would actually start: [`Self::launching`] is how a caller that has resolved a
    /// package says which.
    pub powershell: Option<PathBuf>,
}

impl HomeLayout {
    /// Reads the layout from this process's own environment.
    #[must_use]
    pub fn from_environment() -> Self {
        Self {
            home: std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default(),
            zdotdir: std::env::var_os("ZDOTDIR").map(PathBuf::from),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            powershell: powershell_on_path(),
        }
    }

    /// Returns this layout with the PowerShell a session would launch.
    ///
    /// A qualified package's own executable rather than whichever PowerShell is on the path: the
    /// two can be different editions, and on Windows they keep their profiles in different
    /// directories, so an entry written for one is never read by the other.
    #[must_use]
    pub fn launching(mut self, powershell: PathBuf) -> Self {
        self.powershell = Some(powershell);
        self
    }

    /// Returns where this shell's guarded entry goes.
    ///
    /// Zsh uses `.zshrc` inside the configured `ZDOTDIR` when there is one, because that is the
    /// file the shell actually reads. Bash uses `.bashrc`, plus a marked entry in the first login
    /// file it reads when that file does not already source `.bashrc`. Fish uses a guarded
    /// `conf.d` entry, which runs after the user's own configuration. PowerShell uses the user's
    /// profile.
    #[must_use]
    pub fn targets(&self, kind: ShellKind) -> Vec<StartupTarget> {
        match kind {
            ShellKind::Zsh => vec![StartupTarget {
                kind,
                path: self
                    .zdotdir
                    .clone()
                    .unwrap_or_else(|| self.home.clone())
                    .join(".zshrc"),
                reason: "the interactive file this shell actually reads, inside ZDOTDIR when one is set",
                shared: false,
            }],
            ShellKind::Bash => {
                let login = self.bash_login_file();
                let shared = login.file_name().is_some_and(|name| name == ".profile");
                vec![
                    StartupTarget {
                        kind,
                        path: self.home.join(".bashrc"),
                        reason: "the file a non-login interactive Bash reads",
                        shared: false,
                    },
                    StartupTarget {
                        kind,
                        path: login,
                        reason: "the login file this user has, which a login Bash reads instead",
                        shared,
                    },
                ]
            }
            ShellKind::Fish => vec![StartupTarget {
                kind,
                path: self
                    .xdg_config_home
                    .clone()
                    .unwrap_or_else(|| self.home.join(".config"))
                    .join("fish/conf.d/kalareach.fish"),
                reason: "a guarded conf.d entry; it loads before config.fish and defers its own activation until after it",
                shared: false,
            }],
            // PowerShell is the one shell whose profile path this host does not derive: where it
            // keeps a per-user profile depends on where the platform puts that user's documents,
            // and on Windows that is a known folder a redirection can move. So the shell is asked,
            // and a shell that cannot be asked gets no target rather than an entry written where
            // it will never be read.
            ShellKind::PowerShell => self
                .powershell_profile()
                .map(|path| StartupTarget {
                    kind,
                    path,
                    reason: "the profile this shell itself names, which this entry adds to rather \
                             than replaces",
                    shared: false,
                })
                .into_iter()
                .collect(),
        }
    }

    /// Returns the profile PowerShell reads on this host.
    ///
    /// It is asked for rather than worked out. PowerShell keeps its per-user profile in a
    /// different place on each platform, in a different place for each edition, and on Windows
    /// under whatever directory the user's documents have been redirected to; a path this host
    /// derived could be a file PowerShell never reads, and an entry in a file nothing reads is an
    /// installation that reports success and integrates nothing.
    fn powershell_profile(&self) -> Option<PathBuf> {
        let shell = self.powershell.as_ref()?;
        // The shell's own answer, read from a shell started with no profile of its own so that
        // nothing a user wrote decides where their profile is. `CurrentUserCurrentHost` is the one
        // `kr shell install` adds to: the per-user file this host's PowerShell reads.
        //
        // Bounded, and written to a file rather than a pipe: `kr shell status` runs this, and a
        // shell that will not start must not hold that command open.
        let said = ask(
            shell,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-NoLogo",
                "-Command",
                "$PROFILE.CurrentUserCurrentHost",
            ],
        )?;
        let said = said.trim();
        (!said.is_empty()).then(|| PathBuf::from(said))
    }

    /// Returns the login file Bash reads for this user, which is the first of three that exists.
    ///
    /// A login Bash reads exactly one of `.bash_profile`, `.bash_login` and `.profile`, in that
    /// order, and `.bashrc` only if that file runs it. The entry goes in whichever one Bash will
    /// read, and in none of the others, so that a person who rearranges their login files later
    /// finds one entry rather than three.
    ///
    /// Whether that file happens to run `.bashrc` is not asked, and neither is anything else about
    /// what is inside it. Reading a person's shell text without a shell is guesswork, and a guess
    /// that goes the wrong way leaves a login shell with no integration at all; the two entries
    /// share one guard instead, so the bridge loads once in a shell that reads both of them.
    ///
    /// Where none of the three is there, the entry goes in `.bash_profile`, which is the one Bash
    /// looks for first.
    fn bash_login_file(&self) -> PathBuf {
        for name in [".bash_profile", ".bash_login", ".profile"] {
            let path = self.home.join(name);
            // The file's own metadata, followed through a link: a link whose target is gone is
            // one Bash reads nothing from and goes past, and so does this.
            if std::fs::metadata(&path).is_ok() {
                return path;
            }
        }
        self.home.join(".bash_profile")
    }
}

/// How long a shell is given to answer a question about itself.
const ASK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Asks one program a question and returns what it printed, or nothing.
///
/// The answer goes to a file rather than a pipe, so nothing has to read while the program runs and
/// a descendant that inherited the handle holds nothing of this host's open. The wait is bounded,
/// and a program that outlasts it is terminated and reaped: a shell that will not start must not
/// hold `kr shell` open.
fn ask(program: &Path, arguments: &[&str]) -> Option<String> {
    // A directory of this call's own, created rather than opened and owner-only where the platform
    // has modes. `/tmp` is shared: a name another account can guess is a name it can pre-create,
    // and a file opened through it is a file this host writes on somebody else's behalf.
    let directory = std::env::temp_dir().join(format!("kr-shell-ask-{}", kr_ipc::new_uuid()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        builder.mode(0o700);
    }
    builder.create(&directory).ok()?;
    let said = directory.join("said");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600);
    }
    let Ok(to) = options.open(&said) else {
        let _ = std::fs::remove_dir_all(&directory);
        return None;
    };
    let started = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(to))
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match started {
        Ok(child) => child,
        Err(_) => {
            let _ = std::fs::remove_dir_all(&directory);
            return None;
        }
    };
    let deadline = std::time::Instant::now() + ASK_DEADLINE;
    let mut ended = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                ended = true;
                break Some(status);
            }
            Ok(None) => {}
            Err(_) => break None,
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    if !ended {
        let _ = child.kill();
        let _ = child.wait();
    }
    // A program that did not finish answered nothing, so nothing is read: a descendant can still
    // be writing, and half an answer is worse than none. A successful one is read up to a bound.
    let answer = status
        .filter(std::process::ExitStatus::success)
        .and_then(|_| read_answer(&said));
    let _ = std::fs::remove_dir_all(&directory);
    answer
}

/// The most one answer this host reads from a shell it asked a question of.
const ANSWER_LIMIT: u64 = 64 * 1024;

/// Reads what a shell answered, up to [`ANSWER_LIMIT`].
fn read_answer(path: &Path) -> Option<String> {
    use std::io::Read as _;

    let mut read = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(ANSWER_LIMIT)
        .read_to_string(&mut read)
        .ok()?;
    Some(read)
}

/// Returns the PowerShell this host would launch, when one is on the path.
///
/// The name differs by platform: `pwsh` is PowerShell 6 and later everywhere, and Windows also
/// ships `powershell.exe`, the edition that came with it.
fn powershell_on_path() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(windows) {
        &["pwsh.exe", "powershell.exe"]
    } else {
        &["pwsh"]
    };
    let path = std::env::var_os("PATH")?;
    names.iter().find_map(|name| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

/// The variable one shell's entries share, so the integration loads once in each shell.
pub const ENTRY_GUARD_VARIABLE: &str = "KR_SHELL_ENTRY";

/// What one guarded entry contains.
///
/// The body is the package's own file, sourced by one line. Nothing of the integration's logic is
/// copied into the user's configuration, so upgrading the package changes what runs without
/// rewriting anything the user owns.
#[must_use]
pub fn entry(target: &StartupTarget, package_entry: &Path, nsh_bypass: bool) -> String {
    let kind = target.kind;
    // The path is quoted for the shell that will read this file, by the same rules a launch is
    // quoted by. An installation directory with an apostrophe in it would otherwise end the string
    // and turn the rest of the path into shell syntax.
    let path = crate::host::quoting::quote(kind, &package_entry.display().to_string());
    let mut body = String::new();
    body.push_str(MARKER_BEGIN);
    body.push('\n');
    body.push_str(
        "# Added by `kr shell install`. It is inert outside a KalaReach-created shell, and\n\
         # `kr shell remove` deletes exactly these lines.\n",
    );
    match kind {
        ShellKind::Zsh | ShellKind::Bash => {
            // One shell can read two of these files: a login Bash reads its login file, and that
            // file may run `.bashrc` as well. Both entries test and set the same variable, so the
            // package is sourced once in that shell.
            //
            // The variable is then taken back out of the environment. A shell started inside this
            // one has to load the integration of its own, and a person whose startup file turns
            // `allexport` on would otherwise export every assignment this entry makes, this one
            // included.
            let unexport = match kind {
                ShellKind::Zsh => format!("typeset +x {ENTRY_GUARD_VARIABLE}"),
                _ => format!("export -n {ENTRY_GUARD_VARIABLE}"),
            };
            // `.profile` is read by shells that are not this one, so everything the entry there
            // does is inside a test for the shell it is for, written in the language they share.
            // Bash reading that file as `sh` is in its POSIX mode and is not that shell either.
            let guard = if target.shared {
                format!(
                    "[ -n \"${{BASH_VERSION:-}}\" ] && case \":${{SHELLOPTS:-}}:\" in \
                     *:posix:*) false ;; *) true ;; esac && \
                     [ -z \"${{{ENTRY_GUARD_VARIABLE}:-}}\" ]"
                )
            } else {
                format!("[ -z \"${{{ENTRY_GUARD_VARIABLE}:-}}\" ]")
            };
            let bypass = if nsh_bypass {
                format!("[ -n \"${{KR_SHELL_BRIDGE:-}}\" ] && export {NSH_BYPASS_VARIABLE}=1; ")
            } else {
                String::new()
            };
            body.push_str(&format!(
                "if {guard} && [ -r {path} ]; then {bypass}{ENTRY_GUARD_VARIABLE}=1; \
                 {unexport}; . {path}; fi\n"
            ));
        }
        ShellKind::Fish => {
            if nsh_bypass {
                body.push_str(&format!(
                    "if set -q KR_SHELL_BRIDGE; set -gx {NSH_BYPASS_VARIABLE} 1; end\n"
                ));
            }
            body.push_str(&format!("if test -r {path}; source {path}; end\n"));
        }
        ShellKind::PowerShell => {
            if nsh_bypass {
                body.push_str(&format!(
                    "if ($env:KR_SHELL_BRIDGE) {{ $env:{NSH_BYPASS_VARIABLE} = '1' }}\n"
                ));
            }
            body.push_str(&format!("if (Test-Path {path}) {{ . {path} }}\n"));
        }
    }
    body.push_str(MARKER_END);
    body.push('\n');
    body
}

/// What installing or removing an entry did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// The entry was added.
    Added,
    /// An entry was already there and has been replaced with this one.
    Replaced,
    /// The file already held exactly this entry.
    Unchanged,
    /// The entry was removed.
    Removed,
    /// There was no entry to remove.
    Absent,
}

/// Adds or updates one shell's guarded entry.
///
/// The file is created when it does not exist and appended to when it does. Everything the user
/// wrote is kept: the entry is delimited by its markers and only the text between them is ever
/// rewritten.
///
/// # Errors
///
/// Returns the underlying failure when the file cannot be read or written.
pub fn install(path: &Path, body: &str) -> std::io::Result<Change> {
    let _writing = writing();
    let _held = FileLock::take(path)?;
    let existing = read_or_empty(path)?;
    let (change, updated) = match strip(&existing) {
        Some((before, after)) => {
            let rebuilt = format!("{before}{body}{after}");
            if rebuilt == existing {
                (Change::Unchanged, rebuilt)
            } else {
                (Change::Replaced, rebuilt)
            }
        }
        None => {
            let mut rebuilt = existing.clone();
            if !rebuilt.is_empty() && !rebuilt.ends_with('\n') {
                rebuilt.push('\n');
            }
            rebuilt.push_str(body);
            (Change::Added, rebuilt)
        }
    };
    if change != Change::Unchanged {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        replace(path, &existing, &updated)?;
    }
    Ok(change)
}

/// Removes one shell's guarded entry, and nothing else.
///
/// # Errors
///
/// Returns the underlying failure when the file cannot be read or written.
pub fn remove(path: &Path) -> std::io::Result<Change> {
    let _writing = writing();
    let _held = FileLock::take(path)?;
    let existing = read_or_empty(path)?;
    let Some((before, after)) = strip(&existing) else {
        return Ok(Change::Absent);
    };
    let rebuilt = format!("{before}{after}");
    // A file this entry created and nothing else ever wrote to goes with it. One the user owns
    // stays, with their own lines exactly as they left them. A link the user made is theirs
    // whatever the file it names holds: deleting it would leave that file behind with the entry
    // still in it, and the shell reading a path that no longer exists.
    let created_here = rebuilt.trim().is_empty()
        && before.trim().is_empty()
        && !path
            .symlink_metadata()
            .is_ok_and(|data| data.file_type().is_symlink());
    if created_here {
        std::fs::remove_file(path)?;
    } else {
        replace(path, &existing, &rebuilt)?;
    }
    Ok(Change::Removed)
}

/// How long a startup write waits for another one to finish before it gives up.
const LOCK_PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// A lock beside one startup file, held for a whole read-rebuild-write.
///
/// This is what closes the window between the check before the rename and the rename itself, for
/// the writer that window was about: another `kr` process installing or removing the same entry.
/// The lock file sits beside the startup file, so the two processes need no agreement beyond the
/// directory they are both writing in.
///
/// The lock is the operating system's on both platforms, so a holder that dies releases it and no
/// staleness rule is needed: on Unix it is `flock` on the open file, and on Windows it is the file
/// opened with no sharing at all, which refuses every other opener while the handle is held.
///
/// It says nothing about an editor. A person who saves the file between the check and the rename
/// still has that save replaced, and closing that would need the platform to offer a comparison
/// and a rename in one step.
#[derive(Debug)]
struct FileLock {
    /// The lock file this guard is about.
    path: PathBuf,
    /// The open file the operating system's lock is on, released when this guard drops it.
    held: Option<std::fs::File>,
}

impl FileLock {
    /// Returns where one startup file's lock lives.
    fn beside(path: &Path) -> std::io::Result<PathBuf> {
        let target = resolved(path)?;
        let directory = target
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let name = target.file_name().map_or_else(
            || String::from("startup"),
            |name| name.to_string_lossy().into_owned(),
        );
        // The directory has to be there before anything in it can be locked, and it is this
        // command's to create: a first-time setup writes a profile into a directory the user does
        // not have yet, and a write with no lock taken is the thing this exists to prevent.
        std::fs::create_dir_all(&directory)?;
        Ok(directory.join(format!(".{name}.kalareach-lock")))
    }

    /// Takes the lock for one startup file, waiting for a holder that is still working.
    ///
    /// # Errors
    ///
    /// Returns the underlying failure, or a timeout when another writer held it throughout.
    #[cfg(unix)]
    fn take(path: &Path) -> std::io::Result<Self> {
        let lock = Self::beside(path)?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock)?;
        let deadline = std::time::Instant::now() + LOCK_PATIENCE;
        loop {
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    return Ok(Self {
                        path: lock,
                        held: Some(file),
                    });
                }
                Err(rustix::io::Errno::WOULDBLOCK) => {}
                Err(error) => return Err(std::io::Error::from(error)),
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "another kr process is writing {}; nothing was written",
                        path.display()
                    ),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// Takes the lock for one startup file, waiting for a holder that is still working.
    ///
    /// The lock is the operating system's, not an age rule: the file is opened with no sharing at
    /// all, so a second opener is refused while the first holds its handle and the handle closes
    /// with the process that held it. A writer that died leaves a file nobody is holding, and the
    /// next writer opens it.
    ///
    /// # Errors
    ///
    /// Returns the underlying failure, or a timeout when another writer held it throughout.
    #[cfg(not(unix))]
    fn take(path: &Path) -> std::io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// What Windows says when another handle holds the file.
        const ERROR_SHARING_VIOLATION: i32 = 32;
        /// What it says when a region of it is locked.
        const ERROR_LOCK_VIOLATION: i32 = 33;

        let lock = Self::beside(path)?;
        let deadline = std::time::Instant::now() + LOCK_PATIENCE;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                // No sharing: while this handle is open, nothing else may open the file at all.
                .share_mode(0)
                .open(&lock)
            {
                Ok(file) => {
                    return Ok(Self {
                        path: lock,
                        held: Some(file),
                    });
                }
                // Somebody is holding it. The platform says so with a sharing or lock violation,
                // and it is the raw code that says which: the standard library does not map either
                // to a kind of its own, so a writer that matched on the kind would give up at once
                // and a real permission failure would wait out the whole deadline.
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
                    ) => {}
                Err(error) => return Err(error),
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "another kr process is writing {}; nothing was written",
                        path.display()
                    ),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // The file stays. A waiter is holding the same name open and waiting on the operating
        // system's own lock, and removing the name would let a third process create another file
        // with it: two writers would then hold two different locks and write over each other.
        // Closing the file is what releases the lock, and the empty file left beside the startup
        // file costs nothing.
        let _ = &self.path;
        drop(self.held.take());
    }
}

/// Serialises this process's own startup-file writes.
///
/// Installing and removing both read a file, rebuild it and write it back. Two of them running at
/// once against the same file could otherwise interleave and lose one of the two results. Another
/// process is excluded by [`FileLock`], and what neither covers is a person's own editor, which is
/// what the check before the rename is for.
fn writing() -> std::sync::MutexGuard<'static, ()> {
    static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());

    WRITING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Returns whether a file holds a KalaReach entry.
#[must_use]
pub fn installed(path: &Path) -> bool {
    read_or_empty(path).is_ok_and(|contents| strip(&contents).is_some())
}

/// Splits a file around its KalaReach entry.
fn strip(contents: &str) -> Option<(String, String)> {
    // Whole lines, not text that happens to hold the marker. A person's own file can print the
    // marker, or talk about it, and neither is this host's entry: removing what stands between
    // two such lines would take their own configuration with it.
    let line_at = |from: usize, marker: &str| {
        let mut at = from;
        for line in contents[from..].split_inclusive('\n') {
            if line.trim_end_matches(['\r', '\n']) == marker {
                return Some((at, at + line.len()));
            }
            at += line.len();
        }
        None
    };
    let (begin, _) = line_at(0, MARKER_BEGIN)?;
    let (_, after) = line_at(begin, MARKER_END)?;
    Some((contents[..begin].to_owned(), contents[after..].to_owned()))
}

/// Writes a startup file by replacing it, never by truncating it.
///
/// A short write, a full disk or a crash between the truncation and the write would otherwise take
/// the user's own configuration with it. The new contents are written beside the file and renamed
/// over it, which on every platform this host runs on is one step: the file is either what it was
/// or what it is going to be, and never half of either.
///
/// Three things the rename has to respect. A startup file is often a symlink into a dotfiles
/// checkout, so the replacement is written over the file the link points at and the link is left
/// alone. The file beside it is created exclusively under a name of this call's own, so nothing
/// that happens to be there is truncated and two calls cannot share one temporary. And the file
/// may have changed since the caller read it, so the contents and the file's own identity are
/// checked again immediately before the rename, once the slow part is behind us: a replacement
/// built on stale contents would silently drop whatever was saved in between.
///
/// What remains is one window and one writer. This process's own calls are serialised against each
/// other and another `kr` process is excluded by the lock beside the file, so the writer the window
/// is about is a person's own editor saving between the check and the rename; closing that would
/// need the platform to offer a comparison and a rename in one step. The identity half of the
/// check is a Unix one, and it is used only where the filesystem's numbers hold still: elsewhere a
/// file that was replaced rather than edited is caught by its contents.
fn replace(path: &Path, expected: &str, contents: &str) -> std::io::Result<()> {
    // The file the configuration actually lives in. A symlink is a deliberate arrangement of the
    // user's, and renaming over the link would replace it with a regular file and quietly cut the
    // startup entry off from the checkout it belongs to.
    let target = resolved(path)?;
    let directory = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target.file_name().map_or_else(
        || String::from("startup"),
        |name| name.to_string_lossy().into_owned(),
    );
    let temporary = directory.join(format!(".{name}.kalareach-{}", kr_ipc::new_uuid()));
    // The permissions of the file being replaced, so a profile that was owner-only stays so.
    let permissions = std::fs::metadata(&target)
        .ok()
        .map(|data| data.permissions());
    // The identity this rename stands on, and whether it means anything here. A filesystem that
    // hands out a different number for the same unchanged file is one where an identity check
    // would refuse a write it should have made, so what such a filesystem gets is the contents
    // check alone.
    let identity = stable_identity(&target);
    let prepared = write_new(&temporary, contents).and_then(|()| {
        if let Some(permissions) = permissions {
            std::fs::set_permissions(&temporary, permissions)?;
        }
        // The check the rename stands on, taken here rather than before the write: the write, the
        // permissions and the flush are where the time goes, and a check taken before them says
        // nothing about the file the rename is about to replace.
        if read_or_empty(&target)? != expected
            || identity.is_some_and(|identity| stable_identity(&target) != Some(identity))
        {
            return Err(std::io::Error::other(
                "the startup file changed while this entry was being written, so nothing was \
                 written",
            ));
        }
        std::fs::rename(&temporary, &target)
    });
    if prepared.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    prepared
}

/// Returns the file a startup path resolves to, following a link the user made.
fn resolved(path: &Path) -> std::io::Result<std::path::PathBuf> {
    match path.symlink_metadata() {
        Ok(data) if data.file_type().is_symlink() => std::fs::canonicalize(path),
        _ => Ok(path.to_path_buf()),
    }
}

/// Returns a file's identity, when this filesystem gives it one that holds still.
///
/// A file that was replaced between the caller's read and this rename is a different file, whatever
/// its contents happen to be, and the entry belongs in whichever one the startup path names now.
/// That reasoning needs an identity that is stable for an unchanged file, which not every
/// filesystem offers: some network and userspace filesystems synthesise inode numbers and hand out
/// a different one for the same file. There, an identity check would refuse a write it should have
/// made, so this reads the file twice and reports an identity only when the two readings agree.
///
/// Two agreeing readings are a heuristic, not a proof: a filesystem whose numbers move can answer
/// alike twice, and the refusal that follows is one the contents check would not have made. What
/// they do establish is enough to keep the check off the filesystems that would fail it steadily.
///
/// Two readings that disagree because the file really was replaced in between are covered by the
/// contents check, which runs whether or not there is an identity.
fn stable_identity(path: &Path) -> Option<(u64, u64)> {
    let first = identity_of(path)?;
    (identity_of(path)? == first).then_some(first)
}

/// Returns what the platform says identifies this file.
#[cfg(unix)]
fn identity_of(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    std::fs::metadata(path)
        .ok()
        .map(|data| (data.dev(), data.ino()))
}

#[cfg(not(unix))]
fn identity_of(path: &Path) -> Option<(u64, u64)> {
    let _ = path;
    None
}

/// Creates one file that was not there before and writes it out in full.
///
/// Exclusive creation and owner-only permissions from the first byte: nothing that is already at
/// that name is opened, and nothing else on the machine can read a half-written profile. The
/// contents reach the disk before the caller renames the file into place.
fn write_new(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

fn read_or_empty(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(root: &Path) -> HomeLayout {
        HomeLayout {
            home: root.to_path_buf(),
            zdotdir: None,
            xdg_config_home: None,
            powershell: None,
        }
    }

    #[test]
    fn zsh_follows_the_configured_zdotdir() {
        let root = tempfile::tempdir().expect("a directory");
        let plain = layout(root.path());
        assert_eq!(
            plain.targets(ShellKind::Zsh)[0].path,
            root.path().join(".zshrc")
        );
        let configured = HomeLayout {
            zdotdir: Some(root.path().join("dotfiles/zsh")),
            ..plain
        };
        assert_eq!(
            configured.targets(ShellKind::Zsh)[0].path,
            root.path().join("dotfiles/zsh/.zshrc"),
            "the file the shell actually reads, not the one in the home directory"
        );
    }

    /// Login files this host used to read and no longer does. Every one of them gets an entry.
    const LOGIN_FILES: &[&str] = &[
        "# this used to source ~/.bashrc; it does not any more\n",
        "echo 'see .bashrc for the aliases'\n",
        "BASHRC=~/.bashrc\n",
        "# . ~/.bashrc\n",
        "export EDITOR=vim # source ~/.bashrc\n",
        "PS1='> ' ## . ~/.bashrc\n",
        "echo \"please source ~/.bashrc\"\n",
        "echo 'run . ~/.bashrc yourself'\n",
        "echo source ~/.bashrc\n",
        "echo \"please \\\" source ~/.bashrc\"\n",
        "printf '%s\\n' source ~/.bashrc\n",
        "echo if source ~/.bashrc\n",
        "\"echo\" source ~/.bashrc\n",
        "cat <<EOF\nsource ~/.bashrc\nEOF\n",
        // `<<-` strips leading tabs from the delimiter and nothing else, so a line that
        // begins with a space is body rather than the end of one.
        ": <<-EOF\n EOF\nsource ~/.bashrc\nEOF\n",
        "cat <<'END HERE'\nsource ~/.bashrc\nEND HERE\n",
        // A backslash quotes the delimiter too, so `<<\\EOF` ends at `EOF`.
        "cat <<\\EOF\nsource ~/.bashrc\nEOF\n",
        "cat <<ONE <<TWO\nsource ~/.bashrc\nONE\n. ~/.bashrc\nTWO\n",
        "echo \\\nsource ~/.bashrc\n",
        // A here-document whose delimiter is empty ends at the first empty line.
        ": <<''\nsource ~/.bashrc\n\n",
        // An unquoted delimiter leaves its body expanded, so `x\` and the line after it make
        // `xEOF` rather than the end of the body.
        ": <<EOF\nx\\\nEOF\nsource ~/.bashrc\nEOF\n",
        // A quoted message can hold newlines, and what is inside one is a message.
        "echo \"a message\nsource ~/.bashrc\"\n",
        // A backslash before a newline joins the lines with nothing between them, so this
        // names a command called `source~/.bashrc`.
        "source\\\n~/.bashrc\n",
        // A substitution runs the command inside it in a shell of its own, which leaves the shell
        // this host integrates with nothing.
        "OUT=$(source ~/.bashrc)\n",
        "OUT=`source ~/.bashrc`\n",
        // Parentheses hold array data as readily as a command.
        "parts=(source ~/.bashrc)\n",
        // A substitution that ends leaves the words after it arguments rather than commands.
        "echo $(printf '') source ~/.bashrc\n",
        // `$'…'` takes backslash escapes, so the apostrophe in it does not end the quoting.
        "echo $'it\\'s\nsource ~/.bashrc\n'\n",
        // A separator ends the command before the path, so `source` is given nothing.
        "source; /missing/.bashrc\n",
        // Inside double quotes a backslash goes before the `$` it quotes, so the delimiter is
        // `$EOF` and the line that reads `\$EOF` is body.
        ": <<\"\\$EOF\"\n\\$EOF\nsource ~/.bashrc\n$EOF\n",
        // The inner here-document belongs to the substitution, and the outer body follows the
        // whole command.
        ": <<OUT $(cat <<IN\nOUT\nIN\n)\nsource ~/.bashrc\nOUT\n",
        // Single quotes leave `$HOME` a directory of that name rather than the home.
        "source '$HOME/.bashrc'\n",
        // `||` leads to a command only when what came before it failed.
        "test -f ~/.bashrc || . ~/.bashrc\n",
        // A loop body can run no times at all, and a function body runs when it is called.
        "while false; do . ~/.bashrc; done\n",
        "until true; do . ~/.bashrc; done\n",
        "f() { . ~/.bashrc; }\n",
        // A pipe and a background `&` each lead to a shell of their own.
        "echo x | . ~/.bashrc\n",
        ". ~/.bashrc &\n",
        // A condition this host cannot answer is one it does not read a call through.
        "if false; then . ~/.bashrc; fi\n",
        "false && . ~/.bashrc\n",
        // Double quotes leave `~` a directory of that name rather than the home.
        "source \"~/.bashrc\"\n",
    ];

    /// The same, written the ways a login file that does run `.bashrc` is written.
    const LOGIN_FILES_THAT_SOURCE: &[&str] = &[
        ". ~/.bashrc\n",
        "source ~/.bashrc\n",
        "[ -f ~/.bashrc ] && source \"$HOME/.bashrc\"\n",
        "export PATH=/opt:$PATH; . /home/someone/.bashrc\n",
        "if [ -r ~/.bashrc ]; then . ~/.bashrc; fi\n",
        // A here-document that ends leaves the commands after it commands again.
        "cat <<EOF\nnothing\nEOF\n. ~/.bashrc\n",
        // A here-string opens no body at all.
        "cat <<<'x'\n. ~/.bashrc\n",
        // An assignment in front of a command leaves the command where a command stands.
        "LANG=C source ~/.bashrc\n",
    ];

    /// KR-REQ-07.30: the entry goes in the login file, whatever is written in that file.
    ///
    /// The contents are every shape three reviews of the reader this replaced turned up, which is
    /// the point: none of them is read any more, so none of them can decide anything.
    #[test]
    fn a_login_file_gets_an_entry_whatever_is_written_in_it() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        for contents in LOGIN_FILES.iter().chain(LOGIN_FILES_THAT_SOURCE) {
            std::fs::write(root.path().join(".bash_profile"), contents).expect("writes");
            let targets = home.targets(ShellKind::Bash);
            assert_eq!(
                targets.len(),
                2,
                "both files get an entry whatever the login file says: {contents:?}"
            );
            assert_eq!(targets[0].path, root.path().join(".bashrc"));
            assert_eq!(targets[1].path, root.path().join(".bash_profile"));
            assert!(!targets[1].shared);
        }
    }

    /// KR-REQ-07.30: the entry goes in the one login file Bash reads, and in no other.
    #[test]
    fn the_login_entry_goes_in_the_file_bash_reads() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());

        // None of the three is there, so the entry goes where Bash looks first.
        assert_eq!(
            home.targets(ShellKind::Bash)[1].path,
            root.path().join(".bash_profile")
        );

        // Bash reads exactly one of them, in this order, and so does this.
        for (name, next) in [
            (".profile", ".bash_login"),
            (".bash_login", ".bash_profile"),
            (".bash_profile", ".bash_profile"),
        ] {
            std::fs::write(root.path().join(name), "echo hello\n").expect("writes");
            let targets = home.targets(ShellKind::Bash);
            assert_eq!(targets[1].path, root.path().join(name), "{name} is first");
            assert_eq!(
                targets[1].shared,
                name == ".profile",
                "only .profile is read by shells that are not Bash"
            );
            let _ = next;
        }
    }

    /// KR-REQ-07.30: what a person wrote that looks like an entry is not one.
    #[test]
    fn text_that_names_the_marker_is_not_an_entry() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        let theirs = format!(
            "printf '%s\\n' '{MARKER_BEGIN}'\nexport KEEP_ME=1\nprintf '%s\\n' '{MARKER_END}'\n"
        );
        std::fs::write(&path, &theirs).expect("writes");
        assert!(
            !installed(&path),
            "a file that prints the marker holds no entry"
        );
        assert_eq!(remove(&path).expect("reads"), Change::Absent);
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            theirs,
            "and nothing of theirs was taken out"
        );

        // An entry beside it is still found, replaced and removed exactly.
        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/entry"),
            false,
        );
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert!(installed(&path));
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(std::fs::read_to_string(&path).expect("reads"), theirs);
    }

    /// KR-REQ-07.30: a login file Bash reads nothing from is one it goes past, and so is this.
    #[cfg(unix)]
    #[test]
    fn a_login_file_that_is_a_broken_link_is_not_the_one_bash_reads() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        std::os::unix::fs::symlink(root.path().join("gone"), root.path().join(".bash_profile"))
            .expect("links");
        std::fs::write(root.path().join(".profile"), "echo hello\n").expect("writes");
        let targets = home.targets(ShellKind::Bash);
        assert_eq!(
            targets[1].path,
            root.path().join(".profile"),
            "a link with nothing at the end of it is not a file Bash reads"
        );
        assert!(targets[1].shared);
    }

    /// KR-REQ-07.16, KR-REQ-07.30: each shell loads the integration once, and a login shell that
    /// also runs `.bashrc` still loads it once.
    #[cfg(unix)]
    #[test]
    fn a_shell_loads_the_integration_exactly_once() {
        let bash = Path::new("/bin/bash");
        if !bash.exists() {
            eprintln!("skipped: this host has no /bin/bash to start");
            return;
        }
        for login in [
            "echo hello\n",
            ". ~/.bashrc\n",
            "[ -f ~/.bashrc ] && . ~/.bashrc\n",
        ] {
            let home = tempfile::Builder::new()
                .prefix("kr-bash-home-")
                .tempdir()
                .expect("a home directory");
            let loaded = home.path().join("loaded");
            let package = home.path().join("entry.sh");
            std::fs::write(&package, format!("printf x >> {}\n", loaded.display()))
                .expect("writes the package's entry");
            std::fs::write(home.path().join(".bashrc"), "").expect("writes .bashrc");
            std::fs::write(home.path().join(".bash_profile"), login)
                .expect("writes the login file");
            let layout = HomeLayout {
                home: home.path().to_path_buf(),
                zdotdir: None,
                xdg_config_home: None,
                powershell: None,
            };
            for target in layout.targets(ShellKind::Bash) {
                install(&target.path, &entry(&target, &package, false)).expect("installs");
            }

            // A login Bash: it reads the login file, and in two of these three that file runs
            // `.bashrc` as well, so both entries run in the one shell.
            assert_eq!(
                loads(bash, home.path(), &["--login", "-c", ":"], &loaded),
                1,
                "a login shell loads it once: {login:?}"
            );
            // And an interactive Bash that is not a login shell, which reads `.bashrc` alone.
            assert_eq!(
                loads(bash, home.path(), &["-i", "-c", ":"], &loaded),
                1,
                "an interactive shell loads it once: {login:?}"
            );
        }
    }

    /// Starts one Bash with a home of its own and returns how many times the package was sourced.
    #[cfg(unix)]
    fn loads(bash: &Path, home: &Path, arguments: &[&str], loaded: &Path) -> usize {
        let _ = std::fs::remove_file(loaded);
        let mut child = std::process::Command::new(bash)
            .args(arguments)
            .env("HOME", home)
            .current_dir(home)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("starts a shell");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => {}
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::read(loaded).map(|read| read.len()).unwrap_or(0)
    }

    /// A target for one shell, for the tests that only care what an entry contains.
    fn for_shell(kind: ShellKind) -> StartupTarget {
        StartupTarget {
            kind,
            path: PathBuf::from("/tmp/startup"),
            reason: "a test",
            shared: false,
        }
    }

    #[test]
    fn a_second_writer_waits_for_the_first_and_neither_loses_its_entry() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "export EDITOR=vim\n").expect("writes");

        // A lock is taken for the whole read-rebuild-write, so a writer that is not this process
        // is kept out rather than racing the rename.
        let lock = FileLock::beside(&path).expect("names the lock");
        let held = FileLock::take(&path).expect("takes the lock");
        assert!(lock.is_file(), "the lock is beside the file it is about");
        // A second attempt waits for the first and gives up rather than writing beside it.
        let refused = FileLock::take(&path).expect_err("one writer at a time");
        assert_eq!(refused.kind(), std::io::ErrorKind::TimedOut);
        drop(held);
        // The name stays where a waiter can be holding the same file open; what the drop releases
        // is the kernel's lock, which the next writer takes at once.
        let after = FileLock::take(&path).expect("the next writer takes it straight away");
        drop(after);

        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        );
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert!(
            std::fs::read_to_string(&path)
                .expect("reads")
                .starts_with("export EDITOR=vim"),
            "the user's own line is still first"
        );
    }

    /// KR-REQ-07.29: a first-time setup creates the directory and still takes a lock in it.
    #[test]
    fn a_profile_in_a_directory_that_is_not_there_yet_is_written_under_a_lock() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join("config/powershell/profile.ps1");
        let lock = FileLock::beside(&path).expect("names the lock");
        assert!(
            lock.parent().expect("a directory").is_dir(),
            "the directory the lock lives in is created before the lock is taken"
        );
        let held = FileLock::take(&path).expect("takes the lock");
        assert!(lock.is_file());
        drop(held);

        let body = entry(
            &for_shell(ShellKind::PowerShell),
            Path::new("/opt/kr/entry.ps1"),
            false,
        );
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert!(installed(&path));
    }

    /// KR-REQ-07.40: a filesystem whose identity numbers move does not refuse a legitimate write.
    #[test]
    fn an_unstable_identity_leaves_the_write_to_the_contents_check() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "export EDITOR=vim\n").expect("writes");
        // On a filesystem that holds still, two readings agree and the identity is used.
        assert_eq!(stable_identity(&path), identity_of(&path));
        // A path that names nothing has no identity either way, and the write is decided by the
        // contents alone, which is what a filesystem with moving numbers gets.
        assert_eq!(stable_identity(&root.path().join("absent")), None);

        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        );
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "export EDITOR=vim\n"
        );
    }

    /// KR-REQ-07.29: PowerShell's profile is the one that shell itself names.
    ///
    /// Unix, because the shell it asks is a program this test writes, and writing one needs a
    /// shebang and an executable bit. What the code under test does with the answer is the same on
    /// every platform.
    #[cfg(unix)]
    #[test]
    fn the_powershell_profile_is_the_one_that_shell_names() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        assert!(
            home.targets(ShellKind::PowerShell).is_empty(),
            "a host with no PowerShell has no profile to add an entry to, and none is guessed"
        );

        // A shell that answers: the entry goes where it said, wherever that is.
        let wanted = root.path().join("Documents/PowerShell/profile.ps1");
        let asking = HomeLayout {
            powershell: Some(fake_powershell(root.path(), &wanted.display().to_string())),
            ..home.clone()
        };
        let targets = asking.targets(ShellKind::PowerShell);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, wanted);

        // A shell that answers nothing leaves this host with no profile rather than one it made up.
        let silent = HomeLayout {
            powershell: Some(fake_powershell(root.path(), "")),
            ..home
        };
        assert!(silent.targets(ShellKind::PowerShell).is_empty());
    }

    /// Writes a program that prints one line, which is all this host asks PowerShell for.
    #[cfg(unix)]
    fn fake_powershell(root: &Path, says: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = root.join(format!("pwsh-{}", says.len()));
        std::fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{says}'\n"))
            .expect("writes a program");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("makes it runnable");
        // A file this thread has just written is briefly unrunnable: another thread's fork still
        // holds the descriptor it was written through, and the kernel refuses to run it until that
        // fork reaches its own program. Run it here until it runs, so the test measures the code
        // under test rather than that window.
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::process::Command::new(&path)
                .stdout(std::process::Stdio::null())
                .status()
            {
                Ok(_) => break path,
                Err(error) => assert!(
                    std::time::Instant::now() < until,
                    "the written program never ran: {error}"
                ),
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn the_entry_is_added_beside_what_the_user_wrote_and_removed_without_it() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        let theirs = "export EDITOR=vim\nalias ll='ls -la'\n";
        std::fs::write(&path, theirs).expect("writes");
        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        );
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        let after = std::fs::read_to_string(&path).expect("reads");
        assert!(after.starts_with(theirs), "the user's own lines are first");
        assert!(after.contains(MARKER_BEGIN) && after.contains(MARKER_END));
        assert!(installed(&path));
        // A second install is not a second entry.
        assert_eq!(install(&path, &body).expect("installs"), Change::Unchanged);
        let updated = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            true,
        );
        assert_eq!(
            install(&path, &updated).expect("installs"),
            Change::Replaced
        );
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("reads")
                .matches(MARKER_BEGIN)
                .count(),
            1
        );
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(std::fs::read_to_string(&path).expect("reads"), theirs);
        assert_eq!(remove(&path).expect("removes"), Change::Absent);
    }

    #[cfg(unix)]
    #[test]
    fn a_startup_file_that_is_a_link_keeps_pointing_at_the_file_it_named() {
        // A startup file is very often a link into a checkout of the user's own. Writing the entry
        // has to reach the file the link names, or the entry would land in a regular file that
        // replaced the link and every later change in the checkout would stop arriving.
        let root = tempfile::tempdir().expect("a directory");
        let checkout = root.path().join("dotfiles");
        std::fs::create_dir_all(&checkout).expect("creates");
        let real = checkout.join("zshrc");
        let theirs = "export EDITOR=vim\n";
        std::fs::write(&real, theirs).expect("writes");
        let link = root.path().join(".zshrc");
        std::os::unix::fs::symlink(&real, &link).expect("links");

        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        );
        assert_eq!(install(&link, &body).expect("installs"), Change::Added);
        assert!(
            link.symlink_metadata()
                .expect("reads")
                .file_type()
                .is_symlink(),
            "the link is still a link"
        );
        let written = std::fs::read_to_string(&real).expect("reads");
        assert!(written.starts_with(theirs) && written.contains(MARKER_BEGIN));

        assert_eq!(remove(&link).expect("removes"), Change::Removed);
        assert!(
            link.symlink_metadata()
                .expect("reads")
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).expect("reads"), theirs);
    }

    #[cfg(unix)]
    #[test]
    fn removing_an_entry_from_a_linked_file_keeps_the_link_and_empties_the_file_it_names() {
        // The link is the user's arrangement, not this entry's. Deleting it because the file it
        // names came out empty would leave the shell reading a path that is not there, and the
        // checkout holding an entry nothing can remove.
        let root = tempfile::tempdir().expect("a directory");
        let checkout = root.path().join("dotfiles");
        std::fs::create_dir_all(&checkout).expect("creates");
        let real = checkout.join("zshrc");
        std::fs::write(&real, "").expect("writes an empty file");
        let link = root.path().join(".zshrc");
        std::os::unix::fs::symlink(&real, &link).expect("links");

        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        );
        assert_eq!(install(&link, &body).expect("installs"), Change::Added);
        assert_eq!(remove(&link).expect("removes"), Change::Removed);
        assert!(
            link.symlink_metadata()
                .expect("the link is still there")
                .file_type()
                .is_symlink()
        );
        assert!(
            !installed(&real),
            "and the file it names no longer holds the entry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nothing_beside_the_startup_file_is_written_over_and_nothing_is_left_behind() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "setopt autocd\n").expect("writes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("sets");
        // A file at the name the replacement used to take. Nothing may open it.
        let bystander = root.path().join(".zshrc.kalareach-new");
        std::fs::write(&bystander, "not ours\n").expect("writes");

        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        );
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert_eq!(
            std::fs::read_to_string(&bystander).expect("reads"),
            "not ours\n"
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("reads")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "the file keeps the permissions it had"
        );
        let leftovers: Vec<_> = std::fs::read_dir(root.path())
            .expect("lists")
            .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
            .filter(|name| {
                let name = name.to_string_lossy();
                // The lock file is not a leftover: it is the name a waiter holds open, and on
                // Unix it stays so that two writers cannot end up holding two different locks.
                name.contains("kalareach-")
                    && name != ".zshrc.kalareach-new"
                    && !name.ends_with("kalareach-lock")
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_startup_file_that_changed_since_it_was_read_is_left_alone() {
        // `install` reads, rebuilds and writes. Between the read and the write the user's editor
        // may have saved the same file, and a replacement built on what was read would throw that
        // away without a word.
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "first\n").expect("writes");
        let rebuilt = "first\nours\n";
        std::fs::write(&path, "theirs, saved in between\n").expect("writes");
        let error = replace(&path, "first\n", rebuilt).expect_err("refuses");
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "theirs, saved in between\n"
        );
        assert!(error.to_string().contains("changed"), "{error}");
    }

    #[test]
    fn the_bypass_is_only_ever_set_inside_a_kalareach_shell() {
        for kind in ShellKind::ALL {
            let with = entry(&for_shell(*kind), Path::new("/opt/kr/entry"), true);
            assert!(
                with.contains(NSH_BYPASS_VARIABLE),
                "{kind} offers the documented bypass"
            );
            assert!(
                with.contains("KR_SHELL_BRIDGE"),
                "{kind} sets it only where the bridge was exported"
            );
            let without = entry(&for_shell(*kind), Path::new("/opt/kr/entry"), false);
            assert!(
                !without.contains(NSH_BYPASS_VARIABLE),
                "{kind} sets nothing when the option is off"
            );
        }
    }

    #[test]
    fn a_path_with_an_apostrophe_stays_one_word() {
        for kind in ShellKind::ALL {
            let body = entry(
                &for_shell(*kind),
                Path::new("/home/it's mine/kr/entry"),
                false,
            );
            // The apostrophe is escaped rather than ending the string, so the line still names one
            // path and nothing after it is read as shell syntax.
            assert!(
                !body.contains("/home/it's mine/kr/entry"),
                "{kind} left the apostrophe unescaped: {body}"
            );
            assert!(body.contains("mine/kr/entry"), "{kind}: {body}");
        }
    }

    #[test]
    fn nothing_replaces_a_profile_or_points_at_another_zdotdir() {
        for kind in ShellKind::ALL {
            let body = entry(&for_shell(*kind), Path::new("/opt/kr/entry"), true);
            for forbidden in ["ZDOTDIR=", "--rcfile", "--norc", "--noprofile", "exec "] {
                assert!(
                    !body.contains(forbidden),
                    "{kind}'s entry contains {forbidden}"
                );
            }
        }
    }
}
