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
    /// The value of `USERPROFILE`, which is where Windows keeps a user's own directories.
    pub user_profile: Option<PathBuf>,
    /// The value of `OneDrive`, when a Windows installation has redirected the user's documents.
    pub onedrive: Option<PathBuf>,
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
            user_profile: std::env::var_os("USERPROFILE").map(PathBuf::from),
            onedrive: std::env::var_os("OneDrive").map(PathBuf::from),
        }
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
            }],
            ShellKind::Bash => {
                let mut targets = vec![StartupTarget {
                    kind,
                    path: self.home.join(".bashrc"),
                    reason: "the file a non-login interactive Bash reads",
                }];
                if let Some(login) = self.bash_login_file() {
                    targets.push(StartupTarget {
                        kind,
                        path: login,
                        reason: "the first login file this user has, which does not source .bashrc",
                    });
                }
                targets
            }
            ShellKind::Fish => vec![StartupTarget {
                kind,
                path: self
                    .xdg_config_home
                    .clone()
                    .unwrap_or_else(|| self.home.join(".config"))
                    .join("fish/conf.d/kalareach.fish"),
                reason: "a guarded conf.d entry; it loads before config.fish and defers its own activation until after it",
            }],
            ShellKind::PowerShell => vec![StartupTarget {
                kind,
                path: self.powershell_profile(),
                reason: "the user's own profile, which this entry adds to rather than replaces",
            }],
        }
    }

    /// Returns the profile PowerShell reads on this platform.
    ///
    /// PowerShell keeps its per-user profile where the platform puts a user's documents, and the
    /// two platforms do not agree: Windows uses `Documents\PowerShell` under the user's profile
    /// directory, following the `USERPROFILE` and `OneDrive` redirection a modern installation
    /// does, and everything else uses `.config/powershell` under the home directory. Writing the
    /// Unix path on Windows would add an entry to a file PowerShell never reads.
    fn powershell_profile(&self) -> PathBuf {
        const PROFILE: &str = "Microsoft.PowerShell_profile.ps1";

        if cfg!(windows) {
            // `Documents` is redirected when OneDrive's known-folder move is on, and the variable
            // it sets is what says where. Without it the profile directory is under the user's own
            // profile, which `USERPROFILE` names and `HOME` usually does not.
            let documents = self
                .onedrive
                .clone()
                .or_else(|| self.user_profile.clone())
                .unwrap_or_else(|| self.home.clone())
                .join("Documents");
            return documents.join("PowerShell").join(PROFILE);
        }
        self.xdg_config_home
            .clone()
            .unwrap_or_else(|| self.home.join(".config"))
            .join("powershell")
            .join(PROFILE)
    }

    /// Returns the first login file this user has, when it does not already source `.bashrc`.
    ///
    /// Bash reads exactly one of these for a login shell, in this order, and a file that already
    /// sources `.bashrc` needs no entry of its own: the entry in `.bashrc` will run.
    ///
    /// What counts as sourcing it is a `source` or `.` of a path whose last component is
    /// `.bashrc`, on a line that is not a comment. A file that merely mentions the name — in a
    /// comment, in a message, in a variable that is never read — is not a file that runs it, and
    /// treating it as one would leave a login shell with no entry at all.
    fn bash_login_file(&self) -> Option<PathBuf> {
        for name in [".bash_profile", ".bash_login", ".profile"] {
            let path = self.home.join(name);
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            if contents.lines().any(sources_bashrc) {
                return None;
            }
            return Some(path);
        }
        None
    }
}

/// Returns whether one line of a login file sources `.bashrc`.
///
/// The shape is a `source` or `.` command whose next word is a path ending in `.bashrc`, wherever
/// on the line it appears: a login file writes it inside a test, after a `then`, behind a `&&`.
/// A line that merely contains the name — in a comment, in a message, in a variable nothing reads
/// — is not a line that runs it, and treating it as one would leave a login shell with no entry.
fn sources_bashrc(line: &str) -> bool {
    let line = line.trim();
    if line.starts_with('#') {
        return false;
    }
    let words: Vec<&str> = line.split_whitespace().collect();
    words.windows(2).any(|pair| {
        let verb = pair[0].trim_start_matches([';', '&', '|']);
        if verb != "source" && verb != "." {
            return false;
        }
        let argument = pair[1].trim_matches(['"', '\'', ';']);
        std::path::Path::new(argument)
            .file_name()
            .is_some_and(|name| name == ".bashrc")
    })
}

/// What one guarded entry contains.
///
/// The body is the package's own file, sourced by one line. Nothing of the integration's logic is
/// copied into the user's configuration, so upgrading the package changes what runs without
/// rewriting anything the user owns.
#[must_use]
pub fn entry(kind: ShellKind, package_entry: &Path, nsh_bypass: bool) -> String {
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
            if nsh_bypass {
                body.push_str(&format!(
                    "[ -n \"${{KR_SHELL_BRIDGE:-}}\" ] && export {NSH_BYPASS_VARIABLE}=1\n"
                ));
            }
            body.push_str(&format!("[ -r {path} ] && . {path}\n"));
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

/// How old a lock file has to be before it is taken for one nobody is holding.
///
/// A startup write is a read, a rebuild and a rename of a small file. One that has held the lock
/// for this long is not running; it is a process that died with the file still there, and leaving
/// it would make every later write fail on a machine that had crashed once.
const LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// A lock beside one startup file, held for a whole read-rebuild-write.
///
/// This is what closes the window between the check before the rename and the rename itself, for
/// the writer that window was about: another `kr` process installing or removing the same entry.
/// The lock is a file created exclusively beside the startup file, so the two processes need no
/// agreement beyond the directory they are both writing in.
///
/// It says nothing about an editor. A person who saves the file between the check and the rename
/// still has that save replaced, and closing that would need the platform to offer a comparison
/// and a rename in one step.
struct FileLock {
    path: PathBuf,
}

impl FileLock {
    /// Takes the lock for one startup file, waiting for a holder that is still working.
    ///
    /// # Errors
    ///
    /// Returns the underlying failure, or a timeout when another writer held it throughout.
    fn take(path: &Path) -> std::io::Result<Self> {
        let target = resolved(path)?;
        let directory = target.parent().unwrap_or_else(|| Path::new("."));
        let name = target.file_name().map_or_else(
            || String::from("startup"),
            |name| name.to_string_lossy().into_owned(),
        );
        let lock = directory.join(format!(".{name}.kalareach-lock"));
        let deadline = std::time::Instant::now() + LOCK_PATIENCE;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock)
            {
                Ok(mut file) => {
                    use std::io::Write as _;

                    // What is in it is for a person reading a directory, not for this code: the
                    // exclusive creation is the lock.
                    let _ = writeln!(file, "kr {}", std::process::id());
                    return Ok(Self { path: lock });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock
                        .metadata()
                        .and_then(|data| data.modified())
                        .is_ok_and(|written| {
                            written.elapsed().is_ok_and(|age| age > LOCK_STALE_AFTER)
                        })
                    {
                        // Nobody is holding it. Removing it races another writer doing the same,
                        // and the loser simply takes the lock the winner released.
                        let _ = std::fs::remove_file(&lock);
                        continue;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "another kr process is writing {}; nothing was written",
                                target.display()
                            ),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                // The directory is not there yet, which is the caller's to create. A lock it
                // cannot take is not a reason to refuse the write: the file cannot exist either.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Self {
                        path: PathBuf::new(),
                    });
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
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
    let begin = contents.find(MARKER_BEGIN)?;
    let end = contents[begin..].find(MARKER_END)? + begin;
    let after = end + MARKER_END.len();
    let after = contents[after..]
        .strip_prefix('\n')
        .map_or(&contents[after..], |rest| rest);
    Some((contents[..begin].to_owned(), after.to_owned()))
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
            user_profile: None,
            onedrive: None,
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

    #[test]
    fn bash_gets_a_login_entry_only_when_the_login_file_ignores_bashrc() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        // No login file at all.
        assert_eq!(home.targets(ShellKind::Bash).len(), 1);
        // One that already sources .bashrc needs nothing of its own.
        std::fs::write(
            root.path().join(".bash_profile"),
            "[ -f ~/.bashrc ] && . ~/.bashrc\n",
        )
        .expect("writes");
        assert_eq!(home.targets(ShellKind::Bash).len(), 1);
        // One that does not.
        std::fs::write(
            root.path().join(".bash_profile"),
            "export PATH=$PATH:/opt\n",
        )
        .expect("writes");
        let targets = home.targets(ShellKind::Bash);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].path, root.path().join(".bashrc"));
        assert_eq!(targets[1].path, root.path().join(".bash_profile"));
    }

    /// KR-REQ-07.30: only a login file that actually runs `.bashrc` counts as one that does.
    #[test]
    fn a_login_file_that_only_mentions_bashrc_still_gets_its_own_entry() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        for mentions in [
            "# this used to source ~/.bashrc; it does not any more\n",
            "echo 'see .bashrc for the aliases'\n",
            "BASHRC=~/.bashrc\n",
            "# . ~/.bashrc\n",
        ] {
            std::fs::write(root.path().join(".bash_profile"), mentions).expect("writes");
            assert_eq!(
                home.targets(ShellKind::Bash).len(),
                2,
                "a login file that names .bashrc without running it still needs an entry: \
                 {mentions:?}"
            );
        }
        for sources in [
            ". ~/.bashrc\n",
            "source ~/.bashrc\n",
            "[ -f ~/.bashrc ] && source \"$HOME/.bashrc\"\n",
            "export PATH=/opt:$PATH; . /home/someone/.bashrc\n",
            "if [ -r ~/.bashrc ]; then . ~/.bashrc; fi\n",
        ] {
            std::fs::write(root.path().join(".bash_profile"), sources).expect("writes");
            assert_eq!(
                home.targets(ShellKind::Bash).len(),
                1,
                "a login file that runs .bashrc needs no entry of its own: {sources:?}"
            );
        }
    }

    /// KR-REQ-07.40: two writers of one startup file do not interleave, whichever process each
    /// is in.
    #[test]
    fn a_second_writer_waits_for_the_first_and_neither_loses_its_entry() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "export EDITOR=vim\n").expect("writes");

        // A lock is taken for the whole read-rebuild-write, so a writer that is not this process
        // is kept out rather than racing the rename.
        let held = FileLock::take(&path).expect("takes the lock");
        let lock = root
            .path()
            .join(".{}.kalareach-lock".replace("{}", ".zshrc"));
        assert!(lock.is_file(), "the lock is beside the file it is about");
        drop(held);
        assert!(!lock.exists(), "and it goes when the write is finished");

        // A lock nobody is holding does not stop a write for ever.
        std::fs::write(&lock, "kr 1\n").expect("writes a lock file");
        let stale =
            std::time::SystemTime::now() - LOCK_STALE_AFTER - std::time::Duration::from_secs(1);
        std::fs::File::open(&lock)
            .and_then(|file| file.set_times(std::fs::FileTimes::new().set_modified(stale)))
            .expect("ages the lock file");
        let reclaimed = FileLock::take(&path).expect("reclaims a lock nobody is holding");
        drop(reclaimed);

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert!(
            std::fs::read_to_string(&path)
                .expect("reads")
                .starts_with("export EDITOR=vim"),
            "the user's own line is still first"
        );
        assert!(!lock.exists(), "and no lock is left behind");
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

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "export EDITOR=vim\n"
        );
    }

    /// KR-REQ-07.29: PowerShell's profile is the one this platform's PowerShell reads.
    #[test]
    fn the_powershell_profile_is_this_platforms_own() {
        let root = tempfile::tempdir().expect("a directory");
        let home = layout(root.path());
        let path = &home.targets(ShellKind::PowerShell)[0].path;
        assert_eq!(
            path.file_name().expect("a file name"),
            "Microsoft.PowerShell_profile.ps1"
        );
        if cfg!(windows) {
            assert!(
                path.to_string_lossy().contains("Documents"),
                "Windows keeps the profile under the user's documents: {}",
                path.display()
            );
            // A redirected documents directory is where the profile actually is.
            let redirected = HomeLayout {
                onedrive: Some(root.path().join("OneDrive")),
                ..home.clone()
            };
            assert_eq!(
                redirected.targets(ShellKind::PowerShell)[0].path,
                root.path()
                    .join("OneDrive/Documents/PowerShell/Microsoft.PowerShell_profile.ps1")
            );
        } else {
            assert_eq!(
                *path,
                root.path()
                    .join(".config/powershell/Microsoft.PowerShell_profile.ps1")
            );
            let configured = HomeLayout {
                xdg_config_home: Some(root.path().join("xdg")),
                ..home.clone()
            };
            assert_eq!(
                configured.targets(ShellKind::PowerShell)[0].path,
                root.path()
                    .join("xdg/powershell/Microsoft.PowerShell_profile.ps1")
            );
        }
    }

    #[test]
    fn the_entry_is_added_beside_what_the_user_wrote_and_removed_without_it() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        let theirs = "export EDITOR=vim\nalias ll='ls -la'\n";
        std::fs::write(&path, theirs).expect("writes");
        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
        assert_eq!(install(&path, &body).expect("installs"), Change::Added);
        let after = std::fs::read_to_string(&path).expect("reads");
        assert!(after.starts_with(theirs), "the user's own lines are first");
        assert!(after.contains(MARKER_BEGIN) && after.contains(MARKER_END));
        assert!(installed(&path));
        // A second install is not a second entry.
        assert_eq!(install(&path, &body).expect("installs"), Change::Unchanged);
        let updated = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), true);
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

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
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

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
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

        let body = entry(ShellKind::Zsh, Path::new("/opt/kr/zsh-entry.zsh"), false);
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
                name.contains("kalareach-") && name != ".zshrc.kalareach-new"
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
            let with = entry(*kind, Path::new("/opt/kr/entry"), true);
            assert!(
                with.contains(NSH_BYPASS_VARIABLE),
                "{kind} offers the documented bypass"
            );
            assert!(
                with.contains("KR_SHELL_BRIDGE"),
                "{kind} sets it only where the bridge was exported"
            );
            let without = entry(*kind, Path::new("/opt/kr/entry"), false);
            assert!(
                !without.contains(NSH_BYPASS_VARIABLE),
                "{kind} sets nothing when the option is off"
            );
        }
    }

    #[test]
    fn a_path_with_an_apostrophe_stays_one_word() {
        for kind in ShellKind::ALL {
            let body = entry(*kind, Path::new("/home/it's mine/kr/entry"), false);
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
            let body = entry(*kind, Path::new("/opt/kr/entry"), true);
            for forbidden in ["ZDOTDIR=", "--rcfile", "--norc", "--noprofile", "exec "] {
                assert!(
                    !body.contains(forbidden),
                    "{kind}'s entry contains {forbidden}"
                );
            }
        }
    }
}
