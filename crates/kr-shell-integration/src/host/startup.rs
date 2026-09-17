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
                path: self
                    .home
                    .join(".config/powershell/Microsoft.PowerShell_profile.ps1"),
                reason: "the user's own profile, which this entry adds to rather than replaces",
            }],
        }
    }

    /// Returns the first login file this user has, when it does not already source `.bashrc`.
    ///
    /// Bash reads exactly one of these for a login shell, in this order. A file that already
    /// sources `.bashrc` needs no entry of its own: the entry in `.bashrc` will run.
    fn bash_login_file(&self) -> Option<PathBuf> {
        for name in [".bash_profile", ".bash_login", ".profile"] {
            let path = self.home.join(name);
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            if contents.contains(".bashrc") {
                return None;
            }
            return Some(path);
        }
        None
    }
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
    let existing = read_or_empty(path)?;
    let Some((before, after)) = strip(&existing) else {
        return Ok(Change::Absent);
    };
    let rebuilt = format!("{before}{after}");
    // A file this entry created and nothing else ever wrote to goes with it. One the user owns
    // stays, with their own lines exactly as they left them.
    if rebuilt.trim().is_empty() && before.trim().is_empty() {
        std::fs::remove_file(path)?;
    } else {
        replace(path, &existing, &rebuilt)?;
    }
    Ok(Change::Removed)
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
/// alone. The file may have changed since it was read, and a replacement built on stale contents
/// would silently drop whatever was written in between, so the contents are checked again first.
/// And the file beside it is created exclusively under a name of this call's own, so nothing that
/// happens to be there is truncated and two calls cannot share one temporary.
fn replace(path: &Path, expected: &str, contents: &str) -> std::io::Result<()> {
    // The file the configuration actually lives in. A symlink is a deliberate arrangement of the
    // user's, and renaming over the link would replace it with a regular file and quietly cut the
    // startup entry off from the checkout it belongs to.
    let target = match path.symlink_metadata() {
        Ok(data) if data.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    if read_or_empty(&target)? != expected {
        return Err(std::io::Error::other(
            "the startup file changed while this entry was being written, so nothing was written",
        ));
    }
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
    match write_new(&temporary, contents) {
        Ok(()) => {}
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
    }
    if let Some(permissions) = permissions
        && let Err(error) = std::fs::set_permissions(&temporary, permissions)
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    match std::fs::rename(&temporary, &target) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
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
