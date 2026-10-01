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

use serde::{Deserialize, Serialize};

use crate::contract::qualification::ShellKind;

/// The line that opens a KalaReach entry.
pub const MARKER_BEGIN: &str = "# >>> KalaReach shell integration >>>";

/// The line that closes it.
pub const MARKER_END: &str = "# <<< KalaReach shell integration <<<";

/// The PowerShell form of the opening marker.
pub const MARKER_BEGIN_POWERSHELL: &str = "# >>> KalaReach shell integration >>>";

/// The line that opens the entry at the end of a PowerShell profile, which checks the reader.
///
/// It is an entry of its own with markers of its own, so that one file can hold both PowerShell
/// entries, as a profile that is a link to the other one does, and removal takes out each.
pub const CHECK_MARKER_BEGIN: &str = "# >>> KalaReach reader check >>>";

/// The line that closes it.
pub const CHECK_MARKER_END: &str = "# <<< KalaReach reader check <<<";

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
    /// Where in the file the entry goes.
    pub placement: Placement,
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
                placement: Placement::End,
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
                        placement: Placement::End,
                    },
                    StartupTarget {
                        kind,
                        path: login,
                        reason: "the login file this user has, which a login Bash reads instead",
                        shared,
                        placement: Placement::End,
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
                placement: Placement::End,
            }],
            // PowerShell is the one shell whose profile paths this host does not derive: where it
            // keeps a per-user profile depends on where the platform puts that user's documents,
            // and on Windows that is a known folder a redirection can move. So the shell is asked,
            // and a shell that cannot be asked gets no target rather than an entry written where
            // it will never be read.
            //
            // It reads two per-user profiles, the one every host reads and then the one its own
            // host reads, and the entry is in both. The bridge is opened at the start of the first,
            // before anything the person wrote there or in the second can ask a question of a shell
            // whose input the session would refuse; what the second ends with is checked once
            // everything the person configured has run.
            ShellKind::PowerShell => self
                .powershell
                .as_deref()
                .and_then(|shell| {
                    self.powershell_profiles().map(|(all_hosts, current_host)| {
                        powershell_targets(shell, all_hosts, current_host)
                    })
                })
                .unwrap_or_default(),
        }
    }

    /// Returns the two per-user profiles PowerShell reads on this host, the one every host reads
    /// and the one its own host reads after it.
    ///
    /// They are asked for rather than worked out. PowerShell keeps its per-user profiles in a
    /// different place on each platform, in a different place for each edition, and on Windows
    /// under whatever directory the user's documents have been redirected to; a path this host
    /// derived could be a file PowerShell never reads, and an entry in a file nothing reads is an
    /// installation that reports success and integrates nothing.
    fn powershell_profiles(&self) -> Option<(PathBuf, PathBuf)> {
        let shell = self.powershell.as_ref()?;
        // The shell's own answer, read from a shell started with no profile of its own so that
        // nothing a user wrote decides where their profile is: one path on each of two lines.
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
                "$PROFILE.CurrentUserAllHosts; $PROFILE.CurrentUserCurrentHost",
            ],
        )?;
        let mut lines = said.lines().map(str::trim).filter(|line| !line.is_empty());
        let all_hosts = PathBuf::from(lines.next()?);
        let current_host = PathBuf::from(lines.next()?);
        // A shell that named one profile, or more than two, answered something else.
        lines.next().is_none().then_some((all_hosts, current_host))
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

/// Returns the entries PowerShell's two per-user profiles get, given where it keeps them.
///
/// The first profile it reads is the one every host reads, and the entry after its prologue opens
/// the bridge before anything the person wrote there or in the second can ask a question of a shell
/// whose input the session would refuse. The second is the one its own host reads, and the entry at
/// its end checks the reader once everything the person configured has run. `shell` is the
/// PowerShell whose profiles they are, which is the one that finds where the first entry goes and
/// checks that each entry sits among whole statements.
///
/// The two entries have markers of their own, so a profile that is a link to the other, or the same
/// file under two names, holds both: the one that opens the bridge below its prologue and the one
/// that checks the reader at its end.
#[must_use]
pub fn powershell_targets(
    shell: &Path,
    all_hosts: PathBuf,
    current_host: PathBuf,
) -> Vec<StartupTarget> {
    vec![
        StartupTarget {
            kind: ShellKind::PowerShell,
            path: all_hosts,
            reason: "the profile this shell reads first of the user's own, which opens the bridge \
                     before anything the user wrote can ask a question; the entry adds to it \
                     rather than replaces it",
            shared: false,
            placement: Placement::AfterPrologue {
                shell: shell.to_path_buf(),
            },
        },
        StartupTarget {
            kind: ShellKind::PowerShell,
            path: current_host,
            reason: "the profile this shell reads last, which checks the reader once everything \
                     the user configured has run; the entry adds to it rather than replaces it",
            shared: false,
            placement: Placement::Last {
                shell: shell.to_path_buf(),
            },
        },
    ]
}

/// How long a shell is given to answer a question about itself.
const ASK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long PowerShell is given to place an entry in a profile, or to check one it placed.
///
/// These are the two questions that read and parse a person's profile, and a PowerShell that starts
/// cold on a busy machine, and most of all on Windows, takes longer than it does to name a path.
/// The install that waits for them has nothing else to do, and an answer that came late is better
/// than a refusal with no reason.
const PLACEMENT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Asks one program a question and returns what it printed, or nothing.
///
/// The answer goes to a file rather than a pipe, so nothing has to read while the program runs and
/// a descendant that inherited the handle holds nothing of this host's open. The wait is bounded,
/// and a program that outlasts it is terminated and reaped: a shell that will not start must not
/// hold `kr shell` open.
fn ask(program: &Path, arguments: &[&str]) -> Option<String> {
    ask_with(program, arguments, &[], ASK_DEADLINE)
}

/// Asks one program a question about some text and returns what it printed, or nothing.
///
/// Each of `inputs` is a variable name and the text it stands for. The text is written to a file in
/// the call's private directory and the variable holds the file's path, so the program reads the
/// text exactly as it is, whatever it contains, and nothing has to be quoted into its arguments.
fn ask_with(
    program: &Path,
    arguments: &[&str],
    inputs: &[(&str, &str)],
    allowed: std::time::Duration,
) -> Option<String> {
    // A directory of this call's own, created rather than opened and owner-only where the platform
    // has modes. `/tmp` is shared: a name another account can guess is a name it can pre-create,
    // and a file opened through it is a file this host writes on somebody else's behalf.
    let directory = std::env::temp_dir().join(format!("kr-shell-ask-{}", kr_ipc::new_uuid()));
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt as _;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
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
    let mut variables = Vec::new();
    for (name, text) in inputs {
        let file = directory.join(name);
        if std::fs::write(&file, text).is_err() {
            let _ = std::fs::remove_dir_all(&directory);
            return None;
        }
        variables.push((*name, file));
    }
    let mut command = std::process::Command::new(program);
    command
        .args(arguments)
        .envs(variables)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(to))
        .stderr(std::process::Stdio::null());
    // A shell keeps a cache, an identifier and a module directory under the home's XDG directories
    // whenever it starts, and answering a question must not put them in the person's home. They go
    // under this call's own directory and leave with it.
    #[cfg(unix)]
    command
        .env("XDG_CACHE_HOME", directory.join("cache"))
        .env("XDG_DATA_HOME", directory.join("data"));
    let started = command.spawn();
    let mut child = match started {
        Ok(child) => child,
        Err(_) => {
            let _ = std::fs::remove_dir_all(&directory);
            return None;
        }
    };
    let deadline = std::time::Instant::now() + allowed;
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

/// What the entry at the end of a PowerShell profile runs: the module's own check of the reader,
/// in a shell that loaded the module.
pub const POWERSHELL_READER_CHECK: &str =
    "if (Get-Module KalaReach.ShellBridge) { Confirm-KalaReachReadLine }";

/// The variable one shell's entries share, so the integration loads once in each shell.
pub const ENTRY_GUARD_VARIABLE: &str = "KR_SHELL_ENTRY";

/// A package entry that cannot be named in a startup file, because its path is not text.
///
/// A startup file is text, and so is the path an entry names in it. A path that is not UTF-8 has
/// no spelling there: converted with replacement characters, it would name another path, which
/// the shell reading the file would then source or fail to find. It is refused instead, by name.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{} cannot be written into a startup file: it is not UTF-8", .path.display())]
pub struct NotText {
    /// The package's entry, as the package names it.
    pub path: PathBuf,
}

/// What one guarded entry contains.
///
/// The body is the package's own file, sourced by one line. Nothing of the integration's logic is
/// copied into the user's configuration, so upgrading the package changes what runs without
/// rewriting anything the user owns.
///
/// # Errors
///
/// Returns [`NotText`] when the package's entry is not UTF-8, which no startup file can name.
pub fn entry(
    target: &StartupTarget,
    package_entry: &Path,
    nsh_bypass: bool,
) -> Result<String, NotText> {
    let kind = target.kind;
    let text = package_entry.to_str().ok_or_else(|| NotText {
        path: package_entry.to_path_buf(),
    })?;
    // The path is quoted for the shell that will read this file, by the same rules a launch is
    // quoted by. An installation directory with an apostrophe in it would otherwise end the string
    // and turn the rest of the path into shell syntax.
    let path = crate::host::quoting::quote(kind, text);
    let mut body = String::new();
    let (marker_begin, marker_end) = target.placement.markers();
    body.push_str(marker_begin);
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
        ShellKind::PowerShell => match &target.placement {
            // The first of the user's profiles loads the module that opens the bridge.
            Placement::AfterPrologue { .. } => {
                if nsh_bypass {
                    body.push_str(&format!(
                        "if ($env:KR_SHELL_BRIDGE) {{ $env:{NSH_BYPASS_VARIABLE} = '1' }}\n"
                    ));
                }
                body.push_str(&format!(
                    "if (Test-Path -LiteralPath {path}) {{ . {path} }}\n"
                ));
            }
            // The last of them asks the module whether the reader it went in front of is still the
            // one the host calls. Nothing here is the integration's logic: the module is the one
            // that knows, and a shell that never loaded it has nothing to ask.
            Placement::Last { .. } | Placement::End => {
                body.push_str(&format!("{POWERSHELL_READER_CHECK}\n"));
            }
        },
    }
    body.push_str(marker_end);
    body.push('\n');
    Ok(body)
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

/// The line that says a marked block began on a line of its own because the file it was added to
/// did not end in one. The block owns that line break: the removal takes it back with the block, so
/// a file that had no final line break is given back exactly as it was.
const SEPARATOR_NOTE: &str = "# The file above did not end in a line break, so this entry began on a line of its own; \
                              `kr shell remove` takes that line break out again.";

/// The block with the separator note as its second line.
fn with_separator_note(body: &str) -> String {
    body.replacen(
        &format!("{MARKER_BEGIN}\n"),
        &format!("{MARKER_BEGIN}\n{SEPARATOR_NOTE}\n"),
        1,
    )
}

/// Whether a block owns the line break that stands before it.
fn owns_separator(block: &str) -> bool {
    block.lines().any(|line| line == SEPARATOR_NOTE)
}

/// Where in a startup file a guarded entry goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Placement {
    /// After everything the user wrote, so the entry runs once their configuration has.
    End,
    /// Before everything the user wrote that is a statement, so the entry runs before anything
    /// they wrote can ask a question.
    ///
    /// A PowerShell profile begins with parts that have to stay first: a `using` statement is
    /// accepted only before every other statement, and a script `param` block only before the
    /// script's own. Where they end is a question about PowerShell's grammar, so PowerShell answers
    /// it: the program named here parses the profile and says where its last `using` statement or
    /// `param` block stops. The entry goes on the line after, and only where nothing but a comment
    /// or a semicolon is left on the line the prologue ends on, because an entry cannot be put in
    /// the middle of a line without moving what is after it. The profile is then parsed again with
    /// the entry in it, and the entry is refused unless every statement between its markers is a
    /// whole statement of the profile's own top level, every statement of the profile's own comes
    /// after the entry, and everything else is as it was.
    AfterPrologue {
        /// The PowerShell that answers, which is the one this profile belongs to.
        shell: PathBuf,
    },
    /// After everything the user wrote, in a PowerShell profile: the same end as `End`, checked the
    /// same way as `AfterPrologue` is, so that an entry can never land inside a statement the
    /// profile leaves open, and every statement of the profile's own comes before it.
    Last {
        /// The PowerShell that answers, which is the one this profile belongs to.
        shell: PathBuf,
    },
}

impl Placement {
    /// Returns the lines that open and close the entry placed this way.
    #[must_use]
    pub const fn markers(&self) -> (&'static str, &'static str) {
        match self {
            Self::End | Self::AfterPrologue { .. } => (MARKER_BEGIN, MARKER_END),
            Self::Last { .. } => (CHECK_MARKER_BEGIN, CHECK_MARKER_END),
        }
    }

    /// Returns the PowerShell that places and checks an entry put this way, when it takes one.
    fn shell(&self) -> Option<&Path> {
        match self {
            Self::End => None,
            Self::AfterPrologue { shell } | Self::Last { shell } => Some(shell),
        }
    }
}

/// Adds or updates one shell's guarded entry.
///
/// The file is created when it does not exist. A new entry goes where `placement` says, and one
/// already there is rebuilt where `placement` says as well, so an entry an earlier install put at
/// the end of a profile that needs it at the start moves. Everything the user wrote is kept: the
/// entry is delimited by its markers and only the text between them is ever rewritten. Where the
/// file did not end in a line break and the entry goes at the end, the entry starts on a line of
/// its own and owns that line break, which the removal takes back with it.
///
/// The lock that holds two writers apart is in `record`'s directory, keyed by the file, so nothing
/// is written in the person's home but the entry.
///
/// # Errors
///
/// Returns the underlying failure when the file cannot be read or written.
pub fn install(
    path: &Path,
    body: &str,
    placement: &Placement,
    record: &EntryRecord,
) -> std::io::Result<Change> {
    let _writing = writing();
    let _held = FileLock::take_for_startup_file(path, &record.lock_directory())?;
    let existing = read_or_empty(path)?;
    let (change, updated) = planned(&existing, body, placement)?;
    if change != Change::Unchanged {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        replace(path, &existing, &updated)?;
    }
    Ok(change)
}

/// Returns what [`install`] would do to a file, and writes nothing.
///
/// A dry run says what a real one does, including the move of an entry an earlier install put where
/// `placement` no longer says, and a refusal, rather than that an entry is there.
///
/// # Errors
///
/// Returns the underlying failure when the file cannot be read, or when PowerShell cannot say where
/// an entry goes or would refuse the result.
pub fn plan(path: &Path, body: &str, placement: &Placement) -> std::io::Result<Change> {
    Ok(planned(&read_or_empty(path)?, body, placement)?.0)
}

/// Returns what installing `body` into a file with these contents does, and the contents it leaves.
fn planned(existing: &str, body: &str, placement: &Placement) -> std::io::Result<(Change, String)> {
    // A signed profile is never changed: what PowerShell reads as a signature, and where one leaves
    // the text it signs, are PowerShell's own rules. The words are looked for in the file as it was
    // read, before this placement's entry is cut out of it, because that cut can hold the block.
    if placement.shell().is_some() && holds_signature_words(existing) {
        return Err(cannot_take_the_entry(SIGNED));
    }
    let (begin, end) = placement.markers();
    let stripped = strip(existing, begin, end);
    let had_entry = stripped.is_some();
    let theirs = stripped.as_ref().map_or_else(
        || existing.to_owned(),
        |(before, _block, after)| format!("{before}{after}"),
    );
    let rebuilt = match placement {
        Placement::End => match stripped {
            Some((before, block, after)) => {
                let body = if owns_separator(&block) {
                    with_separator_note(body)
                } else {
                    body.to_owned()
                };
                format!("{before}{body}{after}")
            }
            None if !existing.is_empty() && !existing.ends_with('\n') => {
                format!("{existing}\n{}", with_separator_note(body))
            }
            None => appended(existing, body),
        },
        Placement::AfterPrologue { shell } => {
            let (rebuilt, _) = after_the_prologue(shell, &theirs, body, placement)?;
            rebuilt
        }
        Placement::Last { .. } => {
            let rebuilt = appended(&theirs, body);
            checked(&theirs, &rebuilt, placement)?;
            rebuilt
        }
    };
    Ok(if !had_entry {
        (Change::Added, rebuilt)
    } else if rebuilt == existing {
        (Change::Unchanged, rebuilt)
    } else {
        (Change::Replaced, rebuilt)
    })
}

/// Puts `body` after everything in a file, on a line of its own.
fn appended(existing: &str, body: &str) -> String {
    let mut rebuilt = existing.to_owned();
    if !rebuilt.is_empty() && !rebuilt.ends_with('\n') {
        rebuilt.push('\n');
    }
    rebuilt.push_str(body);
    rebuilt
}

/// Puts `body` into a PowerShell profile after the parts that have to stay first, at the point the
/// `shell` names, and checks that PowerShell reads the result as it read the profile.
///
/// A byte-order mark stays the first bytes of the file and belongs to no line, so the entry's first
/// line is a whole line of the file and is found again, exactly, when it is removed.
fn after_the_prologue(
    shell: &Path,
    theirs: &str,
    body: &str,
    placement: &Placement,
) -> std::io::Result<(String, usize)> {
    if second_mark(theirs) {
        return Err(cannot_take_the_entry(
            "it begins with a second byte-order mark",
        ));
    }
    let (mark, text) = match theirs.strip_prefix('\u{feff}') {
        Some(text) => ("\u{feff}", text),
        None => ("", theirs),
    };
    let at = prologue_end(shell, text)?;
    let (head, rest) = text.split_at(at);
    // The prologue's line is the last of a file with no final line end, and PowerShell has said
    // that nothing but whitespace, a semicolon or a comment follows the prologue on it. This is an
    // entry added at the end, and it is added the way one is.
    let rebuilt = if rest.is_empty() && !head.is_empty() && !head.ends_with('\n') {
        format!("{mark}{}", appended(head, body))
    } else {
        format!("{mark}{head}{body}{rest}")
    };
    checked(theirs, &rebuilt, placement)?;
    Ok((rebuilt, at))
}

/// Refuses an entry PowerShell would not read as part of the profile it was added to.
fn checked(old: &str, new: &str, placement: &Placement) -> std::io::Result<()> {
    match entry_refused(old, new, placement)? {
        None => Ok(()),
        Some(why) => Err(cannot_take_the_entry(&why)),
    }
}

/// The question both scripts ask first about a profile's text: whether an entry can be added to it
/// at all.
///
/// A profile whose line ends cannot be told from each other is refused by name and left as it is. A
/// profile that begins with a second byte-order mark is refused before either script is asked, by
/// [`second_mark`], because reading a file takes one mark off it and the question could not see the
/// second. A signed profile is refused before either script is asked too, by
/// [`holds_signature_words`], from the file as it was read.
macro_rules! unsafe_profile {
    () => {
        "function Unsafe($text) { \
            if ($text -match \"`r(?!`n)\") { return 'it has a line end that is a carriage return alone' }; \
            $null \
        }; "
    };
}

/// Whether a profile's text begins with a second byte-order mark, after the one that is the file's
/// encoding.
///
/// The first mark belongs to no line, and a second one would be read as part of the first token, so
/// PowerShell already fails on such a profile and an entry's offsets would be one character short.
fn second_mark(text: &str) -> bool {
    text.strip_prefix('\u{feff}')
        .is_some_and(|rest| rest.starts_with('\u{feff}'))
}

/// Why a signed profile is refused.
const SIGNED: &str = "it is signed, and any change to it breaks its signature";

/// What begins the signature block that a PowerShell signer adds to a script.
const SIGNATURE_BEGIN: &[u8] = b"# SIG # Begin signature block";

/// Whether a profile's text holds the words that begin a signature block, in any case.
///
/// A profile that holds them is taken for signed wherever they are, so one that only mentions them
/// in a string is refused too.
fn holds_signature_words(text: &str) -> bool {
    text.as_bytes()
        .windows(SIGNATURE_BEGIN.len())
        .any(|window| window.eq_ignore_ascii_case(SIGNATURE_BEGIN))
}

/// The refusal of a profile an entry cannot be put into, with its reason.
fn cannot_take_the_entry(why: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "this profile cannot take the entry: {why}, so nothing was written"
    ))
}

/// The script that says where a profile's entry goes.
///
/// It prints the UTF-16 offset of the start of the line after the last `using` statement or
/// `param` block, which is the start of the file when there are none, or the reason the profile
/// cannot take the entry there. The offset is given only when what is left on the line the prologue
/// ends on is whitespace, a semicolon or a comment that ends on that line: an entry put in the
/// middle of a line would move what follows it, and one put after the next line end could land
/// inside a statement that began on the prologue's line. When no line end follows the prologue,
/// that line runs to the end of the text and the same is asked of all of it.
const PLACE_SCRIPT: &str = concat!(
    "$ErrorActionPreference = 'Stop'; ",
    unsafe_profile!(),
    "$utf8 = New-Object System.Text.UTF8Encoding $false; \
     $text = [System.IO.File]::ReadAllText($env:KR_PROFILE_TEXT, $utf8); \
     $why = Unsafe $text; \
     if ($null -ne $why) { [Console]::Out.Write('kr-refused ' + $why); return }; \
     $tokens = $null; $errors = $null; \
     $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors); \
     $at = 0; \
     foreach ($using in @($ast.UsingStatements)) { $at = [Math]::Max($at, $using.Extent.EndOffset) }; \
     if ($null -ne $ast.ParamBlock) { $at = [Math]::Max($at, $ast.ParamBlock.Extent.EndOffset) }; \
     if ($at -eq 0) { [Console]::Out.Write('kr-placed 0'); return }; \
     $lf = $text.IndexOf(\"`n\", $at); \
     $lineEnd = if ($lf -lt 0) { $text.Length } else { $lf }; \
     foreach ($token in $tokens) { \
         if ($token.Extent.EndOffset -le $at -or $token.Extent.StartOffset -gt $lineEnd) { continue }; \
         if ($lf -ge 0 -and $token.Extent.StartOffset -lt $lf -and $token.Extent.EndOffset -gt $lf + 1) { \
             [Console]::Out.Write('kr-refused a comment or a string runs over the line its using statements or param block end on'); return }; \
         if ($token.Kind -notin 'Comment', 'NewLine', 'Semi', 'EndOfInput') { \
             [Console]::Out.Write('kr-refused a statement shares the line its using statements or param block end on, and an entry cannot go between them; put it on a line of its own'); return } \
     }; \
     if ($lf -lt 0) { [Console]::Out.Write('kr-placed ' + $text.Length) } else { [Console]::Out.Write('kr-placed ' + ($lf + 1)) }"
);

/// The script that says whether an entry sits in a profile where it belongs, as whole statements,
/// and changed nothing else.
///
/// It parses the profile before and after. The entry is refused unless it adds no parse error the
/// profile did not have and takes none away: a profile that does not run is not one an entry may
/// start running. For a profile that parsed, the entry is refused unless every top-level statement
/// of the new text lies wholly between the entry's two marker lines or wholly outside them, no
/// statement or block holds the marker lines inside it, and the entry is on the side of the
/// profile's own statements it was asked to be: before every one of them, below the `using`
/// statements and `param` block, for the entry that opens the bridge, and after every one of them
/// for the entry that checks the reader. The statements outside are the profile's own top-level
/// statements, with the same text in the same order, and its `using` statements and `param` block
/// are as they were. This holds whatever put the entry where it is, which is the point of asking
/// the parser again instead of trusting the question that placed it.
const VERIFY_SCRIPT: &str = concat!(
    "$ErrorActionPreference = 'Stop'; ",
    unsafe_profile!(),
    "$utf8 = New-Object System.Text.UTF8Encoding $false; \
     function Read($name) { [System.IO.File]::ReadAllText([Environment]::GetEnvironmentVariable($name), $utf8) }; \
     function Parse($text) { \
         $tokens = $null; $errors = $null; \
         $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors); \
         @{ Ast = $ast; Tokens = $tokens; Errors = @($errors | ForEach-Object { $_.ErrorId }) } \
     }; \
     function Refuse($why) { [Console]::Out.Write('kr-refused ' + $why) }; \
     function Same($a, $b) { [string]::Equals([string]$a, [string]$b, [System.StringComparison]::Ordinal) }; \
     $oldText = Read 'KR_PROFILE_OLD'; $newText = Read 'KR_PROFILE_NEW'; $order = Read 'KR_ORDER'; \
     $why = Unsafe $oldText; \
     if ($null -ne $why) { Refuse $why; return }; \
     $old = Parse $oldText; $new = Parse $newText; \
     $had = @{}; foreach ($id in $old.Errors) { $had[$id] = 1 + [int]$had[$id] }; \
     $added = @(); \
     foreach ($id in $new.Errors) { if ($had[$id] -gt 0) { $had[$id] = $had[$id] - 1 } else { $added += $id } }; \
     if ($added.Count -gt 0) { Refuse ('PowerShell would report ' + ($added -join ',')); return }; \
     $ended = 0; foreach ($left in $had.Values) { $ended += $left }; \
     if ($ended -gt 0) { Refuse 'the entry would change which errors PowerShell reports for the profile'; return }; \
     if ($old.Errors.Count -gt 0) { [Console]::Out.Write('kr-verified'); return }; \
     $beginText = Read 'KR_BEGIN'; $endText = Read 'KR_END'; \
     $begin = @($new.Tokens | Where-Object { $_.Kind -eq 'Comment' -and (Same $_.Text $beginText) }); \
     $end = @($new.Tokens | Where-Object { $_.Kind -eq 'Comment' -and (Same $_.Text $endText) }); \
     if ($begin.Count -ne 1 -or $end.Count -ne 1) { Refuse 'its entry is not one block between its markers'; return }; \
     $from = $begin[0].Extent.StartOffset; $to = $end[0].Extent.EndOffset; \
     $inside = @(); $outside = @(); \
     foreach ($statement in @($new.Ast.EndBlock.Statements)) { \
         $start = $statement.Extent.StartOffset; $stop = $statement.Extent.EndOffset; \
         if ($start -ge $from -and $stop -le $to) { $inside += $statement } \
         elseif ($stop -le $from -or $start -ge $to) { $outside += $statement } \
         else { Refuse 'its entry would sit inside a statement of the profile'; return } \
     }; \
     $holding = @($new.Ast.FindAll({ param($node) $node.Extent.StartOffset -lt $from -and $node.Extent.EndOffset -gt $to -and -not ($node -is [System.Management.Automation.Language.ScriptBlockAst] -and $node.Parent -eq $null) -and -not ($node -is [System.Management.Automation.Language.NamedBlockAst]) }, $true)); \
     if ($holding.Count -gt 0) { Refuse 'its entry would sit inside a block of the profile'; return }; \
     foreach ($statement in $outside) { \
         if ($order -eq 'first' -and $statement.Extent.StartOffset -lt $from) { Refuse 'a statement of the profile would run before the entry'; return }; \
         if ($order -eq 'last' -and $statement.Extent.StartOffset -gt $to) { Refuse 'a statement of the profile would run after the entry'; return } \
     }; \
     if ($order -eq 'first') { \
         $prologue = @($new.Ast.UsingStatements) + @($new.Ast.ParamBlock | Where-Object { $null -ne $_ }); \
         foreach ($part in $prologue) { if ($part.Extent.EndOffset -gt $from) { Refuse 'its using statements or param block would come after the entry'; return } } \
     }; \
     $join = [string][char]1; \
     $oldTop = @($old.Ast.EndBlock.Statements | ForEach-Object { $_.Extent.Text }) -join $join; \
     $newTop = @($outside | ForEach-Object { $_.Extent.Text }) -join $join; \
     if (-not (Same $oldTop $newTop)) { Refuse 'the statements of the profile are not what they were'; return }; \
     $oldUsing = @($old.Ast.UsingStatements | ForEach-Object { $_.Extent.Text }) -join $join; \
     $newUsing = @($new.Ast.UsingStatements | ForEach-Object { $_.Extent.Text }) -join $join; \
     $oldParam = if ($null -ne $old.Ast.ParamBlock) { $old.Ast.ParamBlock.Extent.Text } else { '' }; \
     $newParam = if ($null -ne $new.Ast.ParamBlock) { $new.Ast.ParamBlock.Extent.Text } else { '' }; \
     if (-not (Same $oldUsing $newUsing) -or -not (Same $oldParam $newParam)) { Refuse 'its using statements or param block are not what they were'; return }; \
     [Console]::Out.Write('kr-verified')"
);

/// Returns the byte offset in `text` at which PowerShell says an entry goes.
fn prologue_end(shell: &Path, text: &str) -> std::io::Result<usize> {
    let said = ask_with(
        shell,
        &["-NoProfile", "-NonInteractive", "-NoLogo", "-Command", PLACE_SCRIPT],
        &[("KR_PROFILE_TEXT", text)],
        PLACEMENT_DEADLINE,
    )
    .ok_or_else(|| {
        std::io::Error::other(
            "PowerShell did not say where the entry goes: it did not answer in time or could not start",
        )
    })?;
    let said = said.trim();
    if let Some(why) = said.strip_prefix("kr-refused ") {
        return Err(cannot_take_the_entry(why));
    }
    let utf16 = said
        .strip_prefix("kr-placed ")
        .and_then(|offset| offset.parse::<usize>().ok())
        .ok_or_else(|| {
            std::io::Error::other("PowerShell's answer about the entry was not understood")
        })?;
    // PowerShell counts UTF-16 code units. A count that falls inside a character is not one.
    let mut units = 0;
    for (index, character) in text.char_indices() {
        if units == utf16 {
            return Ok(index);
        }
        units += character.len_utf16();
        if units > utf16 {
            break;
        }
    }
    if units == utf16 {
        return Ok(text.len());
    }
    Err(std::io::Error::other(
        "PowerShell's answer about the entry is not inside the profile",
    ))
}

/// Returns why an entry would not sit in a profile as whole statements, or nothing when it would.
fn entry_refused(old: &str, new: &str, placement: &Placement) -> std::io::Result<Option<String>> {
    let Some(shell) = placement.shell() else {
        return Ok(None);
    };
    if second_mark(old) {
        return Ok(Some("it begins with a second byte-order mark".to_owned()));
    }
    let markers = placement.markers();
    let order = match placement {
        Placement::AfterPrologue { .. } => "first",
        _ => "last",
    };
    let said = ask_with(
        shell,
        &["-NoProfile", "-NonInteractive", "-NoLogo", "-Command", VERIFY_SCRIPT],
        &[
            ("KR_PROFILE_OLD", old.strip_prefix('\u{feff}').unwrap_or(old)),
            ("KR_PROFILE_NEW", new.strip_prefix('\u{feff}').unwrap_or(new)),
            ("KR_BEGIN", markers.0),
            ("KR_END", markers.1),
            ("KR_ORDER", order),
        ],
        PLACEMENT_DEADLINE,
    )
    .ok_or_else(|| {
        std::io::Error::other(
            "PowerShell did not check the profile with the entry in it: it did not answer in time or could not start",
        )
    })?;
    let said = said.trim();
    if said == "kr-verified" {
        return Ok(None);
    }
    said.strip_prefix("kr-refused ")
        .map(|why| Some(why.to_owned()))
        .ok_or_else(|| {
            std::io::Error::other("PowerShell's check of the profile was not understood")
        })
}

/// Removes one shell's guarded entry, and nothing else.
///
/// # Errors
///
/// Returns the underlying failure when the file cannot be read or written.
pub fn remove(path: &Path, record: &EntryRecord) -> std::io::Result<Change> {
    let _writing = writing();
    let _held = FileLock::take_for_startup_file(path, &record.lock_directory())?;
    let existing = read_or_empty(path)?;
    // Each of the entries a file can hold, with its own markers: PowerShell's two can be in one
    // file when its two profiles are.
    let mut rebuilt = existing.clone();
    let mut found = false;
    for (begin, end) in [
        (MARKER_BEGIN, MARKER_END),
        (CHECK_MARKER_BEGIN, CHECK_MARKER_END),
    ] {
        if let Some((before, block, after)) = strip(&rebuilt, begin, end) {
            // The line break the entry took with it goes with it, where the entry is still the last
            // thing in the file. Where the person has written after it, the file is no longer the
            // one that was there, and the line break stays.
            let before = if owns_separator(&block) && after.is_empty() {
                before.strip_suffix('\n').unwrap_or(&before).to_owned()
            } else {
                before
            };
            rebuilt = format!("{before}{after}");
            found = true;
        }
    }
    if !found {
        return Ok(Change::Absent);
    }
    // A file this entry created and nothing else ever wrote to goes with it. One the user owns
    // stays, with their own lines exactly as they left them. A link the user made is theirs
    // whatever the file it names holds: deleting it would leave that file behind with the entry
    // still in it, and the shell reading a path that no longer exists.
    let created_here = rebuilt.trim().is_empty()
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

/// The name of the record `kr shell install` keeps of the startup files it put an entry in.
pub const ENTRY_RECORD_NAME: &str = "shell-entries.json";

/// The longest record this build reads: far more than a record of every startup file a home has.
const ENTRY_RECORD_LIMIT: u64 = 1024 * 1024;

/// The startup files `kr shell install` has put an entry in, for each shell.
///
/// Removal works from this record and from nothing else: not from where an entry would go now,
/// which moves when a `ZDOTDIR` is set or unset, a login file is created or another PowerShell
/// answers, and never from the text a report shows. Each file is kept as its path's own bytes, so
/// a name that is not text is kept exactly and names that file and no other.
///
/// It is one owner-only file in the installation's state directory, replaced whole by every change,
/// and changed only while it is held for a whole install or removal ([`EntryRecord::hold`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryRecord {
    /// The owner-only directory the record is kept in.
    directory: PathBuf,
    /// The record itself.
    path: PathBuf,
}

/// Why the record could not be used.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The record, or the directory it is kept in, could not be read or written as this user's
    /// own.
    #[error("{0}")]
    Store(#[from] kr_ipc::IpcError),
    /// The file there is not a record this build writes.
    #[error("the file is not a record of startup entries")]
    NotARecord,
}

/// What the record holds.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded {
    /// Each file an entry was written to, with the shell the entry is for.
    entries: Vec<RecordedEntry>,
}

/// One file an entry was written to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedEntry {
    /// The shell the entry is for.
    shell: ShellKind,
    /// The file's path as its own bytes in hexadecimal ([`encoded`]).
    path: String,
}

impl EntryRecord {
    /// The record kept in an installation's state directory.
    #[must_use]
    pub fn in_state_directory(state: &Path) -> Self {
        Self {
            directory: state.to_path_buf(),
            path: state.join(ENTRY_RECORD_NAME),
        }
    }

    /// Where the record is kept.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory the locks that hold two writers of one startup file apart are kept in, beside
    /// the record: a lock is the installation's, and nothing of it is written in the person's home.
    #[must_use]
    pub fn lock_directory(&self) -> PathBuf {
        self.directory.join("entry-locks")
    }

    /// The files the record names for `kind`, in the order they were recorded, as the record is
    /// now: what a dry run reports from, since it writes nothing and holds nothing.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Store`] when the record cannot be read as this user's own, and
    /// [`RecordError::NotARecord`] when what is there is not a record.
    pub fn files(&self, kind: ShellKind) -> Result<Vec<PathBuf>, RecordError> {
        self.read()?
            .entries
            .iter()
            .filter(|entry| entry.shell == kind)
            .map(|entry| decoded(&entry.path).ok_or(RecordError::NotARecord))
            .collect()
    }

    /// Holds the record for one whole install or removal, waiting while another holds it.
    ///
    /// An install records its files and writes its entries, and a removal reads the record,
    /// removes the entries and forgets the files, all while the record is held; a second `kr`
    /// waits for the first to let go. A removal can therefore never read the record between an
    /// install's recording a file and its writing the entry there, find no entry and forget the
    /// file, which would leave an entry the record does not name and no removal would take out.
    ///
    /// # Errors
    ///
    /// Returns [`RecordError::Store`] when the directory cannot be made this user's own, or when
    /// another `kr` held the record for the whole of the wait.
    pub fn hold(&self) -> Result<HeldRecord<'_>, RecordError> {
        kr_ipc::paths::create_private_tree(&self.directory, &self.directory)?;
        let lock = FileLock::take(&self.path)
            .map_err(|error| kr_ipc::IpcError::io("lock", &self.path, error))?;
        Ok(HeldRecord {
            record: self,
            _lock: lock,
        })
    }

    /// Reads the record; there being none is a record that names nothing.
    fn read(&self) -> Result<Recorded, RecordError> {
        match kr_ipc::paths::read_owner_only_file(&self.path, ENTRY_RECORD_LIMIT)? {
            None => Ok(Recorded::default()),
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| RecordError::NotARecord),
        }
    }
}

/// The record, held for one whole install or removal ([`EntryRecord::hold`]); it is let go when
/// this is dropped.
#[derive(Debug)]
pub struct HeldRecord<'a> {
    /// The record held.
    record: &'a EntryRecord,
    /// The lock that holds it, beside the record in the same directory. Dropping it lets go.
    _lock: FileLock,
}

impl HeldRecord<'_> {
    /// The files the record names for `kind`, in the order they were recorded.
    ///
    /// # Errors
    ///
    /// Returns what [`EntryRecord::files`] returns.
    pub fn files(&self, kind: ShellKind) -> Result<Vec<PathBuf>, RecordError> {
        self.record.files(kind)
    }

    /// Records `files` for `kind`, beside what the record names already.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::files`] returns, and [`RecordError::Store`] when the record cannot be
    /// written.
    pub fn add(&self, kind: ShellKind, files: &[PathBuf]) -> Result<(), RecordError> {
        self.change(|entries| {
            for file in files {
                let entry = RecordedEntry {
                    shell: kind,
                    path: encoded(file),
                };
                if !entries.contains(&entry) {
                    entries.push(entry);
                }
            }
        })
    }

    /// Takes `file` out of what the record names for `kind`.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::add`] returns.
    pub fn forget(&self, kind: ShellKind, file: &Path) -> Result<(), RecordError> {
        let forgotten = RecordedEntry {
            shell: kind,
            path: encoded(file),
        };
        self.change(|entries| entries.retain(|entry| *entry != forgotten))
    }

    /// Reads the record, changes it and writes it back whole.
    fn change(&self, edit: impl FnOnce(&mut Vec<RecordedEntry>)) -> Result<(), RecordError> {
        let mut recorded = self.record.read()?;
        edit(&mut recorded.entries);
        let bytes = serde_json::to_vec(&recorded).map_err(|_| RecordError::NotARecord)?;
        kr_ipc::paths::write_owner_only_file(&self.record.path, &bytes)?;
        Ok(())
    }
}

/// A path as the record keeps it: its own bytes in hexadecimal, two digits to a byte.
#[cfg(unix)]
fn encoded(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;

    path.as_os_str()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A path as the record keeps it: its UTF-16 units in hexadecimal, four digits to a unit, so an
/// unpaired surrogate is kept as it is.
#[cfg(not(unix))]
fn encoded(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt as _;

    path.as_os_str()
        .encode_wide()
        .map(|unit| format!("{unit:04x}"))
        .collect()
}

/// The path a record entry names, or `None` for text [`encoded`] does not write.
#[cfg(unix)]
fn decoded(text: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    let bytes = hexadecimal_units(text, 2)?
        .into_iter()
        .map(|unit| u8::try_from(unit).ok())
        .collect::<Option<Vec<u8>>>()?;
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

/// The path a record entry names, or `None` for text [`encoded`] does not write.
#[cfg(not(unix))]
fn decoded(text: &str) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;

    let units = hexadecimal_units(text, 4)?
        .into_iter()
        .map(|unit| u16::try_from(unit).ok())
        .collect::<Option<Vec<u16>>>()?;
    Some(PathBuf::from(std::ffi::OsString::from_wide(&units)))
}

/// Reads text as units of `digits` lower-case hexadecimal digits each; `None` for anything else,
/// and for no units at all, which names no file.
fn hexadecimal_units(text: &str, digits: usize) -> Option<Vec<u32>> {
    if text.is_empty()
        || !text.len().is_multiple_of(digits)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    text.as_bytes()
        .chunks(digits)
        .map(|unit| u32::from_str_radix(std::str::from_utf8(unit).ok()?, 16).ok())
        .collect()
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

    /// Takes the lock for one startup file, kept in `locks` under a name made from where the file
    /// is, waiting for a holder that is still working.
    ///
    /// Nothing is written beside the startup file: the lock is the installation's own, in its own
    /// directory, and two installs of one file, whatever the link it was reached through, name the
    /// same lock because the name is made from the file the path resolves to.
    ///
    /// # Errors
    ///
    /// Returns the underlying failure, or a timeout when another writer held it throughout.
    fn take_for_startup_file(path: &Path, locks: &Path) -> std::io::Result<Self> {
        let name = lock_name(path)?;
        // The installation's state directory is the root, made this user's own like everything
        // under it, and the lock directory is inside it.
        kr_ipc::paths::create_private_tree(locks.parent().unwrap_or(locks), locks)
            .map_err(std::io::Error::other)?;
        Self::acquire(locks.join(format!("{name}.lock")), path)
    }

    /// Takes the lock for one startup file, waiting for a holder that is still working.
    ///
    /// # Errors
    ///
    /// Returns the underlying failure, or a timeout when another writer held it throughout.
    #[cfg(unix)]
    fn take(path: &Path) -> std::io::Result<Self> {
        Self::acquire(Self::beside(path)?, path)
    }

    /// Takes the lock held at `lock` on behalf of the file `path`.
    #[cfg(unix)]
    fn acquire(lock: PathBuf, path: &Path) -> std::io::Result<Self> {
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
        Self::acquire(Self::beside(path)?, path)
    }

    /// Takes the lock held at `lock` on behalf of the file `path`.
    #[cfg(not(unix))]
    fn acquire(lock: PathBuf, path: &Path) -> std::io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// What Windows says when another handle holds the file.
        const ERROR_SHARING_VIOLATION: i32 = 32;
        /// What it says when a region of it is locked.
        const ERROR_LOCK_VIOLATION: i32 = 33;

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
        // Closing the file is what releases the lock, and the empty file left in the
        // installation's own lock directory costs nothing.
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

/// Returns whether a file holds the entry that `placement` puts in it.
///
/// Each entry is found by its own markers: the entry that opens PowerShell's bridge is not the one
/// that checks its reader, and a file that holds one holds nothing of the other.
#[must_use]
pub fn installed(path: &Path, placement: &Placement) -> bool {
    let (begin, end) = placement.markers();
    read_or_empty(path).is_ok_and(|contents| strip(&contents, begin, end).is_some())
}

/// Returns whether a file holds any KalaReach entry, whichever of them it is, for what removes them
/// all.
#[must_use]
pub fn holds_an_entry(path: &Path) -> bool {
    read_or_empty(path).is_ok_and(|contents| {
        strip(&contents, MARKER_BEGIN, MARKER_END).is_some()
            || strip(&contents, CHECK_MARKER_BEGIN, CHECK_MARKER_END).is_some()
    })
}

/// Splits a file around its KalaReach entry: what comes before it, the entry itself, and what comes
/// after it.
///
/// A byte-order mark is the file's encoding and belongs to no line: an entry at the start of a file
/// that has one begins on the line after it, and is found there.
fn strip(contents: &str, marker_begin: &str, marker_end: &str) -> Option<(String, String, String)> {
    let (mark, text) = match contents.strip_prefix('\u{feff}') {
        Some(text) => ("\u{feff}", text),
        None => ("", contents),
    };
    // Whole lines, not text that happens to hold the marker. A person's own file can print the
    // marker, or talk about it, and neither is this host's entry: removing what stands between
    // two such lines would take their own configuration with it.
    let line_at = |from: usize, marker: &str| {
        let mut at = from;
        for line in text[from..].split_inclusive('\n') {
            if line.trim_end_matches(['\r', '\n']) == marker {
                return Some((at, at + line.len()));
            }
            at += line.len();
        }
        None
    };
    let (begin, _) = line_at(0, marker_begin)?;
    let (_, after) = line_at(begin, marker_end)?;
    Some((
        format!("{mark}{}", &text[..begin]),
        text[begin..after].to_owned(),
        text[after..].to_owned(),
    ))
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
        // nothing about the file the rename is about to replace. On Windows another program can
        // hold the file for a moment and the rename is tried again while it does, so the check is
        // made again before every attempt: the person can save the file while the rename waits.
        kr_flush::retry_while_held(|| {
            if read_or_empty(&target)? != expected
                || identity.is_some_and(|identity| stable_identity(&target) != Some(identity))
            {
                return Err(std::io::Error::other(
                    "the startup file changed while this entry was being written, so nothing was \
                     written",
                ));
            }
            std::fs::rename(&temporary, &target)
        })
    });
    if prepared.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    prepared
}

/// Returns the name of the lock that holds one startup file, a digest of where the file is.
///
/// Every way of reaching the file through links gives one name: a link at the file, a link at any
/// directory above it, and a path that spells a directory another way (`..`, `.`) all resolve to the
/// same place. A directory that is not there yet is resolved as far as it exists, so a first-time
/// setup that creates it names the lock of the file it is about to write. A name that differs only
/// in letter case on a filesystem that ignores it, and two mounts of one directory, are not unified;
/// the record every install and removal holds beforehand is what keeps those apart.
fn lock_name(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest as _, Sha256};

    let key = resolved_as_far_as_it_exists(&resolved(path)?)?;
    let digest = Sha256::digest(key.as_os_str().as_encoded_bytes());
    Ok(digest.iter().fold(String::new(), |mut name, byte| {
        name.push_str(&format!("{byte:02x}"));
        name
    }))
}

/// Returns `path` made absolute with every link in the part that exists followed and every `.` and
/// `..` resolved, and the rest, which is not there, spelled as it was given.
fn resolved_as_far_as_it_exists(path: &Path) -> std::io::Result<PathBuf> {
    use std::path::Component;

    let mut found = PathBuf::new();
    // Whether the walk has gone below what exists: from there on a component is only a name.
    let mut missing = false;
    let given;
    let path = if path.is_absolute() {
        path
    } else {
        given = std::env::current_dir()?.join(path);
        &given
    };
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                found.pop();
                // Back out of a directory that is not there is back on one that may be: what
                // follows is resolved again from here.
                match std::fs::canonicalize(&found) {
                    Ok(real) => {
                        found = real;
                        missing = false;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing = true,
                    Err(error) => return Err(error),
                }
            }
            Component::Normal(name) if !missing => {
                found.push(name);
                match std::fs::canonicalize(&found) {
                    Ok(real) => found = real,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing = true,
                    Err(error) => return Err(error),
                }
            }
            other => found.push(other.as_os_str()),
        }
    }
    Ok(found)
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

    /// Opens `file` with a handle that shares reading and writing but not its deletion, as a
    /// program that reads each file as it is written holds it.
    #[cfg(windows)]
    fn hold(file: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;

        /// Reading and writing are shared; deleting is not.
        const FILE_SHARE_READ_WRITE: u32 = 0x0001 | 0x0002;

        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ_WRITE)
            .open(file)
            .expect("the file is held")
    }

    /// Counts the renames refused as held on this thread while the guard stands. At the first of
    /// them, `meanwhile` is given the hold, and lets go of it when it drops it.
    #[cfg(windows)]
    fn at_the_first_refusal(
        holding: std::fs::File,
        meanwhile: impl FnOnce(std::fs::File) + 'static,
    ) -> (
        std::rc::Rc<std::cell::Cell<u32>>,
        kr_flush::testing::AfterHeldRefusal,
    ) {
        let refusals = std::rc::Rc::new(std::cell::Cell::new(0));
        let counted = std::rc::Rc::clone(&refusals);
        let mut first = Some((holding, meanwhile));
        let hook = kr_flush::testing::after_held_refusal(move || {
            counted.set(counted.get() + 1);
            if let Some((holding, meanwhile)) = first.take() {
                meanwhile(holding);
            }
        });
        (refusals, hook)
    }

    /// The names a directory holds.
    #[cfg(windows)]
    fn names_in(directory: &Path) -> Vec<String> {
        std::fs::read_dir(directory)
            .expect("lists the directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// On Windows a startup file that another program holds without sharing its deletion, as a
    /// scanner holds a file it has just seen, is replaced once that program lets go, and nothing
    /// is left beside it.
    #[cfg(windows)]
    #[test]
    fn a_held_startup_file_is_replaced_once_it_is_let_go() {
        let root = tempfile::tempdir().expect("a directory");
        let profile = root.path().join("profile.ps1");
        std::fs::write(&profile, "Set-Alias ll Get-ChildItem\n").expect("writes");
        let (refusals, guard) = at_the_first_refusal(hold(&profile), drop);
        let replaced = replace(
            &profile,
            "Set-Alias ll Get-ChildItem\n",
            "Set-Alias ll Get-ChildItem\n# the entry\n",
        );
        drop(guard);
        replaced.expect("replaced once it is let go");
        assert_eq!(refusals.get(), 1, "refused once while it was held");
        assert_eq!(
            std::fs::read_to_string(&profile).expect("reads"),
            "Set-Alias ll Get-ChildItem\n# the entry\n"
        );
        assert_eq!(names_in(root.path()), ["profile.ps1"]);
    }

    /// On Windows the check a replacement stands on, that the file is still what was read, is
    /// made again before every attempt: an edit saved while the held replacement waits is kept,
    /// the replacement says the file changed, and nothing is left beside it.
    #[cfg(windows)]
    #[test]
    fn a_startup_file_edited_while_its_replacement_waits_is_not_replaced() {
        let root = tempfile::tempdir().expect("a directory");
        let profile = root.path().join("profile.ps1");
        std::fs::write(&profile, "Set-Alias ll Get-ChildItem\n").expect("writes");
        let edited = profile.clone();
        let (refusals, guard) = at_the_first_refusal(hold(&profile), move |holding| {
            use std::io::Write as _;

            // The person's editor saves while the first attempt is refused.
            std::fs::OpenOptions::new()
                .append(true)
                .open(&edited)
                .and_then(|mut file| file.write_all(b"Set-Alias g git\n"))
                .expect("the person saves an edit");
            drop(holding);
        });
        let replaced = replace(
            &profile,
            "Set-Alias ll Get-ChildItem\n",
            "Set-Alias ll Get-ChildItem\n# the entry\n",
        );
        drop(guard);
        assert_eq!(refusals.get(), 1);
        let refused = replaced.expect_err("the file changed while the replacement waited");
        assert!(
            refused.to_string().contains("the startup file changed"),
            "{refused}"
        );
        assert_eq!(
            std::fs::read_to_string(&profile).expect("reads"),
            "Set-Alias ll Get-ChildItem\nSet-Alias g git\n",
            "the edit is kept"
        );
        assert_eq!(names_in(root.path()), ["profile.ps1"]);
    }

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
            !holds_an_entry(&path),
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
        )
        .expect("the path is text");
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Added
        );
        assert!(holds_an_entry(&path));
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
    ///
    /// It starts `/bin/bash`, which every Linux and macOS host this runs on has. A host without one
    /// fails here and says so, because a check that returned early would be counted as one that
    /// passed.
    #[cfg(unix)]
    #[test]
    fn a_shell_loads_the_integration_exactly_once() {
        let bash = Path::new("/bin/bash");
        assert!(
            bash.is_file(),
            "this host has no /bin/bash to start, so this check cannot run here"
        );
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
            // The shell is told where to record each load as text, so a path that is not text is
            // refused here rather than written as another path the count would never be read from.
            let told = loaded.to_str().unwrap_or_else(|| {
                panic!(
                    "{} is not UTF-8, so no shell can be told it",
                    loaded.display()
                )
            });
            std::fs::write(&package, format!("printf x >> '{told}'\n"))
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
                install(
                    &target.path,
                    &entry(&target, &package, false).expect("the path is text"),
                    &Placement::End,
                )
                .expect("installs");
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

    /// The record every test here writes through: the locks are in its directory, apart from the
    /// files under test.
    fn record() -> &'static EntryRecord {
        static RECORD: std::sync::OnceLock<(tempfile::TempDir, EntryRecord)> =
            std::sync::OnceLock::new();
        &RECORD
            .get_or_init(|| {
                let directory = tempfile::tempdir().expect("a directory");
                let record = EntryRecord::in_state_directory(&directory.path().join("state"));
                (directory, record)
            })
            .1
    }

    fn install(path: &Path, body: &str, placement: &Placement) -> std::io::Result<Change> {
        super::install(path, body, placement, record())
    }

    fn remove(path: &Path) -> std::io::Result<Change> {
        super::remove(path, record())
    }

    /// The PowerShell a test that places an entry in a profile asks, which is whichever one is on
    /// the path. A test that only reads what an entry contains never starts it.
    fn a_powershell() -> PathBuf {
        powershell_on_path().unwrap_or_else(|| PathBuf::from("pwsh"))
    }

    /// Where the entry that opens the bridge goes, for a test that places one.
    fn after_the_prologue() -> Placement {
        Placement::AfterPrologue {
            shell: a_powershell(),
        }
    }

    /// Where the entry that checks the reader goes, for a test that places one.
    fn at_the_last() -> Placement {
        Placement::Last {
            shell: a_powershell(),
        }
    }

    /// A target for one shell, for the tests that only care what an entry contains.
    ///
    /// PowerShell's is the one that opens the bridge, after the prologue of the first profile; the
    /// other shells' go last.
    fn for_shell(kind: ShellKind) -> StartupTarget {
        StartupTarget {
            kind,
            path: PathBuf::from("/tmp/startup"),
            reason: "a test",
            shared: false,
            placement: if kind == ShellKind::PowerShell {
                after_the_prologue()
            } else {
                Placement::End
            },
        }
    }

    #[test]
    fn a_second_writer_waits_for_the_first_and_neither_loses_its_entry() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "export EDITOR=vim\n").expect("writes");

        // A lock is taken for the whole read-rebuild-write, so a writer that is not this process
        // is kept out rather than racing the rename.
        let locks = record().lock_directory();
        let held = FileLock::take_for_startup_file(&path, &locks).expect("takes the lock");
        assert!(
            std::fs::read_dir(&locks)
                .expect("the lock directory")
                .count()
                >= 1,
            "the lock is in the installation's own directory"
        );
        // A second attempt waits for the first and gives up rather than writing beside it.
        let refused =
            FileLock::take_for_startup_file(&path, &locks).expect_err("one writer at a time");
        assert_eq!(refused.kind(), std::io::ErrorKind::TimedOut);
        drop(held);
        // The name stays where a waiter can be holding the same file open; what the drop releases
        // is the kernel's lock, which the next writer takes at once.
        let after = FileLock::take_for_startup_file(&path, &locks)
            .expect("the next writer takes it straight away");
        drop(after);

        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        )
        .expect("the path is text");
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Added
        );
        assert!(
            std::fs::read_to_string(&path)
                .expect("reads")
                .starts_with("export EDITOR=vim"),
            "the user's own line is still first"
        );
    }

    /// KR-REQ-26.05: two ways of reaching one startup file are one lock, so two installs through
    /// them cannot write the file at once and lose an entry.
    #[cfg(unix)]
    #[test]
    fn every_way_of_reaching_a_startup_file_names_one_lock() {
        let root = tempfile::tempdir().expect("a directory");
        let real = root.path().join("dotfiles");
        std::fs::create_dir(&real).expect("a directory");
        std::fs::write(real.join(".zshrc"), "export EDITOR=vim\n").expect("writes");
        // The home's own directory is a link to the checkout.
        let linked = root.path().join("home");
        std::os::unix::fs::symlink(&real, &linked).expect("links the directory");
        // And the file is a link of its own, in a directory that is a link to another.
        let other = root.path().join("other");
        std::fs::create_dir(&other).expect("a directory");
        std::os::unix::fs::symlink(real.join(".zshrc"), other.join(".zshrc")).expect("links");
        let through_other = root.path().join("alias");
        std::os::unix::fs::symlink(&other, &through_other).expect("links the directory");

        let by_real = lock_name(&real.join(".zshrc")).expect("a name");
        for alias in [
            linked.join(".zshrc"),
            other.join(".zshrc"),
            through_other.join(".zshrc"),
            real.join("../dotfiles/.zshrc"),
        ] {
            assert_eq!(
                lock_name(&alias).expect("a name"),
                by_real,
                "{} is the same file and takes another lock",
                alias.display()
            );
        }
        // A directory that is not there yet is resolved as far as it exists.
        let before = lock_name(&linked.join("config/profile.ps1")).expect("a name");
        std::fs::create_dir(real.join("config")).expect("a directory");
        assert_eq!(
            lock_name(&real.join("config/profile.ps1")).expect("a name"),
            before,
            "the lock of a file in a directory that was not there changes when it is made"
        );
        // A `..` after a directory that is not there is still a step back out of it.
        assert_eq!(
            lock_name(&linked.join("config/../config/profile.ps1")).expect("a name"),
            before,
            "a `..` below a missing directory was dropped"
        );
        assert_eq!(
            lock_name(&linked.join("not-there/../.zshrc")).expect("a name"),
            by_real,
            "a missing directory and its `..` changed the file's lock"
        );
        // A link met after a missing directory is followed when the `..` has gone back out of it.
        let alias = root.path().join("alias-to-dotfiles");
        std::os::unix::fs::symlink(&real, &alias).expect("links the directory");
        assert_eq!(
            lock_name(&root.path().join("missing/../alias-to-dotfiles/.zshrc")).expect("a name"),
            by_real,
            "a link after a missing directory and its `..` was not followed"
        );
        // And a different file is a different lock.
        assert_ne!(lock_name(&real.join(".bashrc")).expect("a name"), by_real);
    }

    /// KR-REQ-07.29: a first-time setup creates the directory and still takes a lock in it.
    #[test]
    fn a_profile_in_a_directory_that_is_not_there_yet_is_written_under_a_lock() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join("config/powershell/profile.ps1");
        let locks = record().lock_directory();
        let held = FileLock::take_for_startup_file(&path, &locks).expect("takes the lock");
        assert!(
            !path.parent().expect("a directory").exists(),
            "a lock in a directory of the person's home is never what makes the directory"
        );
        drop(held);

        let body = entry(
            &for_shell(ShellKind::PowerShell),
            Path::new("/opt/kr/entry.ps1"),
            false,
        )
        .expect("the path is text");
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Added
        );
        assert!(holds_an_entry(&path));
    }

    /// KR-REQ-07.23: every shell's entry but PowerShell's opening one is the last thing in the file,
    /// and a second install is no change.
    ///
    /// The other shells have their reader with the shell itself, and their entry says after the
    /// user's configuration that the hooks are live.
    #[test]
    fn the_entries_of_the_other_shells_go_last() {
        let root = tempfile::tempdir().expect("a directory");
        let theirs = "export EDITOR=vim\nread -r name\n";
        for (kind, file) in [
            (ShellKind::Zsh, ".zshrc"),
            (ShellKind::Bash, ".bashrc"),
            (ShellKind::Fish, "config.fish"),
        ] {
            let path = root.path().join(file);
            std::fs::write(&path, theirs).expect("writes");
            let target = for_shell(kind);
            let body = entry(&target, Path::new("/opt/kr/entry"), false).expect("the path is text");
            assert_eq!(
                install(&path, &body, &target.placement).expect("installs"),
                Change::Added
            );
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                format!("{theirs}{body}"),
                "{kind:?}"
            );
            assert_eq!(
                install(&path, &body, &target.placement).expect("installs"),
                Change::Unchanged,
                "{kind:?}: a second install is no change"
            );
            assert_eq!(remove(&path).expect("removes"), Change::Removed);
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                theirs,
                "{kind:?}"
            );
        }
    }

    /// KR-REQ-07.23: PowerShell's opening entry is the first thing in a profile with no prologue,
    /// and an entry an earlier install put at the end is moved there.
    ///
    /// The entry loads the module that opens the bridge, so a profile that asks a question ahead of
    /// it would ask a shell the session does not yet take input for.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn a_powershell_entry_goes_first_in_a_profile_with_no_prologue() {
        let root = tempfile::tempdir().expect("a directory");
        let theirs = "# my profile\n$env:EDITOR = 'vim'\nRead-Host 'name'\n";
        let target = for_shell(ShellKind::PowerShell);
        let body = entry(&target, Path::new("/opt/kr/entry"), false).expect("the path is text");
        let path = root.path().join("profile.ps1");
        std::fs::write(&path, theirs).expect("writes");
        assert_eq!(
            install(&path, &body, &target.placement).expect("installs"),
            Change::Added
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            format!("{body}{theirs}")
        );
        assert_eq!(
            install(&path, &body, &target.placement).expect("installs"),
            Change::Unchanged,
            "a second install is no change"
        );
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(std::fs::read_to_string(&path).expect("reads"), theirs);

        // An entry an earlier install left at the end moves to the start, with the user's lines in
        // the order they wrote them.
        let earlier = root.path().join("earlier.ps1");
        std::fs::write(&earlier, theirs).expect("writes");
        assert_eq!(
            install(&earlier, &body, &Placement::End).expect("installs"),
            Change::Added
        );
        assert_eq!(
            install(&earlier, &body, &target.placement).expect("moves"),
            Change::Replaced
        );
        assert_eq!(
            std::fs::read_to_string(&earlier).expect("reads"),
            format!("{body}{theirs}")
        );
    }

    /// Returns the parse errors PowerShell itself reports for a profile's text, by identifier.
    #[cfg(unix)]
    fn parse_errors_of(text: &str) -> Vec<String> {
        let directory = tempfile::tempdir().expect("a directory");
        let file = directory.path().join("profile.ps1");
        std::fs::write(&file, text.trim_start_matches('\u{feff}')).expect("writes");
        let asked = std::process::Command::new(powershell_on_path().expect("a PowerShell"))
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$t = $null; $e = $null; \
                 $null = [System.Management.Automation.Language.Parser]::ParseInput(\
                     [System.IO.File]::ReadAllText($env:KR_PROFILE), [ref]$t, [ref]$e); \
                 $e | ForEach-Object { $_.ErrorId }",
            ])
            .env("KR_PROFILE", &file)
            .output()
            .expect("PowerShell runs");
        let mut found = String::from_utf8_lossy(&asked.stdout)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        found.sort();
        found
    }

    /// Runs a profile as PowerShell would, and returns what each statement of it and each entry
    /// recorded, in the order they ran.
    ///
    /// Every statement of a test profile records its own name in `$global:order`, and the package
    /// entry the profile's entry sources records `entry`. This is the judge that does not look at
    /// the text at all: it is what a shell that read the profile did.
    #[cfg(unix)]
    fn what_ran(text: &str) -> String {
        let directory = tempfile::tempdir().expect("a directory");
        let file = directory.path().join("profile.ps1");
        std::fs::write(&file, text.trim_start_matches('\u{feff}')).expect("writes");
        let asked = std::process::Command::new(powershell_on_path().expect("a PowerShell"))
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$global:order = @(); . $env:KR_PROFILE; $global:order -join ','",
            ])
            .env("KR_PROFILE", &file)
            .output()
            .expect("PowerShell runs");
        String::from_utf8_lossy(&asked.stdout).trim().to_owned()
    }

    /// The entry that opens the bridge, sourcing a package file that records `entry` when it runs.
    #[cfg(unix)]
    fn recording_entry(directory: &Path) -> String {
        let package = directory.join("entry.ps1");
        std::fs::write(&package, "$global:order += 'entry'\n").expect("writes");
        entry(&for_shell(ShellKind::PowerShell), &package, false).expect("the path is text")
    }

    /// KR-REQ-07.23: the PowerShell entry that opens the bridge runs before every statement of the
    /// profile and changes what none of them does, whatever the profile begins with.
    ///
    /// The judge is what a shell that reads the profile does, not what the text looks like: each
    /// statement records its name as it runs, so the order the entry and the person's statements ran
    /// in, before and after, says whether the entry landed between whole statements. Each profile
    /// here is valid PowerShell in a shape a line scan gets wrong: a parenthesis in a string or a
    /// comment inside a `param` block, attributes stacked above it or on a line of their own, a tab
    /// after `using`, a `using module` whose hashtable runs over several lines, and a here-string
    /// holding a parenthesis. A fresh install and an entry moved from the end land in the same place.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn a_powershell_entry_runs_before_the_profile_and_changes_nothing_it_does() {
        let root = tempfile::tempdir().expect("a directory");
        let target = for_shell(ShellKind::PowerShell);
        let body = recording_entry(root.path());
        let user = "$global:order += 'user'\n";
        for (name, theirs) in [
            (
                "quoted parenthesis",
                format!("param(\n  [string]$Name = ')',\n  [string]$Other = 'x'\n)\n{user}"),
            ),
            (
                "commented parenthesis",
                format!("param(\n  # )\n  $a\n)\n{user}"),
            ),
            (
                "attribute and param on stacked lines",
                format!("[CmdletBinding()]\n[OutputType([string])]\n\n# why\nparam()\n{user}"),
            ),
            (
                "another attribute first",
                format!(
                    "[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoid', '')]\nparam()\n{user}"
                ),
            ),
            (
                "tab after using",
                format!("using\tnamespace System\n{user}"),
            ),
            (
                "a comment after using",
                format!("using namespace System # note\n{user}"),
            ),
            (
                "a semicolon after using",
                format!("using namespace System;\n{user}"),
            ),
            (
                "using a module by hashtable",
                format!(
                    "using module @{{\n  ModuleName = 'Microsoft.PowerShell.Utility'\n  ModuleVersion = '1.0'\n}}\n{user}"
                ),
            ),
            (
                "here-string with a parenthesis",
                format!("param(\n  $a = @'\n)\n'@\n)\n{user}"),
            ),
            (
                "a block comment after param",
                format!("param() <# note #>\n{user}"),
            ),
            (
                "a statement over several lines",
                format!("$global:order += 'a'; $global:order += (\n  'b'\n)\n{user}"),
            ),
            ("only statements", user.to_owned()),
            (
                "a byte-order mark and statements",
                format!("\u{feff}{user}"),
            ),
            (
                "crlf line ends",
                "using namespace System\r\n$global:order += 'user'\r\n".to_owned(),
            ),
        ] {
            let ran_before = what_ran(&theirs);
            let errors_before = parse_errors_of(&theirs);
            let path = root.path().join(format!("{}.ps1", name.replace(' ', "-")));
            std::fs::write(&path, &theirs).expect("writes");
            install(&path, &body, &target.placement).expect("installs");
            let written = std::fs::read_to_string(&path).expect("reads");
            assert_eq!(
                parse_errors_of(&written),
                errors_before,
                "{name}:\n{written}"
            );
            assert_eq!(
                what_ran(&written),
                format!("entry,{ran_before}")
                    .trim_end_matches(',')
                    .to_owned(),
                "{name}: the entry runs first and everything after it runs as it did:\n{written}"
            );

            // An entry an earlier install left at the end moves, and lands where a new one does.
            let earlier = root
                .path()
                .join(format!("{}-earlier.ps1", name.replace(' ', "-")));
            std::fs::write(&earlier, &theirs).expect("writes");
            install(&earlier, &body, &Placement::End).expect("installs");
            install(&earlier, &body, &target.placement).expect("moves");
            assert_eq!(
                std::fs::read_to_string(&earlier).expect("reads"),
                written,
                "{name}: a moved entry lands where a new one does"
            );

            // And removal gives back the person's own bytes.
            assert_eq!(remove(&path).expect("removes"), Change::Removed);
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                theirs,
                "{name}: removal did not give the profile back"
            );
        }
    }

    /// KR-REQ-07.23: a profile an entry cannot be put into without moving or swallowing something of
    /// the person's is refused by name and left exactly as it was.
    ///
    /// The line a profile's `using` statements or `param` block end on is the one an entry cannot be
    /// put in the middle of, so a statement that shares it is refused: it would run before the bridge
    /// if the entry went after it, and the entry would land inside it if the statement went on over
    /// the next lines. A profile that is signed, and one with a carriage return alone for a line end,
    /// are refused for what an entry would do to them, at the end of the file as at its start. A
    /// profile whose last statement is open at the end of the file already has a parse error and does
    /// not run, so an entry that goes at the end of one is held to adding none.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn a_profile_an_entry_cannot_be_put_into_whole_is_refused_by_name_and_left_as_it_was() {
        let root = tempfile::tempdir().expect("a directory");
        let target = for_shell(ShellKind::PowerShell);
        let body = recording_entry(root.path());
        let last = Placement::Last {
            shell: a_powershell(),
        };
        let checking = entry(
            &StartupTarget {
                placement: last.clone(),
                ..for_shell(ShellKind::PowerShell)
            },
            Path::new("/opt/kr/entry"),
            false,
        )
        .expect("the path is text");
        for (name, theirs, why, placement, body) in [
            (
                "a prompt on the prologue's line",
                "param() ; Read-Host 'name'\n".to_owned(),
                "a statement shares the line",
                &target.placement,
                &body,
            ),
            (
                "a pipeline that runs on",
                "using namespace System; Get-ChildItem |\n  Select-Object -First 1\n".to_owned(),
                "a statement shares the line",
                &target.placement,
                &body,
            ),
            (
                "a key handler that runs on",
                "using namespace System.Management.Automation; Set-PSReadLineKeyHandler -Key Tab -ScriptBlock {\n  param($key, $arg)\n}\n".to_owned(),
                "a statement shares the line",
                &target.placement,
                &body,
            ),
            (
                "a function that runs on",
                "using namespace System; function Get-Mine {\n  1\n}\n".to_owned(),
                "a statement shares the line",
                &target.placement,
                &body,
            ),
            (
                "an array that runs on",
                "param() ; $a = @(\n  1\n  2\n)\n".to_owned(),
                "a statement shares the line",
                &target.placement,
                &body,
            ),
            (
                "a comment that runs over the line end",
                "using namespace System <# a\nb #>\n$x = 1\n".to_owned(),
                "a comment or a string runs over",
                &target.placement,
                &body,
            ),
            (
                "a signed profile",
                "$x = 1\n# SIG # Begin signature block\n# MIIx\n# SIG # End signature block\n".to_owned(),
                "it is signed",
                &target.placement,
                &body,
            ),
            (
                "a carriage return alone for a line end",
                "using namespace System\r$x = 1\r".to_owned(),
                "a carriage return alone",
                &target.placement,
                &body,
            ),
            (
                "a signed profile at the end",
                "$x = 1\n# SIG # Begin signature block\n# MIIx\n# SIG # End signature block\n".to_owned(),
                "it is signed",
                &last,
                &checking,
            ),
        ] {
            let path = root.path().join(format!("{}.ps1", name.replace(' ', "-")));
            std::fs::write(&path, &theirs).expect("writes");
            let refused = install(&path, body, placement)
                .expect_err(&format!("{name}: the entry was written"));
            let said = refused.to_string();
            assert!(
                said.contains("cannot take the entry") && said.contains(why) && said.contains("nothing was written"),
                "{name}: the refusal says what and why: {said}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                theirs,
                "{name}: the profile was touched"
            );
            assert!(
                plan(&path, body, placement).is_err(),
                "{name}: a dry run says what a real one does"
            );
        }
    }

    /// KR-REQ-07.23: a profile whose `using` statements or `param` block end on its last line, with no
    /// line end after it, is held to the same rule as one with a line end: a statement that shares
    /// the line is refused, and nothing is written.
    ///
    /// The entry goes after the file, so a statement on that line would run before the bridge opens
    /// and could end the profile before the entry runs at all. Whether anything follows the prologue
    /// on its line is asked of the parser whatever the file ends with.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn a_statement_on_the_prologues_last_line_is_refused_when_the_file_has_no_final_line_end() {
        let root = tempfile::tempdir().expect("a directory");
        let target = for_shell(ShellKind::PowerShell);
        let body = recording_entry(root.path());
        for (name, theirs) in [
            ("a prompt after param", "param() ; Read-Host 'name'"),
            (
                "a prompt after using",
                "using namespace System; Read-Host 'name'",
            ),
            (
                "a prompt on the line of the second using",
                "using namespace System\nusing namespace System.IO; Read-Host 'name'",
            ),
            ("a return after param", "param(); return"),
            (
                "a prompt after a separator that is not a line end",
                "param()\u{2028}Read-Host 'name'",
            ),
        ] {
            let path = root.path().join(format!("{}.ps1", name.replace(' ', "-")));
            std::fs::write(&path, theirs).expect("writes");
            let refused = install(&path, &body, &target.placement)
                .expect_err(&format!("{name}: the entry was written"));
            assert!(
                refused.to_string().contains("a statement shares the line"),
                "{name}: {refused}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                theirs,
                "{name}: the profile was touched"
            );
        }
        // The control: nothing but whitespace, a semicolon or a comment after the prologue is the
        // entry's to follow, and it goes on a line of its own.
        for (name, theirs) in [
            ("a comment after param", "param() # note"),
            ("a semicolon after using", "using namespace System;"),
        ] {
            let path = root.path().join(format!("{}.ps1", name.replace(' ', "-")));
            std::fs::write(&path, theirs).expect("writes");
            install(&path, &body, &target.placement)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                format!("{theirs}\n{body}"),
                "{name}"
            );
        }
    }

    /// KR-REQ-07.23: the check of a profile with the entry in it proves where the entry sits as well
    /// as that it is whole: the entry that opens the bridge comes before every statement of the
    /// profile, and the entry that checks the reader after every one.
    ///
    /// A check that only found the entry whole would accept an entry put after a statement that runs
    /// first or before one that has to come first, whatever placed it there.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn the_check_of_a_profile_proves_where_its_entry_sits() {
        let package = Path::new("/opt/kr/entry");
        let load = entry(&for_shell(ShellKind::PowerShell), package, false).expect("text");
        let check = entry(
            &StartupTarget {
                placement: at_the_last(),
                ..for_shell(ShellKind::PowerShell)
            },
            package,
            false,
        )
        .expect("text");
        let first = after_the_prologue();
        let last = at_the_last();
        for (name, old, new, placement, body, refused) in [
            (
                "a prompt before the load entry",
                "param() ; Read-Host 'name'\n".to_owned(),
                format!("param() ; Read-Host 'name'\n{load}"),
                &first,
                &load,
                true,
            ),
            (
                "the load entry after every statement",
                "$x = 1\n".to_owned(),
                format!("$x = 1\n{load}"),
                &first,
                &load,
                true,
            ),
            (
                "the load entry first",
                "$x = 1\n".to_owned(),
                format!("{load}$x = 1\n"),
                &first,
                &load,
                false,
            ),
            (
                "the load entry below the prologue",
                "using namespace System\n$x = 1\n".to_owned(),
                format!("using namespace System\n{load}$x = 1\n"),
                &first,
                &load,
                false,
            ),
            (
                "the check entry before a statement",
                "$x = 1\n".to_owned(),
                format!("{check}$x = 1\n"),
                &last,
                &check,
                true,
            ),
            (
                "the check entry last",
                "$x = 1\n".to_owned(),
                format!("$x = 1\n{check}"),
                &last,
                &check,
                false,
            ),
            (
                "a statement that differs by a character nobody sees",
                "'ab'\n".to_owned(),
                format!("{load}'a\u{ad}b'\n"),
                &first,
                &load,
                true,
            ),
        ] {
            let _ = body;
            let said = entry_refused(old.as_str(), new.as_str(), placement)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                said.is_some(),
                refused,
                "{name}: the check said {said:?}\n{new}"
            );
            if refused && !name.contains("nobody sees") {
                assert!(
                    said.as_deref()
                        .is_some_and(|why| why.contains("before the entry")
                            || why.contains("after the entry")),
                    "{name}: the refusal says which way: {said:?}"
                );
            }
        }
    }

    /// KR-REQ-07.23: an entry that would make PowerShell report fewer errors than the profile has is
    /// refused too: a profile that does not run is not one the entry may start running.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn an_entry_that_would_end_a_parse_error_the_profile_has_is_refused() {
        let root = tempfile::tempdir().expect("a directory");
        let package = Path::new("/opt/kr/entry");
        let load = entry(&for_shell(ShellKind::PowerShell), package, false).expect("text");
        let check = entry(
            &StartupTarget {
                placement: at_the_last(),
                ..for_shell(ShellKind::PowerShell)
            },
            package,
            false,
        )
        .expect("text");
        let last = at_the_last();
        let first = after_the_prologue();
        for (name, theirs, placement, body) in [
            (
                "a value the entry would become",
                "$global:order += 'user'\n$x =\n",
                &last,
                &check,
            ),
            (
                "named blocks after an error",
                "param()\nbegin { 1 }\nend { 2 }\n$global:order += 'tail'\n",
                &first,
                &load,
            ),
            (
                "a continuation at the end",
                "$global:order += 'user' `",
                &last,
                &check,
            ),
        ] {
            let path = root.path().join(format!("{}.ps1", name.replace(' ', "-")));
            std::fs::write(&path, theirs).expect("writes");
            let refused = install(&path, body, placement)
                .expect_err(&format!("{name}: the entry was written"));
            assert!(
                refused.to_string().contains("which errors"),
                "{name}: {refused}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                theirs,
                "{name}: the profile was touched"
            );
        }
    }

    /// KR-REQ-07.23: a profile that begins with two byte-order marks is refused by name, at the start
    /// of the file and at its end, and left as it was.
    ///
    /// The first mark is the file's encoding, and the second would be read as part of the first
    /// token, so PowerShell already fails on such a file; an entry's offsets would also be one
    /// character short.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn a_profile_with_two_byte_order_marks_is_refused_by_name() {
        let root = tempfile::tempdir().expect("a directory");
        let package = Path::new("/opt/kr/entry");
        let load = entry(&for_shell(ShellKind::PowerShell), package, false).expect("text");
        let check = entry(
            &StartupTarget {
                placement: at_the_last(),
                ..for_shell(ShellKind::PowerShell)
            },
            package,
            false,
        )
        .expect("text");
        let theirs = "\u{feff}\u{feff}param()\n$global:order += 'user'\n";
        for (name, placement, body) in [
            ("the start", after_the_prologue(), &load),
            ("the end", at_the_last(), &check),
        ] {
            let path = root.path().join(format!("{name}.ps1"));
            std::fs::write(&path, theirs).expect("writes");
            let refused = install(&path, body, &placement)
                .expect_err(&format!("{name}: the entry was written"));
            assert!(
                refused.to_string().contains("second byte-order mark")
                    && refused.to_string().contains("nothing was written"),
                "{name}: {refused}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                theirs,
                "{name}: the profile was touched"
            );
        }
    }

    /// What a PowerShell signer adds to a script: a line end of its own, then the signature block.
    #[cfg(unix)]
    const SIGNER_BLOCK: &str =
        "\r\n# SIG # Begin signature block\r\n# MIIx\r\n# SIG # End signature block\r\n";

    /// KR-REQ-07.23: a signed profile is never changed, in either placement, and the refusal names
    /// the signature.
    ///
    /// What PowerShell reads as a signature, and where one leaves the text it signs, are PowerShell's
    /// own rules, and every attempt to follow them (an entry already in place left alone, an entry
    /// placed before the block) is a way of writing into a profile whose signature the host
    /// mistook. So the rule is the simplest one: a profile that holds the words of a signature block,
    /// in any case, is refused, with the entries it already holds in it, with an entry in the wrong
    /// place, with the words in a string, and with the words inside the lines of the entry an install
    /// would replace; nothing is written, and a dry run says what a real run does.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn a_signed_profile_is_never_changed() {
        let root = tempfile::tempdir().expect("a directory");
        let package = Path::new("/opt/kr/entry");
        let first = after_the_prologue();
        let last = at_the_last();
        let load = entry(&for_shell(ShellKind::PowerShell), package, false).expect("text");
        let check = entry(
            &StartupTarget {
                placement: last.clone(),
                ..for_shell(ShellKind::PowerShell)
            },
            package,
            false,
        )
        .expect("text");
        let both = format!("using namespace System\n{load}$x = 1\n{check}");
        // A profile put to install and to a dry run is refused by name, and is as it was.
        let refused_and_untouched =
            |name: &str, theirs: &str, placement: &Placement, body: &str| {
                let path = root
                    .path()
                    .join(format!("{}.ps1", name.replace([' ', '\''], "-")));
                std::fs::write(&path, theirs).expect("writes");
                let refused = install(&path, body, placement)
                    .expect_err(&format!("{name}: a signed profile was written to"));
                assert!(
                    refused.to_string().contains("it is signed")
                        && refused.to_string().contains("nothing was written"),
                    "{name}: the refusal names the signature: {refused}"
                );
                assert!(
                    plan(&path, body, placement).is_err(),
                    "{name}: a dry run says what a real one does"
                );
                assert_eq!(
                    std::fs::read_to_string(&path).expect("reads"),
                    theirs,
                    "{name}: the profile was touched"
                );
            };
        for (name, theirs) in [
            (
                "signed with no entry",
                format!("using namespace System\n$x = 1\n{SIGNER_BLOCK}"),
            ),
            (
                "signed after both entries were written",
                format!("{both}{SIGNER_BLOCK}"),
            ),
            (
                "signed with the entries in the wrong place",
                format!("Read-Host 'name'\n{load}$x = 1\n{check}Read-Host 'again'\n{SIGNER_BLOCK}"),
            ),
            (
                "an entry the parser's own errors hide",
                format!("class KrDerived : KrBase {{}}\nRead-Host 'name'\n{load}{SIGNER_BLOCK}"),
            ),
            (
                "a profile with errors of its own",
                format!("class KrBroken {{\n{SIGNER_BLOCK}"),
            ),
            (
                "the words in another case",
                "Get-Date\n# sig # begin signature block\n# MIIx\n".to_owned(),
            ),
            (
                "the words in a comment that only starts with them",
                "Get-Date\n# SIG # Begin signature block # explanation\n".to_owned(),
            ),
            (
                "the words in a here-string",
                "$example = @'\n# SIG # Begin signature block\n'@\n".to_owned(),
            ),
            (
                "a block inside a function",
                format!("function Get-Later {{\n'x'\n{check}{SIGNER_BLOCK}}}\n"),
            ),
        ] {
            for (placement, body) in [(&first, &load), (&last, &check)] {
                refused_and_untouched(name, &theirs, placement, body);
            }
        }
        // The words are looked for in the file as it was read, and not in what is left of it when the
        // entry an install replaces is cut out: an entry's own lines can hold the block, and a begin
        // line with no end line takes the block and the text before it into the cut.
        for (name, theirs, placement, body) in [
            (
                "the words inside the entry that opens the bridge",
                format!("$x = 1\n{MARKER_BEGIN}\n{SIGNER_BLOCK}{MARKER_END}\n"),
                &first,
                &load,
            ),
            (
                "the words inside the entry that checks the reader",
                format!("$x = 1\n{CHECK_MARKER_BEGIN}\n{SIGNER_BLOCK}{CHECK_MARKER_END}\n"),
                &last,
                &check,
            ),
            (
                "a begin line of the entry that opens the bridge, the block, and a whole entry",
                format!("$x = 1\n{MARKER_BEGIN}\n$y = 2{SIGNER_BLOCK}{load}"),
                &first,
                &load,
            ),
            (
                "a begin line of the entry that checks the reader, the block, and a whole entry",
                format!("$x = 1\n{CHECK_MARKER_BEGIN}\n$y = 2{SIGNER_BLOCK}{check}"),
                &last,
                &check,
            ),
        ] {
            refused_and_untouched(name, &theirs, placement, body);
        }
        // The controls: the lines of an entry that hold no signature are replaced like any entry, and
        // an ordinary profile takes both entries, so what refuses the files above is the words.
        let path = root.path().join("replaced-load.ps1");
        std::fs::write(
            &path,
            format!("$x = 1\n{MARKER_BEGIN}\nGet-Date\n{MARKER_END}\n"),
        )
        .expect("writes");
        assert_eq!(
            install(&path, &load, &first).expect("replaces"),
            Change::Replaced
        );
        let path = root.path().join("replaced-check.ps1");
        std::fs::write(
            &path,
            format!("$x = 1\n{CHECK_MARKER_BEGIN}\nGet-Date\n{CHECK_MARKER_END}\n"),
        )
        .expect("writes");
        assert_eq!(
            install(&path, &check, &last).expect("replaces"),
            Change::Replaced
        );
        let path = root.path().join("unsigned.ps1");
        std::fs::write(&path, "using namespace System\n$x = 1\n").expect("writes");
        assert_eq!(
            install(&path, &load, &first).expect("installs"),
            Change::Added
        );
        assert_eq!(
            install(&path, &check, &last).expect("installs"),
            Change::Added
        );
        assert_eq!(std::fs::read_to_string(&path).expect("reads"), both);
    }

    /// KR-REQ-07.23: whether a file holds an entry is asked of the markers of the entry in question:
    /// the entry that opens the bridge is not the entry that checks the reader.
    #[test]
    fn a_file_holds_the_entry_whose_markers_it_has_and_not_the_other() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join("profile.ps1");
        let load = format!("{MARKER_BEGIN}\nImport-Module x\n{MARKER_END}\n");
        let check =
            format!("{CHECK_MARKER_BEGIN}\nConfirm-KalaReachReadLine\n{CHECK_MARKER_END}\n");
        let first = Placement::AfterPrologue {
            shell: PathBuf::from("pwsh"),
        };
        let last = Placement::Last {
            shell: PathBuf::from("pwsh"),
        };
        std::fs::write(&path, format!("Get-Date\n{load}")).expect("writes");
        assert!(installed(&path, &first) && installed(&path, &Placement::End));
        assert!(!installed(&path, &last), "the load entry is not the check");
        assert!(holds_an_entry(&path));
        std::fs::write(&path, format!("Get-Date\n{check}")).expect("writes");
        assert!(installed(&path, &last));
        assert!(!installed(&path, &first) && !installed(&path, &Placement::End));
        assert!(holds_an_entry(&path));
        std::fs::write(&path, "Get-Date\n").expect("writes");
        assert!(!holds_an_entry(&path));
    }

    /// KR-REQ-07.23: the two PowerShell entries differ by what they do. The one after the prologue
    /// of the first profile loads the module that opens the bridge, and the one at the end of the
    /// last profile asks the module whether the reader it went in front of is still the one the
    /// host calls, which is a question only the end of the last profile can put.
    #[test]
    fn the_powershell_entry_at_the_start_loads_the_bridge_and_the_one_at_the_end_checks_the_reader()
    {
        let mut check = for_shell(ShellKind::PowerShell);
        check.placement = at_the_last();
        let package = Path::new("/opt/kr/entry");

        let loading =
            entry(&for_shell(ShellKind::PowerShell), package, false).expect("the path is text");
        assert!(loading.contains("Test-Path") && loading.contains("/opt/kr/entry"));
        assert!(!loading.contains("Confirm-KalaReachReadLine"));
        let checking = entry(&check, package, false).expect("the path is text");
        assert!(checking.contains("Confirm-KalaReachReadLine"));
        assert!(
            !checking.contains("/opt/kr/entry"),
            "the check copies nothing of the package and names none of it: {checking}"
        );
    }

    /// KR-REQ-07.23: the entry that checks the reader is the last thing in its profile after an
    /// upgrade too, where an earlier install had put the entry that opens the bridge at the start of
    /// that same profile.
    ///
    /// The two entries have markers of their own, so the check is added at the end and does not take
    /// the old entry's place at the start, where it would run before the rest of the profile had
    /// changed anything. The old entry loads the module a second time, which does nothing, and
    /// removal takes out both.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn the_check_entry_goes_to_the_end_of_a_profile_an_earlier_install_put_the_load_entry_at_the_start_of()
     {
        let root = tempfile::tempdir().expect("a directory");
        let mut check = for_shell(ShellKind::PowerShell);
        check.placement = at_the_last();
        let package = Path::new("/opt/kr/entry");
        let loading =
            entry(&for_shell(ShellKind::PowerShell), package, false).expect("the path is text");
        let checking = entry(&check, package, false).expect("the path is text");
        let theirs = "$env:EDITOR = 'vim'\nfunction PSConsoleHostReadLine { 'theirs' }\n";
        let path = root.path().join("Microsoft.PowerShell_profile.ps1");
        std::fs::write(&path, format!("{loading}{theirs}")).expect("writes");

        assert_eq!(
            install(&path, &checking, &check.placement).expect("installs"),
            Change::Added
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            format!("{loading}{theirs}{checking}"),
            "the check is after everything the person wrote"
        );
        assert_eq!(
            install(&path, &checking, &check.placement).expect("installs"),
            Change::Unchanged
        );
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(std::fs::read_to_string(&path).expect("reads"), theirs);

        // The other shells' entries stay where they are put: a person who moved one on purpose
        // keeps it there.
        let zsh = for_shell(ShellKind::Zsh);
        let body = entry(&zsh, package, false).expect("the path is text");
        let rc = root.path().join(".zshrc");
        std::fs::write(&rc, format!("{body}export A=1\n")).expect("writes");
        assert_eq!(
            install(&rc, &body, &Placement::End).expect("installs"),
            Change::Unchanged
        );
    }

    /// KR-REQ-07.23: a profile that is one file under both of its names holds both entries, the one
    /// that opens the bridge below its prologue and the one that checks the reader at its end, and
    /// removal gives the file back as it was.
    ///
    /// A profile that is a link to the other, even to one that is not there yet, is this case: the
    /// two targets name the one file, and each entry has markers of its own.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn one_file_under_both_profile_names_holds_both_entries() {
        let root = tempfile::tempdir().expect("a directory");
        let real = root.path().join("dotfiles-profile.ps1");
        let link = root.path().join("Microsoft.PowerShell_profile.ps1");
        // The link comes first and the file it names is not there yet.
        std::os::unix::fs::symlink(&real, &link).expect("links");
        let targets = powershell_targets(&a_powershell(), real.clone(), link.clone());
        assert_eq!(
            targets.len(),
            2,
            "each profile gets its entry, whatever the names are"
        );
        let theirs = "using namespace System\n$global:order += 'user'\n";
        std::fs::write(&real, theirs).expect("writes");
        let package = Path::new("/opt/kr/entry");
        let bodies = targets
            .iter()
            .map(|target| entry(target, package, false).expect("the path is text"))
            .collect::<Vec<_>>();
        for (target, body) in targets.iter().zip(&bodies) {
            install(&target.path, body, &target.placement).expect("installs");
        }
        assert_eq!(
            std::fs::read_to_string(&real).expect("reads"),
            format!(
                "using namespace System\n{}$global:order += 'user'\n{}",
                bodies[0], bodies[1]
            )
        );
        assert!(
            link.symlink_metadata()
                .expect("reads")
                .file_type()
                .is_symlink()
        );
        assert_eq!(remove(&real).expect("removes"), Change::Removed);
        assert_eq!(std::fs::read_to_string(&real).expect("reads"), theirs);
    }

    /// KR-REQ-07.23: each of the two entries goes where its placement says, into a profile of its
    /// own, and removal gives both files back as they were.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn each_powershell_entry_goes_into_its_profile_and_comes_out_again() {
        let root = tempfile::tempdir().expect("a directory");
        let package = Path::new("/opt/kr/entry");
        let first = root.path().join("profile.ps1");
        let last = root.path().join("Microsoft.PowerShell_profile.ps1");
        let targets = powershell_targets(&a_powershell(), first.clone(), last.clone());
        let theirs = "using namespace System\nRead-Host 'name'\n";
        for file in [&first, &last] {
            std::fs::write(file, theirs).expect("writes");
        }
        let bodies = targets
            .iter()
            .map(|target| entry(target, package, false).expect("the path is text"))
            .collect::<Vec<_>>();
        for (target, body) in targets.iter().zip(&bodies) {
            install(&target.path, body, &target.placement).expect("installs");
        }
        let first_text = std::fs::read_to_string(&first).expect("reads");
        assert_eq!(
            first_text,
            format!("using namespace System\n{}Read-Host 'name'\n", bodies[0]),
            "the load is directly below the prologue"
        );
        assert_eq!(
            std::fs::read_to_string(&last).expect("reads"),
            format!("{theirs}{}", bodies[1]),
            "the check is the last thing the last profile does"
        );
        for file in [&first, &last] {
            assert_eq!(remove(file).expect("removes"), Change::Removed);
            assert_eq!(std::fs::read_to_string(file).expect("reads"), theirs);
        }
    }

    /// KR-REQ-07.23: a PowerShell entry goes directly below what PowerShell requires to come first,
    /// and removal gives the profile back byte for byte.
    ///
    /// A profile that begins with `using` statements, a script `param` block or a byte-order mark
    /// still parses, in every shell and not only the ones KalaReach starts. The byte-order mark is
    /// the file's encoding and belongs to no line, so the entry is found again where it was put
    /// when the profile has nothing before it but the mark.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn a_powershell_entry_stays_directly_below_what_a_profile_must_begin_with() {
        let root = tempfile::tempdir().expect("a directory");
        let target = for_shell(ShellKind::PowerShell);
        let body = entry(&target, Path::new("/opt/kr/entry"), false).expect("the path is text");
        for (name, theirs, prologue) in [
            (
                "using",
                "using namespace System.Management.Automation\nusing namespace System.Text\n$env:A = 1\n",
                "using namespace System.Management.Automation\nusing namespace System.Text\n",
            ),
            (
                "comments",
                "# my profile\n#Requires -Version 7\n\n$env:A = 1\n",
                "",
            ),
            (
                "block comment",
                "<#\n  notes\n#>\nusing namespace System\n$env:A = 1\n",
                "<#\n  notes\n#>\nusing namespace System\n",
            ),
            (
                "param",
                "using namespace System\n[CmdletBinding()]\nparam(\n  [string]$Name\n)\n$env:A = 1\n",
                "using namespace System\n[CmdletBinding()]\nparam(\n  [string]$Name\n)\n",
            ),
            (
                "byte-order mark and using",
                "\u{feff}using namespace System\n$env:A = 1\n",
                "\u{feff}using namespace System\n",
            ),
            (
                "byte-order mark and a statement",
                "\u{feff}$env:A = 1\n",
                "\u{feff}",
            ),
            (
                "crlf line ends",
                "using namespace System\r\n$env:A = 1\r\n",
                "using namespace System\r\n",
            ),
        ] {
            let path = root.path().join(format!("{}.ps1", name.replace(' ', "-")));
            std::fs::write(&path, theirs).expect("writes");
            assert_eq!(
                install(&path, &body, &target.placement).expect("installs"),
                Change::Added,
                "{name}"
            );
            let written = std::fs::read_to_string(&path).expect("reads");
            assert_eq!(
                written,
                format!("{prologue}{body}{}", &theirs[prologue.len()..]),
                "{name}: the entry sits directly below the prologue"
            );
            assert_eq!(
                install(&path, &body, &target.placement).expect("installs"),
                Change::Unchanged,
                "{name}: a second install is no change"
            );
            assert_eq!(remove(&path).expect("removes"), Change::Removed);
            assert_eq!(
                std::fs::read_to_string(&path).expect("reads"),
                theirs,
                "{name}: removal did not give the profile back"
            );
        }
    }

    /// KR-REQ-07.23: a profile that is nothing but a prologue with no final line end gets its entry
    /// the way any file does, on a line of its own.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn a_powershell_profile_that_is_only_a_prologue_gets_its_entry_on_a_line_of_its_own() {
        let root = tempfile::tempdir().expect("a directory");
        let target = for_shell(ShellKind::PowerShell);
        let body = entry(&target, Path::new("/opt/kr/entry"), false).expect("the path is text");
        let path = root.path().join("profile.ps1");
        std::fs::write(&path, "using namespace System").expect("writes");
        install(&path, &body, &target.placement).expect("installs");
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            format!("using namespace System\n{body}")
        );
        assert!(holds_an_entry(&path));
    }

    /// KR-REQ-07.23: an entry that would make PowerShell report an error the profile did not have
    /// is refused, and the profile is left exactly as it was.
    ///
    /// The refusal is the parser's own check of the result, so it holds for whatever the profile
    /// is. The entry here is one that cannot parse, which no profile can make a good neighbour.
    #[cfg(unix)]
    #[test]
    #[ignore = "needs a PowerShell on the path; it runs with --include-ignored where one is installed, as continuous integration's shell-packages job does"]
    fn an_entry_that_would_add_a_parse_error_is_refused_and_the_profile_is_untouched() {
        let root = tempfile::tempdir().expect("a directory");
        let target = for_shell(ShellKind::PowerShell);
        let path = root.path().join("profile.ps1");
        let theirs = "Get-Date\n";
        std::fs::write(&path, theirs).expect("writes");
        let broken = format!("{MARKER_BEGIN}\nif (\n{MARKER_END}\n");
        let refused = install(&path, &broken, &target.placement).expect_err("refused");
        assert!(
            refused.to_string().contains("nothing was written"),
            "the refusal says so: {refused}"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("reads"), theirs);

        // A profile that already has an error keeps it: the entry is held to adding none.
        let already = root.path().join("already.ps1");
        let theirs = "using module NotInstalledAnywhere\nGet-Date\n";
        std::fs::write(&already, theirs).expect("writes");
        let body = entry(&target, Path::new("/opt/kr/entry"), false).expect("the path is text");
        install(&already, &body, &target.placement)
            .expect("a profile with its own error is added to");
        assert_eq!(remove(&already).expect("removes"), Change::Removed);
        assert_eq!(std::fs::read_to_string(&already).expect("reads"), theirs);
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
        )
        .expect("the path is text");
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Added
        );
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

        // A shell that answers: the entries go where it said, wherever that is. The first profile
        // it reads opens the bridge and the last one checks the reader.
        let all_hosts = root.path().join("Documents/PowerShell/profile.ps1");
        let current_host = root
            .path()
            .join("Documents/PowerShell/Microsoft.PowerShell_profile.ps1");
        let asking = HomeLayout {
            powershell: Some(fake_powershell(
                root.path(),
                &format!("{}\n{}", all_hosts.display(), current_host.display()),
            )),
            ..home.clone()
        };
        let shell = asking.powershell.clone().expect("a shell");
        let targets = asking.targets(ShellKind::PowerShell);
        assert_eq!(
            targets
                .iter()
                .map(|target| (target.path.clone(), target.placement.clone()))
                .collect::<Vec<_>>(),
            [
                (
                    all_hosts.clone(),
                    Placement::AfterPrologue {
                        shell: shell.clone()
                    }
                ),
                (current_host, Placement::Last { shell })
            ]
        );

        // A shell that answers nothing leaves this host with no profile rather than one it made up.
        let silent = HomeLayout {
            powershell: Some(fake_powershell(root.path(), "")),
            ..home.clone()
        };
        assert!(silent.targets(ShellKind::PowerShell).is_empty());

        // One that names a single profile has named none this host can check a reader at the end
        // of, and no entry is written for half an answer.
        let once = HomeLayout {
            powershell: Some(fake_powershell(root.path(), "/home/a/profile.ps1")),
            ..home.clone()
        };
        assert!(once.targets(ShellKind::PowerShell).is_empty());

        // Two names for one file are two targets all the same: the entries have markers of their own
        // and one file holds both.
        let twice = HomeLayout {
            powershell: Some(fake_powershell(
                root.path(),
                "/home/a/profile.ps1\n/home/a/profile.ps1",
            )),
            ..home
        };
        assert_eq!(twice.targets(ShellKind::PowerShell).len(), 2);
    }

    /// KR-REQ-26.05: asking PowerShell where its profile is leaves nothing of PowerShell's own in
    /// the person's home.
    ///
    /// PowerShell keeps a cache, a telemetry identifier and a module directory under the home's
    /// XDG directories whenever it starts, so the shell this host asks for its profile is pointed
    /// at directories of the question's own, which go with it. The program here writes where
    /// PowerShell writes, under a home of its own, and says what it was told.
    #[cfg(unix)]
    #[test]
    fn asking_powershell_for_its_profile_leaves_the_home_as_it_was() {
        let root = tempfile::tempdir().expect("a directory");
        let home = root.path().join("home");
        std::fs::create_dir(&home).expect("a home");
        let seen = root.path().join("seen");
        let program = root.path().join("pwsh-writes");
        let text = root.path().join("pwsh-writes.text");
        std::fs::write(
            &text,
            format!(
                "#!/bin/sh\n[ \"${{1:-}}\" = --version ] && exit 0\nHOME='{home}'\n\
                 cache=\"${{XDG_CACHE_HOME:-$HOME/.cache}}/powershell\"\n\
                 data=\"${{XDG_DATA_HOME:-$HOME/.local/share}}/powershell/Modules\"\n\
                 mkdir -p \"$cache\" \"$data\" && : > \"$cache/StartupProfileData-NonInteractive\"\n\
                 printf '%s\\n%s\\n' \"$XDG_CACHE_HOME\" \"$XDG_DATA_HOME\" > '{seen}'\n\
                 printf '%s\\n' '{profile}'\n",
                home = home.display(),
                seen = seen.display(),
                profile = home.join(".config/powershell/profile.ps1").display(),
            ),
        )
        .expect("writes the program's text");
        kr_ipc::testing::place_and_start_once(&text, &program, &["--version"]);
        std::fs::remove_file(&text).expect("the program's text goes once it is in place");

        let asking = HomeLayout {
            powershell: Some(program),
            ..layout(&home)
        };
        let targets = asking.targets(ShellKind::PowerShell);
        assert_eq!(targets.len(), 1, "the shell's answer is taken");
        assert_eq!(
            std::fs::read_dir(&home).expect("the home reads").count(),
            0,
            "the question left something of the shell's own in the home"
        );
        let told = std::fs::read_to_string(&seen).expect("the program saw its environment");
        let ours = std::env::temp_dir().join("kr-shell-ask-");
        for directory in told.lines() {
            assert!(
                directory.starts_with(&*ours.to_string_lossy()),
                "{directory:?} is not a directory of the question's own"
            );
        }
        assert_eq!(told.lines().count(), 2, "both directories are named");
    }

    /// Writes a program that prints what it was given, which is all this host asks PowerShell for.
    ///
    /// Its text is written beside it and placed by a process of its own, so this process never
    /// holds the program open for writing, and a child another test starts is never handed a
    /// descriptor that would keep the program from starting.
    #[cfg(unix)]
    fn fake_powershell(root: &Path, says: &str) -> PathBuf {
        use std::hash::{Hash as _, Hasher as _};

        // Named by what it says, so two programs that say different things are never one file.
        let mut name = std::collections::hash_map::DefaultHasher::new();
        says.hash(&mut name);
        let name = name.finish();
        let path = root.join(format!("pwsh-{name:016x}"));
        let text = root.join(format!("pwsh-{name:016x}.text"));
        std::fs::write(&text, format!("#!/bin/sh\nprintf '%s\\n' '{says}'\n"))
            .expect("writes the program's text");
        // Started once here, where nothing is timed: the first start of a program just written can
        // take seconds on a machine that checks what it runs, and the question this host asks has a
        // deadline of its own.
        kr_ipc::testing::place_and_start_once(&text, &path, &["--version"]);
        std::fs::remove_file(&text).expect("the program's text goes once it is in place");
        path
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
        )
        .expect("the path is text");
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Added
        );
        let after = std::fs::read_to_string(&path).expect("reads");
        assert!(after.starts_with(theirs), "the user's own lines are first");
        assert!(after.contains(MARKER_BEGIN) && after.contains(MARKER_END));
        assert!(holds_an_entry(&path));
        // A second install is not a second entry.
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Unchanged
        );
        let updated = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            true,
        )
        .expect("the path is text");
        assert_eq!(
            install(&path, &updated, &Placement::End).expect("installs"),
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
        )
        .expect("the path is text");
        assert_eq!(
            install(&link, &body, &Placement::End).expect("installs"),
            Change::Added
        );
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
        )
        .expect("the path is text");
        assert_eq!(
            install(&link, &body, &Placement::End).expect("installs"),
            Change::Added
        );
        assert_eq!(remove(&link).expect("removes"), Change::Removed);
        assert!(
            link.symlink_metadata()
                .expect("the link is still there")
                .file_type()
                .is_symlink()
        );
        assert!(
            !holds_an_entry(&real),
            "and the file it names no longer holds the entry"
        );
    }

    /// KR-REQ-26.05: the install and the removal write nothing in the startup file's directory but
    /// the file itself.
    #[cfg(unix)]
    #[test]
    fn an_install_and_a_removal_leave_nothing_in_the_files_directory_but_the_file() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        std::fs::write(&path, "export EDITOR=vim\n").expect("writes");
        let names = || {
            let mut names: Vec<String> = std::fs::read_dir(root.path())
                .expect("lists")
                .map(|entry| {
                    entry
                        .expect("an entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            names.sort();
            names
        };
        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        )
        .expect("the path is text");
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Added
        );
        assert_eq!(
            names(),
            [".zshrc"],
            "the install left something beside the file"
        );
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(
            names(),
            [".zshrc"],
            "the removal left something beside the file"
        );
    }

    /// KR-REQ-26.05: a file that did not end in a line break is given back exactly as it was. The
    /// entry begins on a line of its own, and the line break that took is the entry's, so the
    /// removal takes it back; where the person has written after the entry since, the file is no
    /// longer the one that was there and the break stays.
    #[test]
    fn a_file_with_no_final_line_break_is_given_back_exactly() {
        let root = tempfile::tempdir().expect("a directory");
        let path = root.path().join(".zshrc");
        let body = entry(
            &for_shell(ShellKind::Zsh),
            Path::new("/opt/kr/zsh-entry.zsh"),
            false,
        )
        .expect("the path is text");

        std::fs::write(&path, "export EDITOR=vim").expect("writes");
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Added
        );
        // Installing again keeps the entry, and what it took with it.
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs again"),
            Change::Unchanged
        );
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "export EDITOR=vim"
        );

        // The person wrote a line after the entry, so what was there before it is not at the end.
        std::fs::write(&path, "export EDITOR=vim").expect("writes");
        install(&path, &body, &Placement::End).expect("installs");
        let with_more = format!(
            "{}alias ll='ls -l'\n",
            std::fs::read_to_string(&path).expect("reads")
        );
        std::fs::write(&path, with_more).expect("writes");
        assert_eq!(remove(&path).expect("removes"), Change::Removed);
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "export EDITOR=vim\nalias ll='ls -l'\n"
        );

        // A file that did end in a line break needs none, and is given back the same.
        std::fs::write(&path, "export EDITOR=vim\n").expect("writes");
        install(&path, &body, &Placement::End).expect("installs");
        remove(&path).expect("removes");
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "export EDITOR=vim\n"
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
        )
        .expect("the path is text");
        assert_eq!(
            install(&path, &body, &Placement::End).expect("installs"),
            Change::Added
        );
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
        assert!(
            leftovers.is_empty(),
            "the install left something beside the startup file: {leftovers:?}"
        );
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
            let with = entry(&for_shell(*kind), Path::new("/opt/kr/entry"), true)
                .expect("the path is text");
            assert!(
                with.contains(NSH_BYPASS_VARIABLE),
                "{kind} offers the documented bypass"
            );
            assert!(
                with.contains("KR_SHELL_BRIDGE"),
                "{kind} sets it only where the bridge was exported"
            );
            let without = entry(&for_shell(*kind), Path::new("/opt/kr/entry"), false)
                .expect("the path is text");
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
            )
            .expect("the path is text");
            // The apostrophe is escaped rather than ending the string, so the line still names one
            // path and nothing after it is read as shell syntax.
            assert!(
                !body.contains("/home/it's mine/kr/entry"),
                "{kind} left the apostrophe unescaped: {body}"
            );
            assert!(body.contains("mine/kr/entry"), "{kind}: {body}");
        }
    }

    /// KR-REQ-07.29: a package entry that is not text is refused by name, rather than written into
    /// a startup file as another path.
    ///
    /// Unix, where a path is bytes and one of them can be a byte UTF-8 has no character for.
    #[cfg(unix)]
    #[test]
    fn a_package_entry_that_is_not_text_is_refused_rather_than_written_as_another_path() {
        use std::os::unix::ffi::OsStrExt as _;

        let package = Path::new(std::ffi::OsStr::from_bytes(b"/opt/kr\xff/entry"));
        for kind in ShellKind::ALL {
            let refused = entry(&for_shell(*kind), package, false)
                .expect_err("a path that is not text has no spelling in a startup file");
            assert_eq!(refused.path, package, "{kind}: the refusal names the path");
            assert!(
                refused.to_string().contains("not UTF-8"),
                "{kind} says why: {refused}"
            );
        }
    }

    #[test]
    fn nothing_replaces_a_profile_or_points_at_another_zdotdir() {
        for kind in ShellKind::ALL {
            let body = entry(&for_shell(*kind), Path::new("/opt/kr/entry"), true)
                .expect("the path is text");
            for forbidden in ["ZDOTDIR=", "--rcfile", "--norc", "--noprofile", "exec "] {
                assert!(
                    !body.contains(forbidden),
                    "{kind}'s entry contains {forbidden}"
                );
            }
        }
    }

    /// The record keeps each file by its exact name for the shell it is for, keeps a file once
    /// however often an install writes to it, and forgets one file without the others. It is the
    /// owner's alone, in a state directory it creates when there is none yet.
    #[test]
    fn the_record_keeps_each_file_by_its_exact_name_for_its_shell() {
        let root = tempfile::tempdir().expect("a directory");
        let record = EntryRecord::in_state_directory(&root.path().join("state"));
        assert!(
            record.files(ShellKind::Zsh).expect("reads").is_empty(),
            "no record yet names nothing"
        );
        let zshrc = PathBuf::from("/home/the person's home/.zshrc");
        let bashrc = PathBuf::from("/home/the person's home/.bashrc");
        let profile = PathBuf::from("/home/the person's home/.bash_profile");
        let held = record.hold().expect("holds");
        held.add(ShellKind::Zsh, std::slice::from_ref(&zshrc))
            .expect("records");
        held.add(ShellKind::Bash, &[bashrc.clone(), profile.clone()])
            .expect("records");
        held.add(ShellKind::Zsh, std::slice::from_ref(&zshrc))
            .expect("records");
        assert_eq!(
            record.files(ShellKind::Zsh).expect("reads"),
            vec![zshrc.clone()]
        );
        assert_eq!(
            record.files(ShellKind::Bash).expect("reads"),
            vec![bashrc.clone(), profile.clone()]
        );
        assert!(record.files(ShellKind::Fish).expect("reads").is_empty());
        held.forget(ShellKind::Bash, &bashrc).expect("forgets");
        drop(held);
        assert_eq!(record.files(ShellKind::Bash).expect("reads"), vec![profile]);
        assert_eq!(record.files(ShellKind::Zsh).expect("reads"), vec![zshrc]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = std::fs::metadata(record.path())
                .expect("the record is there")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "the record is the owner's alone: {mode:o}");
        }
    }

    /// A name that is not text is kept byte for byte, and it is not the name its text makes of it,
    /// which has a replacement character in it and is another file.
    #[cfg(unix)]
    #[test]
    fn the_record_keeps_a_name_that_is_not_text_byte_for_byte() {
        use std::os::unix::ffi::OsStrExt as _;

        let root = tempfile::tempdir().expect("a directory");
        let record = EntryRecord::in_state_directory(&root.path().join("state"));
        let name = PathBuf::from(std::ffi::OsStr::from_bytes(b"/home/h\xffme/.zshrc"));
        record
            .hold()
            .expect("holds")
            .add(ShellKind::Zsh, std::slice::from_ref(&name))
            .expect("records");
        let kept = record.files(ShellKind::Zsh).expect("reads");
        assert_eq!(kept, vec![name.clone()]);
        assert_ne!(kept[0], PathBuf::from(name.to_string_lossy().into_owned()));
    }

    /// What is not a record is refused rather than read as one that names nothing, which would have
    /// a removal leave every entry and say nothing about why; so is a record at a link, which could
    /// name somebody else's files.
    #[test]
    fn what_is_not_a_record_is_refused() {
        let root = tempfile::tempdir().expect("a directory");
        let state = root.path().join("state");
        kr_ipc::paths::create_private_tree(&state, &state).expect("an owner-only directory");
        let record = EntryRecord::in_state_directory(&state);
        for written in [
            "not a record",
            r#"{"entries":[{"shell":"zsh","path":"2F"}]}"#,
            r#"{"entries":[{"shell":"zsh","path":""}]}"#,
            r#"{"entries":[{"shell":"zsh","path":"2f7"}]}"#,
            r#"{"entries":[{"shell":"zsh","path":"+f2f"}]}"#,
            r#"{"entries":[{"shell":"ksh","path":"2f"}]}"#,
            r#"{"entries":[],"more":1}"#,
        ] {
            kr_ipc::paths::write_owner_only_file(record.path(), written.as_bytes())
                .expect("writes");
            assert!(
                matches!(record.files(ShellKind::Zsh), Err(RecordError::NotARecord)),
                "{written} is refused"
            );
        }
        #[cfg(unix)]
        {
            std::fs::remove_file(record.path()).expect("removes");
            let elsewhere = root.path().join("elsewhere.json");
            kr_ipc::paths::write_owner_only_file(&elsewhere, br#"{"entries":[]}"#).expect("writes");
            std::os::unix::fs::symlink(&elsewhere, record.path()).expect("links");
            assert!(matches!(
                record.files(ShellKind::Zsh),
                Err(RecordError::Store(_))
            ));
        }
    }

    /// A second holder of the record waits until the first lets go, and gets it then.
    #[test]
    fn a_second_holder_of_the_record_waits_for_the_first_to_let_go() {
        let root = tempfile::tempdir().expect("a directory");
        let record = EntryRecord::in_state_directory(&root.path().join("state"));
        let first = record.hold().expect("holds");
        let (held, second) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let holding = record.hold().expect("holds once the first lets go");
                held.send(()).expect("says so");
                drop(holding);
            });
            assert!(
                second
                    .recv_timeout(std::time::Duration::from_millis(300))
                    .is_err(),
                "the second holder waits while the first holds the record"
            );
            drop(first);
            second
                .recv_timeout(LOCK_PATIENCE)
                .expect("the second holder has it once the first lets go");
        });
    }
}
