//! Building the root shell's environment.
//!
//! Section 7 sets out three rules that decide every variable. The creator's snapshot is an input,
//! not a promise: execution-context values take precedence over it. Physical-terminal identity is
//! removed rather than passed through, because a shell that believes it is inside iTerm2 will
//! enable features this terminal does not supply. Reserved KalaReach values come only from the
//! worker, so a caller cannot smuggle one in through its own environment.
//!
//! The terminal identity is `xterm-256color`, and the database that names it is the worker's own:
//! [`materialise_terminfo`] writes the pinned entry into the worker's state directory and `build`
//! points the session's terminfo library at it. A creator's own database directories are kept
//! behind it and reported, so they still serve every other terminal name.

use std::collections::BTreeMap;
use std::path::PathBuf;

use kr_protocol::session::EnvironmentVariable;

/// The terminal identity every KalaReach session declares.
pub const TERM: &str = "xterm-256color";

/// The colour support every KalaReach session declares.
pub const COLORTERM: &str = "truecolor";

/// The terminal program every KalaReach session declares.
pub const TERM_PROGRAM: &str = "KalaReach";

/// The variable a terminfo library reads its first database directory from.
pub const TERMINFO_VARIABLE: &str = "TERMINFO";

/// The variable that lists the database directories a terminfo library reads after its first.
pub const TERMINFO_DIRS_VARIABLE: &str = "TERMINFO_DIRS";

/// The directory inside a worker's state directory that holds the private terminfo database.
pub const TERMINFO_DIRECTORY: &str = "terminfo";

/// The variable that names the session a command is running inside.
///
/// It identifies a candidate session, never an authority: the host validates the caller's local
/// peer and its session binding before it accepts anything quoted from here.
pub const SESSION_VARIABLE: &str = "KR_SESSION";

/// The variable that names the private endpoint a session's own worker answers on.
///
/// It is set for a command the session established a worker-owned backend for, and for no other
/// process. The endpoint is owner-only, and reaching it proves nothing on its own: the host still
/// validates the caller's local peer and its session binding.
pub const WORKER_ENDPOINT_VARIABLE: &str = "KR_WORKER_ENDPOINT";

/// The prefix reserved for KalaReach's own bootstrap values.
///
/// A creator's snapshot cannot set one of these. They come from the worker or not at all.
pub const RESERVED_PREFIX: &str = "KR_";

/// Physical-terminal identity variables that are removed from an inherited environment.
///
/// Each one names a terminal emulator the session is not. Passing them through would let a shell
/// plugin enable an escape-sequence feature on the strength of a false identity, and the failure
/// would show up as corrupted output rather than as a missing feature.
pub const TERMINAL_IDENTITY_VARIABLES: &[&str] = &[
    "ITERM_SESSION_ID",
    "ITERM_PROFILE",
    "LC_TERMINAL",
    "LC_TERMINAL_VERSION",
    "VTE_VERSION",
    "WT_SESSION",
    "WT_PROFILE_ID",
    "KONSOLE_VERSION",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
];

/// Prefixes of physical-terminal identity variables that are removed.
pub const TERMINAL_IDENTITY_PREFIXES: &[&str] = &["KONSOLE_DBUS_"];

/// Variables that describe the creator's own terminal device rather than the new session's.
pub const CREATOR_TERMINAL_VARIABLES: &[&str] = &["SSH_TTY", "TERM", "COLORTERM", "SHELL"];

/// What the environment of one session was built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentSources {
    /// Where `PATH` came from.
    pub path: &'static str,
    /// Where the locale came from.
    pub locale: &'static str,
    /// Where the working directory came from.
    pub cwd: &'static str,
    /// Which terminfo database the session reads `TERM` from, and what it was given instead.
    pub terminfo: TerminfoSelection,
}

/// The terminfo database a session reads its terminal's capabilities from.
///
/// The private database comes first, so the capabilities an application reads are the ones the
/// terminal engine answers and acts on. A creator's own `TERMINFO` and `TERMINFO_DIRS` are neither
/// dropped nor obeyed: they follow the private directory in the session's search, so they still
/// name the terminals the private database has no entry for, and they are recorded here as what
/// they were.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TerminfoSelection {
    /// The private database directory `TERMINFO` names, or none when this session reads whatever
    /// database its host has.
    pub directory: Option<String>,
    /// The creator's `TERMINFO`, now searched after the private directory.
    pub creator_terminfo: Option<String>,
    /// The creator's `TERMINFO_DIRS`, kept as it was.
    pub creator_terminfo_dirs: Option<String>,
}

impl TerminfoSelection {
    /// Whether the creator supplied a database directory of its own.
    #[must_use]
    pub const fn overridden(&self) -> bool {
        self.creator_terminfo.is_some() || self.creator_terminfo_dirs.is_some()
    }
}

/// The environment a root shell is launched with, and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchEnvironment {
    /// The complete variable set, in name order.
    pub variables: BTreeMap<String, String>,
    /// The provenance the host records for diagnostics.
    pub sources: EnvironmentSources,
    /// The identity variables that were removed, so diagnostics can show the policy.
    pub removed: Vec<String>,
}

impl LaunchEnvironment {
    /// Returns the variables as a sorted vector of pairs.
    #[must_use]
    pub fn to_pairs(&self) -> Vec<(String, String)> {
        self.variables
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

/// The execution context a worker runs in.
///
/// These values come from the selected desktop or headless context, never from the creator's
/// snapshot and never from another desktop's session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionContext {
    /// Values the selected broker supplies, such as `DISPLAY` or `XDG_RUNTIME_DIR`.
    pub variables: BTreeMap<String, String>,
    /// The login session a desktop-bound worker is tied to.
    pub desktop: Option<kr_protocol::identity::DesktopBinding>,
    /// The directory of the private terminfo database this worker wrote, when it wrote one.
    ///
    /// A worker that could not write it, and a host with no terminfo library, leave this empty, and
    /// the session then reads whatever database its host has.
    pub terminfo: Option<PathBuf>,
}

/// The variables a desktop context supplies, in the order a session needs them.
///
/// A desktop-bound session needs the display and the session bus to reach the desktop it belongs
/// to. A headless one has none of them, and passing a stale one through from a creator's snapshot
/// would point the session at a desktop that is not there.
pub const DESKTOP_VARIABLES: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_CURRENT_DESKTOP",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_ID",
    "XDG_SESSION_TYPE",
];

impl ExecutionContext {
    /// Resolves the context a worker of this profile runs in.
    ///
    /// A desktop-bound worker takes the desktop values from the environment this process was
    /// started in, which is the login session the service manager placed it in. A headless worker
    /// takes none of them: it must keep working after that login session ends, and a session that
    /// carried a dead display would fail at the first application that used it.
    ///
    /// The presentation the create request chose is not an input here. An invisible session in a
    /// desktop context keeps that desktop's access, because where a session is shown and where it
    /// runs are different questions.
    #[must_use]
    pub fn resolve(profile: kr_protocol::identity::WorkerProfile) -> Self {
        let mut variables = BTreeMap::new();
        if profile == kr_protocol::identity::WorkerProfile::DesktopBound {
            for name in DESKTOP_VARIABLES {
                if let Ok(value) = std::env::var(name) {
                    variables.insert((*name).to_owned(), value);
                }
            }
        }
        Self {
            desktop: (profile == kr_protocol::identity::WorkerProfile::DesktopBound)
                .then(desktop_binding),
            variables,
            terminfo: None,
        }
    }
}

/// Reads the login session a desktop-bound worker is tied to.
///
/// The binding is the desktop's derived name and the generation it was taken at. Both come from
/// [`crate::desktop`], which asks the platform about the login session rather than reading a
/// variable out of this process's own environment: a variable cannot say whether the login it
/// names is still the one that is there, and the generation is what tells a reused session number
/// apart from the login that held it before, as far as the platform's own answer goes.
///
/// A host with no boot identity to bind to, or no graphical login session, records no binding.
/// That is not the end of the question for a desktop-bound session: a reading that failed a moment
/// before the session was created would otherwise be a session that could never lose its desktop,
/// so its watch keeps asking and adopts the login session it is in when the platform names one.
#[must_use]
pub fn desktop_binding() -> kr_protocol::identity::DesktopBinding {
    let Ok(boot) = kr_ipc::identity::boot_identity() else {
        return kr_protocol::identity::DesktopBinding::none();
    };
    crate::desktop::binding(&crate::desktop::context(
        kr_protocol::identity::WorkerProfile::DesktopBound,
        boot,
    ))
}

/// Builds the environment for one root shell.
///
/// The order is fixed: start from the creator's snapshot with terminal identity filtered out, let
/// the execution context overwrite whatever it supplies, and finish with the values the worker
/// owns outright. User startup files can change any of them afterwards, which is normal.
#[must_use]
pub fn build(
    snapshot: &[EnvironmentVariable],
    context: &ExecutionContext,
    shell_path: &str,
    release: &str,
    session_id: kr_protocol::ids::SessionId,
) -> LaunchEnvironment {
    let mut variables = BTreeMap::new();
    let mut removed = Vec::new();
    let mut path_from_snapshot = false;
    let mut locale_from_snapshot = false;
    let mut terminfo = TerminfoSelection {
        directory: context
            .terminfo
            .as_deref()
            .and_then(|directory| directory.to_str())
            .map(str::to_owned),
        ..TerminfoSelection::default()
    };

    for variable in snapshot {
        if terminfo.directory.is_some() && is_terminfo_search(&variable.name) {
            // A creator's database directories are searched after the private one, which is
            // decided below once every variable has been seen.
            let held = if variable.name == TERMINFO_VARIABLE {
                &mut terminfo.creator_terminfo
            } else {
                &mut terminfo.creator_terminfo_dirs
            };
            *held = Some(variable.value.clone());
            continue;
        }
        if is_terminal_identity(&variable.name) || is_creator_terminal(&variable.name) {
            removed.push(variable.name.clone());
            continue;
        }
        if variable.name.starts_with(RESERVED_PREFIX) {
            // Reserved bootstrap values come from the worker. A creator cannot preload one.
            removed.push(variable.name.clone());
            continue;
        }
        if DESKTOP_VARIABLES.contains(&variable.name.as_str()) {
            // The desktop belongs to the execution context, not to whoever asked for the session.
            // A headless worker supplies none of these on purpose, and letting the creator's copy
            // survive would give it a display, a message bus and a runtime directory belonging to a
            // login it is not in and that may already have ended.
            removed.push(variable.name.clone());
            continue;
        }
        if variable.name == "PATH" {
            path_from_snapshot = true;
        }
        if variable.name == "LANG" || variable.name.starts_with("LC_") {
            locale_from_snapshot = true;
        }
        variables.insert(variable.name.clone(), variable.value.clone());
    }

    let mut path_source = if path_from_snapshot {
        "creator snapshot"
    } else {
        "execution context"
    };
    let mut locale_source = if locale_from_snapshot {
        "creator snapshot"
    } else {
        "execution context"
    };

    for (name, value) in &context.variables {
        if name == "PATH" {
            path_source = "execution context";
        }
        if name == "LANG" || name.starts_with("LC_") {
            locale_source = "execution context";
        }
        variables.insert(name.clone(), value.clone());
    }

    // The worker owns these outright. They are the session's declared identity, and changing them
    // is the intentional part of the policy rather than an oversight.
    variables.insert("TERM".to_owned(), TERM.to_owned());
    variables.insert("COLORTERM".to_owned(), COLORTERM.to_owned());
    variables.insert("TERM_PROGRAM".to_owned(), TERM_PROGRAM.to_owned());
    variables.insert("TERM_PROGRAM_VERSION".to_owned(), release.to_owned());
    if let Some(directory) = &terminfo.directory {
        variables.insert(TERMINFO_VARIABLE.to_owned(), directory.clone());
        // The library reads `TERMINFO` first and `TERMINFO_DIRS` after it, so what the creator
        // had in the first goes at the front of the second and keeps its place in the search.
        let fallback: Vec<&str> = [
            terminfo.creator_terminfo.as_deref(),
            terminfo.creator_terminfo_dirs.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !fallback.is_empty() {
            variables.insert(TERMINFO_DIRS_VARIABLE.to_owned(), fallback.join(":"));
        }
    }
    // A child invocation of this path is not a second active root integration; `SHELL` names the
    // executable that was actually launched.
    variables.insert("SHELL".to_owned(), shell_path.to_owned());
    // The session a command inside this shell is running in. It names a candidate, and it is not a
    // credential: a command that quotes it still reaches the host over an authenticated local
    // socket, and the host checks the caller before it acts. Setting it is what lets `kr close`
    // and `kr status` mean "this one" without being told.
    variables.insert(SESSION_VARIABLE.to_owned(), session_id.to_string());

    removed.sort_unstable();
    removed.dedup();

    LaunchEnvironment {
        variables,
        sources: EnvironmentSources {
            path: path_source,
            locale: locale_source,
            cwd: "create request",
            terminfo,
        },
        removed,
    }
}

fn is_terminal_identity(name: &str) -> bool {
    TERMINAL_IDENTITY_VARIABLES.contains(&name)
        || TERMINAL_IDENTITY_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn is_creator_terminal(name: &str) -> bool {
    CREATOR_TERMINAL_VARIABLES.contains(&name)
}

fn is_terminfo_search(name: &str) -> bool {
    name == TERMINFO_VARIABLE || name == TERMINFO_DIRS_VARIABLE
}

/// Writes the private terminfo database into the worker's state directory and returns where it is.
///
/// The database is the pinned `xterm-256color` entry, compiled from the same data the terminal
/// engine answers capability queries from. It is written from this build's own data rather than
/// found on the host, so it cannot drift from the engine, and it is written again only when the
/// file on disk is not the current one. Workers of several sessions may do this at once: each
/// replaces a file whole, so none reads a partial one.
///
/// # Errors
///
/// Returns an error when the directory or a file in it cannot be written, or when the state
/// directory's path is not text an environment variable can carry.
#[cfg(unix)]
pub fn materialise_terminfo(state_dir: &std::path::Path) -> std::io::Result<PathBuf> {
    let directory = state_dir.join(TERMINFO_DIRECTORY);
    if directory.to_str().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the state directory's path is not valid text",
        ));
    }
    kr_term::terminfo::write_database(&directory)?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The session these tests build an environment for.
    fn test_session() -> kr_protocol::ids::SessionId {
        kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]))
    }

    fn snapshot(pairs: &[(&str, &str)]) -> Vec<EnvironmentVariable> {
        pairs
            .iter()
            .map(|(name, value)| EnvironmentVariable {
                name: (*name).to_owned(),
                value: (*value).to_owned(),
            })
            .collect()
    }

    #[test]
    fn terminal_identity_is_removed_and_replaced() {
        let built = build(
            &snapshot(&[
                ("ITERM_SESSION_ID", "w0t0p0"),
                ("ITERM_PROFILE", "Default"),
                ("LC_TERMINAL", "iTerm2"),
                ("KONSOLE_DBUS_SESSION", "/Sessions/1"),
                ("TERM", "xterm-kitty"),
                ("SSH_TTY", "/dev/ttys004"),
                ("PATH", "/usr/bin"),
            ]),
            &ExecutionContext::default(),
            "/bin/zsh",
            "0.1.0",
            test_session(),
        );
        assert!(!built.variables.contains_key("ITERM_SESSION_ID"));
        assert!(!built.variables.contains_key("ITERM_PROFILE"));
        assert!(!built.variables.contains_key("LC_TERMINAL"));
        assert!(!built.variables.contains_key("KONSOLE_DBUS_SESSION"));
        assert!(!built.variables.contains_key("SSH_TTY"));
        assert_eq!(built.variables.get("TERM").map(String::as_str), Some(TERM));
        assert_eq!(
            built.variables.get("COLORTERM").map(String::as_str),
            Some(COLORTERM)
        );
        assert_eq!(
            built.variables.get("TERM_PROGRAM").map(String::as_str),
            Some(TERM_PROGRAM)
        );
        assert_eq!(
            built
                .variables
                .get("TERM_PROGRAM_VERSION")
                .map(String::as_str),
            Some("0.1.0")
        );
        assert_eq!(
            built.variables.get("SHELL").map(String::as_str),
            Some("/bin/zsh")
        );
        assert_eq!(built.sources.path, "creator snapshot");
    }

    #[test]
    fn connection_facts_that_describe_the_environment_are_kept() {
        let built = build(
            &snapshot(&[
                ("SSH_CONNECTION", "10.0.0.1 52000 10.0.0.2 22"),
                ("SSH_CLIENT", "10.0.0.1 52000 22"),
            ]),
            &ExecutionContext::default(),
            "/bin/zsh",
            "0.1.0",
            test_session(),
        );
        assert!(built.variables.contains_key("SSH_CONNECTION"));
        assert!(built.variables.contains_key("SSH_CLIENT"));
    }

    #[test]
    fn the_execution_context_wins_over_the_creator_snapshot() {
        let mut context = ExecutionContext::default();
        context
            .variables
            .insert("DISPLAY".to_owned(), ":0".to_owned());
        context
            .variables
            .insert("PATH".to_owned(), "/opt/bin".to_owned());
        let built = build(
            &snapshot(&[("PATH", "/usr/bin"), ("DISPLAY", ":99")]),
            &context,
            "/bin/zsh",
            "0.1.0",
            test_session(),
        );
        assert_eq!(
            built.variables.get("PATH").map(String::as_str),
            Some("/opt/bin")
        );
        assert_eq!(
            built.variables.get("DISPLAY").map(String::as_str),
            Some(":0")
        );
        assert_eq!(built.sources.path, "execution context");
    }

    #[test]
    fn a_creator_cannot_preload_a_reserved_value() {
        let built = build(
            &snapshot(&[("KR_SESSION_TOKEN", "forged")]),
            &ExecutionContext::default(),
            "/bin/zsh",
            "0.1.0",
            test_session(),
        );
        assert!(!built.variables.contains_key("KR_SESSION_TOKEN"));
        assert!(built.removed.iter().any(|name| name == "KR_SESSION_TOKEN"));
    }

    fn with_private_database(directory: &str) -> ExecutionContext {
        ExecutionContext {
            terminfo: Some(PathBuf::from(directory)),
            ..ExecutionContext::default()
        }
    }

    fn built_with(creator: &[(&str, &str)], context: &ExecutionContext) -> LaunchEnvironment {
        build(
            &snapshot(creator),
            context,
            "/bin/zsh",
            "0.1.0",
            test_session(),
        )
    }

    #[test]
    fn the_private_terminfo_database_is_the_first_one_a_session_reads() {
        let built = built_with(
            &[("PATH", "/usr/bin")],
            &with_private_database("/state/terminfo"),
        );
        assert_eq!(
            built.variables.get("TERMINFO").map(String::as_str),
            Some("/state/terminfo")
        );
        assert!(
            !built.variables.contains_key("TERMINFO_DIRS"),
            "a creator with no database directories leaves the search as it was"
        );
        assert_eq!(
            built.sources.terminfo.directory.as_deref(),
            Some("/state/terminfo")
        );
        assert!(!built.sources.terminfo.overridden());
        assert_eq!(built.variables.get("TERM").map(String::as_str), Some(TERM));
    }

    #[test]
    fn a_creators_database_directories_follow_the_private_one_and_are_reported() {
        let built = built_with(
            &[
                ("TERMINFO", "/home/a/.terminfo"),
                ("TERMINFO_DIRS", "/opt/one:/opt/two"),
            ],
            &with_private_database("/state/terminfo"),
        );
        // The private directory is read first, and the creator's own `TERMINFO` keeps the place it
        // had ahead of its `TERMINFO_DIRS`.
        assert_eq!(
            built.variables.get("TERMINFO").map(String::as_str),
            Some("/state/terminfo")
        );
        assert_eq!(
            built.variables.get("TERMINFO_DIRS").map(String::as_str),
            Some("/home/a/.terminfo:/opt/one:/opt/two")
        );
        let selection = &built.sources.terminfo;
        assert!(selection.overridden());
        assert_eq!(
            selection.creator_terminfo.as_deref(),
            Some("/home/a/.terminfo")
        );
        assert_eq!(
            selection.creator_terminfo_dirs.as_deref(),
            Some("/opt/one:/opt/two")
        );
    }

    #[test]
    fn either_of_a_creators_database_variables_alone_is_kept_too() {
        let only_dirs = built_with(
            &[("TERMINFO_DIRS", "/opt/one")],
            &with_private_database("/state/terminfo"),
        );
        assert_eq!(
            only_dirs.variables.get("TERMINFO_DIRS").map(String::as_str),
            Some("/opt/one")
        );
        assert!(only_dirs.sources.terminfo.overridden());

        let only_first = built_with(
            &[("TERMINFO", "/home/a/.terminfo")],
            &with_private_database("/state/terminfo"),
        );
        assert_eq!(
            only_first
                .variables
                .get("TERMINFO_DIRS")
                .map(String::as_str),
            Some("/home/a/.terminfo")
        );
        assert_eq!(
            only_first.variables.get("TERMINFO").map(String::as_str),
            Some("/state/terminfo")
        );
    }

    #[test]
    fn a_session_with_no_private_database_reads_what_its_creator_named() {
        let built = built_with(
            &[("TERMINFO", "/home/a/.terminfo")],
            &ExecutionContext::default(),
        );
        assert_eq!(
            built.variables.get("TERMINFO").map(String::as_str),
            Some("/home/a/.terminfo")
        );
        assert_eq!(built.sources.terminfo, TerminfoSelection::default());
    }

    #[cfg(unix)]
    #[test]
    fn the_private_database_is_written_inside_the_state_directory() {
        let state = std::env::temp_dir().join(format!("kr-worker-terminfo-{}", std::process::id()));
        std::fs::create_dir_all(&state).expect("a state directory");
        let directory = materialise_terminfo(&state).expect("the database is written");
        assert_eq!(directory, state.join(TERMINFO_DIRECTORY));
        let description = kr_term::terminfo::Description::pinned();
        for entry in description.entry_paths(&directory) {
            assert_eq!(
                std::fs::read(&entry).expect("an entry"),
                kr_term::terminfo::compiled().expect("compiles")
            );
        }
        // Writing it again, as the next session's worker does, changes nothing.
        assert_eq!(
            materialise_terminfo(&state).expect("the database is current"),
            directory
        );
        let _ = std::fs::remove_dir_all(&state);
    }
}
