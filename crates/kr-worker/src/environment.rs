//! Building the root shell's environment.
//!
//! Section 7 sets out three rules that decide every variable. The creator's snapshot is an input,
//! not a promise: execution-context values take precedence over it. Physical-terminal identity is
//! removed rather than passed through, because a shell that believes it is inside iTerm2 will
//! enable features this terminal does not supply. Reserved KalaReach values come only from the
//! worker, so a caller cannot smuggle one in through its own environment.
//!
//! The terminal identity is `xterm-256color`, and the database that names it is the worker's own:
//! `materialise_terminfo` writes the pinned entry into the worker's state directory and `build`
//! points the session's terminfo library at it. A creator's own database directories are kept
//! behind it and reported, so they still serve every other terminal name. A Windows build has no
//! `materialise_terminfo`, since Windows has no terminfo library of its own, and its sessions are
//! given no private directory.

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
pub const RESERVED_PREFIX: &str = kr_protocol::hostinfo::configuration::RESERVED_VARIABLE_PREFIX;

/// Physical-terminal identity variables that are removed from an inherited environment.
///
/// Each one names a terminal emulator the session is not. Passing them through would let a shell
/// plugin enable an escape-sequence feature on the strength of a false identity, and the failure
/// would show up as corrupted output rather than as a missing feature. The lists a creator's
/// environment is filtered by are the protocol's, which is also what a configuration is refused
/// additions by: one list of the names this host owns.
pub const TERMINAL_IDENTITY_VARIABLES: &[&str] =
    kr_protocol::hostinfo::configuration::TERMINAL_IDENTITY_VARIABLES;

/// Prefixes of physical-terminal identity variables that are removed.
pub const TERMINAL_IDENTITY_PREFIXES: &[&str] =
    kr_protocol::hostinfo::configuration::TERMINAL_IDENTITY_PREFIXES;

/// Variables that describe the creator's own terminal device rather than the new session's.
pub const CREATOR_TERMINAL_VARIABLES: &[&str] =
    kr_protocol::hostinfo::configuration::CREATOR_TERMINAL_VARIABLES;

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
/// they were. When no private database could be supplied they are recorded too, and stay exactly
/// where the creator put them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TerminfoSelection {
    /// The private database directory `TERMINFO` names, or none when this session reads whatever
    /// database its host has.
    pub directory: Option<String>,
    /// Why there is no private database, when there is none.
    pub unavailable: Option<String>,
    /// The creator's `TERMINFO`, searched after the private directory when there is one.
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

    /// The selection as one line of text, for the worker's own log.
    ///
    /// What the creator supplied is the creator's text, so a control character in it, a line break
    /// above all, is written as its escape: a value cannot end the line and begin another that
    /// reads as the worker's.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut line = match (&self.directory, &self.unavailable) {
            (Some(directory), _) => format!("terminfo: private database {}", one_line(directory)),
            (None, Some(reason)) => format!(
                "terminfo: no private database ({}); the host's own applies",
                one_line(reason)
            ),
            (None, None) => "terminfo: no private database; the host's own applies".to_owned(),
        };
        if self.overridden() {
            line.push_str("; the creator's");
            if let Some(directory) = &self.creator_terminfo {
                line.push_str(&format!(" TERMINFO={}", one_line(directory)));
            }
            if let Some(directories) = &self.creator_terminfo_dirs {
                line.push_str(&format!(" TERMINFO_DIRS={}", one_line(directories)));
            }
            line.push_str(if self.directory.is_some() {
                " follow it"
            } else {
                " stay as they were"
            });
        }
        line
    }
}

/// `text` with every control character written as its escape, so it stays on one line and a
/// viewer cannot be made to break it or to reorder what follows.
///
/// That is every control character, the line and paragraph separators (U+2028, U+2029) and every
/// character the Unicode standard names a bidirectional control: the Arabic letter mark (U+061C),
/// the direction marks (U+200E, U+200F), the embeddings and overrides (U+202A to U+202E) and the
/// isolates (U+2066 to U+2069).
fn one_line(text: &str) -> String {
    text.chars()
        .flat_map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
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
    /// Why the worker has no private terminfo database, when it has none.
    pub terminfo_unavailable: Option<String>,
}

/// The variables a desktop context supplies, in the order a session needs them.
///
/// A desktop-bound session needs the display and the session bus to reach the desktop it belongs
/// to. A headless one has none of them, and passing a stale one through from a creator's snapshot
/// would point the session at a desktop that is not there.
pub const DESKTOP_VARIABLES: &[&str] = kr_protocol::hostinfo::configuration::DESKTOP_VARIABLES;

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
            terminfo_unavailable: None,
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
        unavailable: context.terminfo_unavailable.clone(),
        ..TerminfoSelection::default()
    };

    for variable in snapshot {
        if is_terminfo_search(&variable.name) {
            let held = if variable.name == TERMINFO_VARIABLE {
                &mut terminfo.creator_terminfo
            } else {
                &mut terminfo.creator_terminfo_dirs
            };
            *held = Some(variable.value.clone());
            if terminfo.directory.is_some() {
                // Searched after the private one, which is decided below once every variable has
                // been seen.
                continue;
            }
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
/// engine answers capability queries from. It lives in a directory named by a digest of the
/// compiled bytes, so a directory is never rewritten with other contents: a worker of a build whose
/// data differs writes a directory of its own, and a session started by an older build keeps
/// reading the database its own engine answers from. A directory that already holds the current
/// bytes is left alone, and a file is replaced whole, so workers of several sessions can do this at
/// once and none reads a partial file.
///
/// # Errors
///
/// Returns an error when the directory or a file in it cannot be written, or when the state
/// directory's path is not text an environment variable can carry.
#[cfg(unix)]
pub fn materialise_terminfo(state_dir: &std::path::Path) -> std::io::Result<PathBuf> {
    materialise_description(state_dir, &kr_term::terminfo::Description::pinned())
}

/// [`materialise_terminfo`] for any description, so the naming can be tested with two.
///
/// # Errors
///
/// As [`materialise_terminfo`], and when the description cannot be compiled.
#[cfg(unix)]
pub fn materialise_description(
    state_dir: &std::path::Path,
    description: &kr_term::terminfo::Description,
) -> std::io::Result<PathBuf> {
    use sha2::{Digest as _, Sha256};
    let bytes = description
        .compile()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let digest = Sha256::digest(&bytes);
    let name: String = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let directory = state_dir.join(TERMINFO_DIRECTORY).join(name);
    if directory.to_str().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the state directory's path is not valid text",
        ));
    }
    description.install(&directory)?;
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

    /// KR-REQ-07.25: one list of the names this host owns. What the worker removes from a
    /// creator's environment is what a configuration is refused as an addition, and no ordinary
    /// name is either.
    #[test]
    fn the_names_the_worker_removes_are_the_names_a_configuration_may_not_add() {
        use kr_protocol::hostinfo::configuration::host_owns_variable;

        let owned: Vec<&str> = DESKTOP_VARIABLES
            .iter()
            .chain(TERMINAL_IDENTITY_VARIABLES)
            .chain(CREATOR_TERMINAL_VARIABLES)
            .copied()
            .chain(["KR_SESSION", "KR_ANYTHING", "KONSOLE_DBUS_SESSION"])
            .collect();
        for name in owned {
            assert!(host_owns_variable(name), "{name} is owned");
            let built = built_with(&[(name, "from-a-creator")], &ExecutionContext::default());
            assert!(
                built.removed.iter().any(|removed| removed == name),
                "{name} is removed from a creator's environment"
            );
        }
        for name in [
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "EDITOR",
            "GOPATH",
            "TERMINFO_X",
        ] {
            assert!(
                !host_owns_variable(name),
                "{name} is nobody's but the person's"
            );
            let built = built_with(&[(name, "from-a-creator")], &ExecutionContext::default());
            assert_eq!(
                built.variables.get(name).map(String::as_str),
                Some("from-a-creator"),
                "{name} is kept"
            );
        }
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
        assert_eq!(built.sources.terminfo.directory, None);
        assert_eq!(
            built.sources.terminfo.creator_terminfo.as_deref(),
            Some("/home/a/.terminfo"),
            "the override is reported even when there is no private database"
        );
        assert!(built.sources.terminfo.overridden());
    }

    #[cfg(unix)]
    #[test]
    fn the_private_database_is_written_inside_the_state_directory() {
        let state = std::env::temp_dir().join(format!("kr-worker-terminfo-{}", std::process::id()));
        std::fs::create_dir_all(&state).expect("a state directory");
        let directory = materialise_terminfo(&state).expect("the database is written");
        assert_eq!(
            directory.parent(),
            Some(state.join(TERMINFO_DIRECTORY).as_path())
        );
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

    /// A worker of a build whose data differs writes a directory of its own, and the directory an
    /// older build's sessions read keeps the bytes that build's engine answers from.
    #[cfg(unix)]
    #[test]
    fn a_build_with_other_data_never_rewrites_the_directory_another_build_reads() {
        let state =
            std::env::temp_dir().join(format!("kr-worker-terminfo-two-{}", std::process::id()));
        std::fs::create_dir_all(&state).expect("a state directory");
        let older = kr_term::terminfo::Description::pinned();
        let mut newer = older.clone();
        newer
            .strings
            .insert("cup".to_owned(), "\x1b[%p2%d;%p1%dH".to_owned());
        let first = materialise_description(&state, &older).expect("the older build's database");
        let second = materialise_description(&state, &newer).expect("the newer build's database");
        assert_ne!(first, second, "the data differs, so the directory does");
        assert_eq!(
            std::fs::read(&older.entry_paths(&first)[0]).expect("the older entry"),
            older.compile().expect("compiles"),
            "the older build's directory still holds the older bytes"
        );
        assert_eq!(
            std::fs::read(&newer.entry_paths(&second)[0]).expect("the newer entry"),
            newer.compile().expect("compiles")
        );
        // And the older build writing again finds its own directory current, not the newer one.
        assert_eq!(
            materialise_description(&state, &older).expect("again"),
            first
        );
        let _ = std::fs::remove_dir_all(&state);
    }

    /// A creator's values are the creator's text: a line break in one cannot start a line of the
    /// worker's own.
    #[test]
    fn a_creators_value_cannot_end_the_line_the_worker_logs() {
        let hostile = built_with(
            &[
                (
                    "TERMINFO",
                    "/x\nkr-worker: session s: terminfo: private database /evil",
                ),
                ("TERMINFO_DIRS", "/a\r\u{1b}[31m:/b\u{85}c"),
            ],
            &with_private_database("/state/terminfo/ab"),
        );
        let line = hostile.sources.terminfo.describe();
        assert!(
            !line.chars().any(char::is_control),
            "the line holds a control character: {line:?}"
        );
        let separators = built_with(
            &[("TERMINFO", "/a\u{2028}b\u{2029}c\u{202e}d\u{200f}e")],
            &with_private_database("/state/terminfo/ab"),
        );
        let marked = separators.sources.terminfo.describe();
        assert!(
            !marked.chars().any(|character| matches!(
                character,
                '\u{2028}' | '\u{2029}' | '\u{202e}' | '\u{200f}'
            )),
            "the line holds a separator or a direction mark: {marked:?}"
        );
        assert!(
            marked.contains(r"/a\u{2028}b\u{2029}c\u{202e}d\u{200f}e"),
            "{marked}"
        );
        assert!(
            line.contains(r"TERMINFO=/x\nkr-worker: session s:"),
            "{line}"
        );
        assert!(line.contains(r"\r\u{1b}[31m"), "{line}");
        let plain = built_with(
            &[("TERMINFO", "/home/a/\u{e9}.terminfo")],
            &with_private_database("/state/terminfo/ab"),
        );
        assert!(
            plain
                .sources
                .terminfo
                .describe()
                .contains("/home/a/\u{e9}.terminfo"),
            "text that is not a control character is written as it is"
        );
    }

    /// Every character the Unicode standard names as a bidirectional control, and both separators,
    /// is written as an escape, and text that only reads right to left is not.
    #[test]
    fn every_bidirectional_control_and_separator_is_written_as_an_escape() {
        let controls = [
            '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
            '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{2028}', '\u{2029}',
        ];
        for control in controls {
            let built = built_with(
                &[("TERMINFO", &format!("/a{control}b"))],
                &with_private_database("/state/terminfo/ab"),
            );
            let line = built.sources.terminfo.describe();
            assert!(
                !line.contains(control),
                "U+{:04X} reached the line as it is: {line:?}",
                u32::from(control)
            );
            assert!(
                line.contains(&format!("/a{}b", control.escape_default())),
                "U+{:04X} is not written as its escape: {line:?}",
                u32::from(control)
            );
        }
        let arabic = built_with(
            &[(
                "TERMINFO",
                "/\u{627}\u{644}\u{639}\u{631}\u{628}\u{64a}\u{629}",
            )],
            &with_private_database("/state/terminfo/ab"),
        );
        assert!(
            arabic
                .sources
                .terminfo
                .describe()
                .contains("/\u{627}\u{644}\u{639}\u{631}\u{628}\u{64a}\u{629}"),
            "letters that read right to left are text, not controls"
        );
    }

    #[test]
    fn the_selection_reads_as_one_line_in_each_case() {
        let private = built_with(
            &[("TERMINFO", "/home/a/.terminfo")],
            &with_private_database("/state/terminfo/ab"),
        );
        assert_eq!(
            private.sources.terminfo.describe(),
            "terminfo: private database /state/terminfo/ab; the creator's \
             TERMINFO=/home/a/.terminfo follow it"
        );
        let failed = built_with(
            &[("TERMINFO_DIRS", "/opt/one")],
            &ExecutionContext {
                terminfo_unavailable: Some("the disk is full".to_owned()),
                ..ExecutionContext::default()
            },
        );
        assert_eq!(
            failed.sources.terminfo.describe(),
            "terminfo: no private database (the disk is full); the host's own applies; the \
             creator's TERMINFO_DIRS=/opt/one stay as they were"
        );
        assert_eq!(
            failed.variables.get("TERMINFO_DIRS").map(String::as_str),
            Some("/opt/one"),
            "a creator's search stays where the creator put it"
        );
    }
}
