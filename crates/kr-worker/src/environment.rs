//! Building the root shell's environment.
//!
//! Section 7 sets out three rules that decide every variable. The creator's snapshot is an input,
//! not a promise: execution-context values take precedence over it. Physical-terminal identity is
//! removed rather than passed through, because a shell that believes it is inside iTerm2 will
//! enable features this terminal does not supply. Reserved KalaReach values come only from the
//! worker, so a caller cannot smuggle one in through its own environment.

use std::collections::BTreeMap;

use kr_protocol::session::EnvironmentVariable;

/// The terminal identity every KalaReach session declares.
pub const TERM: &str = "xterm-256color";

/// The colour support every KalaReach session declares.
pub const COLORTERM: &str = "truecolor";

/// The terminal program every KalaReach session declares.
pub const TERM_PROGRAM: &str = "KalaReach";

/// The variable that names the session a command is running inside.
///
/// It identifies a candidate session, never an authority: the host validates the caller's local
/// peer and its session binding before it accepts anything quoted from here.
pub const SESSION_VARIABLE: &str = "KR_SESSION";

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
        }
    }
}

/// Reads the login session a desktop-bound worker is tied to.
///
/// The generation is what makes the binding checkable later: a session identifier that is reused
/// after a logout names a different login, and a worker that compared only the identifier would
/// keep running against a desktop that had gone.
#[must_use]
pub fn desktop_binding() -> kr_protocol::identity::DesktopBinding {
    let named = std::env::var("XDG_SESSION_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("SECURITYSESSIONID").ok());
    let generation = named.as_deref().and_then(|value| {
        u64::from_str_radix(value.trim().trim_start_matches("0x"), 16)
            .ok()
            .or_else(|| value.trim().parse::<u64>().ok())
    });
    kr_protocol::identity::DesktopBinding {
        desktop_session_id: kr_protocol::scalars::Nullable(named.and_then(|value| {
            kr_protocol::ids::DesktopSessionId::new(value.trim().to_owned()).ok()
        })),
        login_generation: kr_protocol::scalars::Nullable(
            generation.map(kr_protocol::scalars::U64::new),
        ),
    }
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

    for variable in snapshot {
        if is_terminal_identity(&variable.name) || is_creator_terminal(&variable.name) {
            removed.push(variable.name.clone());
            continue;
        }
        if variable.name.starts_with(RESERVED_PREFIX) {
            // Reserved bootstrap values come from the worker. A creator cannot preload one.
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
}
