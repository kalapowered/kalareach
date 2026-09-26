//! The backend an integrated invocation is given before it runs.
//!
//! Each case establishes backends the way the session does when the root shell asks to resolve an
//! invocation, from a Claude Code connector installed in the catalogue store's layout. What is
//! checked here is what establishing creates, what it refuses before creating anything, and when a
//! backend no launch took is retired. The launch that presents itself to a backend is proved with
//! the real launcher in `kr-hook`'s own suite.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a backend's endpoint, credential and launch record exist before the answer; a bypass creates nothing; one line runs one integrated invocation; each session has a root of its own; a declared package establishes with its flags and variables; a session entry whose flags are not the package's, a run that splits the flags and an executable no match rule recognises establish nothing; a bypassed invocation exports nothing |

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::root::{CwdRevision, PromptGeneration};
use kr_protocol::scalars::Uuid;
use kr_protocol::session::CommandIntegration;
use kr_worker::broker::Broker;
use kr_worker::broker::commands::{CommandBackends, CommandBackendsConfig, EstablishRequest};
use kr_worker::broker::connectors::{ConnectorSources, fixture};
use kr_worker::persistence::JournalHealth;

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// A short private directory, because a socket path has a small bound on every Unix.
fn private_directory(prefix: &str) -> PathBuf {
    let name: String = kr_ipc::new_uuid()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    let directory = std::env::temp_dir().join(format!("{prefix}{name}"));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is made private");
    }
    directory
}

/// Everything one case needs: a store with the connector installed, a launcher and an executable
/// on the internal disk, and the session's backends.
struct Setup {
    directory: PathBuf,
    backends: CommandBackends,
    broker: Arc<Broker>,
    executable: PathBuf,
    runtime: PathBuf,
}

impl Setup {
    fn new() -> Self {
        Self::with(|config| config)
    }

    fn with(adjust: impl FnOnce(CommandBackendsConfig) -> CommandBackendsConfig) -> Self {
        Self::shaped(&fixture::Shape::claude_code(), &["bin", "claude"], adjust)
    }

    /// A store with a package of `shape` installed, and its executable at `executable` inside the
    /// case's own directory.
    fn shaped(
        shape: &fixture::Shape,
        executable: &[&str],
        adjust: impl FnOnce(CommandBackendsConfig) -> CommandBackendsConfig,
    ) -> Self {
        let directory = private_directory("kcb");
        let bin = directory.join("bin");
        std::fs::create_dir_all(&bin).expect("a bin directory");
        let launcher = bin.join("kr-hook");
        let executable = executable
            .iter()
            .fold(directory.clone(), |path, part| path.join(part));
        std::fs::create_dir_all(executable.parent().expect("a directory"))
            .expect("the executable's directory");
        std::fs::copy("/bin/sleep", &launcher).expect("a launcher stands in");
        std::fs::copy("/bin/sleep", &executable).expect("an executable stands in");
        let sources = Arc::new(ConnectorSources::new());
        let store = directory.join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let source = fixture::package(&store, &launcher, shape).expect("the package");
        assert!(
            sources.replace(vec![source]).is_empty(),
            "the connector is installed"
        );
        // The case's own directory, so a backend's socket path stays inside the bound it has on
        // macOS: the session root and the backend's directory add two short levels below it.
        let runtime = directory.clone();
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
        let config = adjust(CommandBackendsConfig {
            session_id: session(),
            environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            os_user: "someone".to_owned(),
            runtime_dir: runtime.clone(),
            sources,
            launcher: Some(launcher),
        });
        let backends = CommandBackends::new(
            Arc::clone(&broker),
            config,
            tokio::runtime::Handle::current(),
        );
        Self {
            directory,
            backends,
            broker,
            executable,
            runtime,
        }
    }

    fn integration() -> CommandIntegration {
        CommandIntegration {
            command: fixture::COMMAND.to_owned(),
            flags: fixture::FLAGS
                .iter()
                .map(|flag| (*flag).to_owned())
                .collect(),
            enabled: true,
        }
    }

    /// The directories established so far, in the session's root, which the first establish makes.
    fn established(&self) -> Vec<PathBuf> {
        let Some(root) = self.backends.root() else {
            return Vec::new();
        };
        match std::fs::read_dir(root) {
            Ok(entries) => entries
                .map(|entry| entry.expect("an entry").path())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = self.backends.close();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn root_shell() -> ProcessStartIdentity {
    kr_ipc::identity::current_process_start_identity().expect("this process")
}

fn words(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

struct Invocation {
    typed: Vec<String>,
    arguments: Vec<String>,
    added: Vec<String>,
}

fn invocation(typed: &[&str]) -> Invocation {
    invocation_adding(typed, &fixture::FLAGS)
}

/// An invocation the shell answered by adding `added` after what was typed.
fn invocation_adding(typed: &[&str], added: &[&str]) -> Invocation {
    let added = words(added);
    let mut arguments = words(typed);
    arguments.extend(added.iter().cloned());
    Invocation {
        typed: words(typed),
        arguments,
        added,
    }
}

fn gemini(flags: &[&str]) -> CommandIntegration {
    CommandIntegration {
        command: "gemini".to_owned(),
        flags: words(flags),
        enabled: true,
    }
}

fn registration_name(answer: &kr_protocol::root::CommandBackend) -> String {
    PathBuf::from(&answer.environment[0].value)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a registration's name")
        .to_owned()
}

fn request<'a>(
    setup: &'a Setup,
    invocation: &'a Invocation,
    integration: &'a CommandIntegration,
    generation: u64,
) -> EstablishRequest<'a> {
    EstablishRequest {
        prompt_generation: PromptGeneration::new(generation),
        typed: &invocation.typed,
        arguments: &invocation.arguments,
        added: &invocation.added,
        integration,
        executable: setup.executable.to_str().expect("a text path"),
        cwd: setup.directory.to_str().expect("a text path"),
        cwd_revision: CwdRevision::new(1),
        root_shell: root_shell(),
    }
}

/// KR-REQ-12.07: an integrated resolve is answered with a backend whose endpoint, credential and
/// launch record exist before the answer does, and which reserves nothing yet.
#[tokio::test]
async fn kr_req_12_07_an_integrated_invocation_gets_a_backend_that_exists_before_the_answer() {
    let setup = Setup::new();
    let integration = Setup::integration();
    let claude = invocation(&["claude", "--resume"]);
    let answer = setup
        .backends
        .establish(&request(&setup, &claude, &integration, 5))
        .expect("a backend is established");
    assert_eq!(answer.session_id, session());
    assert_eq!(answer.prompt_generation, PromptGeneration::new(5));
    assert!(answer.launcher.ends_with("kr-hook"), "{}", answer.launcher);
    assert_eq!(
        answer.environment.len(),
        1,
        "one variable, the registration's path"
    );
    let variable = &answer.environment[0];
    assert_eq!(variable.name, "KR_REGISTRATION");
    let registration = PathBuf::from(&variable.value);
    assert_eq!(
        registration.file_name().and_then(|name| name.to_str()),
        Some("registration.2.2"),
        "the registration's name says the two added flags start at index 2"
    );
    let directory = registration
        .parent()
        .expect("the backend's directory")
        .to_path_buf();
    assert_eq!(setup.established(), vec![directory.clone()]);
    assert!(
        !registration.exists(),
        "no registration exists before a launch presents itself"
    );
    {
        use std::os::unix::fs::MetadataExt as _;
        let credential = std::fs::metadata(directory.join("credential")).expect("a credential");
        assert_eq!(credential.mode() & 0o077, 0, "the credential is owner-only");
    }
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("launch")).expect("a launch record"))
            .expect("the record is JSON");
    assert_eq!(
        record.as_object().map(|record| record.len()),
        Some(2),
        "the record says where to connect and where the credential is, and nothing else: {record}"
    );
    let endpoint = PathBuf::from(record["endpoint"].as_str().expect("an endpoint"));
    assert!(endpoint.exists(), "the endpoint is bound before the answer");
    assert_eq!(
        PathBuf::from(record["credential"].as_str().expect("a credential path")),
        directory.join("credential")
    );
}

/// KR-REQ-12.07: every bypass is decided before anything is created.
#[tokio::test]
async fn kr_req_12_07_a_bypassed_invocation_creates_nothing() {
    let setup = Setup::new();
    let integration = Setup::integration();

    let codex = invocation(&["codex"]);
    let other = CommandIntegration {
        command: "codex".to_owned(),
        ..Setup::integration()
    };
    setup
        .backends
        .establish(&request(&setup, &codex, &other, 1))
        .expect_err("no installed connector integrates codex");

    let stale = CommandIntegration {
        flags: words(&["--older-flag"]),
        ..Setup::integration()
    };
    let claude = invocation(&["claude"]);
    setup
        .backends
        .establish(&request(&setup, &claude, &stale, 2))
        .expect_err("flags the installed connector does not declare");

    let relative = EstablishRequest {
        executable: "bin/claude",
        ..request(&setup, &claude, &integration, 3)
    };
    setup
        .backends
        .establish(&relative)
        .expect_err("a relative executable");

    assert!(
        setup.backends.root().is_none(),
        "no bypass made a directory, an endpoint or a credential"
    );

    let without_launcher = Setup::with(|config| CommandBackendsConfig {
        launcher: None,
        ..config
    });
    without_launcher
        .backends
        .establish(&request(&without_launcher, &claude, &integration, 1))
        .expect_err("an installation with no launcher");
    assert!(without_launcher.established().is_empty());
}

/// On a platform that cannot prove a file closed to other accounts, nothing is established and
/// nothing is created.
#[tokio::test]
async fn a_platform_that_cannot_publish_a_credential_file_establishes_nothing() {
    let setup = Setup::new();
    let integration = Setup::integration();
    let claude = invocation(&["claude"]);
    let gated = CommandBackends::new(
        Arc::clone(&setup.broker),
        CommandBackendsConfig {
            session_id: session(),
            environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            os_user: "someone".to_owned(),
            runtime_dir: setup.runtime.clone(),
            sources: Arc::clone(setup.backends.sources()),
            launcher: Some(setup.directory.join("bin").join("kr-hook")),
        },
        tokio::runtime::Handle::current(),
    )
    .as_if_without_credential_files();
    gated
        .establish(&request(&setup, &claude, &integration, 1))
        .expect_err("refused before anything is made");
    assert!(gated.root().is_none(), "not even the session's root");
}

/// KR-REQ-12.07: one line runs one integrated invocation. A retry of the same invocation gets the
/// backend it was given; another invocation in the line runs as typed; a later line retires the
/// earlier line's backend no launch took, launch record and all.
#[tokio::test]
async fn kr_req_12_07_one_line_runs_one_integrated_invocation() {
    let setup = Setup::new();
    let integration = Setup::integration();
    let first = invocation(&["claude", "a"]);
    let answer = setup
        .backends
        .establish(&request(&setup, &first, &integration, 7))
        .expect("the first invocation gets a backend");
    let retried = setup
        .backends
        .establish(&request(&setup, &first, &integration, 7))
        .expect("a retry of the same invocation");
    assert_eq!(retried, answer, "the retry gets the backend it was given");

    let second = invocation(&["claude", "b"]);
    setup
        .backends
        .establish(&request(&setup, &second, &integration, 7))
        .expect_err("another invocation in the line runs as typed");
    let moved = EstablishRequest {
        cwd_revision: CwdRevision::new(2),
        ..request(&setup, &first, &integration, 7)
    };
    setup
        .backends
        .establish(&moved)
        .expect_err("the same words from another directory revision are another invocation");
    assert_eq!(setup.established().len(), 1);

    let directory = PathBuf::from(&answer.environment[0].value)
        .parent()
        .expect("the directory")
        .to_path_buf();
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("launch")).expect("a launch record"))
            .expect("JSON");
    let endpoint = PathBuf::from(record["endpoint"].as_str().expect("an endpoint"));
    setup
        .backends
        .establish(&request(&setup, &first, &integration, 8))
        .expect("the next line's invocation gets its own backend");
    assert!(!endpoint.exists(), "the earlier line's endpoint is gone");
    assert!(!directory.join("credential").exists(), "and its credential");
    assert!(
        !directory.join("launch").exists(),
        "and its launch record: a launcher that looks late runs what was typed, which the \
         variable's file name says"
    );
}

/// A finished command block ends its line, and a backend no launch took for it is retired.
#[tokio::test]
async fn a_finished_line_retires_its_unbound_backend() {
    let setup = Setup::new();
    let integration = Setup::integration();
    let claude = invocation(&["claude"]);
    let answer = setup
        .backends
        .establish(&request(&setup, &claude, &integration, 3))
        .expect("a backend");
    let directory = PathBuf::from(&answer.environment[0].value)
        .parent()
        .expect("the directory")
        .to_path_buf();
    setup.backends.line_ended(PromptGeneration::new(2));
    assert!(
        directory.join("credential").exists(),
        "an earlier line ending leaves this line's backend"
    );
    setup.backends.line_ended(PromptGeneration::new(3));
    assert!(!directory.join("credential").exists());
    assert!(!directory.join("launch").exists());
}

/// KR-REQ-12.07: two sessions whose identifiers share their first eight digits get roots of their
/// own, so closing one leaves the other's backend where it is.
#[tokio::test]
async fn kr_req_12_07_each_session_has_a_root_of_its_own() {
    let setup = Setup::new();
    let integration = Setup::integration();
    let claude = invocation(&["claude"]);
    let mut neighbour_id = [1_u8; 16];
    neighbour_id[4..].fill(9);
    let neighbour = CommandBackends::new(
        Arc::clone(&setup.broker),
        CommandBackendsConfig {
            session_id: SessionId::new(Uuid::from_bytes(neighbour_id)),
            environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            os_user: "someone".to_owned(),
            runtime_dir: setup.runtime.clone(),
            sources: Arc::clone(setup.backends.sources()),
            launcher: Some(setup.directory.join("bin").join("kr-hook")),
        },
        tokio::runtime::Handle::current(),
    );
    assert_eq!(
        session().to_string().get(..8),
        SessionId::new(Uuid::from_bytes(neighbour_id))
            .to_string()
            .get(..8),
        "the two identifiers share their first eight digits"
    );
    let mine = setup
        .backends
        .establish(&request(&setup, &claude, &integration, 1))
        .expect("a backend for this session");
    let theirs = neighbour
        .establish(&request(&setup, &claude, &integration, 1))
        .expect("a backend for the other");
    assert_ne!(setup.backends.root(), neighbour.root(), "separate roots");
    let _ = setup.backends.close();
    let their_directory = PathBuf::from(&theirs.environment[0].value)
        .parent()
        .expect("the directory")
        .to_path_buf();
    assert!(
        their_directory.join("credential").exists() && their_directory.join("launch").exists(),
        "closing one session leaves the other's backend"
    );
    assert!(
        !PathBuf::from(&mine.environment[0].value)
            .parent()
            .expect("the directory")
            .exists(),
        "and removes its own"
    );
    let _ = neighbour.close();
}

/// KR-REQ-12.07: a package that declares flags and a variable establishes with both: the flags
/// stand where the shell added them, and the answer exports the variable beside the registration,
/// in the order the package declares. Gemini CLI's own declaration adds no flag and exports its
/// variable all the same.
#[tokio::test]
async fn kr_req_12_07_a_declared_package_establishes_with_its_flags_and_variables() {
    let setup = Setup::shaped(
        &fixture::Shape::gemini_cli(&["--kalareach-probe"]),
        &["bin", "gemini"],
        |config| config,
    );
    let integration = gemini(&["--kalareach-probe"]);
    let resumed = invocation_adding(&["gemini", "--resume"], &["--kalareach-probe"]);
    let answer = setup
        .backends
        .establish(&request(&setup, &resumed, &integration, 3))
        .expect("a backend is established");
    let exported: Vec<(&str, &str)> = answer
        .environment
        .iter()
        .map(|variable| (variable.name.as_str(), variable.value.as_str()))
        .collect();
    assert_eq!(exported.len(), 2, "{exported:?}");
    assert_eq!(exported[0].0, "KR_REGISTRATION");
    assert_eq!(exported[1], ("GEMINI_CLI_NO_RELAUNCH", "true"));
    assert_eq!(registration_name(&answer), "registration.2.1");

    let only = Setup::shaped(
        &fixture::Shape::gemini_cli(&[]),
        &["bin", "gemini"],
        |config| config,
    );
    let plain = invocation_adding(&["gemini"], &[]);
    let answer = only
        .backends
        .establish(&request(&only, &plain, &gemini(&[]), 1))
        .expect("a backend is established");
    let names: Vec<&str> = answer
        .environment
        .iter()
        .map(|variable| variable.name.as_str())
        .collect();
    assert_eq!(names, ["KR_REGISTRATION", "GEMINI_CLI_NO_RELAUNCH"]);
    assert_eq!(registration_name(&answer), "registration.0.0");
}

/// KR-REQ-12.07: the session's entry is checked against the package the installation verified:
/// flags other than the declared ones, or the declared ones in another order, establish nothing.
#[tokio::test]
async fn kr_req_12_07_a_session_entry_whose_flags_are_not_the_package_s_establishes_nothing() {
    let setup = Setup::new();
    let claude = invocation(&["claude"]);
    for flags in [
        vec![fixture::FLAGS[0]],
        vec![fixture::FLAGS[1], fixture::FLAGS[0]],
        vec![fixture::FLAGS[0], fixture::FLAGS[1], "--more"],
    ] {
        let entry = CommandIntegration {
            flags: words(&flags),
            ..Setup::integration()
        };
        setup
            .backends
            .establish(&request(&setup, &claude, &entry, 1))
            .expect_err("flags the installed package does not declare");
    }
    assert!(setup.backends.root().is_none(), "nothing was created");
}

/// KR-REQ-12.07: the integration's flags are added whole or not at all. A run that leaves one out,
/// as the shell's answer does when the person typed that one, establishes nothing, so the command
/// runs as typed; one the person typed whole establishes with nothing added.
#[tokio::test]
async fn kr_req_12_07_the_flags_are_added_whole_or_not_at_all() {
    let setup = Setup::new();
    let integration = Setup::integration();
    let split = invocation_adding(&["claude", fixture::FLAGS[0]], &[fixture::FLAGS[1]]);
    setup
        .backends
        .establish(&request(&setup, &split, &integration, 1))
        .expect_err("a value added without its flag");
    assert!(setup.backends.root().is_none(), "nothing was created");
    let typed = invocation_adding(&["claude", fixture::FLAGS[0], fixture::FLAGS[1]], &[]);
    let answer = setup
        .backends
        .establish(&request(&setup, &typed, &integration, 2))
        .expect("the person typed the flags themselves");
    assert_eq!(registration_name(&answer), "registration.0.0");
}

/// A match rule that names the directory an executable is in holds the resolved executable to
/// it: the same name anywhere else establishes nothing.
#[tokio::test]
async fn an_executable_outside_the_directory_its_match_rule_names_establishes_nothing() {
    let shape = fixture::Shape {
        directory: &[".claude-local", "bin"],
        ..fixture::Shape::claude_code()
    };
    let integration = Setup::integration();
    let claude = invocation(&["claude"]);
    let inside = Setup::shaped(&shape, &[".claude-local", "bin", "claude"], |config| config);
    inside
        .backends
        .establish(&request(&inside, &claude, &integration, 1))
        .expect("the executable where the rule names it");
    let outside = Setup::shaped(&shape, &["bin", "claude"], |config| config);
    outside
        .backends
        .establish(&request(&outside, &claude, &integration, 1))
        .expect_err("the executable in a directory the rule does not name");
    assert!(outside.backends.root().is_none(), "nothing was created");
}

/// KR-REQ-12.07: a bypassed invocation exports nothing. The answer for an absolute path, a
/// disabled integration or an unmanaged shell names no backend, and so no variable, whatever the
/// worker established for the same words; an invocation the worker refuses gets no answer to
/// export from.
#[tokio::test]
async fn kr_req_12_07_a_bypassed_invocation_exports_nothing() {
    use kr_shell_integration::host::command::{InvocationContext, resolve};

    let setup = Setup::shaped(
        &fixture::Shape::gemini_cli(&["--kalareach-probe"]),
        &["bin", "gemini"],
        |config| config,
    );
    let integration = gemini(&["--kalareach-probe"]);
    let established = setup
        .backends
        .establish(&request(
            &setup,
            &invocation_adding(&["gemini"], &["--kalareach-probe"]),
            &integration,
            1,
        ))
        .expect("a backend is established");
    assert!(
        established
            .environment
            .iter()
            .any(|variable| variable.name == "GEMINI_CLI_NO_RELAUNCH")
    );
    let managed = InvocationContext {
        managed_root_shell: true,
        interactive: true,
    };
    let disabled = CommandIntegration {
        enabled: false,
        ..integration.clone()
    };
    for (entry, context, argv) in [
        (&integration, managed, words(&["/usr/local/bin/gemini"])),
        (&disabled, managed, words(&["gemini"])),
        (
            &integration,
            InvocationContext {
                managed_root_shell: false,
                interactive: true,
            },
            words(&["gemini"]),
        ),
    ] {
        let resolution = resolve(std::slice::from_ref(entry), context, &argv);
        assert!(!resolution.establishes_backend(), "{argv:?}");
        let answer = resolution.to_answer(Some(established.clone()));
        assert!(
            answer.backend.0.is_none(),
            "{argv:?}: no backend, so no variable"
        );
        assert!(answer.added.is_empty(), "{argv:?}");
        assert!(answer.bypass.0.is_some(), "{argv:?}");
    }
    setup
        .backends
        .establish(&request(
            &setup,
            &invocation_adding(&["gemini"], &["--other"]),
            &gemini(&["--other"]),
            2,
        ))
        .expect_err("an invocation the worker refuses has nothing to export");
}
