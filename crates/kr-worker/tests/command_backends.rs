//! The backend an integrated invocation is given before it runs.
//!
//! Each case establishes backends the way the session does when the root shell asks to resolve an
//! invocation, from a Claude Code connector installed in the catalogue store's layout. What is
//! checked here is what establishing creates, what it refuses before creating anything, and when a
//! backend no launch took is retired. The launch that presents itself to a backend is proved with
//! the real launcher in `kr-hook`'s own suite. The launcher and the application a case stands in for
//! are copies of a program the machine has: `sleep` on Unix and `cmd.exe` on Windows.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.07 | a backend's endpoint, credential and launch record exist before the answer; a bypass creates nothing; one line runs one integrated invocation; each session has a root of its own; a declared package establishes with its flags, and its variables in the launch record rather than the answer; a session entry whose flags are not the package's, a run that splits the flags and an executable no match rule recognises establish nothing; a bypassed invocation exports nothing |

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
    kr_ipc::paths::create_private_directory(&directory).expect("a private directory");
    directory
}

/// The program a case's launcher and application are copies of: one every machine of the platform
/// has, which is never run here.
fn stand_in_program() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(std::env::var_os("SystemRoot").expect("a system directory"))
            .join("System32")
            .join("cmd.exe")
    } else {
        PathBuf::from("/bin/sleep")
    }
}

/// An executable's file name on this platform.
fn executable_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

/// Says that the endpoint a launch record names is gone.
///
/// A socket's file is removed as the backend is retired, so it is gone when `establish` returns. A
/// pipe is gone when the last handle to it closes, which is when the listener's task has been
/// dropped, and that task is dropped by the runtime and not by the caller that retired the backend,
/// so there it is waited for, within the liveness bound.
async fn endpoint_goes(endpoint: &str) {
    if cfg!(unix) {
        assert!(
            !endpoint_exists(endpoint),
            "the earlier line's endpoint is gone"
        );
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while endpoint_exists(endpoint) {
        assert!(
            std::time::Instant::now() < deadline,
            "the earlier line's endpoint is gone"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Whether the endpoint a launch record names exists: a socket's path on Unix, and a pipe in the
/// system's list of them on Windows, which is read without connecting to any.
fn endpoint_exists(endpoint: &str) -> bool {
    match endpoint.strip_prefix(r"\\.\pipe\") {
        Some(name) => std::fs::read_dir(r"\\.\pipe\").is_ok_and(|mut pipes| {
            pipes.any(|pipe| pipe.is_ok_and(|pipe| pipe.file_name().to_string_lossy() == name))
        }),
        None => std::path::Path::new(endpoint).exists(),
    }
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
        let launcher = bin.join(executable_name("kr-hook"));
        let executable = executable
            .iter()
            .fold(directory.clone(), |path, part| path.join(part));
        let executable = executable.with_file_name(executable_name(
            &executable
                .file_name()
                .expect("a file name")
                .to_string_lossy(),
        ));
        std::fs::create_dir_all(executable.parent().expect("a directory"))
            .expect("the executable's directory");
        std::fs::copy(stand_in_program(), &launcher).expect("a launcher stands in");
        std::fs::copy(stand_in_program(), &executable).expect("an executable stands in");
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
            registered_forwarder: Some(launcher.clone()),
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
            plugin_id: kr_protocol::ids::PluginId::new("kalareach/claude-code")
                .expect("a plugin identifier"),
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
        plugin_id: kr_protocol::ids::PluginId::new("kalareach/gemini-cli")
            .expect("a plugin identifier"),
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
    assert!(
        answer.launcher.ends_with(&executable_name("kr-hook")),
        "{}",
        answer.launcher
    );
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
    // Read as the host reads it: a file another account can read, by its mode or by its access
    // list, is refused and not read.
    kr_ipc::paths::read_owner_only_file(&directory.join("credential"), 4096)
        .expect("the credential is owner-only")
        .expect("a credential");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("launch")).expect("a launch record"))
            .expect("the record is JSON");
    assert_eq!(
        record.as_object().map(|record| record.len()),
        Some(3),
        "the record says where to connect, where the credential is and which variables the \
         package declares, and nothing else: {record}"
    );
    assert_eq!(
        record["variables"],
        serde_json::json!([]),
        "Claude Code's integration declares no variable"
    );
    let endpoint = record["endpoint"].as_str().expect("an endpoint");
    assert!(
        endpoint_exists(endpoint),
        "the endpoint is bound before the answer"
    );
    assert_eq!(
        PathBuf::from(record["credential"].as_str().expect("a credential path")),
        directory.join("credential")
    );
}

/// KR-REQ-12.07: a session's entry names the package it was created with. Where another package
/// integrates the command here, even one that declares the same flags, the entry establishes
/// nothing, so a package whose integration the configuration never turned on is never taken for
/// the one it did. Control: the entry for the package itself establishes.
#[tokio::test]
async fn kr_req_12_07_an_entry_for_another_package_establishes_nothing() {
    let setup = Setup::new();
    let claude = invocation(&["claude"]);
    let another = CommandIntegration {
        plugin_id: kr_protocol::ids::PluginId::new("someone/claude-code")
            .expect("a plugin identifier"),
        ..Setup::integration()
    };
    setup
        .backends
        .establish(&request(&setup, &claude, &another, 1))
        .expect_err("another package integrates claude here");
    assert!(setup.backends.root().is_none(), "nothing was created");
    setup
        .backends
        .establish(&request(&setup, &claude, &Setup::integration(), 2))
        .expect("the package the session was created with");
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
        registered_forwarder: None,
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
            launcher: Some(setup.directory.join("bin").join(executable_name("kr-hook"))),
            registered_forwarder: Some(
                setup.directory.join("bin").join(executable_name("kr-hook")),
            ),
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
    let endpoint = record["endpoint"].as_str().expect("an endpoint").to_owned();
    setup
        .backends
        .establish(&request(&setup, &first, &integration, 8))
        .expect("the next line's invocation gets its own backend");
    endpoint_goes(&endpoint).await;
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
            launcher: Some(setup.directory.join("bin").join(executable_name("kr-hook"))),
            registered_forwarder: Some(
                setup.directory.join("bin").join(executable_name("kr-hook")),
            ),
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

/// The variables a backend's launch record names, in order, for the launcher to set once the launch
/// is committed.
fn recorded_variables(answer: &kr_protocol::root::CommandBackend) -> Vec<(String, String)> {
    let directory = PathBuf::from(&answer.environment[0].value)
        .parent()
        .expect("the backend's directory")
        .to_path_buf();
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.join("launch")).expect("the launch record"),
    )
    .expect("the launch record is JSON");
    record["variables"]
        .as_array()
        .expect("the record names the variables")
        .iter()
        .map(|variable| {
            (
                variable["name"].as_str().expect("a name").to_owned(),
                variable["value"].as_str().expect("a value").to_owned(),
            )
        })
        .collect()
}

/// KR-REQ-12.07, KR-REQ-12.20: a package that declares flags and a variable establishes with both:
/// the flags stand where the shell added them, the answer exports the registration alone, and the
/// launch record names the variable, in the order the package declares, for the launcher to set
/// once the launch is committed. Gemini CLI's own declaration adds no flag and records its variable
/// all the same.
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
    let exported: Vec<&str> = answer
        .environment
        .iter()
        .map(|variable| variable.name.as_str())
        .collect();
    assert_eq!(
        exported,
        ["KR_REGISTRATION"],
        "the shell exports the registration alone"
    );
    assert_eq!(
        recorded_variables(&answer),
        [("GEMINI_CLI_NO_RELAUNCH".to_owned(), "true".to_owned())]
    );
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
    assert_eq!(names, ["KR_REGISTRATION"]);
    assert_eq!(
        recorded_variables(&answer),
        [("GEMINI_CLI_NO_RELAUNCH".to_owned(), "true".to_owned())]
    );
    assert_eq!(registration_name(&answer), "registration.0.0");

    // A package that declares no variable records none.
    let claude = Setup::new();
    let answer = claude
        .backends
        .establish(&request(
            &claude,
            &invocation(&["claude"]),
            &Setup::integration(),
            1,
        ))
        .expect("a backend is established");
    assert!(recorded_variables(&answer).is_empty());
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

fn qoder(flags: Vec<String>) -> CommandIntegration {
    CommandIntegration {
        plugin_id: kr_protocol::ids::PluginId::new("kalareach/qoder-cli")
            .expect("a plugin identifier"),
        command: "qodercli".to_owned(),
        flags,
        enabled: true,
    }
}

/// KR-REQ-12.22: a package whose flags name the forwarder by the placeholder is compared with the
/// session's flags after the same replacement: the session's entry, which the daemon wrote with the
/// installed forwarder's path, establishes, and the answer adds those flags. An entry holding the
/// package's text as declared, the path of another forwarder, or a worker that can name no
/// forwarder, establishes nothing.
#[tokio::test]
async fn kr_req_12_22_flags_that_name_the_forwarder_are_compared_after_it_is_written() {
    let setup = Setup::shaped(
        &fixture::Shape::qoder_cli(),
        &["bin", "qodercli"],
        |config| config,
    );
    let forwarder = setup.directory.join("bin").join(executable_name("kr-hook"));
    let declared = fixture::qoder_flags();
    let written = kr_plugin_sdk::forwarder::expand_flags(&declared, Some(&forwarder))
        .expect("the flags are written with the forwarder");
    assert_ne!(written, declared, "the placeholder is replaced");

    let answered = invocation_adding(
        &["qodercli"],
        &written.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    setup
        .backends
        .establish(&request(&setup, &answered, &qoder(written.clone()), 1))
        .expect("the entry the daemon wrote establishes");
    assert_eq!(
        registration_name(
            &setup
                .backends
                .establish(&request(&setup, &answered, &qoder(written.clone()), 1))
                .expect("a retry gets the backend it was given")
        ),
        "registration.1.2"
    );

    for (why, entry) in [
        ("the package's text as declared", qoder(declared.clone())),
        (
            "another forwarder's path",
            qoder(
                kr_plugin_sdk::forwarder::expand_flags(
                    &declared,
                    Some(
                        &setup
                            .directory
                            .join("elsewhere")
                            .join(executable_name("kr-hook")),
                    ),
                )
                .expect("written"),
            ),
        ),
    ] {
        let later = invocation_adding(
            &["qodercli"],
            &entry.flags.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        setup
            .backends
            .establish(&request(&setup, &later, &entry, 2))
            .expect_err(why);
    }

    let without = Setup::shaped(
        &fixture::Shape::qoder_cli(),
        &["bin", "qodercli"],
        |config| CommandBackendsConfig {
            registered_forwarder: None,
            ..config
        },
    );
    without
        .backends
        .establish(&request(&without, &answered, &qoder(written), 1))
        .expect_err("a worker that can name no forwarder cannot write the flags");
    assert!(without.backends.root().is_none(), "and nothing is created");
}

/// KR-REQ-12.22: flags that start the forwarder by its bare name, as the packages written before the
/// placeholder do, are integrated where the application finds a program by its search path, and
/// nowhere that it looks in its own working directory first: on Windows they establish nothing and the
/// invocation runs as typed. The control is the same package's flags with the forwarder's path.
#[tokio::test]
async fn kr_req_12_22_flags_that_start_the_forwarder_by_its_bare_name_are_not_integrated_on_windows()
 {
    let declared = fixture::qoder_flags();
    let bare: Vec<String> = declared
        .iter()
        .map(|flag| flag.replace(kr_plugin_sdk::forwarder::PLACEHOLDER, "kr-hook"))
        .collect();
    assert_ne!(bare, declared, "the placeholder is replaced");
    let mut shape = fixture::Shape::qoder_cli();
    shape.integration.as_mut().expect("an integration")["flags"] = serde_json::json!(bare);
    let setup = Setup::shaped(&shape, &["bin", "qodercli"], |config| config);
    let answered = invocation_adding(
        &["qodercli"],
        &bare.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let established =
        setup
            .backends
            .establish(&request(&setup, &answered, &qoder(bare.clone()), 1));
    if cfg!(windows) {
        let why = established.expect_err("a bare name is searched for in the working directory");
        assert!(why.contains("bare name"), "{why}");
        assert!(setup.backends.root().is_none(), "nothing was created");
    } else {
        established.expect("where a program is found by the search path, the bare name stands");
    }
}

/// KR-REQ-12.07: where the shell finds a shim and not a program, the invocation establishes nothing
/// and the reason names it: `first hit is <the shim>`. A `.cmd`, a `.bat` and a `.ps1` are run by an
/// interpreter whose identity is not the agent's, so no launch of one could name the agent. Where
/// names are exact there are no shims and the same files are programs. The control on every platform
/// is the program itself.
#[tokio::test]
async fn kr_req_12_07_a_shim_is_the_first_hit_and_establishes_nothing() {
    let setup = Setup::new();
    let integration = Setup::integration();
    let claude = invocation(&["claude"]);
    setup
        .backends
        .establish(&request(&setup, &claude, &integration, 1))
        .expect("the program establishes");
    setup.backends.line_ended(PromptGeneration::new(1));

    for (generation, name) in ["claude.cmd", "claude.bat", "claude.ps1"]
        .into_iter()
        .enumerate()
    {
        let shim = setup.directory.join("bin").join(name);
        std::fs::copy(stand_in_program(), &shim).expect("a shim stands in");
        let asked = EstablishRequest {
            executable: shim.to_str().expect("a text path"),
            ..request(&setup, &claude, &integration, 10 + generation as u64)
        };
        let answered = setup.backends.establish(&asked);
        if cfg!(windows) {
            let why = answered.expect_err(name);
            assert!(
                why.starts_with(&format!("first hit is {}", shim.display())),
                "{name}: {why}"
            );
        } else {
            answered.expect(name);
            setup
                .backends
                .line_ended(PromptGeneration::new(10 + generation as u64));
        }
    }
}

/// KR-REQ-12.07: a command is looked up by the name its platform gives the file: on Windows
/// `CLAUDE`, `Claude.EXE` and `claude.com` are the integrated `claude`, and the vector the answer
/// runs keeps what was typed; where names are exact they are other commands and nothing is
/// established.
#[tokio::test]
async fn kr_req_12_07_a_command_is_looked_up_by_the_name_its_platform_gives_the_file() {
    let setup = Setup::new();
    let integration = Setup::integration();
    for (generation, typed) in ["CLAUDE", "Claude.EXE", "claude.com"]
        .into_iter()
        .enumerate()
    {
        let spelt = invocation(&[typed, "--resume"]);
        let asked = request(&setup, &spelt, &integration, 1 + generation as u64);
        let answered = setup.backends.establish(&asked);
        if cfg!(windows) {
            let backend = answered.unwrap_or_else(|why| panic!("{typed}: {why}"));
            assert!(
                backend.launcher.ends_with(&executable_name("kr-hook")),
                "{typed}"
            );
            assert_eq!(
                registration_name(&backend),
                "registration.2.2",
                "{typed}: the flags stand after what was typed"
            );
            setup
                .backends
                .line_ended(PromptGeneration::new(1 + generation as u64));
        } else {
            answered.expect_err(typed);
        }
    }
    assert!(
        cfg!(windows) || setup.backends.root().is_none(),
        "a command of another name creates nothing"
    );
}

/// KR-REQ-12.07: a package whose rule names a program with a `.com` file stem recognises it by the
/// name it declares, though a command is looked up without its `.com`.
#[cfg(windows)]
#[tokio::test]
async fn kr_req_12_07_a_rule_whose_file_stem_ends_in_com_recognises_the_command_it_names() {
    let shape = fixture::Shape {
        executable: "agent.com",
        integration: Some(fixture::declaration("agent.com", &fixture::FLAGS, &[])),
        native_bridge: false,
        ..fixture::Shape::claude_code()
    };
    let setup = Setup::shaped(&shape, &["bin", "agent.com"], |config| config);
    let integration = CommandIntegration {
        command: "agent.com".to_owned(),
        ..Setup::integration()
    };
    setup
        .backends
        .establish(&request(
            &setup,
            &invocation(&["agent.com"]),
            &integration,
            1,
        ))
        .expect("the package that declares the name recognises it");
}

/// KR-REQ-12.07: two packages whose integrated commands the platform reads as one name are both left
/// out, as two that spell it alike are, so a package cannot take a command another integrates by
/// spelling it another way. The control is a pair of packages whose commands are two names, which
/// both integrate.
#[cfg(windows)]
#[test]
fn kr_req_12_07_two_packages_whose_commands_are_one_name_integrate_neither() {
    let directory = private_directory("kcn");
    let launcher = directory.join(executable_name("kr-hook"));
    std::fs::copy(stand_in_program(), &launcher).expect("a launcher stands in");
    let package = |pair: &str, name: &'static str, executable: &'static str, command: &str| {
        let root = directory.join(pair).join(name);
        std::fs::create_dir_all(&root).expect("a store");
        fixture::package(
            &root,
            &launcher,
            &fixture::Shape {
                plugin_name: name,
                executable,
                integration: Some(fixture::declaration(command, &fixture::FLAGS, &[])),
                native_bridge: false,
                ..fixture::Shape::claude_code()
            },
        )
        .expect("the package is written")
    };

    let two_names = ConnectorSources::new();
    let refused = two_names.replace(vec![
        package("two", "claude-code", "claude", "claude"),
        package("two", "codex-cli", "codex", "codex"),
    ]);
    assert!(refused.is_empty(), "two commands integrate: {refused:?}");
    assert!(two_names.for_command("Claude.EXE").is_some());
    assert!(two_names.for_command("codex").is_some());

    let one_name = ConnectorSources::new();
    let refused = one_name.replace(vec![
        package("one", "claude-code", "claude", "claude"),
        package("one", "claude-shadow", "claude.exe", "claude.exe"),
    ]);
    assert_eq!(refused.len(), 2, "both packages are left out");
    assert!(one_name.for_command("claude").is_none());
    assert!(one_name.for_command("CLAUDE.exe").is_none());
    let _ = std::fs::remove_dir_all(&directory);
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
    assert_eq!(
        recorded_variables(&established),
        [("GEMINI_CLI_NO_RELAUNCH".to_owned(), "true".to_owned())]
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
