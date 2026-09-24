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
//! | KR-REQ-12.07 | a backend's endpoint, credential and launch record exist before the answer; a bypass creates nothing; one line runs one integrated invocation |

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
    root: PathBuf,
}

impl Setup {
    fn new() -> Self {
        Self::with(|config| config)
    }

    fn with(adjust: impl FnOnce(CommandBackendsConfig) -> CommandBackendsConfig) -> Self {
        let directory = private_directory("kr-cb-");
        let bin = directory.join("bin");
        std::fs::create_dir_all(&bin).expect("a bin directory");
        let launcher = bin.join("kr-hook");
        let executable = bin.join("claude");
        std::fs::copy("/bin/sleep", &launcher).expect("a launcher stands in");
        std::fs::copy("/bin/sleep", &executable).expect("an executable stands in");
        let sources = Arc::new(ConnectorSources::new());
        let store = directory.join("store");
        std::fs::create_dir_all(&store).expect("a store");
        let source = fixture::claude_code_package(&store, &launcher).expect("the package");
        assert!(
            sources.replace(vec![source]).is_empty(),
            "the connector is installed"
        );
        let root = directory.join("c");
        let broker = Arc::new(
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
        );
        let config = adjust(CommandBackendsConfig {
            session_id: session(),
            environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            os_user: "someone".to_owned(),
            root: root.clone(),
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
            root,
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

    /// The directories established so far.
    fn established(&self) -> Vec<PathBuf> {
        match std::fs::read_dir(&self.root) {
            Ok(entries) => entries
                .map(|entry| entry.expect("an entry").path())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.backends.close();
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
    let added = words(&fixture::FLAGS);
    let mut arguments = words(typed);
    arguments.extend(added.iter().cloned());
    Invocation {
        typed: words(typed),
        arguments,
        added,
    }
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
    assert_eq!(record["added"], serde_json::json!(fixture::FLAGS));
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
        setup.established().is_empty(),
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
            root: setup.root.clone(),
            sources: Arc::clone(setup.backends.sources()),
            launcher: Some(setup.directory.join("bin").join("kr-hook")),
        },
        tokio::runtime::Handle::current(),
    )
    .as_if_without_credential_files();
    gated
        .establish(&request(&setup, &claude, &integration, 1))
        .expect_err("refused before anything is made");
    assert!(setup.established().is_empty());
}

/// KR-REQ-12.07: one line runs one integrated invocation. A retry of the same invocation gets the
/// backend it was given; another invocation in the line runs as typed; a later line retires the
/// earlier line's backend no launch took, and leaves its launch record.
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
        directory.join("launch").exists(),
        "its launch record stays, for a launcher that looks late"
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
    assert!(directory.join("launch").exists());
}
