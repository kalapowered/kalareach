//! The contact skill's installation through the control daemon, and what a refused change leaves
//! behind.
//!
//! Two things are covered here.
//!
//! * **An installation a client can read.** The daemon installs `kalareach-contact` at user and
//!   project scope, records the removal operations that undo it, reports that record, and removes
//!   exactly what it recorded. The daemon is the `kr-controller` binary, run as a process of its
//!   own with a home directory the test made, because a user-scope installation resolves an agent's
//!   configuration from the daemon's own home. Each answer is decoded the way `kr skill` decodes it.
//! * **A refusal before the marker.** Installing and removing change files, so section 9 applies: a
//!   marker is written before the change and an outcome after it, and a marker with no outcome means
//!   the change may have happened. A change the daemon will not make must be refused *before* the
//!   marker, or an exact retry would answer `OUTCOME_UNKNOWN` about a change that never began, and
//!   the person asking would be told to go and look at files nothing ever touched. The refusal used
//!   is a removal at project scope with no project directory: it is decided from the request alone,
//!   so nothing outside this test's own temporary host is read or written.
//!
//! Nothing outside a test's own temporary tree is read or written. The daemon keeps its keys in
//! that tree's secrets directory, and its binary is copied into the tree, on the internal disk,
//! before it is started.

use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::skill::{AgentTarget, AgentToolsParams, InstallScope};

/// A supervisor that starts nothing. No worker is needed to ask the daemon to remove a skill.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

struct Host {
    _temp: kr_ipc::testing::TempHost,
    _controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    state_dir: std::path::PathBuf,
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let state_dir = environment.state_dir().to_path_buf();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(NoWorkers),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    Host {
        _temp: temp,
        _controller: controller,
        environment_id,
        endpoint,
        state_dir,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_the_daemon_will_not_do_leaves_no_dispatch_marker() {
    let host = host().await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let target = ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    // A project removal that says nothing about which project. There is no such removal to do.
    let params = AgentToolsParams {
        agent: AgentTarget::Codex,
        scope: InstallScope::Project,
        project_dir: Nullable::null(),
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());

    let refused = client
        .mutate(Method::AgentToolsRemove, action_id, target.clone(), &params)
        .await
        .expect("the call reaches the daemon")
        .expect_err("and is refused");

    // The request is what is wrong with it, on every platform: the daemon gets as far as asking
    // which project the removal is for.
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    let actions = host.state_dir.join("agent-tools/actions");
    assert!(
        !actions.exists()
            || std::fs::read_dir(&actions)
                .expect("reads the directory")
                .next()
                .is_none(),
        "a refusal before the change writes no marker, so an exact retry is refused again rather \
         than answered as an outcome nobody knows"
    );

    // The same request again is refused the same way, not answered with an unknown outcome.
    let again = client
        .mutate(Method::AgentToolsRemove, action_id, target, &params)
        .await
        .expect("the call reaches the daemon")
        .expect_err("and is refused again");
    assert_eq!(again.code, ErrorCode::InvalidArgument, "{again:?}");
}

mod fence_support;

/// KR-REQ-09.09, 09.12 and 26.16: a withdrawal whose fence could not be raised stops an
/// installation before its dispatch marker. The daemon admits the change on its own socket; at the
/// marker it asks the check every service asks from inside its work, under the connection table
/// the marker is written beside, and the refusal is the fence's own. The installation is Codex's at
/// project scope, into a directory of this test's own: nothing is written there, and no marker is
/// left, so an exact retry is refused again rather than answered as an outcome nobody knows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_is_not_dispatched_while_a_fence_is_owed() {
    let host = host().await;
    let project = tempfile::TempDir::new().expect("a project directory on the internal disk");
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let registry = fence_support::owe_a_fence(&host._controller, &host._temp.environment()).await;
    let target = ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let params = AgentToolsParams {
        agent: AgentTarget::Codex,
        scope: InstallScope::Project,
        project_dir: Nullable::some(project.path().display().to_string()),
    };

    let refused = client
        .mutate(
            Method::AgentToolsInstall,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("the fence stops the installation");

    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("could not be raised"),
        "{refused:?}"
    );
    assert!(
        std::fs::read_dir(project.path())
            .expect("reads the project directory")
            .next()
            .is_none(),
        "nothing was written into the project"
    );
    let actions = host.state_dir.join("agent-tools/actions");
    assert!(
        !actions.exists()
            || std::fs::read_dir(&actions)
                .expect("reads the directory")
                .next()
                .is_none(),
        "a refusal before the change writes no marker"
    );
    fence_support::clear_the_fault(&registry);
}

/// A daemon this test started, killed where it stands when it goes out of scope.
struct Daemon(Option<std::process::Child>);

impl Daemon {
    fn kill(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Starts the copied daemon on this test's directories, with `home` as its home directory.
fn start_daemon(
    program: &std::path::Path,
    host: &kr_ipc::testing::TempHost,
    home: &std::path::Path,
) -> Daemon {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(host.root().join("daemon.log"))
        .expect("opens the daemon's log");
    let child = std::process::Command::new(program)
        .current_dir(host.root())
        .env("HOME", home)
        .arg("--runtime-dir")
        .arg(host.root().join("r"))
        .arg("--state-dir")
        .arg(host.root().join("s"))
        .arg("--worker")
        .arg(host.root().join("no-such-worker"))
        .arg("--secret-store")
        .arg("file")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().expect("duplicates the log"))
        .stderr(log)
        .spawn()
        .expect("the daemon starts");
    Daemon(Some(child))
}

/// Connects to the daemon once it answers.
async fn connect_to_daemon(host: &kr_ipc::testing::TempHost) -> LocalClient {
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        if let Ok(client) = LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await {
            return client;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not answer within two minutes; its log says: {}",
            std::fs::read_to_string(host.root().join("daemon.log"))
                .unwrap_or_else(|error| format!("<unreadable: {error}>"))
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Asks for an installation change and decodes the answer as `kr skill` does.
async fn change<T: kr_protocol::wire::WireMessage>(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
    method: Method,
    params: &AgentToolsParams,
) -> T {
    client
        .mutate(
            method,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
        .unwrap_or_else(|error| panic!("{} failed: {error:?}", method.as_str()))
        .to_typed()
        .unwrap_or_else(|error| panic!("the answer to {} decodes: {error}", method.as_str()))
}

/// Reads an installation's record and decodes the answer as `kr skill status` does.
async fn recorded(
    client: &mut LocalClient,
    params: &AgentToolsParams,
) -> kr_protocol::skill::AgentToolsStatusResult {
    client
        .request(Method::AgentToolsStatus, params)
        .await
        .expect("the call reaches the daemon")
        .expect("agent_tools.status succeeds")
        .to_typed()
        .unwrap_or_else(|error| panic!("the answer to agent_tools.status decodes: {error}"))
}

/// The operations, in an order that does not depend on the order they were run in.
fn sorted(operations: &[kr_protocol::skill::ChangeOperation]) -> Vec<String> {
    let mut rendered: Vec<String> = operations
        .iter()
        .map(|operation| format!("{operation:?}"))
        .collect();
    rendered.sort();
    rendered
}

fn json_document(path: &std::path::Path) -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .expect("JSON")
}

/// KR-REQ-11.50: through the real control daemon, `agent_tools.install`, `agent_tools.status` and
/// `agent_tools.remove` install `kalareach-contact` for one agent at user scope and for another at
/// project scope, and every answer, each carrying change operations, decodes in this Rust client
/// exactly as `kr skill install`, `kr skill status` and `kr skill remove` decode it. Each
/// installation writes the skill package and the `kr agent-tools --stdio` entry beside the settings
/// already there and is recorded with the removal operations that undo it; the record is the
/// host's, so a replacement daemon reads it back; and removal runs exactly that record, leaving
/// every other setting as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_skill_installs_reports_and_removes_at_both_scopes_by_its_removal_record() {
    use kr_protocol::skill::{AgentToolsInstallResult, AgentToolsRemoveResult, InstalledFile};

    let host = kr_ipc::testing::TempHost::create();
    let program = host
        .root()
        .join(format!("kr-controller{}", std::env::consts::EXE_SUFFIX));
    kr_ipc::testing::place_program(
        std::path::Path::new(env!("CARGO_BIN_EXE_kr-controller")),
        &program,
    );
    let home = host.root().join("home");
    let project = host.root().join("project");
    std::fs::create_dir_all(&home).expect("a home directory");
    std::fs::create_dir_all(project.join(".codex")).expect("a project directory");
    // Somebody's own settings, which neither the installation nor the removal may disturb.
    std::fs::write(
        home.join(".claude.json"),
        r#"{"mcpServers":{"theirs":{"command":"their-server"}},"theme":"dark"}"#,
    )
    .expect("writes the user's configuration");
    std::fs::write(
        project.join(".codex/config.toml"),
        "# a comment somebody wrote\nmodel = \"theirs\"\n\n[mcp_servers.theirs]\ncommand = \"their-server\"\n",
    )
    .expect("writes the project's configuration");

    let environment_id = host.environment_id();
    let user = AgentToolsParams {
        agent: AgentTarget::ClaudeCode,
        scope: InstallScope::User,
        project_dir: Nullable::null(),
    };
    let in_project = AgentToolsParams {
        agent: AgentTarget::Codex,
        scope: InstallScope::Project,
        project_dir: Nullable::some(project.display().to_string()),
    };

    let mut daemon = start_daemon(&program, &host, &home);
    let mut client = connect_to_daemon(&host).await;
    let installed_user: AgentToolsInstallResult = change(
        &mut client,
        environment_id,
        Method::AgentToolsInstall,
        &user,
    )
    .await;
    let installed_project: AgentToolsInstallResult = change(
        &mut client,
        environment_id,
        Method::AgentToolsInstall,
        &in_project,
    )
    .await;
    for installed in [&installed_user, &installed_project] {
        assert!(!installed.already_installed);
        assert!(
            installed.unresolved.is_empty(),
            "{:?}",
            installed.unresolved
        );
        assert!(
            installed
                .manifest
                .operations
                .iter()
                .any(|operation| matches!(
                    operation,
                    kr_protocol::skill::ChangeOperation::WriteFile { .. }
                )),
            "an installation records the files it wrote with their digests"
        );
    }

    // What each installation wrote, and what it left alone.
    let user_skill = home.join(".claude/skills/kalareach-contact");
    let project_skill = project.join(".agents/skills/kalareach-contact");
    for skill in [&user_skill, &project_skill] {
        for file in ["SKILL.md", "TOOLS.md", "manifest.json"] {
            assert!(
                skill.join(file).is_file(),
                "{} is installed",
                skill.join(file).display()
            );
        }
    }
    let user_configuration = json_document(&home.join(".claude.json"));
    assert_eq!(
        user_configuration["mcpServers"]["kalareach"]["args"],
        serde_json::json!(["agent-tools", "--stdio"])
    );
    assert_eq!(
        user_configuration["mcpServers"]["theirs"]["command"],
        "their-server"
    );
    assert_eq!(user_configuration["theme"], "dark");
    let project_configuration =
        std::fs::read_to_string(project.join(".codex/config.toml")).expect("reads");
    assert!(project_configuration.contains("[mcp_servers.kalareach]"));
    assert!(project_configuration.contains("\"agent-tools\""));
    assert!(project_configuration.contains("# a comment somebody wrote"));
    assert!(project_configuration.contains("[mcp_servers.theirs]"));
    // Each manifest names the skill directory its scope resolved to.
    assert_eq!(installed_user.manifest.scope, InstallScope::User);
    assert_eq!(
        installed_user.manifest.root,
        user_skill.display().to_string()
    );
    assert_eq!(installed_project.manifest.scope, InstallScope::Project);
    assert_eq!(
        installed_project.manifest.root,
        project_skill.display().to_string()
    );

    // Each installation's record, read back as the removal it would run.
    let recorded_user = recorded(&mut client, &user).await;
    let recorded_project = recorded(&mut client, &in_project).await;
    for (record, installed) in [
        (&recorded_user, &installed_user),
        (&recorded_project, &installed_project),
    ] {
        assert!(record.installed);
        assert!(record.drift.is_empty(), "{:?}", record.drift);
        assert!(!record.files.is_empty());
        assert!(record.files.iter().all(InstalledFile::is_intact));
        assert!(!record.removal.is_empty());
        assert_eq!(
            sorted(&record.removal),
            sorted(&installed.manifest.operations),
            "the removal record undoes exactly what the installation did"
        );
    }

    // The same installation asked for again changes nothing and says so.
    let again: AgentToolsInstallResult = change(
        &mut client,
        environment_id,
        Method::AgentToolsInstall,
        &user,
    )
    .await;
    assert!(again.already_installed);

    // The record is the host's rather than the daemon process's: a replacement reads it back.
    drop(client);
    daemon.kill();
    let _daemon = start_daemon(&program, &host, &home);
    let mut client = connect_to_daemon(&host).await;
    assert_eq!(
        recorded(&mut client, &user).await.removal,
        recorded_user.removal
    );
    assert_eq!(
        recorded(&mut client, &in_project).await.removal,
        recorded_project.removal
    );

    // Removal runs the record: everything it installed goes, and nothing else does.
    let removed_user: AgentToolsRemoveResult =
        change(&mut client, environment_id, Method::AgentToolsRemove, &user).await;
    let removed_project: AgentToolsRemoveResult = change(
        &mut client,
        environment_id,
        Method::AgentToolsRemove,
        &in_project,
    )
    .await;
    assert_eq!(
        sorted(&removed_user.removed),
        sorted(&recorded_user.removal)
    );
    assert_eq!(
        sorted(&removed_project.removed),
        sorted(&recorded_project.removal)
    );
    assert!(
        removed_user.retained.is_empty(),
        "{:?}",
        removed_user.retained
    );
    assert!(
        removed_project.retained.is_empty(),
        "{:?}",
        removed_project.retained
    );
    assert!(!user_skill.exists());
    assert!(!project_skill.exists());
    let user_configuration = json_document(&home.join(".claude.json"));
    assert!(user_configuration["mcpServers"].get("kalareach").is_none());
    assert_eq!(
        user_configuration["mcpServers"]["theirs"]["command"],
        "their-server"
    );
    assert_eq!(user_configuration["theme"], "dark");
    let project_configuration =
        std::fs::read_to_string(project.join(".codex/config.toml")).expect("reads");
    assert!(!project_configuration.contains("kalareach"));
    assert!(project_configuration.contains("# a comment somebody wrote"));
    assert!(project_configuration.contains("[mcp_servers.theirs]"));
    let after_user = recorded(&mut client, &user).await;
    let after_project = recorded(&mut client, &in_project).await;
    assert!(!after_user.installed);
    assert!(!after_project.installed);
    assert!(after_user.removal.is_empty());
    assert!(after_project.removal.is_empty());
}
