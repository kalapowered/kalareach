//! `kr project`, `kr workspace`, `kr changeset`, `kr diff`, `kr device` and `kr plugin`, run the way
//! a person runs them, against a real control daemon.
//!
//! The daemon is this test's own: the real `kr-controller` service, started in this process on a
//! host tree of the test's own, with its real endpoint, handshake and admission, and a supervisor
//! that starts no worker, because none of these commands needs a session. `kr` is the real binary,
//! copied to the internal disk and run with that tree's directories on plain pipes. The
//! repositories are real ones, built with installed Git in a directory on the internal disk.
//!
//! Every command runs at least once, and each command family is refused once by the daemon for
//! something it does not have. One case is answered by a scripted daemon instead: an installation
//! that needs the owner's confirmation. The catalogue refuses an unknown repository before it
//! decides whether an installation needs a confirmation, and a repository is added only with an
//! owner device's signed confirmation, which nothing in this suite has, so a real daemon never
//! reaches that answer here.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, BuildId, DeviceId, GrantId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};
use serde_json::Value;

mod support;

/// A well-formed identifier nothing on the host has.
const NOBODY: &str = "0badc0de-0000-4000-8000-000000000001";

/// The package the development catalogue fixture carries, by its manifest digest.
const PACKAGE: &str = "kalareach/example-declarative";
const PACKAGE_DIGEST: &str = "f8434aef081de78d9b63e34d1172b9a64399182a7420bb4f0b3352762a5aeccb";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A supervisor that starts nothing. None of these commands needs a worker.
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

/// A host tree, its running daemon, and a directory for repositories.
struct Host {
    temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    work: tempfile::TempDir,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.clients.abort();
    }
}

impl Host {
    async fn start() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store in the test tree");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(NoWorkers),
            worker_program: PathBuf::from("/nonexistent/kr-worker"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
        Self {
            temp,
            controller,
            clients,
            work: tempfile::TempDir::new().expect("a directory on the internal disk"),
        }
    }

    fn work(&self) -> &Path {
        self.work.path()
    }

    /// A path in the directory the repositories live in, as a command line names it.
    fn at(&self, name: &str) -> String {
        self.work().join(name).display().to_string()
    }

    fn kr(&self, line: &[&str]) -> Output {
        run_kr(&self.temp, line)
    }

    /// Runs `kr` with `--json` and reads what it printed, which has to be a success.
    fn kr_json(&self, line: &[&str]) -> Value {
        let (status, document) = json(&self.temp, line);
        assert_eq!(status, Some(0), "kr {}: {document}", line.join(" "));
        assert_eq!(document["ok"], Value::Bool(true), "{document}");
        document
    }

    /// Runs `kr` with `--json` and reads the refusal it printed.
    fn refused(&self, line: &[&str]) -> Value {
        let (status, document) = json(&self.temp, line);
        assert_eq!(
            document["ok"],
            Value::Bool(false),
            "kr {}: {document}",
            line.join(" ")
        );
        assert_ne!(
            status,
            Some(0),
            "kr {} exits with a failure",
            line.join(" ")
        );
        assert_eq!(
            document["exit_code"].as_i64(),
            status.map(i64::from),
            "the document carries the status: {document}"
        );
        document
    }
}

/// Runs `kr` on plain pipes with `temp`'s directories, from the root directory.
fn run_kr(temp: &kr_ipc::testing::TempHost, line: &[&str]) -> Output {
    Command::new(support::kr())
        .args(line)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.root())
        .env("KR_RUNTIME_DIR", temp.paths().runtime_root())
        .env("KR_STATE_DIR", temp.paths().state_root())
        .current_dir("/")
        .stdin(Stdio::null())
        .output()
        .expect("kr runs")
}

/// Runs `kr` with `--json` and reads the one document it printed.
fn json(temp: &kr_ipc::testing::TempHost, line: &[&str]) -> (Option<i32>, Value) {
    let mut asked = line.to_vec();
    asked.push("--json");
    let output = run_kr(temp, &asked);
    let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "kr {} printed no JSON ({error}): {}{}",
            asked.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), document)
}

/// Runs installed Git in `directory`, to build a repository for the daemon to find.
fn git<const N: usize>(directory: &Path, arguments: [&str; N]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args([
            "-c",
            "user.name=KalaReach Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
        ])
        .args(arguments)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C")
        .output()
        .expect("installed Git runs");
    assert!(
        output.status.success(),
        "the fixture could not be built: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A repository with one commit, a file changed since, and a file Git does not track.
fn repository(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir_all(&path).expect("a directory for the repository");
    git(&path, ["init", "--initial-branch=main"]);
    std::fs::write(path.join("README.md"), "a repository\n").expect("a tracked file");
    git(&path, ["add", "-A"]);
    git(&path, ["commit", "-m", "the first commit"]);
    std::fs::write(path.join("README.md"), "changed after the commit\n").expect("a change");
    std::fs::write(path.join("notes.txt"), "the person's own notes\n").expect("an untracked file");
    path
}

/// The content digest the host reports for `bytes`, in the form `kr diff read` prints it.
fn digest_of(bytes: &[u8]) -> String {
    kr_protocol::scalars::to_base64url(&kr_cbor::sha256(bytes))
}

fn text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

/// KR-REQ-07.47: `kr project` lists, initialises, clones and adopts repositories, `kr workspace`
/// previews, creates, lists and removes a working copy, `kr changeset` captures, reads and
/// materialises a version of it, and `kr diff` reads it and applies and reverts that version, each
/// through the daemon's own methods, each with text for a person and a document for a script.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repositories_workspaces_change_sets_and_diffs_are_managed_through_the_daemon() {
    let host = Host::start().await;
    let listed = host.kr_json(&["project", "list"]);
    assert_eq!(listed["projects"], Value::Array(Vec::new()), "{listed}");
    let shown = host.kr(&["project", "list"]);
    assert_eq!(
        String::from_utf8_lossy(&shown.stdout).trim(),
        "no repositories"
    );

    // Created, cloned and adopted, each at a directory the command names.
    let initialised = host.kr_json(&["project", "init", &host.at("fresh")]);
    assert_eq!(initialised["project"]["label"], "fresh", "{initialised}");
    assert!(
        host.work().join("fresh/.git").is_dir(),
        "a repository exists"
    );
    let source = repository(host.work(), "source");
    let cloned = host.kr_json(&[
        "project",
        "clone",
        &source.display().to_string(),
        &host.at("copy"),
        "--label",
        "the copy",
    ]);
    assert_eq!(cloned["project"]["label"], "the copy", "{cloned}");
    assert_eq!(cloned["project"]["origin"], "cloned", "{cloned}");
    assert!(
        host.work().join("copy/README.md").is_file(),
        "the clone has the content"
    );
    let adopted = host.kr(&["project", "adopt", &source.display().to_string()]);
    let said = String::from_utf8_lossy(&adopted.stdout);
    assert!(adopted.status.success(), "{said}");
    assert!(said.starts_with("Adopted source as repository "), "{said}");
    let listed = host.kr_json(&["project", "list"]);
    let projects = listed["projects"].as_array().expect("a list");
    assert_eq!(projects.len(), 3, "{listed}");
    let project = projects
        .iter()
        .find(|project| project["label"] == "source")
        .map(|project| text(&project["project_repository_id"]))
        .expect("the adopted repository is listed");

    // The repository's own tree, shared where it is: every class of the person's work stays in
    // it, so naming one to leave out is refused before anything is asked.
    let shared = host.kr_json(&["workspace", "create", &project, "--kind", "shared"]);
    assert_eq!(shared["workspace"]["kind"], "shared_existing", "{shared}");
    assert_eq!(shared["workspace"]["label"], "shared", "{shared}");
    let mistaken = host.refused(&[
        "workspace",
        "create",
        &project,
        "--kind",
        "shared",
        "--include",
        "dirty-files",
    ]);
    assert_eq!(mistaken["exit_code"], 2, "{mistaken}");
    assert_eq!(
        std::fs::read_to_string(source.join("notes.txt")).expect("still there"),
        "the person's own notes\n",
        "the person's tree is untouched"
    );

    // A preview writes nothing, and the creation it previews makes the working copy.
    let review = host.at("review");
    let preview = host.kr_json(&[
        "workspace",
        "create",
        &project,
        "--kind",
        "isolated",
        "--isolation",
        "git-worktree",
        "--path",
        &review,
        "--include",
        "dirty-files",
        "--preview",
    ]);
    assert!(preview["workspace"].is_null(), "{preview}");
    assert!(!Path::new(&review).exists(), "a preview creates nothing");
    let created = host.kr_json(&[
        "workspace",
        "create",
        &project,
        "--kind",
        "isolated",
        "--isolation",
        "git-worktree",
        "--path",
        &review,
        "--include",
        "dirty-files",
    ]);
    let workspace = text(&created["workspace"]["workspace_id"]);
    assert_eq!(
        std::fs::read_to_string(Path::new(&review).join("README.md")).expect("carried in"),
        "changed after the commit\n",
        "the class named came across"
    );
    assert!(
        !Path::new(&review).join("notes.txt").exists(),
        "the class not named did not"
    );
    let listed = host.kr_json(&["workspace", "list", "--project", &project]);
    assert_eq!(
        listed["workspaces"].as_array().map(Vec::len),
        Some(2),
        "the shared workspace and the isolated one: {listed}"
    );

    // One pinned version of the work, read back and written out on its own.
    let captured = host.kr_json(&[
        "changeset",
        "capture",
        &workspace,
        "--label",
        "the review",
        "--include",
        "all",
        "--pin",
    ]);
    let change_set = text(&captured["version"]["change_set_id"]);
    assert_eq!(captured["pinned"], Value::Bool(true), "{captured}");
    let read = host.kr_json(&["changeset", "read", &change_set]);
    assert_eq!(read["version"]["label"], "the review", "{read}");
    assert_eq!(read["versions"].as_array().map(Vec::len), Some(1), "{read}");
    let materialised = host.kr_json(&[
        "changeset",
        "materialize",
        &change_set,
        "1",
        "--purpose",
        "review",
    ]);
    let directory = PathBuf::from(text(&materialised["materialisation"]["directory_path"]));
    assert_eq!(
        std::fs::read_to_string(directory.join("README.md")).expect("written out"),
        "changed after the commit\n"
    );

    // The live tree and the captured version read the same way, and the digest a read shows is
    // the one an apply names the path's state with.
    let expected = digest_of(b"changed after the commit\n");
    let live = host.kr_json(&["diff", "read", "--workspace", &workspace]);
    let readme = live["tracked"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["path"] == "README.md"))
        .unwrap_or_else(|| panic!("the live tree's change is read: {live}"));
    assert_eq!(readme["content_digest"], Value::String(expected.clone()));
    let captured_read = host.kr_json(&[
        "diff",
        "read",
        "--change-set",
        &change_set,
        "--version",
        "1",
    ]);
    assert_eq!(
        text(&captured_read["source_version"]["change_set_id"]),
        change_set
    );
    let shown = host.kr(&["diff", "read", "--workspace", &workspace]);
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains(&expected),
        "a person is shown the digest to expect"
    );
    let expectation = format!("README.md={expected}");
    for operation in ["apply", "revert"] {
        let applied = host.kr_json(&[
            "diff",
            operation,
            &change_set,
            "1",
            "--to",
            "proposal",
            "--workspace",
            &workspace,
            "--expect",
            &expectation,
            "--path",
            "README.md",
        ]);
        assert_eq!(applied["destination"], "proposal", "{operation}: {applied}");
        assert!(
            !applied["proposal_version"].is_null(),
            "{operation} makes a proposal: {applied}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(Path::new(&review).join("README.md")).expect("still there"),
        "changed after the commit\n",
        "a proposal writes to no working tree"
    );

    // A preflight of the working tree that finds it as expected writes nothing and succeeds.
    let checked = host.kr_json(&[
        "diff",
        "apply",
        &change_set,
        "1",
        "--to",
        "working-tree",
        "--workspace",
        &workspace,
        "--expect",
        &expectation,
        "--preflight",
    ]);
    assert!(checked["outcome"].is_null(), "nothing ran: {checked}");
    assert_eq!(checked["destination"], "shared_existing", "{checked}");

    // A link has no content digest, and a read does not call it absent: `--expect` could then be
    // given an expectation nobody established.
    std::os::unix::fs::symlink("README.md", Path::new(&review).join("link"))
        .expect("a link in the working copy");
    let live = host.kr_json(&["diff", "read", "--workspace", &workspace]);
    let link = live["untracked"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["path"] == "link"))
        .unwrap_or_else(|| panic!("the link is read: {live}"));
    assert!(link["content_digest"].is_null(), "{link}");
    let shown = host.kr(&["diff", "read", "--workspace", &workspace]);
    let shown = String::from_utf8_lossy(&shown.stdout);
    let line = shown
        .lines()
        .find(|line| line.ends_with("  link"))
        .unwrap_or_else(|| panic!("a line for the link: {shown}"));
    assert!(line.contains(" unavailable "), "{line}");
    std::fs::remove_file(Path::new(&review).join("link")).expect("the link goes again");

    // A removal keeps what the workspace holds until the person says otherwise.
    let kept = host.kr_json(&["workspace", "remove", &workspace]);
    assert_eq!(kept["workspace"]["state"], "removal_pending", "{kept}");
    assert!(Path::new(&review).join("README.md").is_file());
    let removed = host.kr_json(&["workspace", "remove", &workspace, "--remove-retained"]);
    assert_eq!(removed["workspace"]["state"], "removed", "{removed}");
    assert_eq!(
        removed["working_files_removed"],
        Value::Bool(true),
        "{removed}"
    );
}

/// KR-REQ-07.47: each family refuses what the daemon does not have, with the daemon's own reason, a
/// status other than zero and nothing made: an unknown repository, workspace, change set and
/// device, and a plugin repository this host never enrolled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_family_is_refused_what_the_daemon_does_not_have() {
    let host = Host::start().await;
    let nowhere = host.at("nowhere");
    let refusals: [&[&str]; 5] = [
        &["project", "clone", NOBODY, &nowhere],
        &["workspace", "remove", NOBODY],
        &["changeset", "read", NOBODY],
        &["diff", "read", "--change-set", NOBODY, "--version", "1"],
        &["device", "revoke", NOBODY],
    ];
    for line in refusals {
        let refused = host.refused(line);
        assert_eq!(refused["exit_code"], 8, "the daemon refused: {refused}");
        assert!(
            !text(&refused["message"]).is_empty(),
            "and said why: {refused}"
        );
    }
    assert!(!Path::new(&nowhere).exists(), "nothing was made");
    // A source that is not one this host clones from is refused without being repeated, because
    // it can carry a credential.
    let source = "http://someone:hunter2@example.invalid/work.git";
    let output = host.kr(&["project", "clone", source, &nowhere]);
    assert_eq!(output.status.code(), Some(2));
    let refused = host.refused(&["project", "clone", source, &nowhere]);
    for said in [
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        refused.to_string(),
    ] {
        assert!(
            !said.contains("hunter2"),
            "the credential is not repeated: {said}"
        );
    }
    // A workspace that is not an identifier is the person's mistake, and never reaches the daemon.
    let mistaken = host.refused(&["workspace", "remove", "review"]);
    assert_eq!(mistaken["exit_code"], 2, "{mistaken}");
    assert!(text(&mistaken["message"]).contains("is not a workspace identifier"));
}

/// KR-REQ-07.47: `kr device` lists the paired devices with each one's standing and revokes one by
/// its identifier, under this account's own authority on this host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_is_listed_and_revoked() {
    let host = Host::start().await;
    let listed = host.kr_json(&["device", "list"]);
    assert_eq!(listed["devices"], Value::Array(Vec::new()), "{listed}");

    let device = DeviceId::new(Uuid::from_bytes([0xd1; 16]));
    host.controller
        .devices()
        .commit(&kr_controller::service::net::devices::DeviceRecord {
            device_id: device,
            endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([1; 32]),
            device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
            authorisation: kr_protocol::scalars::AuthorisationKey::from_bytes([2; 32]),
            stored_envelope: None,
            device_name: kr_protocol::pairing::DeviceName::new("phone").expect("a name"),
            platform: kr_protocol::pairing::DevicePlatform::Ios,
            grant: Grant {
                grant_id: GrantId::new(Uuid::from_bytes([0x61; 16])),
                parent_grant_id: Nullable::null(),
                issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
                recipient_device_id: device,
                authority_revision: AuthorityRevision::new(1),
                environment_selector: EnvironmentSelector::Any,
                session_selector: SessionSelector::Any,
                actions: [ActionRight::SessionView].into_iter().collect(),
                history: HistoryScope {
                    lower_bound_ms: Nullable::null(),
                    include_live_screen: true,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                expiry: GrantExpiry::Never,
                organisation: Nullable::null(),
            },
            paired_at_ms: TimestampMs::new(1_000),
            revoked_at_ms: None,
            expired_at_ms: None,
            committed_invitation_id: None,
            notification_preview: None,
        })
        .expect("a paired device");

    let listed = host.kr_json(&["device", "list"]);
    assert_eq!(
        listed["devices"][0]["device_id"],
        Value::String(device.to_string()),
        "{listed}"
    );
    assert_eq!(listed["devices"][0]["revoked"], Value::Bool(false));
    let shown = host.kr(&["device", "list"]);
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(
        shown.contains(&device.to_string()) && shown.contains("phone"),
        "{shown}"
    );

    let revoked = host.kr_json(&["device", "revoke", &device.to_string()]);
    let revision: u64 = text(&revoked["authority_revision"])
        .parse()
        .unwrap_or_else(|error| panic!("a revision ({error}): {revoked}"));
    assert!(
        revision > 0,
        "the revocation advanced the revision: {revoked}"
    );
    let listed = host.kr_json(&["device", "list"]);
    assert_eq!(listed["devices"], Value::Array(Vec::new()), "{listed}");
    let listed = host.kr_json(&["device", "list", "--include-revoked"]);
    assert_eq!(
        listed["devices"][0]["revoked"],
        Value::Bool(true),
        "{listed}"
    );
}

/// KR-REQ-07.47: every `kr plugin` and `kr plugin repo` operation is a client of its own method. The
/// two lists answer; each operation on a repository or a package this host does not have is the
/// daemon's own refusal; and adding a repository is refused before anything is sent, because only
/// an owner device confirms a trust root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_plugin_operation_reaches_its_method() {
    let host = Host::start().await;
    let plugins = host.kr_json(&["plugin", "list"]);
    assert_eq!(plugins["plugins"], Value::Array(Vec::new()), "{plugins}");
    let repositories = host.kr_json(&["plugin", "repo", "list"]);
    assert_eq!(
        repositories["catalogues"],
        Value::Array(Vec::new()),
        "{repositories}"
    );

    let root = host.work().join("root.json");
    std::fs::write(&root, "{}").expect("a root file");
    let added = host.refused(&[
        "plugin",
        "repo",
        "add",
        "community",
        "--root",
        &root.display().to_string(),
        "--metadata-url",
        "https://example.invalid/metadata/",
        "--targets-url",
        "https://example.invalid/targets/",
    ]);
    assert_eq!(added["code"], "OWNER_CONFIRMATION_REQUIRED", "{added}");
    assert!(text(&added["message"]).contains("owner device"), "{added}");
    let repositories = host.kr_json(&["plugin", "repo", "list"]);
    assert_eq!(
        repositories["catalogues"],
        Value::Array(Vec::new()),
        "nothing was added"
    );

    let refusals: [&[&str]; 8] = [
        &["plugin", "repo", "sync", "community"],
        &["plugin", "repo", "pin", "community", "--generation", "1"],
        &["plugin", "repo", "remove", "community"],
        &[
            "plugin",
            "install",
            "community",
            PACKAGE,
            "0.1.0",
            "--digest",
            PACKAGE_DIGEST,
        ],
        &["plugin", "remove", PACKAGE],
        &["plugin", "pin", PACKAGE, "--digest", PACKAGE_DIGEST],
        &["plugin", "enable", PACKAGE],
        &["plugin", "disable", PACKAGE],
    ];
    for line in refusals {
        let refused = host.refused(line);
        assert_eq!(refused["exit_code"], 8, "the daemon refused: {refused}");
        assert_ne!(
            refused["code"], "OWNER_CONFIRMATION_REQUIRED",
            "nothing here is a confirmation: {refused}"
        );
    }
    let plugins = host.kr_json(&["plugin", "list"]);
    assert_eq!(
        plugins["plugins"],
        Value::Array(Vec::new()),
        "nothing was installed"
    );
}

/// What a scripted daemon was asked, method by method.
type Asked = Arc<Mutex<Vec<String>>>;

/// What a scripted daemon answers one method with.
type Script = Box<dyn Fn(&str) -> Result<ParamsValue, ProtocolError> + Send + Sync>;

/// A script that answers every method the same way.
fn always(answer: Result<ParamsValue, ProtocolError>) -> Script {
    Box::new(move |_| answer.clone())
}

/// Serves local callers on `temp`'s endpoint, answering every request and mutation as `script`
/// says for its method and recording the name of every method it is asked.
fn scripted_daemon(
    temp: &kr_ipc::testing::TempHost,
    script: Script,
) -> (Asked, tokio::task::JoinHandle<()>) {
    let endpoint = temp
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let environment_id = temp.environment_id();
    let asked: Asked = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&asked);
    let serving = tokio::spawn(async move {
        while let Ok((connection, peer)) = listener.accept().await {
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            let Ok(ControlFrame::Hello(hello)) = reader.read_message::<ControlFrame>().await else {
                continue;
            };
            let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
            let acknowledgement = kr_protocol::local::LocalHelloAck {
                selected_version: kr_protocol::hello::PROTOCOL_VERSION,
                role: kr_protocol::local::LocalRole::Controller,
                connection_id,
                environment_id,
                boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                peer: kr_protocol::local::LocalPeer {
                    uid: kr_protocol::scalars::U64::new(u64::from(peer.uid)),
                    gid: kr_protocol::scalars::U64::new(u64::from(peer.gid)),
                    pid: Nullable::null(),
                },
                action_window: kr_protocol::hello::ActionWindow {
                    action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                        .expect("a window identifier"),
                    connection_id,
                    boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                    issued_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
                    valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
                },
                capabilities: CanonicalSet::new(),
                max_receive: hello.max_receive,
            };
            if writer
                .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
                .await
                .is_err()
            {
                continue;
            }
            while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                let (request_id, method) = match &frame {
                    ControlFrame::Request(request) => {
                        (request.request_id, request.method.as_str().to_owned())
                    }
                    ControlFrame::Mutation(mutation) => {
                        (mutation.request_id, mutation.method.as_str().to_owned())
                    }
                    _ => continue,
                };
                let outcome = match script(&method) {
                    Ok(value) => Outcome::Ok(value),
                    Err(error) => Outcome::Error(error),
                };
                recorded.lock().expect("the record").push(method);
                let response = ControlFrame::Response(Response {
                    request_id,
                    outcome,
                });
                if writer.write_message(&response).await.is_err() {
                    break;
                }
            }
        }
    });
    (asked, serving)
}

/// The installation line both cases below run.
fn install_line() -> Vec<&'static str> {
    vec![
        "plugin",
        "install",
        "community",
        PACKAGE,
        "0.1.0",
        "--digest",
        PACKAGE_DIGEST,
        "--grant",
        "kr.native_bridge.install/1",
    ]
}

/// KR-REQ-07.47: an installation the daemon says needs the owner's confirmation, and that carries
/// none, is refused: the command says it is confirmed and installed from an owner device, exits
/// with a status other than zero, and asks the daemon for nothing more than the installation, so
/// no confirmation is left waiting that nothing could spend. The control is the same installation
/// answered with a result, which the command reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_that_needs_the_owners_confirmation_is_sent_to_an_owner_device() {
    let temp = kr_ipc::testing::TempHost::create();
    let (asked, serving) = scripted_daemon(
        &temp,
        always(Err(ProtocolError::new(
            ErrorCode::OwnerConfirmationRequired,
            "the installation may do more than its repository permits by itself",
        ))),
    );
    let (status, refused) = json(&temp, &install_line());
    assert_eq!(status, Some(8), "{refused}");
    assert_eq!(refused["code"], "OWNER_CONFIRMATION_REQUIRED", "{refused}");
    let message = text(&refused["message"]);
    assert!(message.contains("owner device"), "{message}");
    assert!(
        message.contains("more than its repository permits"),
        "the daemon's reason is kept: {message}"
    );
    assert_eq!(
        *asked.lock().expect("the record"),
        ["plugin.install"],
        "the installation was asked for once and nothing else was"
    );
    serving.abort();

    // The control: the same installation, answered.
    let temp = kr_ipc::testing::TempHost::create();
    let installed = kr_protocol::catalogue::PluginInstallResult {
        plugin: kr_protocol::catalogue::PluginSummary {
            plugin_id: kr_protocol::ids::PluginId::new(PACKAGE).expect("a package"),
            catalogue_id: "community".to_owned(),
            version: "0.1.0".to_owned(),
            package_digest: PACKAGE_DIGEST.to_owned(),
            environment_id: temp.environment_id(),
            enabled: true,
            pinned: false,
            revoked: false,
            live_bindings: kr_protocol::scalars::U64::new(0),
        },
        capabilities: Vec::new(),
    };
    let (asked, serving) = scripted_daemon(
        &temp,
        always(Ok(ParamsValue::from_typed(&installed).expect("a result"))),
    );
    let (status, document) = json(&temp, &install_line());
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["plugin"]["plugin_id"], PACKAGE, "{document}");
    assert_eq!(*asked.lock().expect("the record"), ["plugin.install"]);
    serving.abort();
}

/// KR-REQ-07.47: an apply the daemon began and did not finish is not a success. The command exits
/// with a status other than zero and prints the daemon's whole result, the recovery objects among
/// it, beside the failure. A real daemon reaches this only when something changes the destination
/// part way through a write, so a scripted one answers here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_apply_the_daemon_did_not_finish_is_a_failure_with_its_whole_result() {
    use kr_protocol::changeset::{
        ApplyOutcomeClass, DestinationClass, DiffApplyResult, RecoveryObjects, VersionRef,
    };
    use kr_protocol::ids::{ActionId, ChangeSetId, ChangeSetVersion};

    let temp = kr_ipc::testing::TempHost::create();
    let change_set = ChangeSetId::new(kr_ipc::new_uuid());
    let version = |number| VersionRef {
        change_set_id: change_set,
        version: ChangeSetVersion::new(number),
    };
    let interrupted = DiffApplyResult {
        action_id: ActionId::new(kr_ipc::new_uuid()),
        outcome: Nullable::some(ApplyOutcomeClass::InterruptedApply),
        destination: DestinationClass::SharedExisting,
        applied_version: version(1),
        proposal_version: Nullable::null(),
        reference: Nullable::null(),
        changed_paths: vec!["README.md".to_owned()],
        unresolved_paths: vec!["notes.txt".to_owned()],
        conflicts: Vec::new(),
        progress: Vec::new(),
        recovery: RecoveryObjects {
            before_version: Nullable::some(version(2)),
            after_version: Nullable::null(),
            applied_version: Nullable::some(version(1)),
            staged_path: Nullable::null(),
            staged_leftovers: Vec::new(),
            detail: "the tree before the apply is version 2".to_owned(),
        },
        limitations: Vec::new(),
        detail: "the host stopped after the first path".to_owned(),
        decided_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
    };
    let (asked, serving) = scripted_daemon(
        &temp,
        always(Ok(ParamsValue::from_typed(&interrupted).expect("a result"))),
    );
    let change_set = change_set.to_string();
    let line = [
        "diff",
        "apply",
        change_set.as_str(),
        "1",
        "--to",
        "working-tree",
        "--workspace",
        NOBODY,
        "--expect",
        "README.md=absent",
    ];
    let (status, document) = json(&temp, &line);
    assert_eq!(status, Some(1), "{document}");
    assert_eq!(document["ok"], Value::Bool(false), "{document}");
    assert_eq!(document["code"], "OUTCOME_UNKNOWN", "{document}");
    assert_eq!(document["exit_code"], 1, "{document}");
    assert_eq!(document["outcome"], "interrupted_apply", "{document}");
    assert_eq!(
        document["recovery"]["before_version"]["version"], "2",
        "the recovery objects are kept: {document}"
    );
    let output = run_kr(&temp, &line);
    assert_eq!(output.status.code(), Some(1));
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("changed: README.md"), "{said}");
    assert!(
        said.contains("the destination before it: version 2"),
        "{said}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("did not finish"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        *asked.lock().expect("the record"),
        ["diff.apply", "diff.apply"]
    );
    serving.abort();
}

/// KR-REQ-07.47 and section 9's barrier: a revocation some affected session's worker has not
/// fenced yet is pending, not a success. The command says which worker it waits for and why, exits
/// with a status other than zero, and keeps the whole result in its document. A real daemon waits
/// on a live session's worker that has not answered, which this suite has none of, so a scripted
/// one answers here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_a_worker_has_not_fenced_is_pending_and_not_a_success() {
    use kr_protocol::action::{BarrierState, RevocationBarrier, WorkerBarrier};
    use kr_protocol::sharing::{DeviceListResult, DeviceSummary, RevocationResult};

    let temp = kr_ipc::testing::TempHost::create();
    let device = DeviceId::new(Uuid::from_bytes([0xd4; 16]));
    let session = kr_protocol::ids::SessionId::new(Uuid::from_bytes([0x5e; 16]));
    let listed = DeviceListResult {
        devices: vec![DeviceSummary {
            device_id: device,
            display_name: "phone".to_owned(),
            grant_id: GrantId::new(Uuid::from_bytes([0x61; 16])),
            paired_at_ms: TimestampMs::new(1_000),
            acknowledged_revision: Nullable::null(),
            acknowledged_at_ms: Nullable::null(),
            revoked: false,
            keys: Nullable::null(),
            manages_host: false,
        }],
        authority_revision: AuthorityRevision::new(1),
        feed_synchronised_at_ms: Nullable::null(),
        feed_stale: false,
    };
    let revoked = RevocationResult {
        authority_revision: AuthorityRevision::new(2),
        revoked_grants: [GrantId::new(Uuid::from_bytes([0x61; 16]))]
            .into_iter()
            .collect(),
        barrier: RevocationBarrier {
            authority_revision: AuthorityRevision::new(2),
            workers: vec![WorkerBarrier {
                session_id: session,
                state: BarrierState::Pending,
                acknowledged_revision: Nullable::null(),
                rejected_actions: Vec::new(),
                possibly_executed: Vec::new(),
                omitted_actions: kr_protocol::scalars::U64::new(0),
                names_pending: kr_protocol::scalars::U64::new(0),
                detail: "the worker has not answered yet".to_owned(),
            }],
        },
    };
    let listed = ParamsValue::from_typed(&listed).expect("a listing");
    let revoked = ParamsValue::from_typed(&revoked).expect("a revocation");
    let (asked, serving) = scripted_daemon(
        &temp,
        Box::new(move |method| match method {
            "device.list" => Ok(listed.clone()),
            "device.revoke" => Ok(revoked.clone()),
            other => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("this daemon answers no {other}"),
            )),
        }),
    );
    let device = device.to_string();
    let (status, document) = json(&temp, &["device", "revoke", &device]);
    assert_eq!(status, Some(1), "{document}");
    assert_eq!(document["ok"], Value::Bool(false), "{document}");
    assert_eq!(document["code"], "RESOURCE_UNAVAILABLE", "{document}");
    assert_eq!(
        document["barrier"]["workers"][0]["state"], "pending",
        "the per-worker status is kept: {document}"
    );
    let output = run_kr(&temp, &["device", "revoke", &device]);
    assert_eq!(output.status.code(), Some(1));
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("is pending"), "{said}");
    assert!(!said.contains("Revoked device"), "{said}");
    assert!(
        said.contains(&format!(
            "session {session}: pending (the worker has not answered yet)"
        )),
        "{said}"
    );
    assert_eq!(
        *asked.lock().expect("the record"),
        [
            "device.list",
            "device.revoke",
            "device.list",
            "device.revoke"
        ]
    );
    serving.abort();
}
