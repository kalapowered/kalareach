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
//! something it does not have. The owner's confirmation of a repository's root and of an
//! installation is answered by a scripted daemon instead: a real daemon needs a paired owner
//! device to answer a challenge, which nothing in this suite has, and the catalogue refuses an
//! unknown repository before it decides whether an installation needs a confirmation. The
//! scripted daemon issues the challenge, lists what an owner device is shown for it, and refuses
//! the request as needing the confirmation until it decides an owner device has answered.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
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

/// KR-REQ-07.47, KR-REQ-10.52: every `kr plugin` and `kr plugin repo` operation is a client of its
/// own method. The two lists answer; each operation on a repository or a package this host does
/// not have is the daemon's own refusal; and adding a repository asks the host for the owner
/// device's challenge, which a host that is not on the network has no owner device to give: it
/// answers `HOST_NOT_CONFIGURED`, naming the network selection, and nothing is enrolled.
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
    assert_eq!(
        repositories["enrolment_budgets"]["metadata_bytes"],
        Value::String(
            kr_protocol::hostinfo::configuration::EnrolmentBudgets::default()
                .metadata_bytes
                .to_string()
        ),
        "the budgets a repository may ask for: {repositories}"
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
    assert_eq!(added["code"], "HOST_NOT_CONFIGURED", "{added}");
    assert!(text(&added["message"]).contains("network"), "{added}");
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

/// What a scripted daemon answers one method with, given the method and what it was sent.
type Script = Box<dyn Fn(&str, &ParamsValue) -> Result<ParamsValue, ProtocolError> + Send + Sync>;

/// A script that answers every method the same way.
fn always(answer: Result<ParamsValue, ProtocolError>) -> Script {
    Box::new(move |_, _| answer.clone())
}

/// Serves local callers on `temp`'s endpoint, answering every request and mutation as `script`
/// says for its method and recording the name of every method it is asked.
fn scripted_daemon(
    temp: &kr_ipc::testing::TempHost,
    script: Script,
) -> (Asked, tokio::task::JoinHandle<()>) {
    serving(temp, script, None)
}

/// A scripted daemon that performs `method` as `script` says and then closes the connection
/// without answering it, as a host does that stops between doing what it was asked and saying so.
/// A refusal of `method` is still answered.
fn scripted_daemon_that_hangs_up_after(
    temp: &kr_ipc::testing::TempHost,
    script: Script,
    method: &'static str,
) -> (Asked, tokio::task::JoinHandle<()>) {
    serving(temp, script, Some(method))
}

/// The scripted daemon, which closes the connection instead of answering the one `hangs_up_after`
/// names once `script` has performed it.
fn serving(
    temp: &kr_ipc::testing::TempHost,
    script: Script,
    hangs_up_after: Option<&'static str>,
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
                build: None,
            };
            if writer
                .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
                .await
                .is_err()
            {
                continue;
            }
            while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                let (request_id, method, params) = match &frame {
                    ControlFrame::Request(request) => (
                        request.request_id,
                        request.method.as_str().to_owned(),
                        request.params.clone(),
                    ),
                    ControlFrame::Mutation(mutation) => (
                        mutation.request_id,
                        mutation.method.as_str().to_owned(),
                        mutation.params.clone(),
                    ),
                    _ => continue,
                };
                let outcome = match script(&method, &params) {
                    Ok(value) => Outcome::Ok(value),
                    Err(error) => Outcome::Error(error),
                };
                let performed = matches!(outcome, Outcome::Ok(_));
                recorded.lock().expect("the record").push(method.clone());
                if performed && hangs_up_after == Some(method.as_str()) {
                    break;
                }
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

/// The installation line the cases below run.
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
        "approval.respond",
    ]
}

/// An installation whose grant holds a native bridge.
fn native_bridge_install_line() -> Vec<&'static str> {
    vec![
        "plugin",
        "install",
        "community",
        PACKAGE,
        "0.1.0",
        "--digest",
        PACKAGE_DIGEST,
        "--grant",
        "native_bridge.install",
    ]
}

/// What a scripted daemon saw of an owner confirmation: the subjects it was asked a challenge for
/// and the parameters of every request of the effect itself.
#[derive(Default)]
struct Seen {
    subjects: Vec<kr_protocol::confirmation::ConfirmationSubject>,
    effects: Vec<ParamsValue>,
}

/// The publisher's own words for the release the installation cases name.
const STATEMENT: &str =
    "Adds one registration file under the application's own directory, which it runs.";

/// A scripted daemon's owner device: the challenge it issues, what a device is shown for it, and
/// the answer the effect gets once a device has answered.
struct OwnerDevice {
    /// The method the effect is.
    effect: &'static str,
    /// How many requests of the effect are refused as needing the confirmation before an owner
    /// device answers, and none ever when the device never does.
    refusals: Option<usize>,
    /// When the challenge expires, in UTC milliseconds.
    expires_at_ms: u64,
    /// Whether this host has no owner yet.
    initial_bootstrap: bool,
    /// The budgets this host allows a new enrolment, which `catalogue.list` reports.
    budgets: kr_protocol::catalogue::CatalogueBudgets,
    /// What the effect answers once an owner device has answered.
    answer: ParamsValue,
}

impl OwnerDevice {
    fn challenge(
        &self,
        temp: &kr_ipc::testing::TempHost,
    ) -> kr_protocol::confirmation::OwnerConfirmationRequestResult {
        use kr_protocol::ids::ConfirmationId;
        use kr_protocol::pairing::{OwnerConfirmationRequest, SensitiveAction};
        use kr_protocol::scalars::{Digest256, Nonce256};
        let keys = kr_crypto::keys::DeviceKeys::generate()
            .expect("keys")
            .public_keys();
        let _ = temp;
        kr_protocol::confirmation::OwnerConfirmationRequestResult {
            request: OwnerConfirmationRequest {
                confirmation_id: ConfirmationId::new(Uuid::from_bytes([1; 16])),
                action: if self.effect == "catalogue.add" {
                    SensitiveAction::TrustRepositoryRoot
                } else {
                    SensitiveAction::GrantExecutableCapability
                },
                action_digest: Digest256::from_bytes([2; 32]),
                destination_keys: Nullable::null(),
                destination_rights: CanonicalSet::new(),
                host_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
                host_endpoint_id: keys.transport,
                nonce: Nonce256::from_bytes([4; 32]),
                expires_at_ms: TimestampMs::new(self.expires_at_ms),
            },
            initial_bootstrap: self.initial_bootstrap,
        }
    }

    /// What an owner device is shown for the subject the terminal asked a challenge for, built
    /// from the plan the host builds so that it says what the host would.
    fn shown(
        subject: &kr_protocol::confirmation::ConfirmationSubject,
    ) -> kr_protocol::confirmation::ConfirmationDisplay {
        use kr_protocol::confirmation::{
            CatalogueTrustPlan, ConfirmationSubject, PluginInstallPlan,
        };
        match subject {
            ConfirmationSubject::CatalogueAdd(params) => CatalogueTrustPlan::of_request(
                params,
                "a".repeat(64),
                ["key-one".to_owned()].into_iter().collect(),
            )
            .display(),
            ConfirmationSubject::PluginInstall(params) => PluginInstallPlan {
                environment_id: params.environment_id,
                catalogue_id: params.catalogue_id.clone(),
                ceiling: CanonicalSet::new(),
                plugin_id: params.plugin_id.clone(),
                version: params.version.clone(),
                package_digest: params.package_digest.clone(),
                grant: params.grant.iter().cloned().collect(),
                grant_statement: params
                    .grant
                    .iter()
                    .any(|name| name == "native_bridge.install")
                    .then(|| STATEMENT.to_owned()),
            }
            .display(),
            other => panic!("a terminal asks for no challenge for {other:?}"),
        }
    }

    /// The script: it issues the challenge, lists what is shown, and refuses the effect as
    /// needing the confirmation until an owner device has answered.
    fn script(self, temp: &kr_ipc::testing::TempHost, seen: Arc<Mutex<Seen>>) -> Script {
        use kr_protocol::confirmation::{
            ConfirmationSubject, OwnerConfirmationPendingResult, OwnerConfirmationRequestParams,
            PendingConfirmation,
        };
        let challenge = self.challenge(temp);
        Box::new(move |method, params| match method {
            "owner.confirmation.request" => {
                let asked: OwnerConfirmationRequestParams = params.to_typed().expect("the subject");
                seen.lock()
                    .expect("the record")
                    .subjects
                    .push(asked.subject);
                Ok(ParamsValue::from_typed(&challenge).expect("a challenge"))
            }
            "catalogue.list" => Ok(ParamsValue::from_typed(
                &kr_protocol::catalogue::CatalogueListResult {
                    catalogues: Vec::new(),
                    enrolment_budgets: self.budgets,
                },
            )
            .expect("a list")),
            "owner.confirmation.pending" => {
                let subject: ConfirmationSubject = seen
                    .lock()
                    .expect("the record")
                    .subjects
                    .last()
                    .cloned()
                    .expect("a challenge was asked for first");
                Ok(ParamsValue::from_typed(&OwnerConfirmationPendingResult {
                    pending: vec![PendingConfirmation {
                        request: challenge.request.clone(),
                        display: Self::shown(&subject),
                        answered: false,
                    }],
                })
                .expect("a list"))
            }
            effect if effect == self.effect => {
                let mut seen = seen.lock().expect("the record");
                seen.effects.push(params.clone());
                match self.refusals {
                    Some(refusals) if seen.effects.len() > refusals => Ok(self.answer.clone()),
                    _ => Err(ProtocolError::new(
                        ErrorCode::OwnerConfirmationRequired,
                        "no owner device has answered this",
                    )),
                }
            }
            other => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("{other} was not expected"),
            )),
        })
    }
}

/// The budgets a host allows a new enrolment when its owner has narrowed none: the product's own.
fn allowed() -> kr_protocol::catalogue::CatalogueBudgets {
    use kr_protocol::scalars::U64;
    let defaults = kr_protocol::hostinfo::configuration::EnrolmentBudgets::default();
    kr_protocol::catalogue::CatalogueBudgets {
        metadata_bytes: U64::new(defaults.metadata_bytes),
        metadata_entries: U64::new(defaults.metadata_entries),
        retained_generations: U64::new(defaults.retained_generations),
        retained_metadata_bytes: U64::new(defaults.retained_metadata_bytes),
        payload_cache_bytes: U64::new(defaults.cached_payload_bytes),
        full_offline_mirror: defaults.full_offline_mirror,
    }
}

/// A repository added from a terminal, as the command line names it.
fn repo_add_line<'a>(root: &'a str, metadata_url: &'a str) -> Vec<&'a str> {
    vec![
        "plugin",
        "repo",
        "add",
        "community",
        "--root",
        root,
        "--metadata-url",
        metadata_url,
        "--targets-url",
        "file:///srv/community/targets/",
    ]
}

/// The result a repository's `catalogue.add` answers once an owner device has confirmed it.
fn added(kind: kr_protocol::catalogue::CatalogueKind) -> ParamsValue {
    use kr_protocol::catalogue::{CatalogueAddResult, CatalogueBudgets, CatalogueSummary};
    use kr_protocol::scalars::U64;
    ParamsValue::from_typed(&CatalogueAddResult {
        catalogue: CatalogueSummary {
            catalogue_id: "community".to_owned(),
            kind,
            metadata_url: "https://repo.example/metadata/".to_owned(),
            targets_url: "https://repo.example/targets/".to_owned(),
            root_digest: "a".repeat(64),
            generation: Nullable::null(),
            pinned_generation: Nullable::null(),
            budgets: CatalogueBudgets {
                metadata_bytes: U64::new(1),
                metadata_entries: U64::new(1),
                retained_generations: U64::new(1),
                retained_metadata_bytes: U64::new(1),
                payload_cache_bytes: U64::new(1),
                full_offline_mirror: false,
            },
            ceiling: Vec::new(),
            entries: U64::new(0),
            synced_at_ms: Nullable::null(),
        },
    })
    .expect("a result")
}

/// The result a package's `plugin.install` answers once an owner device has confirmed it.
fn installed(temp: &kr_ipc::testing::TempHost) -> ParamsValue {
    ParamsValue::from_typed(&kr_protocol::catalogue::PluginInstallResult {
        plugin: kr_protocol::catalogue::PluginSummary {
            plugin_id: kr_protocol::ids::PluginId::new(PACKAGE).expect("a package"),
            catalogue_id: "community".to_owned(),
            version: "0.1.0".to_owned(),
            package_digest: PACKAGE_DIGEST.to_owned(),
            environment_id: temp.environment_id(),
            enabled: true,
            pinned: false,
            revoked: false,
            live_bindings: kr_protocol::scalars::Nullable::null(),
            admission: kr_protocol::scalars::Nullable::null(),
        },
        capabilities: Vec::new(),
    })
    .expect("a result")
}

/// KR-REQ-07.47, KR-REQ-10.05: a repository added from a terminal asks the host for the challenge
/// that confirms exactly this request, says that an owner device has to confirm it and what that
/// device is shown, repeats the request with no proof until the host spends the owner device's
/// answer, and reports the repository. The subject the challenge was asked for is the request
/// that is then sent, no proof beside it, and a repository at a `file` location is a local one and
/// at any other a community one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repository_added_from_a_terminal_is_confirmed_on_an_owner_device_and_added() {
    use kr_protocol::catalogue::{CatalogueAddParams, CatalogueKind};
    use kr_protocol::confirmation::ConfirmationSubject;
    for (metadata_url, kind) in [
        ("https://repo.example/metadata/", CatalogueKind::Community),
        ("file:///srv/community/metadata/", CatalogueKind::Local),
    ] {
        let temp = kr_ipc::testing::TempHost::create();
        let root = temp.root().join("root.json");
        std::fs::write(&root, br#"{"signed":"a root"}"#).expect("a root file");
        let root = root.display().to_string();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (asked, serving) = scripted_daemon(
            &temp,
            OwnerDevice {
                effect: "catalogue.add",
                refusals: Some(2),
                expires_at_ms: kr_ipc::now_ms().get() + 600_000,
                initial_bootstrap: false,
                budgets: allowed(),
                answer: added(kind),
            }
            .script(&temp, Arc::clone(&seen)),
        );

        let output = run_kr(&temp, &repo_add_line(&root, metadata_url));
        let said = String::from_utf8_lossy(&output.stdout).into_owned();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{said}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            said.contains("An owner device is asked to trust the root"),
            "the terminal says that an owner device has to confirm, and what: {said}"
        );
        assert!(
            said.contains("key-one"),
            "the key the owner is trusting: {said}"
        );
        assert!(said.contains("community"), "the repository: {said}");

        let seen = seen.lock().expect("the record");
        let [ConfirmationSubject::CatalogueAdd(subject)] = seen.subjects.as_slice() else {
            panic!("one challenge, for a repository: {:?}", seen.subjects);
        };
        assert_eq!(subject.kind, kind);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&subject.root)
                .expect("the root travels as standard base64"),
            br#"{"signed":"a root"}"#,
            "the root is the file's bytes"
        );
        assert!(
            subject.owner_confirmation.0.is_none(),
            "no proof beside the subject"
        );
        assert_eq!(
            seen.effects.len(),
            3,
            "two refusals and the request the host spent"
        );
        for effect in &seen.effects {
            let sent: CatalogueAddParams = effect.to_typed().expect("the request");
            assert_eq!(
                &sent,
                subject.as_ref(),
                "every request sent is the exact one the challenge was asked for"
            );
        }
        let methods = asked.lock().expect("the record").clone();
        assert_eq!(
            methods
                .iter()
                .filter(|name| *name == "owner.confirmation.request")
                .count(),
            1,
            "one challenge, not one for each repeat: {methods:?}"
        );
        assert!(
            methods.iter().all(|name| matches!(
                name.as_str(),
                "catalogue.list"
                    | "owner.confirmation.request"
                    | "owner.confirmation.pending"
                    | "catalogue.add"
            )),
            "{methods:?}"
        );
        drop(seen);

        // The same command for a script: the challenge it waited on is in the document.
        let (status, document) = json(&temp, &repo_add_line(&root, metadata_url));
        assert_eq!(status, Some(0), "{document}");
        assert_eq!(
            document["catalogue"]["catalogue_id"], "community",
            "{document}"
        );
        assert!(
            document["confirmation"]["confirmation_id"].is_string(),
            "{document}"
        );
        assert!(
            document["confirmation"]["expires_at_ms"].is_string()
                || document["confirmation"]["expires_at_ms"].is_number(),
            "{document}"
        );
        serving.abort();
    }
}

/// KR-REQ-07.47: a repository added from a terminal asks for the budgets the host says it allows,
/// as `catalogue.list` reports them, and the request repeated until an owner device answers is the
/// one the challenge was asked for. What the host enforces is what it accepted, which a document on
/// disk may no longer say, so the command reads it from the host and not from a file: here the file
/// names other numbers, and the host's are the ones asked for. A host that allows less metadata
/// than the product's default would refuse a request for the default, and the command has no
/// option to change it. The control is a host that allows the product's defaults.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repository_added_from_a_terminal_asks_for_the_budgets_this_host_allows() {
    use kr_protocol::catalogue::{CatalogueAddParams, CatalogueBudgets, CatalogueKind};
    use kr_protocol::confirmation::ConfirmationSubject;
    use kr_protocol::hostinfo::configuration::{Change, ConfiguredEnrolmentBudgets};
    use kr_protocol::scalars::U64;
    let narrowed = CatalogueBudgets {
        metadata_bytes: U64::new(32 * 1024 * 1024),
        metadata_entries: U64::new(50_000),
        retained_generations: U64::new(1),
        retained_metadata_bytes: U64::new(32 * 1024 * 1024),
        payload_cache_bytes: U64::new(512 * 1024 * 1024),
        full_offline_mirror: false,
    };
    for (what, allows) in [("the defaults", allowed()), ("less than them", narrowed)] {
        let temp = kr_ipc::testing::TempHost::create();
        // A document that names other budgets than the host enforces, which the command ignores.
        kr_cli::doctor::configuration::apply(
            &temp.environment(),
            &Change::Enrolment(ConfiguredEnrolmentBudgets {
                metadata_bytes: Nullable::some(7 * 1024 * 1024),
                ..ConfiguredEnrolmentBudgets::default()
            }),
        )
        .expect("a configuration document");
        let root = temp.root().join("root.json");
        std::fs::write(&root, br#"{"signed":"a root"}"#).expect("a root file");
        let root = root.display().to_string();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (_asked, serving) = scripted_daemon(
            &temp,
            OwnerDevice {
                effect: "catalogue.add",
                refusals: Some(1),
                expires_at_ms: kr_ipc::now_ms().get() + 600_000,
                initial_bootstrap: false,
                budgets: allows,
                answer: added(CatalogueKind::Community),
            }
            .script(&temp, Arc::clone(&seen)),
        );
        let output = run_kr(
            &temp,
            &repo_add_line(&root, "https://repo.example/metadata/"),
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{what}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let seen = seen.lock().expect("the record");
        let [ConfirmationSubject::CatalogueAdd(subject)] = seen.subjects.as_slice() else {
            panic!("one challenge, for a repository: {:?}", seen.subjects);
        };
        assert_eq!(
            subject.budgets, allows,
            "{what}: the budgets the host says it allows"
        );
        for effect in &seen.effects {
            let sent: CatalogueAddParams = effect.to_typed().expect("the request");
            assert_eq!(
                &sent,
                subject.as_ref(),
                "{what}: every request sent is the one the challenge was asked for"
            );
        }
        serving.abort();
    }
}

/// KR-REQ-11.42, KR-REQ-07.47: an installation the daemon says needs the owner's confirmation is
/// asked for on an owner device the same way, and the terminal says what that device is shown: the
/// release and its grant, and for a native bridge the host's own notice that it runs outside the
/// plugin sandbox, apart from what the publisher says it does. The control is an installation the
/// daemon answers at once, which asks no owner device for anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_confirmed_on_an_owner_device_is_installed_with_the_publishers_words() {
    use kr_protocol::catalogue::PluginInstallParams;
    use kr_protocol::confirmation::{ConfirmationSubject, NATIVE_BRIDGE_NOTICE};
    let temp = kr_ipc::testing::TempHost::create();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (asked, serving) = scripted_daemon(
        &temp,
        OwnerDevice {
            effect: "plugin.install",
            refusals: Some(3),
            expires_at_ms: kr_ipc::now_ms().get() + 600_000,
            initial_bootstrap: false,
            budgets: allowed(),
            answer: installed(&temp),
        }
        .script(&temp, Arc::clone(&seen)),
    );
    let output = run_kr(&temp, &native_bridge_install_line());
    let said = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{said}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        said.contains("An owner device is asked to install"),
        "{said}"
    );
    assert!(
        said.contains(NATIVE_BRIDGE_NOTICE),
        "the host's own notice that a native bridge runs outside the sandbox: {said}"
    );
    assert!(
        said.contains(&format!("the publisher says: {STATEMENT}")),
        "the publisher's words, apart from the host's: {said}"
    );
    assert!(said.contains("Installed"), "{said}");
    let seen = seen.lock().expect("the record");
    let [ConfirmationSubject::PluginInstall(subject)] = seen.subjects.as_slice() else {
        panic!("one challenge, for an installation: {:?}", seen.subjects);
    };
    assert!(subject.owner_confirmation.0.is_none());
    assert_eq!(
        seen.effects.len(),
        4,
        "the first request and two repeats refused, then the one spent"
    );
    for effect in &seen.effects {
        let sent: PluginInstallParams = effect.to_typed().expect("the request");
        assert_eq!(
            &sent,
            subject.as_ref(),
            "the request is the one the challenge names"
        );
    }
    assert_eq!(
        asked
            .lock()
            .expect("the record")
            .first()
            .map(String::as_str),
        Some("plugin.install"),
        "an installation is asked for first, as one that needs no confirmation is"
    );
    serving.abort();

    // The control: an installation the daemon answers at once, which asks no owner device.
    let temp = kr_ipc::testing::TempHost::create();
    let (asked, serving) = scripted_daemon(&temp, always(Ok(installed(&temp))));
    let (status, document) = json(&temp, &install_line());
    assert_eq!(status, Some(0), "{document}");
    assert_eq!(document["plugin"]["plugin_id"], PACKAGE, "{document}");
    assert!(document.get("confirmation").is_none(), "{document}");
    assert_eq!(*asked.lock().expect("the record"), ["plugin.install"]);
    serving.abort();
}

/// KR-REQ-07.47: when no owner device answers, the command waits until the challenge's own
/// deadline and ends with a refusal that says nothing was changed, whichever of the two commands
/// it is. The control is the same installation with an owner device that answers, above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_device_that_never_answers_ends_at_the_challenges_deadline_and_changes_nothing() {
    use kr_protocol::catalogue::CatalogueKind;
    for effect in ["plugin.install", "catalogue.add"] {
        let temp = kr_ipc::testing::TempHost::create();
        let root = temp.root().join("root.json");
        std::fs::write(&root, br#"{"signed":"a root"}"#).expect("a root file");
        let root = root.display().to_string();
        let expires_at_ms = kr_ipc::now_ms().get() + 2_500;
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (asked, serving) = scripted_daemon(
            &temp,
            OwnerDevice {
                effect,
                refusals: None,
                expires_at_ms,
                initial_bootstrap: false,
                budgets: allowed(),
                answer: added(CatalogueKind::Community),
            }
            .script(&temp, Arc::clone(&seen)),
        );
        let line = if effect == "plugin.install" {
            install_line()
        } else {
            repo_add_line(&root, "https://repo.example/metadata/")
        };
        let (status, refused) = json(&temp, &line);
        assert!(
            kr_ipc::now_ms().get() >= expires_at_ms,
            "{effect}: the command waited for the challenge to run out"
        );
        assert_eq!(status, Some(8), "{effect}: {refused}");
        assert_eq!(refused["code"], "OWNER_CONFIRMATION_REQUIRED", "{refused}");
        let message = text(&refused["message"]);
        assert!(message.contains("no owner device confirmed"), "{message}");
        assert!(message.contains("Nothing was changed"), "{message}");
        let methods = asked.lock().expect("the record").clone();
        assert!(
            methods.iter().filter(|name| *name == effect).count() >= 2,
            "{effect}: the request was repeated until the deadline: {methods:?}"
        );
        assert_eq!(
            methods
                .iter()
                .filter(|name| *name == "owner.confirmation.request")
                .count(),
            1,
            "{methods:?}"
        );
        serving.abort();
    }
}

/// KR-REQ-07.47: a host that performs a confirmed request and ends the connection before it
/// answers leaves the outcome unknown: the terminal does not call it a host that is not
/// configured or say that nothing was changed, it says that whether the request was performed is
/// not known and to look at what the host lists before asking again, and it asks once more for
/// nothing. The control is a host that answers the same request, which reports it done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_ends_after_a_confirmed_request_leaves_its_outcome_unknown() {
    use kr_protocol::catalogue::CatalogueKind;
    for effect in ["plugin.install", "catalogue.add"] {
        let temp = kr_ipc::testing::TempHost::create();
        let root = temp.root().join("root.json");
        std::fs::write(&root, br#"{"signed":"a root"}"#).expect("a root file");
        let root = root.display().to_string();
        let line = if effect == "plugin.install" {
            install_line()
        } else {
            repo_add_line(&root, "https://repo.example/metadata/")
        };
        let device = |temp: &kr_ipc::testing::TempHost, seen: &Arc<Mutex<Seen>>| {
            OwnerDevice {
                effect,
                refusals: Some(1),
                expires_at_ms: kr_ipc::now_ms().get() + 600_000,
                initial_bootstrap: false,
                budgets: allowed(),
                answer: if effect == "plugin.install" {
                    installed(temp)
                } else {
                    added(CatalogueKind::Community)
                },
            }
            .script(temp, Arc::clone(seen))
        };

        let seen = Arc::new(Mutex::new(Seen::default()));
        let (asked, serving) =
            scripted_daemon_that_hangs_up_after(&temp, device(&temp, &seen), effect);
        let (status, refused) = json(&temp, &line);
        assert_eq!(
            status,
            Some(1),
            "{effect}: the host refused nothing: {refused}"
        );
        assert_eq!(refused["code"], "OUTCOME_UNKNOWN", "{effect}: {refused}");
        let message = text(&refused["message"]);
        assert!(message.contains("not known"), "{effect}: {message}");
        assert!(
            message.contains("look at what the host lists"),
            "{effect}: {message}"
        );
        assert!(
            !message.contains("Nothing was changed"),
            "{effect}: a request the host may have performed is not reported as changing nothing: \
             {message}"
        );
        let performed = seen.lock().expect("the record").effects.len();
        assert_eq!(
            performed, 2,
            "{effect}: the refusal and the request the host performed, and no third"
        );
        let methods = asked.lock().expect("the record").clone();
        assert_eq!(
            methods.iter().filter(|name| *name == effect).count(),
            2,
            "{effect}: {methods:?}"
        );
        serving.abort();

        // The control: a host that answers the same performed request reports it done.
        let temp = kr_ipc::testing::TempHost::create();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (_asked, serving) = scripted_daemon(&temp, device(&temp, &seen));
        let (status, done) = json(&temp, &line);
        assert_eq!(status, Some(0), "{effect}: {done}");
        serving.abort();
    }
}

/// KR-REQ-10.52: a host that has no owner device yet has nobody to confirm, and the terminal says
/// so at once and how to pair the first one, without waiting for a challenge nobody can answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_owner_device_is_told_how_to_pair_one_and_nothing_waits() {
    use kr_protocol::catalogue::CatalogueKind;
    for effect in ["plugin.install", "catalogue.add"] {
        let temp = kr_ipc::testing::TempHost::create();
        let root = temp.root().join("root.json");
        std::fs::write(&root, br#"{"signed":"a root"}"#).expect("a root file");
        let root = root.display().to_string();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (asked, serving) = scripted_daemon(
            &temp,
            OwnerDevice {
                effect,
                refusals: None,
                expires_at_ms: kr_ipc::now_ms().get() + 600_000,
                initial_bootstrap: true,
                budgets: allowed(),
                answer: added(CatalogueKind::Community),
            }
            .script(&temp, Arc::clone(&seen)),
        );
        let line = if effect == "plugin.install" {
            install_line()
        } else {
            repo_add_line(&root, "https://repo.example/metadata/")
        };
        let (status, refused) = json(&temp, &line);
        assert_eq!(status, Some(8), "{effect}: {refused}");
        assert_eq!(refused["code"], "OWNER_CONFIRMATION_REQUIRED", "{refused}");
        let message = text(&refused["message"]);
        assert!(message.contains("kr pair invite --owner"), "{message}");
        assert!(message.contains("Nothing was changed"), "{message}");
        let methods = asked.lock().expect("the record").clone();
        let expected: &[&str] = if effect == "plugin.install" {
            &["plugin.install", "owner.confirmation.request"]
        } else {
            &["catalogue.list", "owner.confirmation.request"]
        };
        assert_eq!(
            methods, expected,
            "nothing is repeated for an owner nobody can be"
        );
        serving.abort();
    }
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
        revoked_grants_total: kr_protocol::scalars::U64::new(1),
        barrier: RevocationBarrier::new(
            AuthorityRevision::new(2),
            vec![WorkerBarrier {
                session_id: session,
                state: BarrierState::Pending,
                acknowledged_revision: Nullable::null(),
                rejected_actions: Vec::new(),
                rejected_actions_total: kr_protocol::scalars::U64::new(0),
                possibly_executed: Vec::new(),
                possibly_executed_total: kr_protocol::scalars::U64::new(0),
                omitted_actions: kr_protocol::scalars::U64::new(0),
                names_pending: kr_protocol::scalars::U64::new(0),
                detail: "the worker has not answered yet".to_owned(),
            }],
        ),
    };
    let listed = ParamsValue::from_typed(&listed).expect("a listing");
    let revoked = ParamsValue::from_typed(&revoked).expect("a revocation");
    let (asked, serving) = scripted_daemon(
        &temp,
        Box::new(move |method, _| match method {
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
    // The worker's detail is its own text, said as its class and its length.
    let detail = "the worker has not answered yet";
    assert!(
        said.contains(&format!(
            "session {session}: pending ([message withheld, {} bytes])",
            detail.len()
        )),
        "{said}"
    );
    assert!(!said.contains(detail), "{said}");
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
