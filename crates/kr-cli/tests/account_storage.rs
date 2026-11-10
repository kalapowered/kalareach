//! `kr account sign-in --storage`, `kr account sign-out --storage` and `kr account show`, run the
//! way a person runs them, against a real control daemon.
//!
//! The daemon is this test's own: the real `kr-controller` service, started in this process on a
//! host tree of the test's own, from a configuration document that names the storage service, with
//! its real endpoint, handshake and admission. `kr` is the real binary, copied to the internal disk
//! and run with that tree's directories on plain pipes. A debug build of `kr` is given a file to
//! write the address it would open to, so that no browser opens on the machine these run on. The
//! storage service is a stand-in on a loopback socket that the commands never reach: the sign-in
//! only waits for a browser here, and what the daemon does with the browser's answer is the
//! daemon suite's. A daemon that does not list the storage methods is a scripted one.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::host_account::{AccountReport, AccountState};
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::BuildId;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_service_stand_in::serve;
use serde_json::Value;

mod support;

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

/// The configuration document of a host that names these services.
fn document(voice: Option<&str>, storage: Option<&str>) -> ConfigurationDocument {
    let some = |origin: Option<&str>| {
        origin.map_or_else(Nullable::null, |origin| Nullable::some(origin.to_owned()))
    };
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = some(voice);
    document.storage.origin = some(storage);
    document
}

/// A host tree, its running daemon, and the file a debug `kr` writes the address it would open to.
struct Host {
    temp: kr_ipc::testing::TempHost,
    /// Held so that the daemon runs for as long as the host does.
    _controller: Arc<Controller>,
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    opened: PathBuf,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.clients.abort();
    }
}

impl Host {
    /// A host whose daemon reads `document` at start, with `managed` as the origin it treats as the
    /// managed account service in place of the managed service's own.
    async fn start(document: &ConfigurationDocument, managed: Option<&str>) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        environment.create().expect("the environment's directories");
        let path = kr_worker::config::document_path(&environment);
        std::fs::create_dir_all(path.parent().expect("a state directory")).expect("the directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            kr_protocol::hostinfo::configuration::contents(document).as_bytes(),
        )
        .expect("the document");
        let secrets = environment.secrets_dir();
        let controller = kr_controller::testing::taken_over(|| {
            let secrets = secrets.clone();
            kr_controller::testing::with_account_origin(
                managed.map(str::to_owned),
                Controller::start(ControllerSetup {
                    paths: environment.clone(),
                    environment_id,
                    identity: Box::new(move || {
                        let store =
                            open_store_in(&secrets).expect("a secret store in the test tree");
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
                }),
            )
        })
        .await
        .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
        // Each sign-in listens on a loopback port the system gives it, so no case holds the
        // address a browser is registered to come back to.
        let any = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        controller.host_account().listen_on(any);
        controller.storage_account().listen_on(any);
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
        let opened = temp.root().join("opened-address");
        Self {
            temp,
            _controller: controller,
            clients,
            opened,
        }
    }

    /// Runs `kr` on plain pipes with this host's directories, from the root directory.
    fn kr(&self, line: &[&str]) -> Output {
        run_kr(&self.temp, line, Some(&self.opened))
    }

    /// Runs `kr` with `--json` and reads the one document it printed.
    fn json(&self, line: &[&str]) -> (Option<i32>, Value) {
        json(&self.temp, line, Some(&self.opened))
    }

    /// The addresses the commands would have opened in a browser, in order.
    fn opened(&self) -> Vec<String> {
        std::fs::read_to_string(&self.opened)
            .map(|text| text.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }
}

fn run_kr(temp: &kr_ipc::testing::TempHost, line: &[&str], opened: Option<&Path>) -> Output {
    let mut command = Command::new(support::kr());
    command
        .args(line)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.root())
        .env("KR_RUNTIME_DIR", temp.paths().runtime_root())
        .env("KR_STATE_DIR", temp.paths().state_root())
        .current_dir("/")
        .stdin(Stdio::null());
    if let Some(opened) = opened {
        command.env("KR_BROWSER_LOG", opened);
    }
    command.output().expect("kr runs")
}

fn json(
    temp: &kr_ipc::testing::TempHost,
    line: &[&str],
    opened: Option<&Path>,
) -> (Option<i32>, Value) {
    let mut asked = vec!["--json"];
    asked.extend_from_slice(line);
    let output = run_kr(temp, &asked, opened);
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

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// KR-REQ-20.19: `kr account sign-in --storage` says which service it signs in at, and that it is
/// not the managed account service, before the browser is opened, and opens the storage service's
/// authorisation address asking for backup storage and neither voice nor relay leases.
/// `kr account show` then reads the storage account as waiting, beside the managed account, and
/// `kr account sign-out --storage` ends the wait and leaves the managed account as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_storage_sign_in_names_its_service_before_the_browser_opens_and_signs_out_alone() {
    let managed = serve().await;
    let storage = serve().await;
    let host = Host::start(
        &document(Some(managed.origin()), Some(storage.origin())),
        Some(managed.origin()),
    )
    .await;

    // The browser's address goes to this command's own standard output here, so that the order of
    // what the command says and what it does is the order of the lines it prints.
    let output = run_kr(
        &host.temp,
        &["account", "sign-in", "--storage"],
        Some(Path::new("/dev/fd/1")),
    );
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    let printed = String::from_utf8_lossy(&output.stdout).into_owned();
    let lines: Vec<&str> = printed.lines().collect();
    let origin_line = lines
        .iter()
        .position(|line| line.contains(storage.origin()) && line.contains("not the managed"))
        .unwrap_or_else(|| {
            panic!("a line names the service and says it is not the managed one: {printed}")
        });
    // A line that is only an address is the browser's.
    let browser_lines: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("http") && line.contains("/auth/oauth2/authorize"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        browser_lines.len(),
        1,
        "the browser was given one address: {printed}"
    );
    assert!(
        origin_line < browser_lines[0],
        "the service is named before the browser is opened: {printed}"
    );
    let opened = lines[browser_lines[0]];
    let url = url::Url::parse(opened).expect("an address");
    assert_eq!(url.origin().ascii_serialization(), storage.origin());
    assert!(
        lines
            .iter()
            .any(|line| line.contains("Open this address") && line.contains(opened)),
        "the address opened is the address printed: {printed}"
    );
    let asked: Vec<String> = url
        .query_pairs()
        .find(|(name, _)| name == "scope")
        .map(|(_, value)| value.split(' ').map(str::to_owned).collect())
        .expect("the address asks for scopes");
    assert!(
        asked.iter().any(|scope| scope == "backup.write"),
        "{asked:?}"
    );
    assert!(
        !asked
            .iter()
            .any(|scope| scope == "voice" || scope == "relay.lease"),
        "{asked:?}"
    );

    let (status, shown) = host.json(&["account", "show"]);
    assert_eq!(status, Some(0), "{shown}");
    assert_eq!(shown["state"], "signed_out", "the managed account: {shown}");
    assert_eq!(
        shown["storage_account"]["state"], "waiting_for_browser",
        "the storage account waits: {shown}"
    );
    assert_eq!(shown["storage_account"]["service"], storage.origin());

    let output = host.kr(&["account", "sign-out", "--storage"]);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    let (_, shown) = host.json(&["account", "show"]);
    assert_eq!(shown["storage_account"]["state"], "signed_out", "{shown}");
    assert_eq!(shown["state"], "signed_out", "{shown}");

    // As JSON, the one document on standard output names the service only after the browser has
    // opened, so the line that names it and says it is not the managed service goes on standard
    // error first. The browser's address is written there too, for the order to show.
    let output = run_kr(
        &host.temp,
        &["--json", "account", "sign-in", "--storage"],
        Some(Path::new("/dev/fd/2")),
    );
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    let errors = String::from_utf8_lossy(&output.stderr).into_owned();
    let lines: Vec<&str> = errors.lines().collect();
    let notice = lines
        .iter()
        .position(|line| line.contains(storage.origin()) && line.contains("not the managed"))
        .unwrap_or_else(|| {
            panic!("a line names the service and says it is not the managed one: {errors}")
        });
    let browser = lines
        .iter()
        .position(|line| line.starts_with("http") && line.contains("/auth/oauth2/authorize"))
        .unwrap_or_else(|| panic!("the browser was given an address: {errors}"));
    assert!(
        notice < browser,
        "the notice comes before the browser is opened: {errors}"
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("one document");
    assert_eq!(document["service"], storage.origin(), "{document}");

    assert!(
        host.opened().is_empty(),
        "no other command opened an address: {:?}",
        host.opened()
    );
}

/// KR-REQ-20.19: a host with no storage service of its own refuses `--storage` by name, whether
/// its `storage.origin` is unset or names the managed account service, `HOST_NOT_CONFIGURED`
/// naming `storage.origin`, and opens no browser.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_storage_service_of_its_own_refuses_storage_by_name() {
    let managed = serve().await;
    for storage in [None, Some(managed.origin())] {
        let host = Host::start(
            &document(Some(managed.origin()), storage),
            Some(managed.origin()),
        )
        .await;
        for line in [
            ["account", "sign-in", "--storage"],
            ["account", "sign-out", "--storage"],
        ] {
            let (status, refused) = host.json(&line);
            assert_eq!(refused["ok"], false, "{refused}");
            assert_ne!(status, Some(0), "{refused}");
            assert_eq!(refused["code"], "HOST_NOT_CONFIGURED", "{refused}");
            assert!(
                refused["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("storage.origin")),
                "the refusal names storage.origin: {refused}"
            );
        }
        assert!(host.opened().is_empty(), "no browser was opened");
    }
}

/// A host with one account, whose `storage.origin` is unset or names the managed account service,
/// shows that account in the document and the lines it has always had: the golden is the whole
/// document of a host that is signed out, and no line speaks of a storage account. Green before
/// the storage account has a command of its own, and kept by the mutation that has `show` list a
/// storage account for a host that holds none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_one_account_shows_it_in_the_document_it_always_had() {
    let managed = serve().await;
    for storage in [None, Some(managed.origin())] {
        let host = Host::start(
            &document(Some(managed.origin()), storage),
            Some(managed.origin()),
        )
        .await;
        let (status, shown) = host.json(&["account", "show"]);
        assert_eq!(status, Some(0), "{shown}");
        assert_eq!(
            shown,
            serde_json::json!({
                "ok": true,
                "state": "signed_out",
                "service": managed.origin(),
            }),
            "the managed account's document is unchanged"
        );
        let text = host.kr(&["account", "show"]);
        assert_eq!(text.status.code(), Some(0), "{}", said(&text));
        assert!(
            !said(&text).contains("storage"),
            "a host with one account lists one: {}",
            said(&text)
        );
    }
}

/// A scripted daemon on `temp`'s endpoint that answers the methods it lists and refuses every other
/// method as a daemon refuses a method it does not list: `PERMISSION_DENIED`. A connection is
/// answered `account.status` `status_answers` times, and refused it after: a membership that
/// lapsed. The first `storage_refusals` reads of `account.storage_status` are refused as well,
/// listed or not: a membership that lapsed and is renewed by another connection.
fn scripted_daemon(
    temp: &kr_ipc::testing::TempHost,
    listed: &'static [&'static str],
    status_answers: usize,
    storage_refusals: usize,
) -> tokio::task::JoinHandle<()> {
    let endpoint = temp
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let environment_id = temp.environment_id();
    tokio::spawn(async move {
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
            let mut status_answered = 0_usize;
            let mut storage_read = 0_usize;
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
                if method == "account.status" {
                    status_answered += 1;
                }
                if method == "account.storage_status" {
                    storage_read += 1;
                }
                let lapsed = (method == "account.status" && status_answered > status_answers)
                    || (method == "account.storage_status" && storage_read <= storage_refusals);
                let outcome = if listed.contains(&method.as_str()) && !lapsed {
                    let report = AccountReport {
                        service: Nullable::some("https://reach.kala.to".to_owned()),
                        unavailable: Nullable::null(),
                        state: AccountState::SignedOut,
                        last_attempt: Nullable::null(),
                    };
                    Outcome::Ok(ParamsValue::from_typed(&report).expect("a report"))
                } else {
                    Outcome::Error(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "this daemon lists no such method",
                    ))
                };
                let response = ControlFrame::Response(Response {
                    request_id,
                    outcome,
                });
                if writer.write_message(&response).await.is_err() {
                    break;
                }
            }
        }
    })
}

/// KR-REQ-20.19: a daemon of a release before storage accounts refuses the storage methods as it
/// refuses any method it does not list, `PERMISSION_DENIED`, which is also what a grant without the
/// right is refused with. `kr` tells them apart by asking the managed account's status, which asks
/// for the same right: where that is answered, the host's daemon predates storage accounts and
/// `kr` says so; where it is refused too, the refusal is the grant's and is shown as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_that_does_not_list_the_storage_methods_is_said_to_predate_storage_accounts() {
    // The daemon lists the managed account's status and nothing else.
    let host = kr_ipc::testing::TempHost::create();
    host.environment()
        .create()
        .expect("the environment's directories");
    let serving = scripted_daemon(&host, &["account.status"], usize::MAX, 0);
    for line in [
        ["account", "sign-in", "--storage"],
        ["account", "sign-out", "--storage"],
    ] {
        let (status, refused) = json(&host, &line, None);
        assert_ne!(status, Some(0), "{refused}");
        assert_eq!(refused["ok"], false, "{refused}");
        let message = refused["message"].as_str().unwrap_or_default();
        assert!(message.contains("predates storage accounts"), "{refused}");
    }
    // `show` meets the same daemon and lists the one account it has.
    let (status, shown) = json(&host, &["account", "show"], None);
    assert_eq!(status, Some(0), "{shown}");
    assert!(shown.get("storage_account").is_none(), "{shown}");
    serving.abort();

    // The control: a daemon that refuses the managed account's status too is refusing the right,
    // and the refusal is shown as the grant's, not as an old daemon.
    let denied = kr_ipc::testing::TempHost::create();
    denied
        .environment()
        .create()
        .expect("the environment's directories");
    let serving = scripted_daemon(&denied, &[], usize::MAX, 0);
    let (status, refused) = json(&denied, &["account", "sign-in", "--storage"], None);
    assert_ne!(status, Some(0), "{refused}");
    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
    assert!(
        !refused["message"]
            .as_str()
            .unwrap_or_default()
            .contains("predates"),
        "{refused}"
    );
    serving.abort();
}

/// KR-REQ-20.19: a fence this host owes refuses the storage sign-in and sign-out as it refuses every
/// method that takes no admission, `PERMISSION_DENIED`, and the refusal is shown as the daemon gave
/// it, naming `kr doctor`: a daemon that lists the storage methods and answers their status is not
/// one that predates them. The control is the same host with nothing owed, which signs in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_storage_command_refused_for_a_fence_is_shown_as_that_refusal() {
    let managed = serve().await;
    let storage = serve().await;
    let host = Host::start(
        &document(Some(managed.origin()), Some(storage.origin())),
        Some(managed.origin()),
    )
    .await;
    host._controller.hold_fence(true);
    for line in [
        ["account", "sign-in", "--storage"],
        ["account", "sign-out", "--storage"],
    ] {
        let (status, refused) = host.json(&line);
        assert_ne!(status, Some(0), "{refused}");
        assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
        assert!(
            refused["message"]
                .as_str()
                .is_some_and(|message| message.contains("kr doctor")),
            "the refusal is the fence's: {refused}"
        );
    }
    assert!(host.opened().is_empty(), "no browser was opened");
    host._controller.hold_fence(false);
    let output = host.kr(&["account", "sign-in", "--storage"]);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
}

/// KR-REQ-20.19: `kr account show` that is refused the storage account's status after the managed
/// account's status was answered reads a daemon that does not list the method, or a membership that
/// lapsed between the two reads. It asks the managed account's status again: answered, the host has
/// one account and the command succeeds; refused, the command fails with that refusal and does not
/// report a host with one account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn show_does_not_hide_a_refusal_that_arrives_between_its_two_reads() {
    let host = kr_ipc::testing::TempHost::create();
    host.environment()
        .create()
        .expect("the environment's directories");
    // The managed account's status is answered once, and refused after: the lease lapsed.
    let serving = scripted_daemon(&host, &["account.status"], 1, 0);
    let (status, refused) = json(&host, &["account", "show"], None);
    assert_ne!(status, Some(0), "{refused}");
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
    serving.abort();
}

/// KR-REQ-20.19: a membership lease that lapses and is renewed by another connection between the
/// reads that tell an old daemon from a refused caller is not read as an old daemon. The scripted
/// daemon lists the storage status, refuses its first read as a lapsed membership is refused, and
/// answers the managed status and then the storage status: the write is shown as the daemon refused
/// it, and `show` lists the storage account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_membership_renewed_between_the_reads_is_not_an_old_daemon() {
    let host = kr_ipc::testing::TempHost::create();
    host.environment()
        .create()
        .expect("the environment's directories");
    let serving = scripted_daemon(
        &host,
        &["account.status", "account.storage_status"],
        usize::MAX,
        1,
    );
    let (status, refused) = json(&host, &["account", "sign-in", "--storage"], None);
    assert_ne!(status, Some(0), "{refused}");
    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|message| message.contains("this daemon lists no such method")),
        "the refusal is the daemon's own: {refused}"
    );
    let (status, shown) = json(&host, &["account", "show"], None);
    assert_eq!(status, Some(0), "{shown}");
    assert_eq!(shown["storage_account"]["state"], "signed_out", "{shown}");
    serving.abort();
}
