//! `kr destination`, run the way a person runs it, against a real control daemon.
//!
//! The daemon is this test's own: the real `kr-controller` service, started in this process on a
//! host tree of the test's own, with its real endpoint, handshake and admission, its real delivery
//! journal and its real secret store, and a supervisor that starts no worker, because none of
//! these commands needs a session. `kr` is the real binary, copied to the internal disk and run
//! with that tree's directories on plain pipes.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_delivery::destination::{Destination, DestinationId};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, BuildId, DeviceId, GrantId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};
use serde_json::Value;

mod support;

/// What a Slack credential file holds in these tests: shaped like a Slack incoming-webhook
/// address, and nobody's.
const SLACK_ADDRESS: &str =
    "https://hooks.slack.com/services/T0PLANTED/B0PLANTED/credential-marker-6b1f";

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

/// A host tree and its running daemon.
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

    /// Pairs a device with a grant that lets it see every session, and returns the grant: the
    /// authority a destination is told under.
    fn grant(&self) -> GrantId {
        let device = DeviceId::new(Uuid::from_bytes([0xd1; 16]));
        let grant_id = GrantId::new(Uuid::from_bytes([0x61; 16]));
        self.controller
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
                    grant_id,
                    parent_grant_id: Nullable::null(),
                    issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
                    recipient_device_id: device,
                    authority_revision: AuthorityRevision::new(
                        self.controller.policy().authority_revision().get(),
                    ),
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
        grant_id
    }

    /// Runs `kr` on plain pipes with this tree's directories, from the root directory.
    fn kr(&self, line: &[&str]) -> Output {
        Command::new(support::kr())
            .args(line)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temp.root())
            .env("KR_RUNTIME_DIR", self.temp.paths().runtime_root())
            .env("KR_STATE_DIR", self.temp.paths().state_root())
            .current_dir("/")
            .stdin(Stdio::null())
            .output()
            .expect("kr runs")
    }

    /// Runs `kr` with `--json` and reads the one document it printed, and how it exited.
    fn json(&self, line: &[&str]) -> (Option<i32>, Value) {
        let mut asked = line.to_vec();
        asked.push("--json");
        let output = self.kr(&asked);
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

    /// Runs `kr` with `--json` and reads the document of a success.
    fn done(&self, line: &[&str]) -> Value {
        let (status, document) = self.json(line);
        assert_eq!(status, Some(0), "kr {}: {document}", line.join(" "));
        assert_eq!(document["ok"], Value::Bool(true), "{document}");
        document
    }

    /// The destination the daemon's journal holds under an identifier.
    fn destination(&self, id: &str) -> Option<kr_delivery::destination::DestinationRecord> {
        let id = DestinationId::new(id).expect("an identifier");
        self.controller
            .delivery()
            .with(|producer| Ok(producer.journal().destination(&id).expect("a read")))
            .expect("a read")
    }
}

/// KR-REQ-25.23: the owner creates a webhook with `kr destination configure`, sees it in
/// `kr destination list`, and removes it with `kr destination remove`; each is the daemon's own
/// method, with text for a person and a document for a script. The control for the first half is
/// the list before there is a destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_webhook_is_configured_listed_and_removed_through_the_daemon() {
    let host = Host::start().await;
    let grant = host.grant().to_string();

    let before = host.done(&["destination", "list"]);
    assert_eq!(before["destinations"], Value::Array(Vec::new()), "{before}");
    let shown = host.kr(&["destination", "list"]);
    assert!(String::from_utf8_lossy(&shown.stdout).contains("no destinations"));

    let configured = host.done(&[
        "destination",
        "configure",
        "ops",
        "--kind",
        "webhook",
        "--endpoint",
        "https://hooks.example.test/in/ops",
        "--grant",
        &grant,
        "--rule-name",
        "tell the team",
        "--idempotency-header",
        "Idempotency-Key",
    ]);
    assert_eq!(configured["destination_id"], "ops");
    assert_eq!(configured["kind"], "webhook");
    assert_eq!(configured["in_force"], Value::Bool(true));
    assert!(
        configured["recipients_can_read"]
            .as_str()
            .is_some_and(|sentence| sentence.contains("Whoever runs")),
        "{configured}"
    );
    let record = host.destination("ops").expect("the daemon holds it");
    assert!(record.enabled);
    assert_eq!(
        record.rule.as_ref().map(|rule| rule.name.as_str()),
        Some("tell the team")
    );

    let listed = host.done(&["destination", "list"]);
    let destinations = listed["destinations"].as_array().expect("a list");
    assert_eq!(destinations.len(), 1, "{listed}");
    let destination = &destinations[0];
    assert_eq!(destination["destination_id"], "ops");
    assert_eq!(destination["kind"], "webhook");
    assert_eq!(destination["endpoint"], "https://hooks.example.test/in/ops");
    assert_eq!(destination["idempotency_header"], "Idempotency-Key");
    assert_eq!(destination["rule_name"], "tell the team");
    assert_eq!(destination["grant_id"], grant);
    assert_eq!(destination["in_force"], Value::Bool(true));
    let shown = host.kr(&["destination", "list"]);
    let shown = String::from_utf8_lossy(&shown.stdout);
    assert!(
        shown.contains("ops") && shown.contains("https://hooks.example.test/in/ops"),
        "{shown}"
    );

    let removed = host.done(&["destination", "remove", "ops"]);
    assert_eq!(removed["found"], Value::Bool(true));
    assert!(
        host.destination("ops")
            .is_none_or(|record| !record.enabled && record.rule.is_none()),
        "the daemon no longer delivers to it"
    );
    let after = host.done(&["destination", "list"]);
    assert_eq!(after["destinations"], Value::Array(Vec::new()), "{after}");

    // Removing it again is removing it once, and says that nothing was there.
    let again = host.done(&["destination", "remove", "ops"]);
    assert_eq!(again["found"], Value::Bool(false));
    let shown = host.kr(&["destination", "remove", "ops"]);
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains("No destination is configured under ops"),
        "{}",
        String::from_utf8_lossy(&shown.stdout)
    );
}

/// KR-REQ-25.23: a service that sends with a credential is configured from a file that holds it.
/// The credential reaches the daemon's secret store and nothing a person or a script reads: not the
/// command's text, its document, the list, or a refusal. Without the file the command refuses and
/// the daemon holds no destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chat_destination_is_configured_from_a_credential_file_that_is_never_printed() {
    let host = Host::start().await;
    let grant = host.grant().to_string();
    let file = host.work.path().join("slack-address");
    std::fs::write(&file, format!("{SLACK_ADDRESS}\n")).expect("the credential file");
    let file = file.to_string_lossy().into_owned();
    let line = |credential: Option<&str>| {
        let mut line = vec![
            "destination".to_owned(),
            "configure".to_owned(),
            "chat".to_owned(),
            "--kind".to_owned(),
            "slack".to_owned(),
            "--endpoint".to_owned(),
            "#alerts".to_owned(),
            "--grant".to_owned(),
            grant.clone(),
        ];
        if let Some(credential) = credential {
            line.extend(["--credential-file".to_owned(), credential.to_owned()]);
        }
        line
    };
    fn run(line: &[String]) -> Vec<&str> {
        line.iter().map(String::as_str).collect()
    }

    // The refusal without the file.
    let without = line(None);
    let (status, refusal) = host.json(&run(&without));
    assert_ne!(status, Some(0), "{refusal}");
    assert_eq!(refusal["ok"], Value::Bool(false), "{refusal}");
    assert!(host.destination("chat").is_none(), "nothing was configured");

    // With it.
    let with = line(Some(&file));
    let output = host.kr(&run(&with));
    assert!(output.status.success(), "{output:?}");
    let configured = host.done(&run(&with));
    assert_eq!(configured["kind"], "slack");
    assert_eq!(configured["in_force"], Value::Bool(true));
    let record = host.destination("chat").expect("the daemon holds it");
    let Destination::External(external) = &record.destination else {
        panic!("an external destination");
    };
    assert!(
        external.credential.is_some(),
        "the destination names the credential kept for it"
    );

    let listed = host.kr(&["destination", "list"]);
    let (_, listed_json) = host.json(&["destination", "list"]);
    for printed in [
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        String::from_utf8_lossy(&listed.stdout).into_owned(),
        configured.to_string(),
        listed_json.to_string(),
        refusal.to_string(),
    ] {
        assert!(!printed.contains("credential-marker-6b1f"), "{printed}");
    }

    // A replacement the daemon refuses, under a grant that was never issued, changes nothing: not
    // the destination, and not the credential it sends with.
    let replacement = host.work.path().join("replacement-address");
    std::fs::write(
        &replacement,
        "https://hooks.slack.com/services/T0PLANTED/B0PLANTED/replacement-marker-3d9a\n",
    )
    .expect("the replacement credential");
    let nobody = "0badc0de-0000-4000-8000-000000000001";
    let (status, refusal) = host.json(&[
        "destination",
        "configure",
        "chat",
        "--kind",
        "slack",
        "--endpoint",
        "#elsewhere",
        "--grant",
        nobody,
        "--credential-file",
        &replacement.to_string_lossy(),
    ]);
    assert_ne!(status, Some(0), "{refusal}");
    assert_eq!(host.destination("chat"), Some(record.clone()));
    let secrets = host.temp.environment().secrets_dir();
    // Whether the credential kept for the destination is the one that holds `text`.
    let vault = |text: &str| {
        let store = open_store_in(&secrets).expect("the secret store");
        let name = DestinationId::new("chat").expect("an identifier");
        let held = kr_controller::push::secrets::DestinationSecrets::new(
            Arc::from(store.store),
            host.temp.environment_id(),
        )
        .get(&name)
        .expect("a read");
        matches!(
            held.map(|held| held.secret),
            Some(kr_protocol::delivery::DestinationSecret::Slack { webhook_url })
                if webhook_url.expose().contains(text)
        )
    };
    assert!(vault("credential-marker-6b1f"), "the credential it had");
    assert!(!vault("replacement-marker-3d9a"), "and not the refused one");

    // The credential is the daemon's: it sends with it, and it goes with the destination.
    let removed = host.done(&["destination", "remove", "chat"]);
    assert_eq!(removed["found"], Value::Bool(true));
    let secrets = host.temp.environment().secrets_dir();
    let store = open_store_in(&secrets).expect("the secret store");
    let id = DestinationId::new("chat").expect("an identifier");
    let kept = kr_controller::push::secrets::DestinationSecrets::new(
        Arc::from(store.store),
        host.temp.environment_id(),
    )
    .get(&id)
    .expect("a read");
    assert!(kept.is_none(), "the credential went with the destination");
}

/// KR-REQ-25.23: the daemon decides what a destination is allowed, and the command shows its
/// refusal and exits with a failure: a grant that does not stand, and a credential file that holds
/// no credential, which says which file and repeats nothing of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_destination_the_daemon_refuses_is_a_failure_that_leaves_nothing_behind() {
    let host = Host::start().await;
    let nobody = "0badc0de-0000-4000-8000-000000000001";
    let (status, refusal) = host.json(&[
        "destination",
        "configure",
        "ops",
        "--kind",
        "webhook",
        "--endpoint",
        "https://hooks.example.test/in/ops",
        "--grant",
        nobody,
    ]);
    assert_ne!(status, Some(0), "{refusal}");
    assert_eq!(refusal["ok"], Value::Bool(false), "{refusal}");
    assert!(host.destination("ops").is_none());

    let empty = host.work.path().join("empty");
    std::fs::write(&empty, "").expect("an empty file");
    let grant = host.grant().to_string();
    let (status, refusal) = host.json(&[
        "destination",
        "configure",
        "chat",
        "--kind",
        "telegram",
        "--endpoint",
        "123456789",
        "--grant",
        &grant,
        "--credential-file",
        &empty.to_string_lossy(),
    ]);
    assert_ne!(status, Some(0), "{refusal}");
    assert!(
        refusal.to_string().contains("does not hold a bot token"),
        "{refusal}"
    );
    assert!(host.destination("chat").is_none());
}
