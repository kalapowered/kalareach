//! External destinations and the credentials they send with.
//!
//! A Slack or Discord webhook address, a Telegram bot token and a mail submission account are each
//! a credential, and the host keeps each in its secret store under the destination's identifier:
//! handed over once by the owner at this machine, answered back to nobody, never written to the
//! delivery journal or a log, and gone when the destination goes.
//!
//! Everything runs on this machine's loopback interface and in temporary directories on the
//! internal disk. No vendor is contacted.

mod net_support;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_controller::push::secrets::DestinationSecrets;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::open_store_in;
use kr_delivery::destination::{
    DeliveryRule, Destination, DestinationId, DestinationKind, DestinationRecord,
    ExternalDestination, Idempotency,
};
use kr_ipc::client::LocalClient;
use kr_protocol::delivery::{
    DeliveryDestinationSecretSetParams, DeliveryDestinationSecretSetResult, DestinationSecret,
    DestinationSecretKind, MailAccount, MailSecurity, SecretText,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, TimestampMs, U64};

/// The part of every credential here that must never appear outside the secret store.
const SECRET_PART: &str = "kept-in-the-secret-store-only";

fn slack_url() -> String {
    format!("https://hooks.slack.com/services/T0KALA/B0REACH/{SECRET_PART}")
}

fn secret_text(text: &str) -> SecretText {
    SecretText::new(text).expect("a credential")
}

fn slack(destination_id: &str, url: &str) -> DeliveryDestinationSecretSetParams {
    DeliveryDestinationSecretSetParams {
        destination_id: destination_id.to_owned(),
        secret: DestinationSecret::Slack {
            webhook_url: secret_text(url),
        },
    }
}

fn mail_account(from_address: &str) -> MailAccount {
    MailAccount {
        server: "smtp.example.com".to_owned(),
        port: U64::new(465),
        security: MailSecurity::ImplicitTls,
        username: secret_text("alerts@example.com"),
        password: secret_text(SECRET_PART),
        from_address: from_address.to_owned(),
    }
}

/// The store the daemon keeps its secrets in: this environment's own directory, because the test
/// daemon is started with the file store.
fn secrets_of(host: &net_support::Host) -> DestinationSecrets {
    let store = open_store_in(&host.tree().environment().secrets_dir())
        .expect("the store the daemon keeps its secrets in");
    DestinationSecrets::new(Arc::from(store.store), host.environment_id)
}

fn identifier(text: &str) -> DestinationId {
    DestinationId::new(text).expect("an identifier")
}

/// Every file the environment's delivery journal is made of.
fn journal_files(state_dir: &Path) -> Vec<PathBuf> {
    [
        "delivery.sqlite3",
        "delivery.sqlite3-wal",
        "delivery.sqlite3-shm",
    ]
    .into_iter()
    .map(|name| state_dir.join(name))
    .filter(|path| path.exists())
    .collect()
}

fn holds(bytes: &[u8], text: &str) -> bool {
    bytes
        .windows(text.len())
        .any(|window| window == text.as_bytes())
}

/// Asserts that no file of the delivery journal holds the credential's secret part.
fn assert_journal_never_holds_it(state_dir: &Path) {
    let files = journal_files(state_dir);
    assert!(!files.is_empty(), "the journal exists");
    for file in files {
        let bytes = std::fs::read(&file).expect("the journal file reads");
        assert!(
            !holds(&bytes, SECRET_PART),
            "{} holds the credential",
            file.display()
        );
    }
}

async fn set_secret(
    control: &mut LocalClient,
    host: &net_support::Host,
    params: &DeliveryDestinationSecretSetParams,
) -> Result<ParamsValue, ProtocolError> {
    control
        .mutate(
            Method::DeliveryDestinationSecretSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
}

/// Renders an answer the way it travels, so a test can look for the credential in every byte of it.
fn rendered(answer: &Result<ParamsValue, ProtocolError>) -> String {
    match answer {
        Ok(value) => format!(
            "{:?} {}",
            value,
            serde_json::to_string(
                &value
                    .to_typed::<DeliveryDestinationSecretSetResult>()
                    .expect("the result decodes")
            )
            .expect("the result renders")
        ),
        Err(error) => format!("{error:?} {error}"),
    }
}

/// KR-REQ-25.23: the owner at this machine hands a Slack credential over once. The host keeps it in
/// its secret store under the destination's identifier; the answer names the destination, its kind
/// and who reads what it delivers, and never carries the credential; the delivery journal never
/// holds it; a repeat of the same action is answered from its record without storing anything
/// again, and the same action with another credential is a conflict that changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_keeps_a_credential_that_no_answer_carries_back() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;

    let mutation = control
        .compose(
            Method::DeliveryDestinationSecretSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &slack("team", &slack_url()),
        )
        .await
        .expect("a mutation");
    let answer = control
        .repeat(&mutation)
        .await
        .expect("the call reaches the daemon");
    assert!(
        !rendered(&answer).contains(SECRET_PART),
        "the answer carries the credential: {}",
        rendered(&answer)
    );
    let stored: DeliveryDestinationSecretSetResult = answer
        .expect("the owner keeps a credential")
        .to_typed()
        .expect("the result decodes");
    assert_eq!(stored.destination_id, "team");
    assert_eq!(stored.kind, DestinationSecretKind::Slack);
    assert!(
        !stored.in_force,
        "nothing is configured under the identifier yet"
    );
    assert!(
        stored.recipients_can_read.contains("Slack channel")
            && stored
                .recipients_can_read
                .contains("does not make it private"),
        "{}",
        stored.recipients_can_read
    );

    let secrets = secrets_of(&host);
    let held = secrets
        .get(&identifier("team"))
        .expect("the store reads")
        .expect("the credential is kept");
    assert_eq!(
        held.secret,
        DestinationSecret::Slack {
            webhook_url: secret_text(&slack_url())
        }
    );

    // The same action again is answered from its record, and stores nothing again.
    let again = control
        .repeat(&mutation)
        .await
        .expect("the call reaches the daemon")
        .expect("a repeat is answered");
    assert_eq!(
        again
            .to_typed::<DeliveryDestinationSecretSetResult>()
            .expect("the result decodes"),
        stored
    );
    assert_eq!(
        secrets
            .get(&identifier("team"))
            .expect("the store reads")
            .expect("still kept")
            .stamp,
        held.stamp,
        "the repeat wrote nothing"
    );

    // The same action with another credential is a reused identifier, and changes nothing.
    let mut other = mutation.clone();
    other.params = ParamsValue::from_typed(&slack(
        "team",
        "https://hooks.slack.com/services/T0KALA/B0REACH/another",
    ))
    .expect("params");
    let conflict = control
        .repeat(&other)
        .await
        .expect("the call reaches the daemon")
        .expect_err("a reused identifier");
    assert_eq!(conflict.code, ErrorCode::IdConflict);
    assert_eq!(
        secrets
            .get(&identifier("team"))
            .expect("the store reads")
            .expect("still kept")
            .secret,
        held.secret
    );

    assert_journal_never_holds_it(host.tree().environment().state_dir());
    drop(control);
    host.stop().await;
}

/// KR-REQ-25.23: a credential of the wrong shape is refused before anything is kept, and the
/// refusal never repeats it. A Slack credential is Slack's own webhook address, a Telegram token has
/// the shape Telegram issues, and a mail account's addresses carry no line break a header could be
/// built from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_credential_of_the_wrong_shape_is_refused_and_never_repeated() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;

    let refused = [
        slack(
            "elsewhere",
            &format!("https://collector.example.net/services/T0/B0/{SECRET_PART}"),
        ),
        slack(
            "plain",
            &format!("http://hooks.slack.com/services/T0/B0/{SECRET_PART}"),
        ),
        DeliveryDestinationSecretSetParams {
            destination_id: "bot".to_owned(),
            secret: DestinationSecret::Telegram {
                bot_token: secret_text(&format!("not-a-number:{SECRET_PART}")),
            },
        },
        DeliveryDestinationSecretSetParams {
            destination_id: "mail".to_owned(),
            secret: DestinationSecret::Email {
                account: mail_account("alerts@example.com\r\nBcc: someone@example.net"),
            },
        },
        DeliveryDestinationSecretSetParams {
            destination_id: "line\nbreak".to_owned(),
            secret: DestinationSecret::Slack {
                webhook_url: secret_text(&slack_url()),
            },
        },
    ];
    for params in &refused {
        let answer = set_secret(&mut control, &host, params).await;
        assert!(
            !rendered(&answer).contains(SECRET_PART),
            "the refusal repeats the credential: {}",
            rendered(&answer)
        );
        let error = answer.expect_err("a credential of the wrong shape is refused");
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{error:?}");
    }
    let secrets = secrets_of(&host);
    for id in ["elsewhere", "plain", "bot", "mail"] {
        assert!(
            secrets
                .get(&identifier(id))
                .expect("the store reads")
                .is_none(),
            "{id}: nothing was kept"
        );
    }
    drop(control);
    host.stop().await;
}

/// KR-REQ-25.23: parameters that do not read as this method's are refused in one fixed sentence,
/// so a credential sent where the object belongs, under a tag of its own or as a field's name is
/// never repeated back. Nothing is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parameters_that_do_not_read_are_refused_without_repeating_them() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;
    let url = slack_url();
    let malformed = [
        serde_json::json!({ "destination_id": "team", "secret": url }),
        serde_json::json!({ "destination_id": "team", "secret": { "kind": url } }),
        serde_json::json!({
            "destination_id": "team",
            "secret": { "kind": "slack", "webhook_url": url, url.clone(): "extra" },
        }),
        serde_json::json!({
            "destination_id": "team",
            "secret": { "kind": "telegram", "bot_token": 12, "webhook_url": url },
        }),
        serde_json::json!({ "destination_id": "team", "secret": [url] }),
    ];
    for params in &malformed {
        let answer = control
            .mutate(
                Method::DeliveryDestinationSecretSet,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                params,
            )
            .await
            .expect("the call reaches the daemon");
        let error = answer.expect_err("parameters that do not read are refused");
        let rendered = format!("{error:?} {error}");
        assert!(
            !rendered.contains(SECRET_PART),
            "the refusal of {params} repeats the credential: {rendered}"
        );
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{rendered}");
    }
    assert!(
        secrets_of(&host)
            .get(&identifier("team"))
            .expect("the store reads")
            .is_none(),
        "nothing was kept"
    );
    drop(control);
    host.stop().await;
}

/// KR-REQ-25.23: storing a destination's credential is the owner's own act at this machine. A
/// paired device is refused whatever its grant carries, host management included, and nothing is
/// kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_cannot_hand_over_a_credential_whatever_its_grant() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let (_device, session) =
        net_support::paired_device(&host, &owner, &[ActionRight::HostManage]).await;
    let refused = session
        .mutate(
            Method::DeliveryDestinationSecretSet,
            ActionTarget::environment(host.environment_id),
            None,
            &ParamsValue::empty(),
            &slack("team", &slack_url()),
            DurationMs::new(120_000),
        )
        .await
        .expect_err("a paired device cannot hand over a credential");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        secrets_of(&host)
            .get(&identifier("team"))
            .expect("the store reads")
            .is_none(),
        "nothing was kept"
    );
    session.close();
    host.stop().await;
}

fn webhook(id: &str) -> DestinationRecord {
    DestinationRecord {
        id: identifier(id),
        destination: Destination::External(ExternalDestination {
            kind: DestinationKind::Webhook,
            endpoint: "https://hooks.example.net/kalareach".to_owned(),
            idempotency: Idempotency::Unsupported,
            credential: None,
        }),
        rule: Some(DeliveryRule {
            name: "on failure".to_owned(),
            grant_id: None,
        }),
        enabled: true,
        configured_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
    }
}

/// KR-REQ-25.23: a credential goes with its destination. Removing the destination deletes it, and
/// so does configuring a destination that sends with no credential under its identifier: nothing
/// configured there later can pick up a credential nobody gave it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_destination_takes_its_credential_with_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;
    let secrets = secrets_of(&host);
    let delivery = host.controller().delivery();

    set_secret(&mut control, &host, &slack("team", &slack_url()))
        .await
        .expect("the owner keeps a credential");
    assert!(secrets.get(&identifier("team")).expect("a read").is_some());
    let removal = delivery
        .remove(&identifier("team"), kr_ipc::now_ms().get())
        .expect("the destination goes");
    assert!(
        !removal.found,
        "no destination was configured, only its credential"
    );
    assert!(
        secrets.get(&identifier("team")).expect("a read").is_none(),
        "removing the destination deleted its credential"
    );

    set_secret(&mut control, &host, &slack("replaced", &slack_url()))
        .await
        .expect("the owner keeps a credential");
    delivery
        .configure(&webhook("replaced"))
        .expect("a webhook replaces what was there");
    assert!(
        secrets
            .get(&identifier("replaced"))
            .expect("a read")
            .is_none(),
        "a destination that sends with no credential takes the old one with it"
    );

    delivery
        .configure(&webhook("configured"))
        .expect("a webhook");
    set_secret(&mut control, &host, &slack("configured", &slack_url()))
        .await
        .expect("a credential under a webhook's identifier waits for a Slack destination");
    let removal = delivery
        .remove(&identifier("configured"), kr_ipc::now_ms().get())
        .expect("the destination goes");
    assert!(removal.found && !removal.kept_as_history);
    assert!(
        secrets
            .get(&identifier("configured"))
            .expect("a read")
            .is_none()
    );
    assert_eq!(
        delivery
            .with(|producer| Ok(producer
                .journal()
                .destination(&identifier("configured"))
                .expect("a read")))
            .expect("a read"),
        None,
        "a destination nothing names is forgotten"
    );
    drop(control);
    host.stop().await;
}

/// A daemon this test started from its own copy of the program, killed when the guard goes.
#[cfg(unix)]
struct Daemon(Option<std::process::Child>);

#[cfg(unix)]
impl Drop for Daemon {
    fn drop(&mut self) {
        let Some(mut child) = self.0.take() else {
            return;
        };
        if let Ok(pid) = i32::try_from(child.id())
            && let Some(pid) = rustix::process::Pid::from_raw(pid)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
        let _ = child.wait();
    }
}

/// KR-REQ-25.23: the daemon a person runs writes nothing of a credential to its log. The daemon is
/// this build's own program, started from a copy on the internal disk with its secrets in this
/// environment's directory; it is handed one credential it keeps and two it refuses, and
/// afterwards neither its log nor its delivery journal holds any of them.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neither_the_daemons_log_nor_its_journal_carries_a_credential() {
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    let environment_id = host.environment_id();
    let program = host.root().join("kr-controller");
    kr_ipc::testing::place_program(Path::new(env!("CARGO_BIN_EXE_kr-controller")), &program);
    let log_path = host.root().join("daemon.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("opens the daemon's log");
    let daemon = Daemon(Some(
        std::process::Command::new(&program)
            // On the internal disk, never the checkout: a copied program is a new one to the
            // operating system's privacy rules.
            .current_dir(host.root())
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
            .expect("the daemon starts"),
    ));

    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut control = loop {
        if let Ok(client) = LocalClient::connect(
            &endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            net_support::build(),
        )
        .await
        {
            break client;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon did not answer, and its log says: {}",
            std::fs::read_to_string(&log_path).unwrap_or_default()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };

    let target = ActionTarget::environment(environment_id);
    let kept = control
        .mutate(
            Method::DeliveryDestinationSecretSet,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &slack("team", &slack_url()),
        )
        .await
        .expect("the call reaches the daemon");
    assert!(kept.is_ok(), "{kept:?}");
    for refused in [
        slack(
            "elsewhere",
            &format!("https://collector.example.net/services/T0/B0/{SECRET_PART}"),
        ),
        DeliveryDestinationSecretSetParams {
            destination_id: "mail".to_owned(),
            secret: DestinationSecret::Email {
                account: mail_account("not an address"),
            },
        },
    ] {
        let answer = control
            .mutate(
                Method::DeliveryDestinationSecretSet,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &refused,
            )
            .await
            .expect("the call reaches the daemon");
        assert!(answer.is_err(), "{answer:?}");
    }
    drop(control);
    drop(daemon);

    let written = std::fs::read(&log_path).expect("the log reads");
    assert!(
        !holds(&written, SECRET_PART),
        "the daemon's log holds a credential: {}",
        String::from_utf8_lossy(&written)
    );
    assert_journal_never_holds_it(environment.state_dir());
    let secrets = DestinationSecrets::new(
        Arc::from(
            open_store_in(&environment.secrets_dir())
                .expect("the daemon's store")
                .store,
        ),
        environment_id,
    );
    assert!(
        secrets
            .get(&identifier("team"))
            .expect("the store reads")
            .is_some(),
        "the one credential it was given to keep is in its secret store"
    );
}

// ----- Stand-ins for the services, on this machine's loopback interface ----------------------

/// One request a stand-in service received.
#[derive(Clone, Debug)]
struct Received {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    /// Everything but the request line: where a credential that belongs in the path must not be.
    fn outside_the_path(&self) -> String {
        format!("{:?} {}", self.headers, String::from_utf8_lossy(&self.body))
    }
}

/// A plain HTTP service on loopback that answers each request with the next scripted answer, and
/// with `200 ok` once the script runs out.
struct StandIn {
    origin: String,
    received: Arc<std::sync::Mutex<Vec<Received>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    port: u16,
}

impl StandIn {
    fn start(answers: Vec<(u16, String)>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, stopping) = (Arc::clone(&received), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut answers = std::collections::VecDeque::from(answers);
            for connection in listener.incoming() {
                if stopping.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let Ok(mut connection) = connection else {
                    continue;
                };
                let Some(request) = read_request(&mut connection) else {
                    continue;
                };
                seen.lock().expect("the record").push(request);
                let (status, body) = answers
                    .pop_front()
                    .unwrap_or_else(|| (200, "ok".to_owned()));
                let reply = format!(
                    "HTTP/1.1 {status} Stand-in\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = std::io::Write::write_all(&mut connection, reply.as_bytes());
            }
        });
        Self {
            origin: format!("http://127.0.0.1:{port}"),
            received,
            stop,
            port,
        }
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().expect("the record").clone()
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn read_request(connection: &mut std::net::TcpStream) -> Option<Received> {
    use std::io::Read as _;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        let read = connection.read(&mut chunk).ok()?;
        if read == 0 || buffer.len() > 1 << 20 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_owned();
    let target = request_line.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < length {
        let read = connection.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(Received {
        method,
        target,
        headers,
        body,
    })
}

/// The managed transport to a stand-in, reached under the service's own origin: the address the
/// adapter asks for is the service's, and only its origin is swapped for the stand-in's, so the
/// path, the headers and the body are exactly what the service would receive.
#[derive(Debug)]
struct Redirected {
    service: String,
    stand_in: String,
    transport: kr_client::services::HttpService,
}

impl kr_client::services::ServiceHttp for Redirected {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        let redirected = url.replacen(&self.service, &self.stand_in, 1);
        Box::pin(async move { self.transport.post_json(&redirected, body, headers).await })
    }
}

/// The transports a host would reach each service through, each one leading to its stand-in.
#[derive(Debug, Default)]
struct ToStandIns(std::collections::BTreeMap<String, Arc<dyn kr_client::services::ServiceHttp>>);

impl ToStandIns {
    fn with(mut self, service: &str, stand_in: &StandIn) -> Self {
        let transport = kr_client::services::HttpService::new(
            kr_protocol::service::GatewayOrigin::new(stand_in.origin.clone())
                .expect("a loopback origin"),
        )
        .expect("a transport");
        self.0.insert(
            service.to_owned(),
            Arc::new(Redirected {
                service: service.to_owned(),
                stand_in: stand_in.origin.clone(),
                transport,
            }),
        );
        self
    }
}

impl kr_controller::push::transport::DeliveryTransports for ToStandIns {
    fn to(
        &self,
        origin: &kr_protocol::service::GatewayOrigin,
    ) -> Result<Arc<dyn kr_client::services::ServiceHttp>, String> {
        self.0
            .get(origin.as_str())
            .cloned()
            .ok_or_else(|| format!("this test reaches no {origin}"))
    }
}

const SLACK: &str = "https://hooks.slack.com";
const DISCORD: &str = "https://discord.com";
const TELEGRAM: &str = "https://api.telegram.org";

fn discord_url() -> String {
    format!("https://discord.com/api/webhooks/123456789/{SECRET_PART}")
}

fn telegram_token() -> String {
    format!("123456:{SECRET_PART}")
}

fn external(kind: DestinationKind, endpoint: &str) -> ExternalDestination {
    ExternalDestination {
        kind,
        endpoint: endpoint.to_owned(),
        idempotency: Idempotency::Unsupported,
        credential: None,
    }
}

fn session() -> kr_protocol::ids::SessionId {
    kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]))
}

/// The lines a message carries: one a mail server would read as the end of the message, one a
/// chat service would read as a mention of everyone, and one that is not ASCII.
fn lines(now_ms: u64) -> Vec<kr_delivery::external::ContentLine> {
    [
        ".hidden: a line that begins with a dot",
        "<!channel> @everyone <@U012AB3CD> would ping people",
        "caf\u{e9} \u{2615} and a trailing space ",
    ]
    .into_iter()
    .map(|text| kr_delivery::external::ContentLine {
        session_id: Some(session()),
        produced_at_ms: Some(now_ms - 1_000),
        text: text.to_owned(),
    })
    .collect()
}

fn message(kind: DestinationKind) -> kr_delivery::external::ExternalMessage {
    kr_delivery::external::compose(
        kind,
        kr_protocol::push::PushAlert::ApprovalWaiting,
        lines(kr_ipc::now_ms().get()),
        &kr_worker::history_filter::HistoryFilter::new(
            kr_worker::history_filter::ViewerScope::owner(),
        ),
        &kr_protocol::grant::SessionSelector::Any,
        None,
    )
    .expect("a message")
}

/// A runtime whose threads keep the stand-ins and the transports going while a test waits on an
/// adapter the way a pass does.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime")
}

fn chat_sender(
    runtime: &tokio::runtime::Runtime,
    transports: ToStandIns,
) -> kr_controller::push::chat::ChatSender {
    kr_controller::push::chat::ChatSender::new(Arc::new(transports), runtime.handle().clone())
}

/// KR-REQ-25.23: a Slack message is a POST of JSON to the incoming webhook's own address, which
/// is the credential and appears nowhere else in the request; its text is escaped so nothing in it
/// can mention anyone or become a link, and Slack's formatting and unfurling are off. The message
/// says its recipients can read it.
#[test]
fn slack_is_posted_to_its_webhook_address_as_escaped_text() {
    let runtime = runtime();
    let slack = StandIn::start(Vec::new());
    let sender = chat_sender(&runtime, ToStandIns::default().with(SLACK, &slack));
    let outcome = sender.send(
        &external(DestinationKind::Slack, "#alerts"),
        &DestinationSecret::Slack {
            webhook_url: secret_text(&slack_url()),
        },
        &message(DestinationKind::Slack),
    );
    assert_eq!(outcome, kr_delivery::external::ExternalOutcome::Delivered);
    let received = slack.received();
    assert_eq!(received.len(), 1);
    let request = &received[0];
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.target,
        format!("/services/T0KALA/B0REACH/{SECRET_PART}"),
        "the credential is the address"
    );
    assert!(
        !request.outside_the_path().contains(SECRET_PART),
        "and it is nowhere else in the request"
    );
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/json")
    );
    let body = request.json();
    assert_eq!(body["mrkdwn"], false);
    assert_eq!(body["unfurl_links"], false);
    assert_eq!(body["unfurl_media"], false);
    let text = body["text"].as_str().expect("text");
    assert!(
        text.contains("&lt;!channel&gt;") && !text.contains("<!channel>"),
        "{text}"
    );
    assert!(text.contains("&lt;@U012AB3CD&gt;"), "{text}");
    assert!(
        text.contains("does not make it private"),
        "the message says its recipients can read it"
    );
}

/// KR-REQ-25.23: a Discord message is a POST of JSON to the webhook's address with `wait=true`, so
/// a message Discord does not save is an error rather than silence; it allows no mention and
/// suppresses link embeds; the token is in the path and nowhere else; and a message longer than
/// Discord takes is shortened and still ends with the sentence that says who can read it.
#[test]
fn discord_is_posted_to_its_webhook_with_no_mentions_and_confirmed() {
    let runtime = runtime();
    let discord = StandIn::start(vec![(200, "{\"id\":\"1\"}".to_owned())]);
    let sender = chat_sender(&runtime, ToStandIns::default().with(DISCORD, &discord));
    let mut long = message(DestinationKind::Discord);
    long.body = format!(
        "{}\n{}\n\n{}",
        kr_protocol::push::PushAlert::ApprovalWaiting.generic_text(),
        "a very long line ".repeat(400),
        kr_delivery::external::RECIPIENTS_CAN_READ
    );
    let outcome = sender.send(
        &external(DestinationKind::Discord, "#deployments"),
        &DestinationSecret::Discord {
            webhook_url: secret_text(&discord_url()),
        },
        &long,
    );
    assert_eq!(outcome, kr_delivery::external::ExternalOutcome::Delivered);
    let request = &discord.received()[0];
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.target,
        format!("/api/webhooks/123456789/{SECRET_PART}?wait=true")
    );
    assert!(!request.outside_the_path().contains(SECRET_PART));
    let body = request.json();
    assert_eq!(body["allowed_mentions"], serde_json::json!({ "parse": [] }));
    assert_eq!(body["flags"], 4, "link embeds are suppressed");
    let content = body["content"].as_str().expect("content");
    assert!(content.encode_utf16().count() <= 2_000, "{}", content.len());
    assert!(content.contains("Shortened to fit what Discord takes"));
    assert!(content.ends_with(kr_delivery::external::RECIPIENTS_CAN_READ));
}

/// KR-REQ-25.23: a Telegram message is `sendMessage`, POSTed as JSON to the Bot API with the bot's
/// token in the path, where the Bot API takes it, and nowhere else; the chat is the destination's
/// endpoint, as a number; no parse mode, so the text is never read as markup; link previews off.
#[test]
fn telegram_sends_through_the_bot_token_in_the_path() {
    let runtime = runtime();
    let telegram = StandIn::start(vec![(
        200,
        "{\"ok\":true,\"result\":{\"message_id\":1}}".to_owned(),
    )]);
    let sender = chat_sender(&runtime, ToStandIns::default().with(TELEGRAM, &telegram));
    let outcome = sender.send(
        &external(DestinationKind::Telegram, "-1001234567890"),
        &DestinationSecret::Telegram {
            bot_token: secret_text(&telegram_token()),
        },
        &message(DestinationKind::Telegram),
    );
    assert_eq!(outcome, kr_delivery::external::ExternalOutcome::Delivered);
    let request = &telegram.received()[0];
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.target,
        format!("/bot123456:{SECRET_PART}/sendMessage")
    );
    assert!(!request.outside_the_path().contains(SECRET_PART));
    let body = request.json();
    assert_eq!(body["chat_id"], -1_001_234_567_890_i64);
    assert!(body.get("parse_mode").is_none(), "no markup is parsed");
    assert_eq!(body["link_preview_options"]["is_disabled"], true);
    assert!(
        body["text"]
            .as_str()
            .expect("text")
            .contains("does not make it private")
    );
}

/// KR-REQ-25.24: each chat service's answer is read as what it says, and nothing a service says
/// that holds a piece of the credential is repeated, nor is a failure's own message, which names
/// the address.
#[test]
fn a_chat_services_answer_is_read_as_what_it_says() {
    use kr_delivery::external::ExternalOutcome;

    let runtime = runtime();
    type Case = (
        DestinationKind,
        (u16, String),
        fn(&ExternalOutcome) -> bool,
        &'static str,
    );
    let cases: Vec<Case> = vec![
        (
            DestinationKind::Slack,
            (400, "invalid_payload".to_owned()),
            |outcome| matches!(outcome, ExternalOutcome::Refused { .. }),
            "invalid_payload",
        ),
        (
            DestinationKind::Slack,
            (429, String::new()),
            |outcome| matches!(outcome, ExternalOutcome::NotDispatched { .. }),
            "asked for later",
        ),
        (
            DestinationKind::Slack,
            (500, "rollup_error".to_owned()),
            |outcome| matches!(outcome, ExternalOutcome::Unknown { .. }),
            "500",
        ),
        (
            DestinationKind::Slack,
            (400, format!("invalid_payload for {SECRET_PART}")),
            |outcome| matches!(outcome, ExternalOutcome::Refused { .. }),
            "Slack answered 400",
        ),
        (
            DestinationKind::Discord,
            (
                404,
                "{\"message\":\"Unknown Webhook\",\"code\":10015}".to_owned(),
            ),
            |outcome| matches!(outcome, ExternalOutcome::Refused { .. }),
            "404",
        ),
        (
            DestinationKind::Telegram,
            (
                400,
                "{\"ok\":false,\"error_code\":400,\"description\":\"Bad Request: chat not found\"}"
                    .to_owned(),
            ),
            |outcome| matches!(outcome, ExternalOutcome::Refused { .. }),
            "Telegram answered 400",
        ),
        (
            DestinationKind::Telegram,
            (
                401,
                format!(
                    "{{\"ok\":false,\"description\":\"Unauthorized: bot {}\"}}",
                    telegram_token()
                ),
            ),
            |outcome| matches!(outcome, ExternalOutcome::Refused { .. }),
            "401",
        ),
        (
            DestinationKind::Telegram,
            (200, "{\"ok\":false}".to_owned()),
            |outcome| matches!(outcome, ExternalOutcome::Unknown { .. }),
            "without saying",
        ),
    ];
    for (kind, answer, expected, says) in cases {
        let stand_in = StandIn::start(vec![answer.clone()]);
        let (service, endpoint, secret) = match kind {
            DestinationKind::Slack => (
                SLACK,
                "#alerts",
                DestinationSecret::Slack {
                    webhook_url: secret_text(&slack_url()),
                },
            ),
            DestinationKind::Discord => (
                DISCORD,
                "#deployments",
                DestinationSecret::Discord {
                    webhook_url: secret_text(&discord_url()),
                },
            ),
            _ => (
                TELEGRAM,
                "123456789",
                DestinationSecret::Telegram {
                    bot_token: secret_text(&telegram_token()),
                },
            ),
        };
        let sender = chat_sender(&runtime, ToStandIns::default().with(service, &stand_in));
        let outcome = sender.send(&external(kind, endpoint), &secret, &message(kind));
        assert!(expected(&outcome), "{kind} {answer:?} read as {outcome:?}");
        let rendered = format!("{outcome:?}");
        assert!(rendered.contains(says), "{rendered}");
        // Only this host's own words: nothing of the credential, and nothing a service said but
        // one of Slack's documented codes.
        for piece in [
            SECRET_PART,
            "kept-in-the",
            "the-secret",
            "Unknown Webhook",
            "chat not found",
        ] {
            assert!(!rendered.contains(piece), "{piece:?} in {rendered}");
        }
    }

    // A service that quotes the credential back, even cut off part way through it, is not quoted.
    let telegram = StandIn::start(vec![(
        403,
        format!(
            "{{\"ok\":false,\"description\":\"{}{}\"}}",
            "x".repeat(78),
            telegram_token()
        ),
    )]);
    let sender = chat_sender(&runtime, ToStandIns::default().with(TELEGRAM, &telegram));
    let outcome = sender.send(
        &external(DestinationKind::Telegram, "123456789"),
        &DestinationSecret::Telegram {
            bot_token: secret_text(&telegram_token()),
        },
        &message(DestinationKind::Telegram),
    );
    let rendered = format!("{outcome:?}");
    assert!(
        matches!(outcome, ExternalOutcome::Refused { .. }),
        "{rendered}"
    );
    for piece in ["kept-in", "123456:", "xxxxxxxx"] {
        assert!(!rendered.contains(piece), "{piece:?} in {rendered}");
    }

    // No service at all: nothing was sent, and the transport's own message, which names the
    // address and so the credential, is not repeated either.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let unreachable = StandIn {
        origin: format!(
            "http://127.0.0.1:{}",
            closed.local_addr().expect("an address").port()
        ),
        received: Arc::new(std::sync::Mutex::new(Vec::new())),
        stop: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        port: 0,
    };
    drop(closed);
    let sender = chat_sender(&runtime, ToStandIns::default().with(TELEGRAM, &unreachable));
    let outcome = sender.send(
        &external(DestinationKind::Telegram, "123456789"),
        &DestinationSecret::Telegram {
            bot_token: secret_text(&telegram_token()),
        },
        &message(DestinationKind::Telegram),
    );
    assert!(
        matches!(
            outcome,
            kr_delivery::external::ExternalOutcome::NotDispatched { .. }
        ),
        "{outcome:?}"
    );
    assert!(!format!("{outcome:?}").contains(SECRET_PART), "{outcome:?}");
}

// ----- A mail submission server on loopback, with a certificate authority of its own -----------

/// The civil date `days` after 1970-01-01, for a certificate that is valid now whenever the suite
/// runs.
fn civil(days: i64) -> (i32, u8, u8) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (
        i32::try_from(year).expect("a year"),
        u8::try_from(month).expect("a month"),
        u8::try_from(day).expect("a day"),
    )
}

/// Valid from yesterday for `days`: a leaf short enough for every platform's verifier.
fn valid_now(params: &mut rcgen::CertificateParams, days: i64) {
    let today = i64::try_from(kr_ipc::now_ms().get() / 86_400_000).expect("a day");
    let (year, month, day) = civil(today - 1);
    params.not_before = rcgen::date_time_ymd(year, month, day);
    let (year, month, day) = civil(today + days);
    params.not_after = rcgen::date_time_ymd(year, month, day);
}

/// A certificate authority, and what signs with it.
struct Authority {
    der: Vec<u8>,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

fn authority(name: &str) -> Authority {
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("certificate parameters");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name.to_owned());
    valid_now(&mut params, 365);
    let key = rcgen::KeyPair::generate().expect("a key pair");
    let certificate = params.self_signed(&key).expect("a self-signed certificate");
    Authority {
        der: certificate.der().to_vec(),
        issuer: rcgen::Issuer::new(params, key),
    }
}

/// A server configuration presenting a certificate for `localhost` from `authority`.
fn server_tls(authority: &Authority) -> Arc<tokio_rustls::rustls::ServerConfig> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("certificate parameters");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    valid_now(&mut params, 30);
    let key = rcgen::KeyPair::generate().expect("a key pair");
    let leaf = params
        .signed_by(&key, &authority.issuer)
        .expect("a signed certificate");
    let chain = vec![
        leaf.der().clone(),
        tokio_rustls::rustls::pki_types::CertificateDer::from(authority.der.clone()),
    ];
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
        tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
    );
    Arc::new(
        tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("a server configuration"),
    )
}

/// How the stand-in mail server behaves.
#[derive(Clone)]
struct MailScript {
    /// TLS from the first byte, as on port 465, rather than STARTTLS.
    implicit: bool,
    offers_starttls: bool,
    /// Sends a line of its own right after agreeing to STARTTLS, before TLS begins.
    speaks_before_tls: bool,
    mechanisms: &'static str,
    /// Answers AUTH with this, or with the AUTH line itself repeated back when `None`.
    auth_reply: Option<&'static str>,
    rcpt_reply: &'static str,
    /// Answers the message with this, or ends the connection without answering when `None`.
    final_reply: Option<&'static str>,
}

impl MailScript {
    const fn implicit() -> Self {
        Self {
            implicit: true,
            offers_starttls: false,
            speaks_before_tls: false,
            mechanisms: "PLAIN LOGIN",
            auth_reply: Some("235 2.7.0 Authentication successful"),
            rcpt_reply: "250 2.1.5 Ok",
            final_reply: Some("250 2.0.0 Ok: queued as 1"),
        }
    }

    const fn starttls() -> Self {
        Self {
            implicit: false,
            offers_starttls: true,
            ..Self::implicit()
        }
    }
}

/// What the stand-in mail server saw: lines in the clear, lines inside TLS, and the message.
#[derive(Clone, Debug, Default)]
struct MailSeen {
    clear: Vec<String>,
    secure: Vec<String>,
    data: Vec<u8>,
    handshakes: usize,
}

struct MailServer {
    port: u16,
    seen: Arc<std::sync::Mutex<MailSeen>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MailServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MailServer {
    fn start(runtime: &tokio::runtime::Runtime, script: MailScript, presents: &Authority) -> Self {
        let tls = server_tls(presents);
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a loopback port");
            let port = listener.local_addr().expect("an address").port();
            let seen = Arc::new(std::sync::Mutex::new(MailSeen::default()));
            let record = Arc::clone(&seen);
            let acceptor = tokio_rustls::TlsAcceptor::from(tls);
            let task = tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    serve_mail(tcp, acceptor.clone(), script.clone(), Arc::clone(&record)).await;
                }
            });
            Self { port, seen, task }
        })
    }

    fn seen(&self) -> MailSeen {
        self.seen.lock().expect("the record").clone()
    }
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, line: &str) {
    use tokio::io::AsyncWriteExt as _;
    let _ = writer.write_all(format!("{line}\r\n").as_bytes()).await;
    let _ = writer.flush().await;
}

async fn serve_mail(
    tcp: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    script: MailScript,
    seen: Arc<std::sync::Mutex<MailSeen>>,
) {
    use tokio::io::AsyncBufReadExt as _;
    if script.implicit {
        let Ok(tls) = acceptor.accept(tcp).await else {
            return;
        };
        seen.lock().expect("the record").handshakes += 1;
        serve_secure(tls, &script, &seen, true).await;
        return;
    }
    let mut stream = tokio::io::BufReader::new(tcp);
    write_line(stream.get_mut(), "220 stand-in ESMTP").await;
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        seen.lock()
            .expect("the record")
            .clear
            .push(line.trim_end().to_owned());
        let command = line.trim_end().to_ascii_uppercase();
        if command.starts_with("EHLO") {
            let offers = if script.offers_starttls {
                "250-STARTTLS\r\n"
            } else {
                ""
            };
            write_line(
                stream.get_mut(),
                &format!("250-stand-in\r\n{offers}250 8BITMIME"),
            )
            .await;
        } else if command == "STARTTLS" && script.offers_starttls {
            let reply = if script.speaks_before_tls {
                "220 2.0.0 Ready to start TLS\r\n250 2.0.0 said before TLS began"
            } else {
                "220 2.0.0 Ready to start TLS"
            };
            write_line(stream.get_mut(), reply).await;
            let Ok(tls) = acceptor.accept(stream.into_inner()).await else {
                return;
            };
            seen.lock().expect("the record").handshakes += 1;
            serve_secure(tls, &script, &seen, false).await;
            return;
        } else if command == "QUIT" {
            write_line(stream.get_mut(), "221 2.0.0 Bye").await;
            return;
        } else {
            write_line(
                stream.get_mut(),
                "530 5.7.0 Must issue a STARTTLS command first",
            )
            .await;
        }
    }
}

/// Reads one line inside TLS and records it.
async fn read_secure<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut tokio::io::BufReader<S>,
    seen: &Arc<std::sync::Mutex<MailSeen>>,
) -> Option<String> {
    use tokio::io::AsyncBufReadExt as _;
    let mut line = String::new();
    if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
        return None;
    }
    let line = line.trim_end().to_owned();
    seen.lock().expect("the record").secure.push(line.clone());
    Some(line)
}

async fn serve_secure<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    script: &MailScript,
    seen: &Arc<std::sync::Mutex<MailSeen>>,
    greet: bool,
) {
    use tokio::io::AsyncBufReadExt as _;
    let mut stream = tokio::io::BufReader::new(stream);
    if greet {
        write_line(stream.get_mut(), "220 stand-in ESMTP").await;
    }
    loop {
        let Some(line) = read_secure(&mut stream, seen).await else {
            return;
        };
        let command = line.to_ascii_uppercase();
        if command.starts_with("EHLO") {
            write_line(
                stream.get_mut(),
                &format!(
                    "250-stand-in\r\n250-AUTH {}\r\n250 8BITMIME",
                    script.mechanisms
                ),
            )
            .await;
        } else if command.starts_with("AUTH PLAIN") {
            let reply = script
                .auth_reply
                .map_or_else(|| format!("535 5.7.8 {line} rejected"), str::to_owned);
            write_line(stream.get_mut(), &reply).await;
        } else if command == "AUTH LOGIN" {
            write_line(stream.get_mut(), "334 VXNlcm5hbWU6").await;
            if read_secure(&mut stream, seen).await.is_none() {
                return;
            }
            write_line(stream.get_mut(), "334 UGFzc3dvcmQ6").await;
            let Some(password) = read_secure(&mut stream, seen).await else {
                return;
            };
            let reply = script
                .auth_reply
                .map_or_else(|| format!("535 5.7.8 {password} rejected"), str::to_owned);
            write_line(stream.get_mut(), &reply).await;
        } else if command.starts_with("MAIL FROM:") {
            write_line(stream.get_mut(), "250 2.1.0 Ok").await;
        } else if command.starts_with("RCPT TO:") {
            write_line(stream.get_mut(), script.rcpt_reply).await;
        } else if command == "DATA" {
            write_line(stream.get_mut(), "354 End data with <CR><LF>.<CR><LF>").await;
            loop {
                let mut raw = Vec::new();
                if stream.read_until(b'\n', &mut raw).await.unwrap_or(0) == 0 {
                    return;
                }
                let end = raw == b".\r\n";
                seen.lock()
                    .expect("the record")
                    .data
                    .extend_from_slice(&raw);
                if end {
                    break;
                }
            }
            match script.final_reply {
                Some(reply) => write_line(stream.get_mut(), reply).await,
                None => return,
            }
        } else if command == "QUIT" {
            write_line(stream.get_mut(), "221 2.0.0 Bye").await;
            return;
        } else {
            write_line(stream.get_mut(), "502 5.5.2 Command not recognised").await;
        }
    }
}

fn account(server: &MailServer, security: MailSecurity) -> MailAccount {
    MailAccount {
        server: "localhost".to_owned(),
        port: U64::new(u64::from(server.port)),
        security,
        username: secret_text("alerts@example.com"),
        password: secret_text(SECRET_PART),
        from_address: "alerts@example.com".to_owned(),
    }
}

fn mail_sender(
    runtime: &tokio::runtime::Runtime,
    trusted: &Authority,
) -> kr_controller::push::mail::MailSender {
    kr_controller::push::mail::MailSender::new(
        kr_controller::push::mail::MailSubmission::trusting(&trusted.der),
        runtime.handle().clone(),
    )
}

fn plain_token() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("\0alerts@example.com\0{SECRET_PART}"))
}

/// The message a server received, un-stuffed and without the line that ended it.
fn unstuffed(data: &[u8]) -> String {
    let text = String::from_utf8(data.to_vec()).expect("an ASCII message");
    let body = text
        .strip_suffix(".\r\n")
        .expect("the message ends with the line that ends it");
    body.split("\r\n")
        .map(|line| line.strip_prefix('.').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Decodes a quoted-printable body the way a mail client would.
fn decode_quoted_printable(encoded: &str) -> String {
    let joined = encoded.replace("=\r\n", "");
    let bytes = joined.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'=' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("hex");
            decoded.push(u8::from_str_radix(hex, 16).expect("a hex byte"));
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).expect("UTF-8")
}

/// KR-REQ-25.23: email over implicit TLS. Nothing crosses the connection before TLS; the server's
/// certificate is verified through the platform verifier; the account's credential is offered by
/// AUTH PLAIN inside TLS and nowhere else; the envelope names the account's address and the
/// recipient; the message is dot-stuffed, has CR LF and nothing else as line endings, carries its
/// headers and a quoted-printable body that ends with the sentence that says who can read it.
#[test]
fn mail_is_submitted_over_implicit_tls_under_the_account() {
    let runtime = runtime();
    let trusted = authority("kalareach test authority");
    let server = MailServer::start(&runtime, MailScript::implicit(), &trusted);
    let outcome = mail_sender(&runtime, &trusted).send(
        &external(DestinationKind::Email, "person@example.com"),
        &account(&server, MailSecurity::ImplicitTls),
        &message(DestinationKind::Email),
    );
    assert_eq!(outcome, kr_delivery::external::ExternalOutcome::Delivered);
    let seen = server.seen();
    assert!(
        seen.clear.is_empty(),
        "nothing before TLS: {:?}",
        seen.clear
    );
    assert_eq!(seen.handshakes, 1);
    assert_eq!(seen.secure[0], "EHLO [127.0.0.1]");
    assert_eq!(seen.secure[1], format!("AUTH PLAIN {}", plain_token()));
    assert_eq!(seen.secure[2], "MAIL FROM:<alerts@example.com>");
    assert_eq!(seen.secure[3], "RCPT TO:<person@example.com>");
    assert_eq!(seen.secure[4], "DATA");
    assert_eq!(seen.secure.last().map(String::as_str), Some("QUIT"));

    let data = &seen.data;
    assert!(data.ends_with(b"\r\n.\r\n"), "the message ends alone");
    for (index, byte) in data.iter().enumerate() {
        if *byte == b'\n' {
            assert_eq!(data[index - 1], b'\r', "a bare line feed at {index}");
        }
        if *byte == b'\r' {
            assert_eq!(data.get(index + 1), Some(&b'\n'), "a bare carriage return");
        }
    }
    let raw = String::from_utf8(data.clone()).expect("ASCII on the wire");
    assert!(
        raw.contains("\r\n..hidden: a line that begins with a dot"),
        "a line that begins with a dot is sent with a second one"
    );
    let text = unstuffed(data);
    let (headers, body) = text.split_once("\r\n\r\n").expect("headers and a body");
    for header in [
        "From: <alerts@example.com>",
        "To: <person@example.com>",
        "Subject: A KalaReach session is waiting for an approval.",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: quoted-printable",
        "Auto-Submitted: auto-generated",
    ] {
        assert!(headers.split("\r\n").any(|line| line == header), "{header}");
    }
    assert!(headers.contains("\r\nDate: "));
    assert!(headers.contains("\r\nMessage-ID: <"));
    assert!(
        !text.contains(SECRET_PART),
        "the message carries no credential"
    );
    let decoded = decode_quoted_printable(body);
    assert!(decoded.contains("caf\u{e9} \u{2615} and a trailing space "));
    assert!(decoded.contains("<!channel> @everyone"));
    assert!(
        decoded
            .trim_end()
            .ends_with(kr_delivery::external::RECIPIENTS_CAN_READ),
        "{decoded}"
    );
    for line in body.split("\r\n") {
        assert!(line.len() <= 76, "an encoded line of {} bytes", line.len());
    }
}

/// KR-REQ-25.23: over STARTTLS, `EHLO` and `STARTTLS` are all that crosses the connection in the
/// clear; the credential, the envelope and the message all go inside TLS.
#[test]
fn mail_over_starttls_says_only_ehlo_and_starttls_in_the_clear() {
    let runtime = runtime();
    let trusted = authority("kalareach test authority");
    let server = MailServer::start(&runtime, MailScript::starttls(), &trusted);
    let outcome = mail_sender(&runtime, &trusted).send(
        &external(DestinationKind::Email, "person@example.com"),
        &account(&server, MailSecurity::Starttls),
        &message(DestinationKind::Email),
    );
    assert_eq!(outcome, kr_delivery::external::ExternalOutcome::Delivered);
    let seen = server.seen();
    assert_eq!(seen.clear, vec!["EHLO [127.0.0.1]", "STARTTLS"]);
    assert_eq!(seen.handshakes, 1);
    assert_eq!(seen.secure[0], "EHLO [127.0.0.1]");
    assert_eq!(seen.secure[1], format!("AUTH PLAIN {}", plain_token()));
    assert!(!seen.data.is_empty(), "the message went inside TLS");
}

/// KR-REQ-25.23: never downgraded. A server that offers no STARTTLS, one whose certificate this
/// host cannot verify, and one that speaks between agreeing to TLS and starting it are each sent
/// no credential and no message byte; the outcome is that nothing was sent and another attempt
/// would meet the same answer.
#[test]
fn nothing_is_sent_to_a_mail_server_without_verified_tls() {
    use kr_delivery::external::ExternalOutcome;

    let runtime = runtime();
    let trusted = authority("kalareach test authority");
    let stranger = authority("an authority this host does not hold");
    let cases: Vec<(&str, MailScript, &Authority, MailSecurity)> = vec![
        (
            "no STARTTLS offered",
            MailScript {
                offers_starttls: false,
                ..MailScript::starttls()
            },
            &trusted,
            MailSecurity::Starttls,
        ),
        (
            "an untrusted certificate over STARTTLS",
            MailScript::starttls(),
            &stranger,
            MailSecurity::Starttls,
        ),
        (
            "an untrusted certificate over implicit TLS",
            MailScript::implicit(),
            &stranger,
            MailSecurity::ImplicitTls,
        ),
        (
            "a line sent after agreeing to TLS",
            MailScript {
                speaks_before_tls: true,
                ..MailScript::starttls()
            },
            &trusted,
            MailSecurity::Starttls,
        ),
    ];
    for (case, script, presents, security) in cases {
        let server = MailServer::start(&runtime, script, presents);
        let outcome = mail_sender(&runtime, &trusted).send(
            &external(DestinationKind::Email, "person@example.com"),
            &account(&server, security),
            &message(DestinationKind::Email),
        );
        assert!(
            matches!(outcome, ExternalOutcome::Unsendable { .. }),
            "{case}: {outcome:?}"
        );
        let seen = server.seen();
        assert!(
            seen.secure.is_empty() && seen.data.is_empty(),
            "{case}: something was sent: {seen:?}"
        );
        assert!(
            seen.clear
                .iter()
                .all(|line| line == "EHLO [127.0.0.1]" || line == "STARTTLS"),
            "{case}: {:?}",
            seen.clear
        );
    }
}

/// KR-REQ-25.24: each answer of a mail server is read by where it came. Before the line that ends
/// the message: a refused credential or recipient is nothing sent and another attempt would meet
/// the same answer, and nothing after it is said. After it: a 5xx is a refusal, and a 4xx or
/// silence is an outcome nobody knows. A server that offers only LOGIN is signed in to that way. No
/// outcome repeats the server's words, even a server that repeats the credential back.
#[test]
fn a_mail_servers_answer_is_read_by_where_it_came() {
    use kr_delivery::external::ExternalOutcome;

    let runtime = runtime();
    let trusted = authority("kalareach test authority");
    type Case = (&'static str, MailScript, fn(&ExternalOutcome) -> bool, bool);
    let cases: Vec<Case> = vec![
        (
            "a refused credential, repeated back by the server",
            MailScript {
                auth_reply: None,
                ..MailScript::implicit()
            },
            |outcome| matches!(outcome, ExternalOutcome::Unsendable { .. }),
            false,
        ),
        (
            "a refused credential over LOGIN, repeated back by the server",
            MailScript {
                mechanisms: "LOGIN",
                auth_reply: None,
                ..MailScript::implicit()
            },
            |outcome| matches!(outcome, ExternalOutcome::Unsendable { .. }),
            false,
        ),
        (
            "a refused recipient",
            MailScript {
                rcpt_reply: "550 5.1.1 No such user",
                ..MailScript::implicit()
            },
            |outcome| matches!(outcome, ExternalOutcome::Unsendable { .. }),
            false,
        ),
        (
            "a recipient to try later",
            MailScript {
                rcpt_reply: "451 4.3.0 Try again later",
                ..MailScript::implicit()
            },
            |outcome| matches!(outcome, ExternalOutcome::NotDispatched { .. }),
            false,
        ),
        (
            "a message refused after it was sent",
            MailScript {
                final_reply: Some("554 5.7.1 Rejected for policy reasons"),
                ..MailScript::implicit()
            },
            |outcome| matches!(outcome, ExternalOutcome::Refused { .. }),
            true,
        ),
        (
            "a message deferred after it was sent",
            MailScript {
                final_reply: Some("451 4.7.1 Try again later"),
                ..MailScript::implicit()
            },
            |outcome| matches!(outcome, ExternalOutcome::Unknown { .. }),
            true,
        ),
        (
            "no answer after the message was sent",
            MailScript {
                final_reply: None,
                ..MailScript::implicit()
            },
            |outcome| matches!(outcome, ExternalOutcome::Unknown { .. }),
            true,
        ),
        (
            "LOGIN alone",
            MailScript {
                mechanisms: "LOGIN",
                ..MailScript::implicit()
            },
            |outcome| matches!(outcome, ExternalOutcome::Delivered),
            true,
        ),
    ];
    for (case, script, expected, message_sent) in cases {
        let server = MailServer::start(&runtime, script, &trusted);
        let outcome = mail_sender(&runtime, &trusted).send(
            &external(DestinationKind::Email, "person@example.com"),
            &account(&server, MailSecurity::ImplicitTls),
            &message(DestinationKind::Email),
        );
        assert!(expected(&outcome), "{case}: {outcome:?}");
        let rendered = format!("{outcome:?}");
        assert!(
            !rendered.contains(SECRET_PART) && !rendered.contains(&plain_token()),
            "{case}: the outcome repeats the credential: {rendered}"
        );
        let seen = server.seen();
        assert_eq!(
            !seen.data.is_empty(),
            message_sent,
            "{case}: whether the message was sent"
        );
    }
}

// ----- A pass through the real senders ------------------------------------------------------

/// The push seams a pass takes, for a suite that delivers to no paired device.
#[derive(Debug)]
struct NoGateway;

impl kr_delivery::push::PushSender for NoGateway {
    fn send(
        &self,
        _credential: &kr_protocol::push::PushDeliveryCredential,
        _request: &kr_protocol::push::PushDeliveryRequest,
    ) -> kr_delivery::push::SendOutcome {
        panic!("this suite sends no push notification")
    }
}

impl kr_delivery::push::DeliveryStatus for NoGateway {
    fn status(
        &self,
        _credential: &kr_protocol::push::PushDeliveryCredential,
        _notification_id: kr_protocol::ids::NotificationId,
    ) -> kr_delivery::push::StatusAnswer {
        kr_delivery::push::StatusAnswer::Unanswered {
            detail: "this suite asks no gateway".to_owned(),
        }
    }
}

impl kr_delivery::push::SenderCredentials for NoGateway {
    fn current(
        &self,
        _sender_record_id: kr_protocol::ids::PushSenderRecordId,
    ) -> Option<kr_protocol::push::PushDeliveryCredential> {
        None
    }

    fn renew(
        &self,
        _held: &kr_protocol::push::PushDeliveryCredential,
    ) -> kr_delivery::Result<kr_protocol::push::PushDeliveryCredential> {
        Err(kr_delivery::DeliveryError::NotAuthorised(
            "this suite renews nothing".to_owned(),
        ))
    }
}

/// A recipient whose grant covers the one session every message here comes from.
#[derive(Debug)]
struct SessionGrant;

impl kr_delivery::producer::RecipientAuthority for SessionGrant {
    fn scope_for(&self, _rule: &DeliveryRule) -> Option<kr_delivery::producer::RecipientScope> {
        Some(kr_delivery::producer::RecipientScope {
            viewer: kr_worker::history_filter::ViewerScope::owner(),
            sessions: kr_protocol::grant::SessionSelector::These {
                session_ids: [session()].into_iter().collect(),
            },
        })
    }
}

/// A delivery module on the internal disk, and the in-memory store its credentials are kept in.
struct Deliveries {
    module: kr_controller::push::DeliveryModule,
    secrets: DestinationSecrets,
    _directory: tempfile::TempDir,
}

fn deliveries() -> Deliveries {
    let directory = tempfile::tempdir().expect("a directory");
    let secrets = DestinationSecrets::new(
        Arc::new(kr_crypto::store::MemoryStore::new()),
        kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16])),
    );
    let module = kr_controller::push::DeliveryModule::open_at(
        &directory.path().join("delivery.sqlite3"),
        kr_crypto::keys::NotificationPreviewKeyPair::generate().expect("a keypair"),
        kr_crypto::keys::StoredEnvelopeKeyPair::generate().expect("a keypair"),
        secrets.clone(),
    )
    .expect("a delivery module");
    Deliveries {
        module,
        secrets,
        _directory: directory,
    }
}

fn destination(id: &str, kind: DestinationKind, endpoint: &str) -> DestinationRecord {
    DestinationRecord {
        id: identifier(id),
        destination: Destination::External(external(kind, endpoint)),
        rule: Some(DeliveryRule {
            name: "an approval is waiting".to_owned(),
            grant_id: None,
        }),
        enabled: true,
        configured_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
    }
}

impl Deliveries {
    /// The destination as the journal holds it, stamp included.
    fn stored(&self, id: &str) -> DestinationRecord {
        self.module
            .with(|producer| {
                Ok(producer
                    .journal()
                    .destination(&identifier(id))
                    .expect("a read")
                    .expect("configured"))
            })
            .expect("a read")
    }

    /// Takes one event and produces a notification for each destination named.
    fn produce(&self, number: u64, ids: &[&str]) -> Vec<kr_protocol::ids::NotificationId> {
        let now = kr_ipc::now_ms().get();
        let destinations: Vec<DestinationRecord> = ids.iter().map(|id| self.stored(id)).collect();
        let notice = kr_delivery::producer::Notice {
            event: kr_delivery::journal::EventKey::announcement(
                Some(session()),
                "attention.pending_approval/~abcdef",
                number,
            ),
            alert: kr_protocol::push::PushAlert::ApprovalWaiting,
            urgency: kr_protocol::push::PushUrgency::Attention,
            rule: "attention.pending_approval".to_owned(),
            summary: "an approval is waiting".to_owned(),
            session_id: Some(session()),
            environment_id: None,
            observed_at_ms: TimestampMs::new(now),
            collapse_group: "a-session/attention.pending_approval".to_owned(),
            expires_at_ms: TimestampMs::new(now + 60 * 60 * 1000),
        };
        self.module
            .with(|producer| {
                let taken = notice.taken(number).expect("an event record");
                producer
                    .take(
                        kr_delivery::journal::EventSource::Attention,
                        "session-1",
                        &[taken],
                        number,
                        now,
                    )
                    .expect("a page");
                let produced = producer
                    .produce(&notice, &destinations, &SessionGrant, &lines(now), now)
                    .expect("a decision");
                assert_eq!(produced.admitted, ids.len(), "{produced:?}");
                Ok(())
            })
            .expect("produced");
        self.module
            .with(|producer| {
                Ok(producer
                    .journal()
                    .deliveries()
                    .expect("a read")
                    .into_iter()
                    .filter(|record| {
                        record.event
                            == kr_delivery::journal::EventKey::announcement(
                                Some(session()),
                                "attention.pending_approval/~abcdef",
                                number,
                            )
                    })
                    .map(|record| record.notification_id)
                    .collect())
            })
            .expect("a read")
    }

    fn pass(&self, senders: &kr_controller::push::external::ExternalSenders) {
        self.module
            .run_due(
                &NoGateway,
                &NoGateway,
                &NoGateway,
                senders,
                &SessionGrant,
                &|| kr_ipc::now_ms().get(),
            )
            .expect("a pass");
    }

    fn state_of(&self, notification_id: kr_protocol::ids::NotificationId) -> DeliveryRecordView {
        self.module
            .with(|producer| {
                let record = producer
                    .journal()
                    .delivery(notification_id)
                    .expect("a read")
                    .expect("a record");
                Ok(DeliveryRecordView {
                    state: record.state,
                    dispatched: record.dispatched,
                    detail: record.detail.unwrap_or_default(),
                })
            })
            .expect("a read")
    }
}

#[derive(Debug)]
struct DeliveryRecordView {
    state: kr_delivery::journal::DeliveryState,
    dispatched: bool,
    detail: String,
}

/// KR-REQ-25.23: Slack, Discord, Telegram and email destinations are configured only once their
/// credential is kept, and only with no retry claim, and then a pass delivers to each through its
/// own adapter with its own credential, in the place its service takes it. The journal records
/// each as accepted and holds no credential.
#[test]
fn each_kind_is_configured_with_its_credential_and_a_pass_delivers_with_it() {
    let runtime = runtime();
    let (slack, discord) = (StandIn::start(Vec::new()), StandIn::start(Vec::new()));
    let telegram = StandIn::start(vec![(200, "{\"ok\":true,\"result\":{}}".to_owned())]);
    let trusted = authority("kalareach test authority");
    let mail = MailServer::start(&runtime, MailScript::starttls(), &trusted);
    let senders = kr_controller::push::external::ExternalSenders::new(
        Arc::new(
            ToStandIns::default()
                .with(SLACK, &slack)
                .with(DISCORD, &discord)
                .with(TELEGRAM, &telegram),
        ),
        runtime.handle().clone(),
        kr_controller::push::mail::MailSubmission::trusting(&trusted.der),
    );
    let deliveries = deliveries();
    let kinds = [
        (
            "slack",
            destination("slack", DestinationKind::Slack, "#alerts"),
            DestinationSecret::Slack {
                webhook_url: secret_text(&slack_url()),
            },
        ),
        (
            "discord",
            destination("discord", DestinationKind::Discord, "#deployments"),
            DestinationSecret::Discord {
                webhook_url: secret_text(&discord_url()),
            },
        ),
        (
            "telegram",
            destination("telegram", DestinationKind::Telegram, "123456789"),
            DestinationSecret::Telegram {
                bot_token: secret_text(&telegram_token()),
            },
        ),
        (
            "email",
            destination("email", DestinationKind::Email, "person@example.com"),
            DestinationSecret::Email {
                account: account(&mail, MailSecurity::Starttls),
            },
        ),
    ];
    for (id, record, secret) in &kinds {
        let refused = deliveries
            .module
            .configure(record)
            .expect_err("no credential is kept yet");
        assert!(
            refused
                .to_string()
                .contains("delivery.destination.secret.set"),
            "{id}: {refused}"
        );
        let stored = deliveries
            .module
            .store_secret(&record.id, secret)
            .expect("the credential is kept");
        assert!(!stored.in_force, "{id}: nothing is configured under it yet");
        let mut claims_retry = record.clone();
        if let Destination::External(external) = &mut claims_retry.destination {
            external.idempotency = Idempotency::Supported {
                field: "Idempotency-Key".to_owned(),
            };
        }
        assert!(
            deliveries.module.configure(&claims_retry).is_err(),
            "{id}: a service that recognises no repeat is configured without a retry claim"
        );
        deliveries
            .module
            .configure(record)
            .expect("configured once its credential is kept");
        let held = deliveries
            .secrets
            .get(&record.id)
            .expect("a read")
            .expect("kept");
        assert_eq!(
            deliveries
                .stored(id)
                .as_external()
                .and_then(|external| external.credential.clone()),
            Some(held.stamp),
            "{id}: the record names the credential that was kept"
        );
    }
    // A credential of another kind under an identifier is not one a destination sends with.
    deliveries
        .module
        .store_secret(
            &identifier("mismatched"),
            &DestinationSecret::Telegram {
                bot_token: secret_text(&telegram_token()),
            },
        )
        .expect("kept");
    let refused = deliveries
        .module
        .configure(&destination(
            "mismatched",
            DestinationKind::Slack,
            "#alerts",
        ))
        .expect_err("a Telegram credential does not configure a Slack destination");
    assert!(refused.to_string().contains("telegram"), "{refused}");

    let notifications = deliveries.produce(1, &["slack", "discord", "telegram", "email"]);
    assert_eq!(notifications.len(), 4);
    deliveries.pass(&senders);
    for notification_id in &notifications {
        let view = deliveries.state_of(*notification_id);
        assert_eq!(
            view.state,
            kr_delivery::journal::DeliveryState::Accepted,
            "{view:?}"
        );
    }
    assert_eq!(
        slack.received()[0].target,
        format!("/services/T0KALA/B0REACH/{SECRET_PART}")
    );
    assert_eq!(
        discord.received()[0].target,
        format!("/api/webhooks/123456789/{SECRET_PART}?wait=true")
    );
    assert_eq!(
        telegram.received()[0].target,
        format!("/bot123456:{SECRET_PART}/sendMessage")
    );
    assert_eq!(
        mail.seen().secure[1],
        format!("AUTH PLAIN {}", plain_token())
    );
    assert!(
        String::from_utf8_lossy(&mail.seen().data).contains("does not make it private"),
        "the mail says its recipients can read it"
    );
    let journal = deliveries._directory.path().join("delivery.sqlite3");
    for file in [
        journal.clone(),
        journal.with_extension("sqlite3-wal"),
        journal.with_extension("sqlite3-shm"),
    ] {
        if let Ok(bytes) = std::fs::read(&file) {
            assert!(!holds(&bytes, SECRET_PART), "{} holds it", file.display());
        }
    }
}

/// KR-REQ-25.23, KR-REQ-24.12: a credential replaced after a notification was admitted is never
/// used to send it, because the new credential can reach somewhere else. Replaced through the
/// host, the destination's binding changes and the claim takes the notification back. Replaced in
/// the store alone, as a host that stopped between the store and the journal leaves it, the pass
/// finds a credential whose stamp is not the destination's and sends nothing.
#[test]
fn a_replaced_credential_never_carries_what_was_admitted_under_the_old_one() {
    let runtime = runtime();
    let slack = StandIn::start(Vec::new());
    let trusted = authority("kalareach test authority");
    let senders = kr_controller::push::external::ExternalSenders::new(
        Arc::new(ToStandIns::default().with(SLACK, &slack)),
        runtime.handle().clone(),
        kr_controller::push::mail::MailSubmission::trusting(&trusted.der),
    );
    let deliveries = deliveries();
    let first = DestinationSecret::Slack {
        webhook_url: secret_text(&slack_url()),
    };
    let second = DestinationSecret::Slack {
        webhook_url: secret_text("https://hooks.slack.com/services/T0KALA/B0OTHER/elsewhere"),
    };
    for id in ["replaced", "interrupted"] {
        deliveries
            .module
            .store_secret(&identifier(id), &first)
            .expect("kept");
        deliveries
            .module
            .configure(&destination(id, DestinationKind::Slack, "#alerts"))
            .expect("configured");
    }
    let admitted = deliveries.produce(1, &["replaced", "interrupted"]);

    // Replaced through the host: in force at once, and a new binding.
    let replaced = deliveries
        .module
        .store_secret(&identifier("replaced"), &second)
        .expect("kept");
    assert!(replaced.in_force);
    // Replaced in the store alone.
    deliveries
        .secrets
        .put(&identifier("interrupted"), &second)
        .expect("kept");

    deliveries.pass(&senders);
    assert!(slack.received().is_empty(), "{:?}", slack.received());
    for notification_id in admitted {
        let view = deliveries.state_of(notification_id);
        assert_eq!(
            view.state,
            kr_delivery::journal::DeliveryState::Revoked,
            "{view:?}"
        );
        assert!(!view.dispatched, "{view:?}");
    }
}

/// KR-REQ-25.24: a chat service whose answer nobody knows is not sent the message again, because
/// it recognises no repeat: the record is marked as possibly delivered, and the next pass sends
/// nothing. A mail server that refuses the account's credential before any of the message was sent
/// leaves a message this host abandoned, not one that may have arrived.
#[test]
fn each_kind_follows_the_journals_uncertainty_rules() {
    let runtime = runtime();
    let slack = StandIn::start(vec![(503, String::new())]);
    let trusted = authority("kalareach test authority");
    let mail = MailServer::start(
        &runtime,
        MailScript {
            auth_reply: Some("535 5.7.8 Authentication credentials invalid"),
            ..MailScript::implicit()
        },
        &trusted,
    );
    let senders = kr_controller::push::external::ExternalSenders::new(
        Arc::new(ToStandIns::default().with(SLACK, &slack)),
        runtime.handle().clone(),
        kr_controller::push::mail::MailSubmission::trusting(&trusted.der),
    );
    let deliveries = deliveries();
    deliveries
        .module
        .store_secret(
            &identifier("slack"),
            &DestinationSecret::Slack {
                webhook_url: secret_text(&slack_url()),
            },
        )
        .expect("kept");
    deliveries
        .module
        .configure(&destination("slack", DestinationKind::Slack, "#alerts"))
        .expect("configured");
    deliveries
        .module
        .store_secret(
            &identifier("email"),
            &DestinationSecret::Email {
                account: account(&mail, MailSecurity::ImplicitTls),
            },
        )
        .expect("kept");
    deliveries
        .module
        .configure(&destination(
            "email",
            DestinationKind::Email,
            "person@example.com",
        ))
        .expect("configured");
    let notifications = deliveries.produce(1, &["slack", "email"]);
    deliveries.pass(&senders);
    deliveries.pass(&senders);
    assert_eq!(slack.received().len(), 1, "sent once, never again");
    let states: Vec<DeliveryRecordView> = notifications
        .iter()
        .map(|notification_id| deliveries.state_of(*notification_id))
        .collect();
    assert!(
        states.iter().any(|view| view.state
            == kr_delivery::journal::DeliveryState::DuplicateUncertain
            && view.dispatched
            && view.detail.contains("could deliver it twice")),
        "{states:?}"
    );
    assert!(
        states.iter().any(
            |view| view.state == kr_delivery::journal::DeliveryState::Abandoned
                && !view.dispatched
                && view.detail.contains("nothing was sent")
        ),
        "{states:?}"
    );
    assert!(
        mail.seen().data.is_empty(),
        "no message after a refused credential"
    );
    for view in &states {
        assert!(!view.detail.contains(SECRET_PART), "{view:?}");
    }
}
