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
