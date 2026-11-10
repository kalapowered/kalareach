//! The account a host holds at a storage service its owner runs, beside the managed account.
//!
//! A host whose `storage.origin` names a service that is not the managed account service holds a
//! second account, at that service, for storage and for nothing else. These cases start a real
//! daemon from a configuration document, with the managed account service and the storage service
//! as stand-ins on loopback sockets, and show what each client of the daemon presents and where it
//! goes: the voice client and the relay payer present the managed account, the storage clients
//! present the storage account, and the storage account hands out one scope on every path that
//! hands a token out, whatever its grant holds. They also show that a sign-in of either account
//! ends a waiting sign-in of the other, that the managed grant keeps its name, bytes and mark, and
//! that a shipped build refuses a plain-HTTP storage origin before it sends anything.

mod net_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_client::services::AccountToken;
use kr_client::services::account::{AccountService, IssuedGrant, RefreshToken};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::backup_read::{BackupReadParams, BackupReadResult};
use kr_protocol::error::ErrorCode;
use kr_protocol::host_account::{AccountAttempt, AccountState};
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::hostinfo::{DoctorStatus, HostDoctorResult};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, Uuid};
use kr_service_stand_in::{Served, TOKEN, serve};
use net_support::{AccountAt, Host};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

const SIGN_IN: &str = "/api/relay/payer-authorisation/sign-in";
const STATUS: &str = "/api/storage/status";
const SYNC: &str = "/api/sync/exchange";

/// The managed account's access token at the managed stand-in.
const MANAGED: &str = "the-managed-access-token";

/// What the stand-in at the storage service issues a grant that holds more than `backup.write`.
const STORAGE_HOLDING_ALL: &str = "the-storage-token-that-holds-every-scope";

/// A failure guard for a wait: the cases decide on what the daemon did, and this only keeps one that
/// went wrong from hanging.
async fn within<T>(what: &str, work: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(180), work)
        .await
        .unwrap_or_else(|_| panic!("gave up waiting for {what}"))
}

/// One request a [`Recorder`] was given.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
}

/// A service on a loopback socket that answers every request with an empty object and records what
/// it was asked: the account service's own endpoints, which the stand-in of the other services does
/// not record.
struct Recorder {
    origin: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Recorder {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let origin = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("an address").port()
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let record = Arc::clone(&record);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    let end = loop {
                        let Ok(read) = socket.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        head.extend_from_slice(&buffer[..read]);
                        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            break end + 4;
                        }
                    };
                    let text = String::from_utf8_lossy(&head[..end]).into_owned();
                    let mut lines = text.lines();
                    let mut request = lines.next().unwrap_or_default().split(' ');
                    let (method, path) = (
                        request.next().unwrap_or_default().to_owned(),
                        request.next().unwrap_or_default().to_owned(),
                    );
                    let mut authorization = None;
                    let mut length = 0_usize;
                    for line in lines {
                        if let Some((name, value)) = line.split_once(':') {
                            match name.to_ascii_lowercase().as_str() {
                                "authorization" => authorization = Some(value.trim().to_owned()),
                                "content-length" => length = value.trim().parse().unwrap_or(0),
                                _ => {}
                            }
                        }
                    }
                    // The body is read, so that the sender is never answered mid-write.
                    let mut body = head.len() - end;
                    while body < length {
                        let Ok(read) = socket.read(&mut buffer).await else {
                            return;
                        };
                        if read == 0 {
                            break;
                        }
                        body += read;
                    }
                    record.lock().expect("what arrived").push(Seen {
                        method,
                        path,
                        authorization,
                    });
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { origin, seen, task }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("what arrived").clone()
    }
}

fn document(
    voice: Option<&str>,
    relay: Option<&str>,
    storage: Option<&str>,
) -> ConfigurationDocument {
    let some = |origin: Option<&str>| {
        origin.map_or_else(Nullable::null, |origin| Nullable::some(origin.to_owned()))
    };
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = some(voice);
    document.relay.origin = some(relay);
    document.storage.origin = some(storage);
    document
}

/// A grant the account service issued, as a finished browser sign-in leaves it.
fn grant(access: &str, scopes: &[&str]) -> IssuedGrant {
    IssuedGrant {
        access_token: AccountToken::new(access).expect("a token"),
        expires_in_seconds: 3600,
        refresh_token: RefreshToken::new(format!("{access}-refresh")).expect("a token"),
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        subject: "account-1".to_owned(),
    }
}

/// The managed stand-in knows the managed grant: its access token and its refresh token.
fn issue_the_managed_grant(managed: &Served) {
    managed.web().issue_grant_token(
        MANAGED,
        "account-m",
        "grant-m",
        &["openid", "voice", "relay.lease"],
    );
    managed
        .web()
        .issue_grant_refresh(&format!("{MANAGED}-refresh"), "grant-m");
}

async fn doctor(host: &Host) -> HostDoctorResult {
    let mut client = host.client().await;
    client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a result of the declared shape")
}

/// Every request an account service is asked for as an account's own: a revocation, an identity
/// read and a read of what the account has used.
async fn ask_the_account_service(service: &Arc<dyn AccountService>) {
    let token = AccountToken::new("a-token").expect("a token");
    let _ = service
        .revoke(&RefreshToken::new("a-refresh").expect("a token"))
        .await;
    let _ = service.identity(&token).await;
    let _ = service.usage(&token).await;
}

/// The account of each role reaches the account service of its own origin for every request its
/// client makes (a revocation, an identity read and a usage read), and no request of either reaches
/// the other's origin: an account is built from the one origin its service is at.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_account_reaches_the_account_service_at_its_own_origin_and_no_other() {
    let managed = Recorder::start().await;
    let storage = Recorder::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(
        &owner,
        &document(Some(&managed.origin), None, Some(&storage.origin)),
        AccountAt::Origin(managed.origin.clone()),
    )
    .await;

    let controller = host.controller();
    for (account, own, other) in [
        (controller.storage_account(), &storage, &managed),
        (controller.host_account(), &managed, &storage),
    ] {
        let service = account.account_service().expect("an account service");
        ask_the_account_service(&service).await;
        let reached: Vec<(String, String)> = own
            .seen()
            .into_iter()
            .map(|seen| (seen.method, seen.path))
            .collect();
        assert_eq!(
            reached,
            [
                ("POST".to_owned(), "/auth/oauth2/revoke".to_owned()),
                ("GET".to_owned(), "/auth/oauth2/userinfo".to_owned()),
                ("GET".to_owned(), "/api/billing/summary".to_owned()),
            ],
            "every request of the account reached the service at its own origin"
        );
        assert!(
            other.seen().is_empty(),
            "no request of the account reached the other service"
        );
        let own_seen = own.seen();
        assert!(
            own_seen[1..]
                .iter()
                .all(|seen| seen.authorization.as_deref() == Some("Bearer a-token"))
        );
        own.seen.lock().expect("what arrived").clear();
    }
    host.stop().await;
}

/// A host whose storage service is one its owner runs has a line of its own in `kr doctor`, whatever
/// the managed account is: signed out it names the sign-in that mends it, signed in it says the
/// account serves storage and nothing else, and a host whose storage is managed has no such line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_doctor_names_the_storage_account_on_a_line_of_its_own() {
    let managed = serve().await;
    let storage = serve().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(
        &owner,
        &document(None, None, Some(storage.origin())),
        AccountAt::Origin(managed.origin().to_owned()),
    )
    .await;
    let line = |result: HostDoctorResult| {
        result
            .checks
            .into_iter()
            .find(|check| check.id() == "storage-account")
            .expect("the storage account's line")
    };
    let signed_out = line(doctor(&host).await);
    assert_eq!(signed_out.status, DoctorStatus::Warning);
    assert!(
        signed_out
            .remedy()
            .is_some_and(|remedy| remedy.contains("kr account sign-in --storage")),
        "{:?}",
        signed_out.remedy()
    );
    host.controller()
        .storage_account()
        .keep_for_test(grant(TOKEN, &["openid", "backup.write"]))
        .await;
    let signed_in = line(doctor(&host).await);
    assert_eq!(signed_in.status, DoctorStatus::Ok, "{}", signed_in.detail());
    host.stop().await;

    // The control: a host whose storage is the managed service has no such line.
    let host = Host::start_with_document_at(
        &owner,
        &document(None, None, Some(managed.origin())),
        AccountAt::Origin(managed.origin().to_owned()),
    )
    .await;
    assert!(
        doctor(&host)
            .await
            .checks
            .iter()
            .all(|check| check.id() != "storage-account")
    );
    host.stop().await;
}

/// KR-REQ-17.12: providers are selected independently. The voice client and the relay payer
/// present the managed account, the storage, manifest and bundle clients the storage account, and
/// every request reaches only the origin of its own role.
/// The control is the same host with managed storage, which behaves as it does today.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_client_presents_the_account_of_its_role_and_reaches_the_service_of_its_role() {
    let managed = serve().await;
    let storage = serve().await;
    issue_the_managed_grant(&managed);
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(
        &owner,
        &document(
            Some(managed.origin()),
            Some(managed.origin()),
            Some(storage.origin()),
        ),
        AccountAt::Origin(managed.origin().to_owned()),
    )
    .await;
    let controller = host.controller();
    controller
        .host_account()
        .keep_for_test(grant(MANAGED, &["openid", "voice", "relay.lease"]))
        .await;
    controller
        .storage_account()
        .keep_for_test(grant(TOKEN, &["openid", "backup.write"]))
        .await;

    // The relay payer: a pass of the lease keeper signs the host's payer authorisation in.
    within(
        "a pass of the lease keeper",
        controller.relay_keeper().expect("a keeper").after_a_pass(),
    )
    .await;
    // The voice client, as a call's start reads the broker's terms.
    let voice = controller
        .service_clients()
        .managed_inference
        .clone()
        .expect("the voice client");
    let _ = voice.metadata().await;
    // The storage client, through the doctor's read of the storage status, and the bundle client,
    // through a restore's read.
    let _ = doctor(&host).await;
    let mut client = host.client().await;
    let _: Result<Result<BackupReadResult, _>, _> = client
        .request(
            Method::BackupRead,
            &BackupReadParams::Bundle {
                locator: Uuid::from_bytes([7; 16]),
            },
        )
        .await
        .map(|answer| {
            answer.map(|value| value.to_typed().expect("a result of the declared shape"))
        });

    let at_managed = managed.web().arrived();
    let at_storage = storage.web().arrived();
    // What each role presents.
    assert!(
        at_managed
            .iter()
            .any(|request| request.path == SIGN_IN && request.token.as_deref() == Some(MANAGED)),
        "the relay payer presented the managed account: {at_managed:?}"
    );
    assert!(
        at_managed
            .iter()
            .any(|request| request.path == "/api/voice/metadata"
                && request.token.as_deref() == Some(MANAGED)),
        "the voice client presented the managed account"
    );
    assert!(
        at_storage
            .iter()
            .any(|request| request.path == STATUS && request.token.as_deref() == Some(TOKEN)),
        "the storage client presented the storage account"
    );
    assert!(
        at_storage
            .iter()
            .any(|request| request.path == SYNC && request.token.as_deref() == Some(TOKEN)),
        "the bundle client presented the storage account"
    );
    // Nothing carries the other role's account, and each service is asked only for its role.
    assert!(
        at_managed.iter().all(|request| request
            .token
            .as_deref()
            .is_none_or(|token| token == MANAGED)),
        "the managed service was shown only the managed account"
    );
    assert!(
        at_storage
            .iter()
            .all(|request| request.token.as_deref().is_none_or(|token| token == TOKEN)),
        "the storage service was shown only the storage account"
    );
    assert!(
        at_managed.iter().all(|request| {
            !request.path.starts_with("/api/storage")
                && !request.path.starts_with("/api/backup")
                && !request.path.starts_with("/api/sync")
        }),
        "no storage request reached the managed service"
    );
    assert!(
        at_storage.iter().all(|request| {
            !request.path.starts_with("/api/relay") && !request.path.starts_with("/api/voice")
        }),
        "no voice or relay request reached the storage service"
    );
    host.stop().await;
}

/// The storage account's grant holds `voice` and `relay.lease` as well as `backup.write`, and the
/// voice broker and the relay lease service are named at the very origin that storage is. The voice
/// client, the lease keeper and the call watch are given the managed account, so none of them asks
/// the storage account for a token, and what they send carries the managed token or none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_voice_client_and_the_lease_keeper_never_ask_the_storage_account() {
    let managed = serve().await;
    let storage = serve().await;
    storage.web().issue_grant_token(
        STORAGE_HOLDING_ALL,
        "account-s",
        "grant-s",
        &["openid", "backup.write", "voice", "relay.lease"],
    );
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(
        &owner,
        &document(
            Some(storage.origin()),
            Some(storage.origin()),
            Some(storage.origin()),
        ),
        AccountAt::Origin(managed.origin().to_owned()),
    )
    .await;
    let controller = host.controller();
    controller
        .storage_account()
        .keep_for_test(grant(
            STORAGE_HOLDING_ALL,
            &["openid", "backup.write", "voice", "relay.lease"],
        ))
        .await;

    within(
        "a pass of the lease keeper",
        controller.relay_keeper().expect("a keeper").after_a_pass(),
    )
    .await;
    let voice = controller
        .service_clients()
        .managed_inference
        .clone()
        .expect("the voice client");
    let _ = voice.metadata().await;

    // The carrier asks the storage account for the one scope it is for. The voice client and the
    // lease keeper ask it for no scope at all, though its grant holds the scopes they would ask.
    let asked = controller.storage_account().token_scopes_asked();
    assert!(
        asked.iter().all(|scope| scope == "backup.write"),
        "neither the voice client nor the lease keeper asked the storage account: {asked:?}"
    );
    assert!(
        storage.web().arrived().iter().all(|request| {
            (request.path != "/api/voice/metadata" && request.path != SIGN_IN)
                || request.token.is_none()
        }),
        "no voice or relay request carried a token: {:?}",
        storage.web().arrived()
    );
    host.stop().await;
}

/// The storage account hands out `backup.write` and no other scope on every path that hands a token
/// out, whatever its grant holds, and says so in words of its own: the allowance is the account's,
/// apart from the refusal of an origin that is not its own. The control is a request for
/// `backup.write`, which is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_storage_account_hands_out_backup_write_and_no_other_scope_on_every_path() {
    let managed = serve().await;
    let storage = serve().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(
        &owner,
        &document(
            Some(storage.origin()),
            Some(storage.origin()),
            Some(storage.origin()),
        ),
        AccountAt::Origin(managed.origin().to_owned()),
    )
    .await;
    let controller = host.controller();
    let account = controller.storage_account();
    account
        .keep_for_test(grant(
            STORAGE_HOLDING_ALL,
            &["openid", "backup.write", "voice", "relay.lease"],
        ))
        .await;
    let origin = storage.origin();
    let tokens = account.tokens_for(origin);

    for scope in ["voice", "relay.lease"] {
        let refused = tokens
            .token(scope)
            .await
            .expect_err("the token source hands out no such scope");
        assert_allowance(&refused, scope, "the token source");
    }
    let refused = account
        .relay_payer_token(origin, false)
        .await
        .map(|_| ())
        .expect_err("the relay payer's path hands out no such scope");
    assert_allowance(&refused, "relay.lease", "the relay payer's path");
    tokens
        .token("backup.write")
        .await
        .expect("a request for backup.write is answered");
    // Both paths are counted, so the count the voice client's and the lease keeper's case reads is
    // one that sees a request made on either.
    let asked = account.token_scopes_asked();
    for scope in ["voice", "relay.lease", "backup.write"] {
        assert!(asked.iter().any(|asked| asked == scope), "{asked:?}");
    }

    // The managed account's refusal of an origin that is not its own is another refusal.
    let origin_refusal = controller
        .host_account()
        .tokens_for(origin)
        .token("voice")
        .await
        .expect_err("the managed account hands the storage service nothing");
    assert!(
        matches!(&origin_refusal, kr_client::ClientError::Host(error)
            if error.code == ErrorCode::HostNotConfigured),
        "{origin_refusal}"
    );
    host.stop().await;
}

fn assert_allowance(refused: &kr_client::ClientError, scope: &str, path: &str) {
    assert!(
        matches!(refused, kr_client::ClientError::Host(error)
            if error.code == ErrorCode::PermissionDenied),
        "{path}, for {scope}: {refused}"
    );
    assert!(
        refused.to_string().contains("storage account"),
        "{path}, for {scope}: the refusal is the storage account's own: {refused}"
    );
}

/// A sign-in that starts ends a waiting sign-in of either account and takes the one address a
/// browser comes back to, which reads superseded for the one it ended; a grant either account holds
/// is never ended by it; and a second sign-in of the same account replaces the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_ends_a_waiting_sign_in_of_either_account_and_never_a_grant() {
    let managed = serve().await;
    let storage = serve().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document_at(
        &owner,
        &document(Some(managed.origin()), None, Some(storage.origin())),
        AccountAt::Origin(managed.origin().to_owned()),
    )
    .await;
    let controller = host.controller();
    let (managed_account, storage_account) =
        (controller.host_account(), controller.storage_account());
    managed_account
        .keep_for_test(grant(MANAGED, &["openid", "voice"]))
        .await;
    storage_account
        .keep_for_test(grant(TOKEN, &["openid", "backup.write"]))
        .await;
    let managed_mark = managed_account.mark_at(managed.origin());
    let storage_mark = storage_account.mark_at(storage.origin());
    assert!(managed_mark.is_some() && storage_mark.is_some());
    managed_account.listen_on("127.0.0.1:0".parse().expect("an address"));

    let address_of = |account: &kr_controller::account::HostAccount| match account.report().state {
        AccountState::WaitingForBrowser {
            redirect_address,
            authorise_url,
            ..
        } => (redirect_address, authorise_url),
        other => panic!("a sign-in waits for the browser: {}", other.name()),
    };

    managed_account
        .sign_in()
        .await
        .expect("the managed sign-in starts");
    let (address, managed_url) = address_of(managed_account);
    // The storage account's sign-in comes back to the very address the managed one holds, which it
    // can bind only if the managed attempt has let it go.
    storage_account.listen_on(address.parse().expect("the address the daemon bound"));
    storage_account
        .sign_in()
        .await
        .expect("the storage sign-in starts and takes the address");
    let managed_report = managed_account.report();
    assert_eq!(
        managed_report.last_attempt.0,
        Some(AccountAttempt::Superseded),
        "the managed attempt ended because the storage one began"
    );
    assert!(
        matches!(managed_report.state, AccountState::SignedIn { .. }),
        "the managed account is still signed in: {}",
        managed_report.state.name()
    );
    let (storage_address, storage_url) = address_of(storage_account);
    assert_eq!(storage_address, address, "it took the address over");
    assert_ne!(storage_url, managed_url);

    // The other way: a managed sign-in ends the storage one.
    managed_account.listen_on(address.parse().expect("the address the daemon bound"));
    managed_account
        .sign_in()
        .await
        .expect("the managed sign-in starts again and takes the address");
    assert_eq!(
        storage_account.report().last_attempt.0,
        Some(AccountAttempt::Superseded)
    );
    let (_, second_managed_url) = address_of(managed_account);
    assert_ne!(second_managed_url, managed_url);

    // A second sign-in of the same account replaces the first.
    managed_account
        .sign_in()
        .await
        .expect("a third managed sign-in starts");
    assert_eq!(
        managed_account.report().last_attempt.0,
        Some(AccountAttempt::Superseded)
    );
    assert_ne!(address_of(managed_account).1, second_managed_url);

    // Neither grant was touched.
    assert_eq!(managed_account.mark_at(managed.origin()), managed_mark);
    assert_eq!(storage_account.mark_at(storage.origin()), storage_mark);

    // A sign-out of one account ends that account's waiting sign-in and no other: the storage
    // account's sign-out leaves the managed account's sign-in waiting, and the managed account's
    // own ends it.
    storage_account
        .sign_out()
        .await
        .expect("the storage account signs out");
    assert!(
        matches!(
            managed_account.report().state,
            AccountState::WaitingForBrowser { .. }
        ),
        "the other account's sign-in is still waiting"
    );
    assert_eq!(storage_account.mark_at(storage.origin()), None);
    managed_account
        .sign_out()
        .await
        .expect("the managed account signs out");
    assert!(
        !matches!(
            managed_account.report().state,
            AccountState::WaitingForBrowser { .. }
        ),
        "its own sign-out ends its waiting sign-in"
    );
    host.stop().await;
}

/// What the managed account keeps does not move: the scope it is kept under is named by a digest
/// of the managed origin (the release before this one reads that name), the stored document is
/// these members for a fixed grant, and the mark of its subject is the digest the backup binding
/// compares.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_managed_grant_keeps_its_scope_document_and_mark_through_the_daemon() {
    const MANAGED_ORIGIN: &str = "https://reach.kala.to";
    // The first eight bytes of the SHA-256 of the managed origin, worked out apart from this crate.
    const MANAGED_SCOPE_NAME: &str = "5b9814fd7935c791";
    const MANAGED_MARK: &str = "496fdd6d0a0a59eaeca53e35060c67882995ae95b181eac6a546832f34eb5da6";

    let owner = DeviceKeys::generate().expect("owner keys");
    // The document names the managed broker so that the host presents its account; no call is
    // made, so nothing is sent to it.
    let host = Host::start_with_document_at(
        &owner,
        &document(Some(MANAGED_ORIGIN), None, None),
        AccountAt::Managed,
    )
    .await;
    let account = host.controller().host_account();
    account
        .keep_for_test(grant("a-token", &["openid", "voice"]))
        .await;

    let secrets = host.tree().environment().secrets_dir();
    let item = account_item_in(&secrets, "session");
    let kept: Vec<_> = item
        .strip_prefix(&secrets)
        .expect("under the secret store")
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    let scope = format!("{}/host-account/{MANAGED_SCOPE_NAME}", host.environment_id);
    assert_eq!(
        kept.join("/"),
        format!("{scope}/account/session"),
        "the grant is kept under the scope the managed origin names, which the release before this one reads"
    );

    // The stored document, byte for byte, with the identifier (drawn fresh for each grant) and the
    // expiry (a time) read out of it.
    let text = std::fs::read_to_string(&item).expect("the grant is kept");
    let document: serde_json::Value = serde_json::from_str(&text).expect("a grant document");
    let grant_id = document["grantId"].as_str().expect("an identifier");
    let expiry = document["accessExpiresAtMs"].as_u64().expect("an expiry");
    assert_eq!(
        text.replacen(grant_id, "a-grant-id", 1)
            .replacen(&expiry.to_string(), "1", 1),
        concat!(
            r#"{"grantId":"a-grant-id","revision":0,"issuer":"https://reach.kala.to/auth","#,
            r#""clientId":"kalareach-desktop","subject":"account-1","email":null,"name":null,"#,
            r#""nonce":"a-nonce","refreshToken":"a-token-refresh","accessToken":"a-token","#,
            r#""accessExpiresAtMs":1,"scopes":["openid","voice"]}"#
        )
    );
    assert_eq!(
        account
            .mark_at(MANAGED_ORIGIN)
            .expect("an account is signed in")
            .to_hex(),
        MANAGED_MARK
    );
    host.stop().await;
}

/// The file the host's account keeps `item` in, found under a daemon's secret store.
fn account_item_in(secrets: &std::path::Path, item: &str) -> std::path::PathBuf {
    fn find(directory: &std::path::Path, item: &str, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                find(&path, item, found);
            } else if path.file_name().is_some_and(|name| name == item)
                && path
                    .parent()
                    .is_some_and(|parent| parent.ends_with("account"))
                && path.to_string_lossy().contains("host-account")
            {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    find(secrets, item, &mut found);
    assert_eq!(found.len(), 1, "one {item} item of the account: {found:?}");
    found.remove(0)
}

/// KR-REQ-20.19: the program a shipped build makes refuses a storage origin that is served over
/// plain HTTP, whether or not the document names a proxy, and sends nothing before it does: not
/// the revocation that was left to settle, which a build that recovered before it refused would
/// send to the service, or through the proxy.
///
/// A shipped build does not have the `testing` feature this crate's own tests run with, so the
/// program is not the one these tests are built into: `scripts/shipped-controller-gate.sh` builds
/// it into a target directory of its own and names it in `KR_SHIPPED_CONTROLLER`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the program a shipped build makes, which KR_SHIPPED_CONTROLLER names; scripts/shipped-controller-gate.sh builds it and runs this"]
async fn a_shipped_controller_refuses_a_plain_http_storage_origin_before_it_sends_anything() {
    use kr_controller::account::{HostAccount, Service};
    use kr_controller::config::Outbound;
    use kr_protocol::service::GatewayOrigin;

    let shipped = std::env::var_os("KR_SHIPPED_CONTROLLER")
        .expect("KR_SHIPPED_CONTROLLER names the program a shipped build makes");

    for proxy in [false, true] {
        let host = kr_ipc::testing::TempHost::create();
        let service = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener at the origin");
        service
            .set_nonblocking(true)
            .expect("a listener that does not wait");
        let origin = format!(
            "http://127.0.0.1:{}",
            service.local_addr().expect("an address").port()
        );
        let proxy_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("a proxy's listener");
        proxy_listener
            .set_nonblocking(true)
            .expect("a listener that does not wait");
        let mut document = ConfigurationDocument::empty();
        document.revision = 1;
        document.storage.origin = Nullable::some(origin.clone());
        if proxy {
            document.network.proxy_url = Nullable::some(format!(
                "http://127.0.0.1:{}",
                proxy_listener.local_addr().expect("an address").port()
            ));
        }
        let environment = host.environment();
        let path = kr_worker::config::document_path(&environment);
        std::fs::create_dir_all(path.parent().expect("a state directory")).expect("the directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
        )
        .expect("the document");

        // A sign-out that could not reach the service leaves its revocation queued, in the scope
        // the daemon keeps the storage account's grant under: what a daemon that recovered before
        // it refused would send to the origin.
        let store = kr_crypto::store::open_store_in(&environment.secrets_dir())
            .expect("the daemon's secret store");
        let account = HostAccount::new(
            Arc::from(store.store),
            host.environment_id(),
            environment.runtime_root(),
            Ok(Service::at_origin(
                &GatewayOrigin::new(&origin).expect("an origin"),
                Vec::new(),
                Outbound::Closed("the service is not asked".to_owned()),
            )),
            None,
        );
        account
            .keep_for_test(grant("a-token", &["openid", "backup.write"]))
            .await;
        account.sign_out().await.expect("the host signs out");
        drop(account);

        let program = host.root().join("kr-controller");
        kr_ipc::testing::place_program(std::path::Path::new(&shipped), &program);
        let mut child = std::process::Command::new(&program)
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
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the program starts");
        let waited = std::time::Instant::now();
        let connected = |listener: &std::net::TcpListener| !matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock);
        let status = loop {
            assert!(
                !connected(&service) && !connected(&proxy_listener),
                "the program sent something before it refused (proxy: {proxy})"
            );
            if let Some(status) = child.try_wait().expect("the program's state is read") {
                break status;
            }
            if waited.elapsed() > Duration::from_secs(180) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the program did not refuse a plain-HTTP storage origin (proxy: {proxy})");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let mut said = String::new();
        std::io::Read::read_to_string(
            &mut child.stderr.take().expect("its standard error"),
            &mut said,
        )
        .expect("what the program said");

        assert!(
            !status.success(),
            "the program refused (proxy: {proxy}): {said}"
        );
        assert!(
            said.contains("storage.origin"),
            "the refusal names the key (proxy: {proxy}): {said}"
        );
        for (what, listener) in [("the service", &service), ("the proxy", &proxy_listener)] {
            assert!(
                !connected(listener),
                "nothing connected to {what} (proxy: {proxy})"
            );
        }
    }
}

/// KR-REQ-20.19: an account for a storage service whose scope in the secret store has the managed
/// account's name is refused before the account exists, so nothing is settled in that scope: not
/// the managed account's queued revocation, which holds a refresh token and no issuer and which the
/// storage service would otherwise be sent. A truncated digest names a scope, and one for another
/// origin cannot be made to equal the managed one's here, so the case is the one origin the managed
/// account is at: the scope is the same name by construction. The control is a storage service at
/// another origin, which is built.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_storage_account_whose_scope_is_the_managed_accounts_is_refused_before_it_exists() {
    use kr_controller::account::{HostAccount, Service};
    use kr_controller::config::Outbound;
    use kr_protocol::service::GatewayOrigin;

    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    environment.create().expect("the environment's directories");
    let listener = |what: &str| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|error| panic!("{what}: {error}"));
        listener
    };
    let managed_at = listener("the managed service");
    let managed_origin = GatewayOrigin::new(format!(
        "http://127.0.0.1:{}",
        managed_at.local_addr().expect("an address").port()
    ))
    .expect("an origin");
    let other_at = listener("another service");
    let other_origin = GatewayOrigin::new(format!(
        "http://127.0.0.1:{}",
        other_at.local_addr().expect("an address").port()
    ))
    .expect("an origin");
    let opened = kr_crypto::store::open_store_in(&environment.secrets_dir())
        .expect("the daemon's secret store");
    let store: Arc<dyn kr_crypto::store::SecretStore> = Arc::from(opened.store);
    let closed = || Outbound::Closed("the service is not asked".to_owned());

    // A sign-out that could not reach the managed service leaves its revocation queued in the
    // managed scope.
    let seeding = HostAccount::new(
        Arc::clone(&store),
        host.environment_id(),
        environment.runtime_root(),
        Ok(Service::at_origin(&managed_origin, Vec::new(), closed())),
        None,
    );
    seeding
        .keep_for_test(grant("managed-token", &["openid", "voice"]))
        .await;
    seeding.sign_out().await.expect("the host signs out");
    drop(seeding);

    // The managed account, as the daemon holds it, sends nothing: its route is closed.
    let managed = HostAccount::new(
        Arc::clone(&store),
        host.environment_id(),
        environment.runtime_root(),
        Ok(Service::at_origin(&managed_origin, Vec::new(), closed())),
        None,
    );

    // A storage service at the same origin has the same scope, and no account is built for it.
    let refused = HostAccount::for_storage(
        &managed,
        Arc::clone(&store),
        host.environment_id(),
        managed_origin.as_str(),
        Ok(Service::at_origin(
            &managed_origin,
            vec![kr_client::services::account::BACKUP_WRITE_SCOPE],
            Outbound::Direct,
        )),
        None,
    )
    .expect_err("a storage service whose scope is the managed account's is refused");
    assert!(
        matches!(&refused, kr_controller::ControllerError::NotConfigured(text)
            if text.contains("storage.origin")),
        "{refused}"
    );

    // The rule does not depend on what the managed account holds: one that holds no service at all
    // (its outbound route could not be built) leaves the managed scope no less the managed one's.
    let unbuilt = HostAccount::new(
        Arc::clone(&store),
        host.environment_id(),
        environment.runtime_root(),
        Err(kr_protocol::host_account::SignInUnavailable::NotUsable),
        None,
    );
    HostAccount::for_storage(
        &unbuilt,
        Arc::clone(&store),
        host.environment_id(),
        managed_origin.as_str(),
        Ok(Service::at_origin(
            &managed_origin,
            vec![kr_client::services::account::BACKUP_WRITE_SCOPE],
            Outbound::Direct,
        )),
        None,
    )
    .expect_err("the scope is the managed account's whatever that account holds");

    // The control: a storage service at another origin has a scope of its own, and is built.
    HostAccount::for_storage(
        &managed,
        Arc::clone(&store),
        host.environment_id(),
        managed_origin.as_str(),
        Ok(Service::at_origin(
            &other_origin,
            vec![kr_client::services::account::BACKUP_WRITE_SCOPE],
            Outbound::Direct,
        )),
        None,
    )
    .unwrap_or_else(|error| panic!("a storage account at another origin is built: {error}"));

    let connected = |listener: &std::net::TcpListener| !matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock);
    assert!(
        !connected(&managed_at),
        "nothing was sent to the service whose scope is the managed account's"
    );
}
