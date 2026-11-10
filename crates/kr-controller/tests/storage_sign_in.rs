//! The sign-in, sign-out and status of the account a host holds at a storage service its owner
//! runs.
//!
//! A host whose `storage.origin` names a service that is not the managed account service holds a
//! second account, at that service, for storage and nothing else. Three methods of their own sign
//! it in, sign it out and read where it stands, and act on that account and never on the managed
//! one. These cases start a real daemon from a configuration document, with the account services
//! as stand-ins on loopback sockets that speak the account system's wire, and play the person's
//! browser. They show where the browser is sent and what the sign-in asks for, what the daemon
//! keeps and where, what a sign-out removes and revokes and where, and what a host with no storage
//! service of its own is told.

mod net_support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_client::services::account::{
    AccountToken, Client, IssuedGrant, Redirect, RefreshToken, code_challenge, issuer_of,
};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::host_account::{
    AccountAttempt, AccountReport, AccountSignInParams, AccountSignOutParams, AccountSignedOut,
    AccountState, AccountStatusParams,
};
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use net_support::{AccountAt, Host};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The code the stand-in exchanges for tokens: the one it sent the browser back with.
const CODE: &str = "the-code";

/// One request an account service stand-in was given.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    form: BTreeMap<String, String>,
}

/// What an account service stand-in has been told of the sign-in it sent the browser to, and what
/// it has issued.
#[derive(Default)]
struct State {
    issuer: String,
    nonce: String,
    challenge: String,
    scope: String,
    issued: u32,
    access: String,
    refresh: String,
    revoked: Vec<String>,
}

impl State {
    /// A token answer: the next access token and refresh token, and an identity token when the
    /// answer is to an authorisation code.
    fn issue(&mut self, with_identity: bool) -> serde_json::Value {
        self.issued += 1;
        self.access = format!("access-{}", self.issued);
        self.refresh = format!("refresh-{}", self.issued);
        let mut answer = serde_json::json!({
            "access_token": self.access,
            "token_type": "Bearer",
            "expires_in": 600,
            "refresh_token": self.refresh,
            "scope": self.scope,
        });
        if with_identity {
            let encode = |value: &serde_json::Value| {
                base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    serde_json::to_vec(value).expect("json"),
                )
            };
            let now = kr_ipc::now_ms().get() / 1000;
            let claims = serde_json::json!({
                "iss": self.issuer,
                "sub": "account-1",
                "aud": Client::Desktop.id(),
                "nonce": self.nonce,
                "iat": now - 5,
                "exp": now + 3600,
            });
            answer["id_token"] = serde_json::Value::String(format!(
                "{}.{}.signature",
                encode(&serde_json::json!({"alg": "RS256", "typ": "JWT"})),
                encode(&claims)
            ));
        }
        answer
    }
}

/// An account service on a loopback socket that records every request it is given and answers the
/// token endpoint, the identity read and the revocation as the account system does. It is told
/// which sign-in the browser was sent to, as the service knows it from the address the browser
/// opened.
struct AccountServer {
    origin: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for AccountServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AccountServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let origin = format!("http://{}", listener.local_addr().expect("an address"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Mutex::new(State {
            issuer: issuer_of(&origin),
            ..State::default()
        }));
        let (record, held) = (Arc::clone(&seen), Arc::clone(&state));
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (record, held) = (Arc::clone(&record), Arc::clone(&held));
                tokio::spawn(async move {
                    answer(stream, &record, &held).await;
                });
            }
        });
        Self {
            origin,
            seen,
            state,
            task,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("what was seen").clone()
    }

    fn revoked(&self) -> Vec<String> {
        self.state.lock().expect("the state").revoked.clone()
    }

    fn refresh_token(&self) -> String {
        self.state.lock().expect("the state").refresh.clone()
    }

    /// Learns which sign-in the browser was sent to from the address it was sent to.
    fn expect_sign_in(&self, authorise_url: &str) {
        let url = url::Url::parse(authorise_url).expect("an address");
        assert_eq!(url.origin().ascii_serialization(), self.origin);
        let query: BTreeMap<String, String> = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let mut state = self.state.lock().expect("the state");
        state.nonce = query["nonce"].clone();
        state.challenge = query["code_challenge"].clone();
        state.scope = query["scope"].clone();
    }
}

/// Reads one request and answers it as the account system does.
async fn answer(mut stream: TcpStream, record: &Mutex<Vec<Seen>>, state: &Mutex<State>) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let (head_end, length) = loop {
        let read = stream.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            return;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while bytes.len() < head_end + length {
        let read = stream.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            return;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let head = String::from_utf8_lossy(&bytes[..head_end]).into_owned();
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("")
        .to_owned();
    let authorization = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_owned())
    });
    let form: BTreeMap<String, String> =
        url::form_urlencoded::parse(&bytes[head_end..head_end + length])
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
    record.lock().expect("what was seen").push(Seen {
        path: path.clone(),
        form: form.clone(),
    });
    let (status, body) = account_answer(state, &path, authorization.as_deref(), &form);
    let body = serde_json::to_vec(&body).expect("json");
    let mut out = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    let _ = stream.write_all(&out).await;
}

/// The account system's answers: the token endpoint, the identity read and the revocation.
fn account_answer(
    state: &Mutex<State>,
    path: &str,
    authorization: Option<&str>,
    form: &BTreeMap<String, String>,
) -> (u16, serde_json::Value) {
    let mut state = state.lock().expect("the state");
    let refused = || (400, serde_json::json!({"error": "invalid_grant"}));
    match path {
        "/auth/oauth2/token" => match form.get("grant_type").map(String::as_str) {
            Some("authorization_code") => {
                let redeemable = form.get("code").map(String::as_str) == Some(CODE)
                    && form.get("redirect_uri").map(String::as_str)
                        == Some(Redirect::Loopback.uri())
                    && form.get("client_id").map(String::as_str) == Some(Client::Desktop.id())
                    && code_challenge(form.get("code_verifier").map_or("", String::as_str))
                        == state.challenge;
                if redeemable {
                    (200, state.issue(true))
                } else {
                    refused()
                }
            }
            Some("refresh_token")
                if form.get("refresh_token").map(String::as_str)
                    == Some(state.refresh.as_str()) =>
            {
                (200, state.issue(false))
            }
            _ => refused(),
        },
        "/auth/oauth2/userinfo" => {
            if authorization != Some(format!("Bearer {}", state.access).as_str()) {
                return (401, serde_json::json!({"error": "invalid_token"}));
            }
            (
                200,
                serde_json::json!({"sub": "account-1", "email": "owner@example.test"}),
            )
        }
        "/auth/oauth2/revoke" => {
            state
                .revoked
                .push(form.get("token").cloned().unwrap_or_default());
            (200, serde_json::json!({}))
        }
        _ => (404, serde_json::json!({"error": "not_found"})),
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

/// A grant the managed account service issued, as a finished browser sign-in leaves it.
fn managed_grant() -> IssuedGrant {
    IssuedGrant {
        access_token: AccountToken::new("the-managed-access-token").expect("a token"),
        expires_in_seconds: 86_400,
        refresh_token: RefreshToken::new("the-managed-refresh-token").expect("a token"),
        scopes: ["openid", "voice", "relay.lease"]
            .map(str::to_owned)
            .to_vec(),
        subject: "account-m".to_owned(),
    }
}

/// A host over `document`, with the account service at `managed` standing as the managed one.
async fn host_over(document: &ConfigurationDocument, managed: &AccountServer) -> Host {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host =
        Host::start_with_document_at(&owner, document, AccountAt::Origin(managed.origin.clone()))
            .await;
    // Each sign-in listens on a loopback port the system gives it, so suites do not wait for one
    // another and a port a case chose is never one another process can take first.
    let any = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    host.controller().host_account().listen_on(any);
    host.controller().storage_account().listen_on(any);
    host
}

/// A mutation of the host's own account methods on `client`, under `action`.
async fn mutate_on(
    client: &mut kr_ipc::client::LocalClient,
    host: &Host,
    method: Method,
    action: ActionId,
) -> Result<ParamsValue, ProtocolError> {
    let target = ActionTarget::environment(host.environment_id);
    let answer = if method == Method::AccountSignIn || method == Method::AccountStorageSignIn {
        client
            .mutate(method, action, target, &AccountSignInParams {})
            .await
    } else {
        client
            .mutate(method, action, target, &AccountSignOutParams {})
            .await
    };
    answer.expect("the call reaches the daemon")
}

/// A mutation of the host's own account methods at its local socket, under `action`.
async fn mutate(
    host: &Host,
    method: Method,
    action: ActionId,
) -> Result<ParamsValue, ProtocolError> {
    mutate_on(&mut host.client().await, host, method, action).await
}

/// A read of where an account stands, at the host's local socket.
async fn report(host: &Host, method: Method) -> Result<AccountReport, ProtocolError> {
    host.client()
        .await
        .request(method, &AccountStatusParams {})
        .await
        .expect("the call reaches the daemon")
        .map(|answer| answer.to_typed().expect("a report"))
}

/// Starts a sign-in and returns the address the browser opens and the one it comes back to.
async fn start_sign_in(host: &Host, sign_in: Method, status: Method) -> (String, String) {
    mutate(host, sign_in, ActionId::new(kr_ipc::new_uuid()))
        .await
        .expect("the sign-in starts");
    match report(host, status).await.expect("the status reads").state {
        AccountState::WaitingForBrowser {
            authorise_url,
            redirect_address,
            ..
        } => (authorise_url, redirect_address),
        other => panic!("a sign-in waits for the browser: {}", other.name()),
    }
}

/// Waits until no sign-in of the account is waiting or finishing, and returns where it stands.
async fn settled(host: &Host, status: Method) -> AccountReport {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let report = report(host, status).await.expect("the status reads");
            if !matches!(
                report.state,
                AccountState::WaitingForBrowser { .. } | AccountState::Finishing
            ) {
                return report;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the sign-in settles")
}

/// The browser coming back to the daemon with the code the account service gave it.
async fn browser_answers(redirect_address: &str, authorise_url: &str) {
    let url = url::Url::parse(authorise_url).expect("an address");
    let state = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .expect("the sign-in names its state");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", CODE)
        .append_pair("state", &state)
        .append_pair("iss", &issuer_of(&url.origin().ascii_serialization()))
        .finish();
    let mut stream = TcpStream::connect(redirect_address)
        .await
        .expect("the daemon listens");
    stream
        .write_all(
            format!("GET /oauth/callback?{query} HTTP/1.1\r\nHost: {redirect_address}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("the answer is sent");
    let mut page = String::new();
    let _ = stream.read_to_string(&mut page).await;
}

/// The requests `server` was given at the account system's own endpoints: the token endpoint, the
/// identity read and the revocation. Other requests are the daemon's other clients, which a host
/// that names the managed service for them makes of it whatever the accounts do.
fn account_requests(server: &AccountServer) -> Vec<Seen> {
    server
        .seen()
        .into_iter()
        .filter(|seen| seen.path.starts_with("/auth/"))
        .collect()
}

/// The scopes an authorisation address asks for.
fn scopes_asked(authorise_url: &str) -> Vec<String> {
    url::Url::parse(authorise_url)
        .expect("an address")
        .query_pairs()
        .find(|(name, _)| name == "scope")
        .map(|(_, value)| value.split(' ').map(str::to_owned).collect())
        .expect("the address asks for scopes")
}

/// The file the account kept at the service at `origin` holds its grant in, under the daemon's
/// secret store: a scope named by the first eight bytes of a digest of the origin.
fn grant_file(host: &Host, origin: &str) -> std::path::PathBuf {
    let name: String = kr_cbor::sha256(origin.as_bytes())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    host.tree()
        .environment()
        .secrets_dir()
        .join(host.environment_id.to_string())
        .join("host-account")
        .join(name)
        .join("account")
        .join("session")
}

/// KR-REQ-20.19: the storage sign-in waits for a browser at the storage service, asking for backup
/// storage and neither voice nor relay leases, and `account.storage_status` reports it with the
/// address, while the managed account is not waiting. The control is the managed sign-in of the
/// same host, which asks for the scopes of its own clients and not for backup storage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_storage_sign_in_waits_at_the_storage_service_and_asks_for_backup_storage_only() {
    let managed = AccountServer::start().await;
    let storage = AccountServer::start().await;
    let host = host_over(
        &document(
            Some(&managed.origin),
            Some(&managed.origin),
            Some(&storage.origin),
        ),
        &managed,
    )
    .await;

    let (authorise_url, redirect_address) = start_sign_in(
        &host,
        Method::AccountStorageSignIn,
        Method::AccountStorageStatus,
    )
    .await;
    let url = url::Url::parse(&authorise_url).expect("an address");
    assert_eq!(
        url.origin().ascii_serialization(),
        storage.origin,
        "the browser is sent to the storage service"
    );
    assert_eq!(url.path(), "/auth/oauth2/authorize");
    assert!(
        redirect_address.starts_with("127.0.0.1:"),
        "{redirect_address}"
    );
    let asked = scopes_asked(&authorise_url);
    assert!(
        asked.iter().any(|scope| scope == "backup.write"),
        "{asked:?}"
    );
    for other in ["voice", "relay.lease"] {
        assert!(
            !asked.iter().any(|scope| scope == other),
            "the storage sign-in does not ask for {other}: {asked:?}"
        );
    }
    let storage_report = report(&host, Method::AccountStorageStatus)
        .await
        .expect("the status reads");
    assert_eq!(
        storage_report.service.as_ref().map(String::as_str),
        Some(storage.origin.as_str())
    );

    // The managed account is not the one waiting.
    let managed_report = report(&host, Method::AccountStatus)
        .await
        .expect("the status reads");
    assert_eq!(managed_report.state, AccountState::SignedOut);
    assert_eq!(managed_report.last_attempt.0, None);

    // The control: the managed sign-in of the same host asks for what its clients present, and
    // not for backup storage.
    let (managed_url, _) = start_sign_in(&host, Method::AccountSignIn, Method::AccountStatus).await;
    let managed_asked = scopes_asked(&managed_url);
    for wanted in ["voice", "relay.lease"] {
        assert!(
            managed_asked.iter().any(|scope| scope == wanted),
            "the managed sign-in asks for {wanted}: {managed_asked:?}"
        );
    }
    assert!(!managed_asked.iter().any(|scope| scope == "backup.write"));
    assert!(
        managed_url.starts_with(&managed.origin),
        "the managed sign-in goes to the managed service"
    );
    assert!(
        account_requests(&managed).is_empty() && account_requests(&storage).is_empty(),
        "starting a sign-in sends the account services nothing"
    );
    host.stop().await;
}

/// KR-REQ-20.19: a real sign-in at the storage service keeps its grant in that service's scope
/// and nowhere else; the managed account's grant, its file and its mark do not move; a sign-out
/// removes the grant and revokes it at the storage service and not at the managed one; and a
/// repeat of the same action is answered from the record the first left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_storage_sign_in_is_kept_and_ended_at_the_storage_service_and_leaves_the_managed_account_alone()
 {
    let managed = AccountServer::start().await;
    let storage = AccountServer::start().await;
    let host = host_over(
        &document(Some(&managed.origin), None, Some(&storage.origin)),
        &managed,
    )
    .await;
    let managed_account = host.controller().host_account();
    managed_account.keep_for_test(managed_grant()).await;
    let managed_mark = managed_account.mark_at(&managed.origin);
    let managed_file = grant_file(&host, &managed.origin);
    let managed_bytes = std::fs::read(&managed_file).expect("the managed grant is kept");
    let storage_file = grant_file(&host, &storage.origin);
    assert!(!storage_file.exists(), "no storage grant is kept yet");

    // The browser is sent to the storage service, which learns the sign-in from the address.
    let (authorise_url, redirect_address) = start_sign_in(
        &host,
        Method::AccountStorageSignIn,
        Method::AccountStorageStatus,
    )
    .await;
    storage.expect_sign_in(&authorise_url);
    browser_answers(&redirect_address, &authorise_url).await;
    let signed_in = settled(&host, Method::AccountStorageStatus).await;
    assert_eq!(signed_in.last_attempt.0, Some(AccountAttempt::SignedIn));
    match &signed_in.state {
        AccountState::SignedIn { origin, scopes, .. } => {
            assert_eq!(origin, &storage.origin);
            assert!(
                scopes.iter().any(|scope| scope == "backup.write"),
                "{scopes:?}"
            );
            for other in ["voice", "relay.lease"] {
                assert!(!scopes.iter().any(|scope| scope == other), "{scopes:?}");
            }
        }
        other => panic!("the storage account is signed in: {}", other.name()),
    }
    assert!(
        storage
            .seen()
            .iter()
            .any(|seen| seen.path == "/auth/oauth2/token"
                && seen.form.get("grant_type").map(String::as_str) == Some("authorization_code")),
        "the code was exchanged at the storage service"
    );
    assert!(
        storage_file.exists(),
        "the grant is kept in the storage service's scope"
    );
    assert_ne!(storage_file, managed_file);
    assert_eq!(
        std::fs::read(&managed_file).expect("the managed grant is kept"),
        managed_bytes,
        "the managed grant's file did not change"
    );
    assert_eq!(managed_account.mark_at(&managed.origin), managed_mark);
    assert!(
        account_requests(&managed).is_empty(),
        "no account request reached the managed service: {:?}",
        managed.seen()
    );

    // A sign-out ends the storage account at its own service.
    let refresh_token = storage.refresh_token();
    let action = ActionId::new(kr_ipc::new_uuid());
    let mut client = host.client().await;
    let first: AccountSignedOut =
        mutate_on(&mut client, &host, Method::AccountStorageSignOut, action)
            .await
            .expect("the sign-out is answered")
            .to_typed()
            .expect("a sign-out answer");
    assert!(first.was_signed_in && first.service_told, "{first:?}");
    assert!(!storage_file.exists(), "the grant is removed");
    assert_eq!(
        storage.revoked(),
        [refresh_token],
        "revoked at the storage service"
    );
    let after = report(&host, Method::AccountStorageStatus)
        .await
        .expect("the status reads");
    assert_eq!(after.state, AccountState::SignedOut);

    // The managed account is as it was, and the managed service heard nothing.
    assert_eq!(managed_account.mark_at(&managed.origin), managed_mark);
    assert_eq!(
        std::fs::read(&managed_file).expect("the managed grant is kept"),
        managed_bytes
    );
    assert!(
        account_requests(&managed).is_empty(),
        "no account request reached the managed service: {:?}",
        managed.seen()
    );
    assert!(matches!(
        report(&host, Method::AccountStatus)
            .await
            .expect("the status reads")
            .state,
        AccountState::SignedIn { .. }
    ));

    // The same action again is answered from what the first left; another action finds nothing
    // signed in.
    let repeated: AccountSignedOut =
        mutate_on(&mut client, &host, Method::AccountStorageSignOut, action)
            .await
            .expect("the repeat is answered")
            .to_typed()
            .expect("a sign-out answer");
    assert_eq!(repeated, first);
    let fresh: AccountSignedOut = mutate(
        &host,
        Method::AccountStorageSignOut,
        ActionId::new(kr_ipc::new_uuid()),
    )
    .await
    .expect("the sign-out is answered")
    .to_typed()
    .expect("a sign-out answer");
    assert!(!fresh.was_signed_in, "{fresh:?}");
    host.stop().await;
}

/// KR-REQ-20.19: a host whose `storage.origin` is unset, or names the managed account service,
/// holds no storage account and refuses all three methods by name, `HOST_NOT_CONFIGURED` naming
/// `storage.origin`. The control is the managed account's own status, which both hosts answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_storage_service_of_its_own_refuses_all_three_by_name() {
    let managed = AccountServer::start().await;
    for (what, storage) in [
        ("selects no storage service", None),
        ("selects the managed one", Some(managed.origin.as_str())),
    ] {
        let host = host_over(&document(Some(&managed.origin), None, storage), &managed).await;
        let mut refused = Vec::new();
        for method in [Method::AccountStorageSignIn, Method::AccountStorageSignOut] {
            refused.push(
                mutate(&host, method, ActionId::new(kr_ipc::new_uuid()))
                    .await
                    .expect_err("a host with no storage account of its own refuses"),
            );
        }
        refused.push(
            report(&host, Method::AccountStorageStatus)
                .await
                .expect_err("a host with no storage account of its own refuses"),
        );
        for refusal in &refused {
            assert_eq!(
                refusal.code,
                ErrorCode::HostNotConfigured,
                "a host that {what}: {refusal:?}"
            );
            assert!(
                refusal.message.contains("storage.origin"),
                "a host that {what}: {}",
                refusal.message
            );
        }
        assert!(
            report(&host, Method::AccountStatus).await.is_ok(),
            "the managed account's status is answered by a host that {what}"
        );
        host.stop().await;
    }
}

/// KR-REQ-20.19: a daemon started over a configuration document it cannot use selects no storage
/// service, and its refusals of the three storage methods say that the document cannot be used and
/// point at `kr doctor`, not that `storage.origin` is unset: the document may name a service the
/// person runs. The refusal still names `storage.origin` and is `HOST_NOT_CONFIGURED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_over_a_document_it_cannot_use_says_so_in_its_storage_refusals() {
    let managed = AccountServer::start().await;
    let storage = AccountServer::start().await;
    let host = host_over(
        &document(Some(&managed.origin), None, Some(&storage.origin)),
        &managed,
    )
    .await;
    let stopped = host.shut_down().await;
    let settings = stopped.settings().clone();
    net_support::write_unusable_document(stopped.tree());
    let host = stopped.start(settings).await;
    let mut refused = Vec::new();
    for method in [Method::AccountStorageSignIn, Method::AccountStorageSignOut] {
        refused.push(
            mutate(&host, method, ActionId::new(kr_ipc::new_uuid()))
                .await
                .expect_err("a host with no storage account refuses"),
        );
    }
    refused.push(
        report(&host, Method::AccountStorageStatus)
            .await
            .expect_err("a host with no storage account refuses"),
    );
    for refusal in &refused {
        assert_eq!(refusal.code, ErrorCode::HostNotConfigured, "{refusal:?}");
        assert!(
            refusal.message.contains("storage.origin") && refusal.message.contains("kr doctor"),
            "{}",
            refusal.message
        );
    }
    host.stop().await;
}
