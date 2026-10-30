//! Signing in hands the ceremony to the system browser at the fixed origin, through the commands
//! the page calls.
//!
//! KR-REQ-17.19: the native application hands the passkey ceremony to the system browser on the
//! website's fixed HTTPS origin, whose host is the passkey relying party. These tests call the
//! account commands the way the page calls them, through Tauri's invoke path on the mock runtime,
//! with a browser that records what it is asked to open and answers as the service would, and a
//! stub account service. Each client is run: the desktop's loopback redirect, and the phone's app
//! link and private-use redirects.
//!
//! They run where the mock runtime does, on a desktop. A phone's own carrier needs its native half,
//! which the device legs exercise; there these tests build nothing.
#![cfg(desktop)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_tauri::account::carrier::{
    Boxed, Browser, Carrier, Ending, Loopback, Plan, Reply, Unavailable,
};
use companion_tauri::account::{Account, AccountSlot, AccountView};
use kr_client::services::ServiceFuture;
use kr_client::services::account::{
    ACCOUNT_ORIGIN, AUTHORIZE_PATH, AccountIdentity, AccountService, AccountToken, AccountUsage,
    AuthorisationGrant, Carrier as Delivery, Client, Exchanged, ISSUER, IssuedGrant,
    PendingAuthorisation, RECOVERY_BACKUP_SCOPES, RELYING_PARTY_ID, REQUESTED_SCOPES, Redirect,
    RefreshToken, Refreshed, SignedInAccount, StoredGrant, code_challenge,
};
use kr_crypto::store::{MemoryStore, SecretStore};
use kr_loopback::Listener;
use tauri::Url;
use tauri::test::{INVOKE_KEY, mock_builder, mock_context, noop_assets};
use tauri::webview::InvokeRequest;

/// What the stub service was asked to exchange: the redirect and the verifier.
#[derive(Debug, Default)]
struct Exchanges(Mutex<Vec<(Redirect, String)>>);

#[derive(Debug)]
struct Stub {
    exchanges: Arc<Exchanges>,
}

impl AccountService for Stub {
    fn exchange<'a>(&'a self, grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        self.exchanges
            .0
            .lock()
            .expect("the record")
            .push((grant.redirect(), grant.verifier().to_owned()));
        Box::pin(async {
            Ok(Exchanged::Issued(IssuedGrant {
                access_token: AccountToken::new("a-stub-access-token").expect("a token"),
                expires_in_seconds: 600,
                refresh_token: RefreshToken::new("a-stub-refresh-token").expect("a token"),
                scopes: REQUESTED_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_owned())
                    .collect(),
                subject: "account-1".to_owned(),
            }))
        })
    }

    fn refresh<'a>(&'a self, _stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        Box::pin(async { Ok(Refreshed::Ended) })
    }

    fn revoke<'a>(&'a self, _refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn identity<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity> {
        Box::pin(async {
            Ok(AccountIdentity {
                subject: "account-1".to_owned(),
                email: Some("sam@example.com".to_owned()),
                name: None,
            })
        })
    }

    fn usage<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage> {
        Box::pin(async { Ok(AccountUsage::default()) })
    }
}

/// The parameters of an address, each name with every value it carried.
fn parameters(url: &Url) -> BTreeMap<String, Vec<String>> {
    let mut all: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in url.query_pairs() {
        all.entry(name.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    all
}

/// The answer the service sends back for an address the browser was handed.
fn answer_for(opened: &str, redirect: Redirect) -> String {
    let sent = parameters(&Url::parse(opened).expect("an address"));
    let mut answer = Url::parse(redirect.uri()).expect("an address");
    answer
        .query_pairs_mut()
        .append_pair("code", "a-stub-code")
        .append_pair("state", &sent["state"][0])
        .append_pair("iss", ISSUER);
    answer.into()
}

/// A desktop browser: records the address, then answers on the loopback listener.
struct DesktopBrowser {
    opened: Arc<Mutex<Vec<String>>>,
    listening: Arc<Mutex<Option<SocketAddr>>>,
}

impl Browser for DesktopBrowser {
    fn open(&self, url: &str) -> Result<(), String> {
        self.opened.lock().expect("the record").push(url.to_owned());
        let address = self
            .listening
            .lock()
            .expect("the address")
            .expect("the listener is bound before the browser opens");
        let answer = Url::parse(&answer_for(url, Redirect::Loopback)).expect("an address");
        let target = format!("{}?{}", answer.path(), answer.query().expect("a query"));
        std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};
            let mut stream = std::net::TcpStream::connect(address).expect("a connection");
            write!(
                stream,
                "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                address.port()
            )
            .expect("a request");
            let mut page = String::new();
            let _ = stream.read_to_string(&mut page);
        });
        Ok(())
    }
}

/// A phone's session: records the address and returns the service's answer once.
struct PhoneSession {
    redirect: Redirect,
    opened: Arc<Mutex<Vec<String>>>,
}

impl Carrier for PhoneSession {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        let redirect = self.redirect;
        Box::pin(async move { Ok(Plan { redirect }) })
    }

    fn carry<'a>(
        &'a self,
        _plan: &'a Plan,
        url: String,
        pending: &'a mut PendingAuthorisation,
        _cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Boxed<'a, Ending> {
        Box::pin(async move {
            self.opened.lock().expect("the record").push(url.clone());
            let answer = pending.answer(&answer_for(&url, self.redirect), Delivery::Terminal);
            Ending::Answered {
                answer,
                reply: Reply::default(),
            }
        })
    }
}

/// Builds the application on the mock runtime with the account commands, and invokes `command`.
fn invoke(account: Arc<Account>, command: &str) -> serde_json::Value {
    invoke_in(account, None, command)
}

/// As [`invoke`], over an application that also holds `state`.
fn invoke_in(
    account: Arc<Account>,
    state: Option<companion_tauri::state::AppState>,
    command: &str,
) -> serde_json::Value {
    let builder = mock_builder();
    let builder = match state {
        Some(state) => builder.manage(state),
        None => builder,
    };
    let app = builder
        .manage(AccountSlot::ready(account))
        .invoke_handler(tauri::generate_handler![
            companion_tauri::commands::account_status,
            companion_tauri::commands::account_sign_in,
            companion_tauri::commands::account_sign_in_for_recovery,
            companion_tauri::commands::account_sign_in_cancel,
            companion_tauri::commands::account_sign_out,
            companion_tauri::commands::account_usage,
            companion_tauri::commands::account_services,
        ])
        .build(mock_context(noop_assets()))
        .expect("an application on the mock runtime");
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("a window");
    tauri::test::get_ipc_response(
        &webview,
        InvokeRequest {
            cmd: command.to_owned(),
            callback: tauri::ipc::CallbackFn(0),
            error: tauri::ipc::CallbackFn(1),
            url: "tauri://localhost".parse().expect("the bundled origin"),
            body: tauri::ipc::InvokeBody::default(),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_owned(),
        },
    )
    .map(|body| body.deserialize::<serde_json::Value>().expect("json"))
    .expect("the command answers")
}

fn account(
    client: Client,
    carrier: Arc<dyn Carrier>,
    exchanges: &Arc<Exchanges>,
    views: &Arc<Mutex<Vec<AccountView>>>,
) -> Arc<Account> {
    account_in(
        Arc::new(MemoryStore::new()),
        client,
        carrier,
        exchanges,
        views,
    )
}

fn account_in(
    store: Arc<dyn SecretStore>,
    client: Client,
    carrier: Arc<dyn Carrier>,
    exchanges: &Arc<Exchanges>,
    views: &Arc<Mutex<Vec<AccountView>>>,
) -> Arc<Account> {
    let service: Arc<dyn AccountService> = Arc::new(Stub {
        exchanges: Arc::clone(exchanges),
    });
    let signed_in = Arc::new(SignedInAccount::new(Arc::clone(&service), store, client));
    let published = Arc::clone(views);
    let origin =
        kr_protocol::service::GatewayOrigin::new(ACCOUNT_ORIGIN).expect("the account's origin");
    let deletion = companion_tauri::account::deletion::never_deleting(&origin, &signed_in);
    Arc::new(Account::new(
        signed_in,
        service,
        origin,
        carrier,
        Arc::new(move |view| published.lock().expect("the record").push(view.clone())),
        deletion,
    ))
}

/// What one sign-in handed the browser, what the service was asked, and what the page was told.
fn hand_off(client: Client, redirect: Redirect) {
    hand_off_asking(client, redirect, "account_sign_in", &REQUESTED_SCOPES);
}

/// What the sign-in `command` handed the browser, asking for `scopes`, and what followed.
fn hand_off_asking(client: Client, redirect: Redirect, command: &str, scopes: &[&str]) {
    let opened = Arc::new(Mutex::new(Vec::new()));
    let exchanges = Arc::new(Exchanges::default());
    let views = Arc::new(Mutex::new(Vec::new()));
    let carrier: Arc<dyn Carrier> = match redirect {
        Redirect::Loopback => {
            let listening = Arc::new(Mutex::new(None));
            let bound = Arc::clone(&listening);
            Arc::new(Loopback::with_listener(
                Arc::new(DesktopBrowser {
                    opened: Arc::clone(&opened),
                    listening,
                }),
                move || {
                    let listener = Listener::open_at(
                        "127.0.0.1:0".parse().expect("an address"),
                        "127.0.0.1:0",
                    )?;
                    *bound.lock().expect("the address") = Some(listener.local_address());
                    Ok(listener)
                },
                Duration::from_secs(30),
            ))
        }
        Redirect::AppLink | Redirect::PrivateUse => Arc::new(PhoneSession {
            redirect,
            opened: Arc::clone(&opened),
        }),
    };
    let account = account(client, carrier, &exchanges, &views);
    let answer = invoke(Arc::clone(&account), command);

    // Exactly one address reached the browser: the authorisation endpoint on the fixed origin,
    // whose host is the relying party, with exactly this client's parameters.
    let opened = opened.lock().expect("the record").clone();
    assert_eq!(opened.len(), 1, "{client:?} {redirect:?}");
    let url = Url::parse(&opened[0]).expect("an address");
    assert_eq!(url.origin().ascii_serialization(), ACCOUNT_ORIGIN);
    assert_eq!(url.host_str(), Some(RELYING_PARTY_ID));
    assert_eq!(url.path(), AUTHORIZE_PATH);
    let sent = parameters(&url);
    assert!(sent.values().all(|values| values.len() == 1));
    let one = |name: &str| sent[name][0].clone();
    assert_eq!(one("response_type"), "code");
    assert_eq!(one("client_id"), client.id());
    assert_eq!(one("redirect_uri"), redirect.uri());
    assert_eq!(one("scope"), scopes.join(" "));
    assert_eq!(one("code_challenge_method"), "S256");
    assert_eq!(one("prompt"), "login");
    assert_eq!(sent.len(), 9, "{sent:?}");

    // The exchange named the same redirect, with the verifier the challenge was made from.
    let exchanged = exchanges.0.lock().expect("the record").clone();
    assert_eq!(exchanged.len(), 1);
    assert_eq!(exchanged[0].0, redirect);
    assert_eq!(code_challenge(&exchanged[0].1), one("code_challenge"));

    // The page is told where the device stands, and nothing that travelled.
    assert_eq!(answer["state"], "signed_in", "{answer}");
    assert_eq!(answer["email"], "sam@example.com");
    let told = answer.to_string();
    for secret in [
        "a-stub-access-token",
        "a-stub-refresh-token",
        "a-stub-code",
        one("state").as_str(),
        exchanged[0].1.as_str(),
    ] {
        assert!(!told.contains(secret), "{told}");
    }
    // The browser-open state was published before the answer came back.
    let views = views.lock().expect("the record").clone();
    assert!(views.contains(&AccountView::BrowserOpen), "{views:?}");
}

/// KR-REQ-17.19: the desktop hands the ceremony to the default browser and takes the answer on the
/// registered loopback redirect.
#[test]
fn the_desktop_hands_the_ceremony_to_the_browser_at_the_fixed_origin() {
    hand_off(Client::Desktop, Redirect::Loopback);
}

/// KR-REQ-17.19: signing in for recovery asks for the application's scopes and the right to write
/// the account's backup storage, which the application's ordinary sign-in does not ask for.
#[test]
fn signing_in_for_recovery_asks_for_the_right_to_write_backup_storage() {
    assert!(!REQUESTED_SCOPES.contains(&"backup.write"));
    hand_off_asking(
        Client::Desktop,
        Redirect::Loopback,
        "account_sign_in_for_recovery",
        &RECOVERY_BACKUP_SCOPES,
    );
}

/// KR-REQ-17.19: a phone hands it to the browser-backed session, answered on the app link.
#[test]
fn a_phone_hands_the_ceremony_to_the_browser_session_answered_on_the_app_link() {
    hand_off(Client::Mobile, Redirect::AppLink);
}

/// KR-REQ-17.19: an iPhone before iOS 17.4 is answered on the private-use redirect.
#[test]
fn an_older_iphone_hands_the_ceremony_to_the_session_answered_on_the_private_scheme() {
    hand_off(Client::Mobile, Redirect::PrivateUse);
}

/// A sign-in the person cancels while the browser is open changes nothing.
#[test]
fn a_cancelled_sign_in_changes_nothing() {
    struct Waiting;
    impl Carrier for Waiting {
        fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
            Box::pin(async {
                Ok(Plan {
                    redirect: Redirect::AppLink,
                })
            })
        }

        fn carry<'a>(
            &'a self,
            _plan: &'a Plan,
            _url: String,
            _pending: &'a mut PendingAuthorisation,
            mut cancel: tokio::sync::watch::Receiver<bool>,
        ) -> Boxed<'a, Ending> {
            Box::pin(async move {
                while !*cancel.borrow() {
                    if cancel.changed().await.is_err() {
                        break;
                    }
                }
                Ending::Cancelled
            })
        }
    }
    let exchanges = Arc::new(Exchanges::default());
    let views = Arc::new(Mutex::new(Vec::new()));
    let account = account(Client::Mobile, Arc::new(Waiting), &exchanges, &views);
    let signing_in = {
        let account = Arc::clone(&account);
        std::thread::spawn(move || invoke(account, "account_sign_in"))
    };
    while !views
        .lock()
        .expect("the record")
        .contains(&AccountView::BrowserOpen)
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    account.cancel();
    let answer = signing_in.join().expect("the sign-in settles");
    assert_eq!(answer["state"], "signed_out");
    assert_eq!(answer["outcome"], "cancelled");
    assert!(exchanges.0.lock().expect("the record").is_empty());
}

/// A store that keeps and reads items but cannot remove one.
struct RefusingDeletes(MemoryStore);

impl SecretStore for RefusingDeletes {
    fn set(&self, name: &kr_crypto::store::SecretName, secret: &[u8]) -> kr_crypto::Result<()> {
        self.0.set(name, secret)
    }

    fn get(
        &self,
        name: &kr_crypto::store::SecretName,
    ) -> kr_crypto::Result<Option<kr_crypto::secret::SecretVec>> {
        self.0.get(name)
    }

    fn delete(&self, _name: &kr_crypto::store::SecretName) -> kr_crypto::Result<()> {
        Err(kr_crypto::CryptoError::SecretStore {
            message: "the store refused the removal".to_owned(),
        })
    }

    fn describe(&self) -> String {
        "a store that cannot remove".to_owned()
    }
}

/// A sign-out the store refuses leaves the device signed in, and the page is told both: that it is
/// still signed in, and that the sign-out failed.
#[test]
fn a_sign_out_the_store_refuses_says_so_beside_the_signed_in_account() {
    let exchanges = Arc::new(Exchanges::default());
    let views = Arc::new(Mutex::new(Vec::new()));
    let carrier: Arc<dyn Carrier> = Arc::new(PhoneSession {
        redirect: Redirect::AppLink,
        opened: Arc::new(Mutex::new(Vec::new())),
    });
    let account = account_in(
        Arc::new(RefusingDeletes(MemoryStore::new())),
        Client::Mobile,
        carrier,
        &exchanges,
        &views,
    );
    let signed_in = invoke(Arc::clone(&account), "account_sign_in");
    assert_eq!(signed_in["state"], "signed_in", "{signed_in}");

    let answer = invoke(Arc::clone(&account), "account_sign_out");
    assert_eq!(answer["state"], "signed_in", "{answer}");
    assert_eq!(answer["outcome"], "sign_out_failed", "{answer}");
    let status = invoke(account, "account_status");
    assert_eq!(status["outcome"], "sign_out_failed", "{status}");
}

/// A factory of sync clients that records the origins it is asked for and makes the managed client.
#[derive(Debug)]
struct Recording {
    clients: companion_tauri::services::ManagedSyncServices,
    asked: Mutex<Vec<String>>,
}

impl companion_tauri::services::SyncServices for Recording {
    fn installation(
        &self,
        origin: &kr_protocol::service::GatewayOrigin,
    ) -> companion_tauri::error::Result<Arc<dyn kr_client::services::SharedSyncService>> {
        self.asked
            .lock()
            .expect("the record")
            .push(origin.as_str().to_owned());
        self.clients.installation(origin)
    }

    fn presenting(
        &self,
        origin: &kr_protocol::service::GatewayOrigin,
        tokens: Arc<dyn kr_client::services::AccountTokenSource>,
        scope: &'static str,
    ) -> companion_tauri::error::Result<Arc<dyn kr_client::services::SharedSyncService>> {
        self.clients.presenting(origin, tokens, scope)
    }
}

/// The lines a page reads, as (service, configured, explanation).
fn lines(answer: &serde_json::Value) -> Vec<(String, bool, String)> {
    answer
        .as_array()
        .expect("a list of lines")
        .iter()
        .map(|line| {
            (
                line["service"].as_str().expect("a name").to_owned(),
                line["configured"].as_bool().expect("a flag"),
                line["explanation"].as_str().expect("words").to_owned(),
            )
        })
        .collect()
}

/// KR-REQ-17.14: the application says which managed services it holds a client of, in the words
/// the library uses, and for a service it holds none of, what a person does instead. The sync line
/// is derived from the factory the desks use, asked for the origin the setting names, so replacing
/// the factory is what changes the line. A phone leaves relay leases out: the host keeps those.
#[test]
fn the_application_reports_the_managed_services_it_holds_a_client_of() {
    use kr_client::services::{ManagedService, ServiceClients};

    let exchanges = Arc::new(Exchanges::default());
    let views = Arc::new(Mutex::new(Vec::new()));
    let carrier: Arc<dyn Carrier> = Arc::new(PhoneSession {
        redirect: Redirect::AppLink,
        opened: Arc::new(Mutex::new(Vec::new())),
    });
    let account = account(Client::Mobile, carrier, &exchanges, &views);
    let none = ServiceClients::none();

    // An application whose desks are not open holds the account's client and nothing else.
    let bare = lines(&invoke(Arc::clone(&account), "account_services"));
    let names: Vec<&str> = bare.iter().map(|(name, _, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            ManagedService::AccountLogin.as_str(),
            ManagedService::Push.as_str(),
            ManagedService::SyncBackup.as_str(),
            ManagedService::ManagedInference.as_str(),
        ],
        "four services, and not the relay lease service"
    );
    assert_eq!(
        bare.iter().map(|(_, held, _)| *held).collect::<Vec<_>>(),
        [true, false, false, false]
    );
    for (name, held, explanation) in &bare {
        let service = ManagedService::ALL
            .into_iter()
            .find(|service| service.as_str() == name)
            .expect("a service the library names");
        if !held {
            assert_eq!(
                *explanation,
                none.availability_of(service).explanation,
                "{name}: what a person does instead is the library's word"
            );
        }
    }

    // With the sync service setting open and a factory of sync clients installed, the sync line is
    // held, and the factory was asked for the origin the setting names.
    let directory = tempfile::tempdir().expect("a directory");
    let state = companion_tauri::state::AppState::new();
    let setting = companion_tauri::sync_service::SyncService::open(directory.path());
    setting
        .set("https://sync.example")
        .expect("another service is chosen");
    state.sync_service_opened(Arc::new(setting));
    let recording = Arc::new(Recording {
        clients: companion_tauri::services::ManagedSyncServices::new(
            kr_crypto::keys::AuthorisationKeyPair::generate().expect("a key"),
        ),
        asked: Mutex::new(Vec::new()),
    });
    state.sync_clients_replaced(Arc::clone(&recording) as _);
    let held = lines(&invoke_in(account, Some(state), "account_services"));
    assert_eq!(
        held.iter().map(|(_, held, _)| *held).collect::<Vec<_>>(),
        [true, false, true, false]
    );
    assert_eq!(
        *recording.asked.lock().expect("the record"),
        ["https://sync.example".to_owned()],
        "the line is made from the client at the origin the setting names"
    );
}
