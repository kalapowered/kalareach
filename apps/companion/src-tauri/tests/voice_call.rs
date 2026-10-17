//! A phone's voice call, from the page's start to the end of the call.
//!
//! The daemon is kr-controller's in-process host, with its test support included by path, and the
//! device is this crate's own backend on the mock runtime, paired with it through the commands the
//! page calls. The voice service is a stand-in on the loopback interface that answers as the
//! service's contract states: its routes for the host, and the control socket for the phone, on
//! one port, as the origin the host names to the phone is one origin for both. Native code is
//! scripted, because a call's media cannot run in a Rust test; the device legs prove the real one.
//! No test here makes a live provider call.
//!
//! | What | What proves it |
//! | --- | --- |
//! | A call runs from the start to the hang-up, through the host and the service | `a_call_runs_from_the_pages_start_to_its_hang_up` |
//! | No account token for the voice scope starts nothing | `a_device_with_no_voice_token_starts_nothing` |
//! | An expired token is refreshed before a start, and the control presents the new one | `an_expired_token_is_refreshed_before_the_start_and_the_control_presents_the_new_one` |
//! | A token of another account ends the call in words, and a warning stands before the next start | `a_token_of_another_account_ends_the_call_and_a_warning_stands_before_the_next` |
//! | A control whose authentication fails, after the host started the call, closes it everywhere | `a_control_that_is_not_authorised_closes_the_call_the_host_started` |
//! | The notification's stop and a failed connection end the call with no page | `the_notifications_stop_ends_the_call_with_no_page`, `a_failed_connection_ends_the_call_with_no_page` |
//! | News that was lost is checked against what native code holds | `news_that_was_lost_is_checked_against_what_native_code_holds` |
//! | A sign of life that native code refuses as ended ends the call | `a_sign_of_life_native_code_refuses_as_ended_ends_the_call` |
//! | A delegation is answered to the model that nothing was done, once | `a_delegation_is_answered_to_the_model_that_nothing_was_done_once` |
//! | A mute silences the microphone here and is told to the service | `muting_the_microphone_silences_it_here_and_tells_the_service` |
//! | A host that names another voice service gets no token | `a_host_that_names_another_voice_service_gets_no_token` |
//! | A stop that never returns does not hold the host's revocation | `a_stop_native_code_never_returns_does_not_hold_the_revocation` |
//! | A page that is loaded again finds the call and can end it | `a_page_that_is_loaded_again_finds_the_call_and_ends_it` |
//! | Native code that stops answering the signs of life ends the call | `native_code_that_stops_answering_ends_the_call` |
//! | A sign-out during the call ends it | `signing_out_during_a_call_ends_it` |
//! | A lost host is told to the model, and a refusal to vouch for the call is not its return | `a_host_that_is_lost_is_told_to_the_model_and_a_refusal_is_not_its_return` |

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;
#[path = "../../../../crates/kr-controller/tests/voice_support/mod.rs"]
mod voice_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use companion_platform::call::{CallEvent, FailureKind};
use companion_tauri::account::carrier::{Boxed, Carrier, Ending, Plan, Unavailable};
use companion_tauri::account::{Account, AccountSlot};
use companion_tauri::voice::{Calls, Service, Timings};
use kr_client::services::ServiceFuture;
use kr_client::services::account::{
    AccountIdentity, AccountService, AccountToken, AccountUsage, AuthorisationGrant, Client,
    Exchanged, IssuedGrant, PendingAuthorisation, RefreshToken, Refreshed, SignedInAccount,
    StoredGrant,
};
use kr_client::services::voice_control::ControlConnector;
use kr_client::services::{HttpDeadlines, HttpService, managed_response_limits};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::MemoryStore;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use net_support::Host;
use serde_json::json;
use support::call::{OFFER, ScriptedCalls};
use support::{Companion, NoOwner, Phone, StubPaste, WATCHDOG, pair, parts};
use tauri::Manager as _;
use tokio::sync::watch;
use voice_support::StandIn;

/// The access token the phone's account holds first.
const PHONE_TOKEN: &str = "phone-access-token-1";
/// The one a refresh gives it.
const PHONE_TOKEN_REFRESHED: &str = "phone-access-token-2";

/// An account service the phone refreshes through: it issues the second token for the first.
#[derive(Debug, Default)]
struct PhoneService {
    refreshes: AtomicUsize,
}

fn phone_grant(access: &str, expires_in_seconds: u64) -> IssuedGrant {
    IssuedGrant {
        access_token: AccountToken::new(access).expect("a token"),
        expires_in_seconds,
        refresh_token: RefreshToken::new(format!("refresh-for-{access}")).expect("a token"),
        scopes: ["openid", "profile", "email", "offline_access", "voice"]
            .map(str::to_owned)
            .to_vec(),
        subject: "account-1".to_owned(),
    }
}

impl AccountService for PhoneService {
    fn exchange<'a>(&'a self, _grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        Box::pin(async { Ok(Exchanged::Issued(phone_grant(PHONE_TOKEN, 3600))) })
    }

    fn refresh<'a>(&'a self, _stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Refreshed::Rotated(phone_grant(PHONE_TOKEN_REFRESHED, 3600))) })
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

/// A phone that carries no sign-in: the call is what is under test, not the ceremony.
struct NoCarrier;

impl Carrier for NoCarrier {
    fn plan(&self) -> Boxed<'_, Result<Plan, Unavailable>> {
        Box::pin(async { Err(Unavailable::NoReturningBrowser) })
    }

    fn carry<'a>(
        &'a self,
        _plan: &'a Plan,
        _url: String,
        _pending: &'a mut PendingAuthorisation,
        _cancel: watch::Receiver<bool>,
    ) -> Boxed<'a, Ending> {
        Box::pin(async { Ending::Cancelled })
    }
}

/// Timings a test shortens: signs of life often, and a host that is asked for little.
fn quick() -> Timings {
    Timings {
        tick: Duration::from_millis(100),
        host_within: Duration::from_secs(20),
        ..Timings::default()
    }
}

/// The document an operator writes to name the voice service.
fn document_naming(origin: &str) -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = Nullable::some(origin.to_owned());
    document
}

/// Everything one test holds.
struct Scene {
    host: Host,
    stand_in: StandIn,
    platform: Arc<ScriptedCalls>,
    phone: Phone,
    tokens: Arc<SignedInAccount>,
    service: Arc<PhoneService>,
    session: String,
}

impl Scene {
    fn call(
        &self,
        command: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, serde_json::Value> {
        self.phone.companion.call(command, body)
    }

    fn state(&self) -> serde_json::Value {
        self.call("voice_call_state", json!({}))
            .expect("the call's state")
    }

    /// Waits until the call's state satisfies `until`, and returns it.
    async fn state_where(
        &self,
        what: &str,
        until: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let state = self.state();
                if until(&state) {
                    return state;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the call never showed {what}: {}", self.state()))
    }

    /// Asks for a start the way the page does, after reading what a call would be.
    fn start_request(&self, prepared: &serde_json::Value) -> serde_json::Value {
        json!({
            "subject": {},
            "sessionIds": [self.session],
            "durationSeconds": 600,
            "reasoningBudgetMinor": null,
            "prepared": prepared["prepared"],
            "expectedRateVersion": prepared["managed"]["rate"]["version"],
        })
    }

    async fn prepared(&self) -> serde_json::Value {
        self.call(
            "voice_prepare",
            json!({ "params": { "session_ids": [self.session], "selected": [] } }),
        )
        .expect("the host says what a call would be")
    }

    /// Starts a call and returns the host's answer to the page.
    async fn start(&self) -> serde_json::Value {
        let prepared = self.prepared().await;
        self.call("voice_start", self.start_request(&prepared))
            .expect("a call starts")
    }
}

/// A host that brokers calls through the stand-in, a phone paired with it that may start one, and
/// native code that does what it is told.
async fn scene_with(
    timings: Timings,
    signed_in: Option<IssuedGrant>,
    account_origin: Option<&str>,
) -> Scene {
    let stand_in = StandIn::start().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start_with_document(&owner, &document_naming(stand_in.origin())).await;
    host.controller()
        .host_account()
        .keep_for_test(stand_in.host_grant())
        .await;
    stand_in.accept_control_token(PHONE_TOKEN);
    stand_in.accept_control_token(PHONE_TOKEN_REFRESHED);

    let service = Arc::new(PhoneService::default());
    let tokens = Arc::new(SignedInAccount::new(
        Arc::clone(&service) as Arc<dyn AccountService>,
        Arc::new(MemoryStore::new()),
        Client::Mobile,
    ));
    if let Some(grant) = signed_in {
        tokens
            .keep(grant, "a-nonce")
            .await
            .expect("the phone signs in");
    }
    let account = Arc::new(Account::new(
        Arc::clone(&tokens),
        Arc::clone(&service) as Arc<dyn AccountService>,
        Arc::new(NoCarrier),
        Arc::new(|_| {}),
    ));
    let platform = ScriptedCalls::new();
    let calls = Calls::on_phone(
        Arc::clone(&platform) as Arc<dyn companion_platform::call::CallPlatform>,
        Service {
            origin: account_origin
                .unwrap_or_else(|| stand_in.origin())
                .to_owned(),
            http: Arc::new(
                HttpService::with(
                    kr_protocol::service::GatewayOrigin::new(
                        account_origin.unwrap_or_else(|| stand_in.origin()),
                    )
                    .expect("an origin"),
                    HttpDeadlines::default(),
                    managed_response_limits(),
                )
                .expect("a transport"),
            ),
            connector: ControlConnector::platform().expect("a connector"),
        },
        timings,
    );

    let data = tempfile::tempdir().expect("a directory");
    let secrets: Arc<dyn kr_crypto::store::SecretStore> = Arc::new(MemoryStore::new());
    let room: Arc<dyn kr_client::pairing::candidate::CandidateRoom> = Arc::new(host.room.clone());
    let paste = StubPaste::holding("", false);
    let companion = Companion::start_with_voice(
        data.path(),
        parts(Arc::clone(&secrets), Arc::clone(&room)),
        Arc::new(NoOwner),
        Arc::clone(&paste) as Arc<dyn companion_tauri::pairing::PastePlatform>,
        calls,
        AccountSlot::ready(account),
    );
    let phone = Phone {
        companion,
        paste,
        secrets,
        room,
        data,
    };
    pair(
        &phone,
        &host,
        &owner,
        &[ActionRight::SessionView, ActionRight::AgentPrompt],
    )
    .await;
    let session = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()).to_string();
    let scene = Scene {
        host,
        stand_in,
        platform,
        phone,
        tokens,
        service,
        session,
    };
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = scene
                .call("connection_state", json!({}))
                .expect("the connection's state");
            if state["connected"] == true {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the phone reaches the host it paired with");
    scene
        .call(
            "voice_allow",
            json!({ "subject": {}, "params": { "session_ids": [scene.session], "actions": null } }),
        )
        .expect("the person allows voice");
    scene
}

async fn scene() -> Scene {
    scene_with(quick(), Some(phone_grant(PHONE_TOKEN, 3600)), None).await
}

/// The frames the control route read from the device, as the commands they carried.
fn frames_of(scene: &Scene) -> Vec<serde_json::Value> {
    scene
        .stand_in
        .control()
        .report()
        .frames
        .iter()
        .filter_map(|frame| serde_json::from_str(frame).ok())
        .collect()
}

fn commands_sent(scene: &Scene) -> Vec<String> {
    frames_of(scene)
        .iter()
        .filter_map(|frame| frame["command"].as_str().map(str::to_owned))
        .collect()
}

/// A call runs from the start to the hang-up: the device opens its call and makes its offer, the
/// host creates the call at the service with that offer, the device applies the answer, permits
/// the call for the voice session and the moment the host named, and opens its control with its
/// own account's token. The page is given the host's descriptor without the provider's answer.
/// The model is told once that this version cannot act on the host. Hanging up stops the media,
/// has the host revoke the grant, and has the service finalise the call, and the page does not
/// wait for the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_runs_from_the_pages_start_to_its_hang_up() {
    let scene = scene().await;

    let started = scene.start().await;
    let session = &started["value"]["outcome"]["started"]["session"];
    let voice_session_id = session["voice_session_id"]
        .as_str()
        .expect("a voice session");
    assert_eq!(session["call_id"], "call-1");
    assert_eq!(
        session["answer_sdp"], "",
        "the provider's answer, which holds the call's ICE credentials, is native code's and not the page's"
    );
    let steps: Vec<String> = scene
        .platform
        .commands()
        .into_iter()
        .filter(|command| command != "alive")
        .collect();
    assert_eq!(
        steps[..4],
        ["open", "offer", "accept", "permit"],
        "{steps:?}"
    );
    assert_eq!(
        scene.platform.answer().as_deref(),
        Some("v=0\r\na=answered-by-the-stand-in\r\n"),
        "native code applied the answer the service gave the host"
    );
    let permitted = scene.platform.permitted_for().expect("it was permitted");
    assert_eq!(permitted.0, voice_session_id);
    let creation = scene
        .stand_in
        .seen()
        .into_iter()
        .find(|request| request.path == "/api/voice/sessions")
        .expect("the host started the call at the service");
    assert_eq!(creation.body["offerSdp"], OFFER);

    // The control is the phone's, opened with the phone's own token.
    scene
        .stand_in
        .control()
        .until("the control attached", |report| !report.upgrades.is_empty())
        .await;
    assert_eq!(
        scene.stand_in.control().report().upgrades[0]
            .authorization
            .as_deref(),
        Some(format!("Bearer {PHONE_TOKEN}").as_str())
    );
    scene
        .stand_in
        .control()
        .until("the model was told what this version does", |report| {
            report
                .sent
                .iter()
                .any(|sent| sent.command == "instructions")
        })
        .await;
    let running = scene
        .state_where("a running call", |state| {
            state["running"] == true && state["control"] == "connected"
        })
        .await;
    assert_eq!(running["capture"], "capturing");
    assert_eq!(running["session"]["voice_session_id"], voice_session_id);
    assert_eq!(running["session"]["answer_sdp"], "");

    let closure = scene
        .call("voice_stop", json!({ "voiceSessionId": voice_session_id }))
        .expect("the call ends");
    assert_eq!(closure["closed_locally"], true);
    assert_eq!(closure["fence"]["kind"], "not_owed");
    assert_eq!(closure["host_failure"], serde_json::Value::Null);
    assert!(
        scene.platform.count("stop") >= 1,
        "native code was told to stop"
    );
    assert_eq!(
        scene.stand_in.count("/api/voice/sessions/call-1/close"),
        1,
        "the host told the service the call ended"
    );

    // The service is finalised after the page has its answer, by the control.
    let ended = scene
        .state_where("the closure at the service", |state| {
            state["ended"]["broker"] == "closed"
        })
        .await;
    assert_eq!(ended["running"], false);
    assert_eq!(ended["ended"]["cause"], "requested");
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    assert!(commands_sent(&scene).contains(&"close".to_owned()));
    scene.host.stop().await;
}

/// A device with no account token for the voice scope could not control a call, and the service
/// closes a call nobody controls, so nothing is created or asked: no call is opened on the device
/// and the host is not asked to start one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_no_voice_token_starts_nothing() {
    let scene = scene_with(quick(), None, None).await;
    let prepared = scene.prepared().await;

    let refused = scene
        .call("voice_start", scene.start_request(&prepared))
        .expect_err("no account is signed in, so no call starts");

    assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
    assert!(
        scene.platform.commands().is_empty(),
        "native code was asked nothing: {:?}",
        scene.platform.commands()
    );
    assert_eq!(scene.stand_in.count("/api/voice/sessions"), 0);
    assert_eq!(scene.state()["running"], false);
    scene.host.stop().await;
}

/// A token that has run out is replaced before the start, so a start never finds out at the
/// control that its token is old, and the control presents the one the refresh issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_token_is_refreshed_before_the_start_and_the_control_presents_the_new_one() {
    let scene = scene_with(quick(), Some(phone_grant(PHONE_TOKEN, 1)), None).await;
    assert_eq!(scene.service.refreshes.load(Ordering::SeqCst), 0);

    let started = scene.start().await;

    assert!(started["value"]["outcome"]["started"].is_object());
    assert_eq!(scene.service.refreshes.load(Ordering::SeqCst), 1);
    scene
        .stand_in
        .control()
        .until("the control attached", |report| !report.upgrades.is_empty())
        .await;
    assert_eq!(
        scene.stand_in.control().report().upgrades[0]
            .authorization
            .as_deref(),
        Some(format!("Bearer {PHONE_TOKEN_REFRESHED}").as_str())
    );
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.host.stop().await;
}

/// A device whose account is not the one the call was started under finds the service has no such
/// call for it: the call is ended in full (the media, the host's grant, the service), the person
/// is told why in words, and a warning stands before the next start without blocking it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_of_another_account_ends_the_call_and_a_warning_stands_before_the_next() {
    let scene = scene().await;
    scene.stand_in.treat_as_another_account(PHONE_TOKEN);
    assert_eq!(scene.state()["warning"], serde_json::Value::Null);

    let started = scene.start().await;
    assert!(started["value"]["outcome"]["started"].is_object());

    let ended = scene
        .state_where("a call that ended", |state| {
            state["ended"]["cause"] == "no_such_call"
        })
        .await;
    assert_eq!(ended["running"], false);
    assert!(
        ended["ended"]["words"]
            .as_str()
            .is_some_and(|words| words.contains("no such call")),
        "{ended}"
    );
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    assert!(scene.platform.count("stop") >= 1);
    assert_eq!(
        scene.stand_in.count("/api/voice/sessions/call-1/close"),
        1,
        "the host closed the call at the service"
    );
    assert!(
        scene.state()["warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("no such call")),
        "the warning stands: {}",
        scene.state()
    );

    // It does not block a start: the account is now the call's, and the control attaches.
    scene.stand_in.accept_control_token(PHONE_TOKEN);
    let again = scene.start().await;
    assert!(again["value"]["outcome"]["started"].is_object());
    scene
        .state_where("a control that attached", |state| {
            state["running"] == true
                && state["control"] == "connected"
                && state["warning"].is_null()
        })
        .await;
    scene.host.stop().await;
}

/// A control whose token the service does not accept, after the host created the call, closes the
/// call: the media stops, the host revokes the grant and closes the call at the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_control_that_is_not_authorised_closes_the_call_the_host_started() {
    let scene = scene().await;
    // The service has never been told of the token the phone holds.
    scene.stand_in.forget_control_token(PHONE_TOKEN);

    let started = scene.start().await;
    assert!(started["value"]["outcome"]["started"].is_object());

    let ended = scene
        .state_where("an unauthorised control", |state| {
            state["ended"]["cause"] == "not_authorised"
        })
        .await;
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    assert!(scene.platform.count("stop") >= 1);
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    scene.host.stop().await;
}

/// The notification's stop is native code's own end of the call. No page is looking, and the call
/// is ended in full all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_notifications_stop_ends_the_call_with_no_page() {
    let scene = scene().await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;

    scene.platform.tell(CallEvent::Ended);

    let ended = scene
        .state_where("the end", |state| state["ended"]["cause"] == "native_ended")
        .await;
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    scene
        .state_where("the service's closure", |state| {
            state["ended"]["broker"] == "closed"
        })
        .await;
    scene.host.stop().await;
}

/// A connection that fails ends the call the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_connection_ends_the_call_with_no_page() {
    let scene = scene().await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;

    scene.platform.fail_the_connection();

    let ended = scene
        .state_where("the end", |state| {
            state["ended"]["cause"] == "native_failed"
        })
        .await;
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    assert!(scene.platform.count("stop") >= 1);
    scene.host.stop().await;
}

/// News that was lost can be the end of the call. The device asks native code what it holds, and
/// ends the call when it holds none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn news_that_was_lost_is_checked_against_what_native_code_holds() {
    // No sign of life is due for an hour, so only the check of lost news can end this call.
    let timings = Timings {
        tick: Duration::from_secs(3600),
        ..quick()
    };
    let scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;

    // The call ends and its end is never heard: a number is skipped.
    let signs_before = scene.platform.count("alive");
    scene.platform.end_without_saying_so();
    scene.platform.lose_some_news();

    let ended = scene
        .state_where("the end", |state| state["ended"]["cause"] == "native_gone")
        .await;
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    assert!(
        scene.platform.count("held") >= 1,
        "native code was asked what it holds"
    );
    assert_eq!(
        scene.platform.count("alive"),
        signs_before,
        "no sign of life ended it"
    );
    scene.host.stop().await;
}

/// A sign of life that native code answers as a call that has ended ends the call, whether or not
/// its news said so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_of_life_native_code_refuses_as_ended_ends_the_call() {
    let scene = scene().await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;

    scene.platform.refuse_signs_as(FailureKind::Ended);

    let ended = scene
        .state_where("the end", |state| state["ended"]["cause"] == "native_gone")
        .await;
    assert!(scene.platform.count("alive") >= 1);
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    scene.host.stop().await;
}

/// The provider announces a delegation, and this version acts on nothing a person says: the model
/// is told once that nothing was done, whatever the control says again, and the page is given a
/// row that says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegation_is_answered_to_the_model_that_nothing_was_done_once() {
    let scene = scene().await;
    scene.start().await;
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;

    scene.stand_in.control().announce("d-1", 1200);
    let row = scene
        .state_where("a delegation answered", |state| {
            state["delegations"][0]["told"] == true
        })
        .await;
    assert_eq!(row["delegations"][0]["delegation_id"], "d-1");
    assert_eq!(row["delegations"][0]["state"], "not_done");
    assert_eq!(row["delegations"][0]["offset_ms"], 1200);

    // The control opened again lists the delegation among those announced: it is not answered twice.
    scene.stand_in.control().drop_sockets();
    scene
        .stand_in
        .control()
        .until("a second socket", |report| report.upgrades.len() >= 2)
        .await;
    scene
        .stand_in
        .control()
        .until("the socket attached again", |report| report.open >= 1)
        .await;
    let answered = scene
        .stand_in
        .control()
        .report()
        .sent
        .iter()
        .filter(|sent| sent.delegation.as_deref() == Some("d-1"))
        .count();
    assert_eq!(answered, 1, "the model was told once");
    assert_eq!(
        scene.state()["delegations"].as_array().map(Vec::len),
        Some(1)
    );
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.host.stop().await;
}

/// Muting the microphone is native code's, and the service is told as advice to the provider.
/// Silencing the model's voice is native code's alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn muting_the_microphone_silences_it_here_and_tells_the_service() {
    let scene = scene().await;
    scene.start().await;
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;

    let muted = scene
        .call(
            "voice_set_muted",
            json!({ "what": "microphone", "muted": true }),
        )
        .expect("the microphone is muted");
    assert_eq!(muted["capture"], "muted_by_person");
    assert!(
        scene
            .platform
            .commands()
            .contains(&"mute:Microphone:true".to_owned())
    );
    scene
        .stand_in
        .control()
        .until("the service was told", |report| {
            report
                .frames
                .iter()
                .any(|frame| frame.contains(r#""command":"mute""#))
        })
        .await;

    let silenced = scene
        .call(
            "voice_set_muted",
            json!({ "what": "playback", "muted": true }),
        )
        .expect("the voice is silenced");
    assert_eq!(silenced["playing"], false);
    let tellings = commands_sent(&scene);
    assert_eq!(
        tellings
            .iter()
            .filter(|command| command.as_str() == "mute")
            .count(),
        1,
        "only the microphone's mute is advice to the provider: {tellings:?}"
    );
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.host.stop().await;
}

/// The host decides where a call's control is, and the account's token goes only where the
/// account is signed in. A host that names another service gets none: no socket is opened at the
/// service it named, the call is ended in full, and the person is told why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_names_another_voice_service_gets_no_token() {
    // The phone's account is signed in at a service that is not the one the host names.
    let scene = scene_with(
        quick(),
        Some(phone_grant(PHONE_TOKEN, 3600)),
        Some("http://127.0.0.1:9"),
    )
    .await;
    let prepared = scene.prepared().await;

    let refused = scene
        .call("voice_start", scene.start_request(&prepared))
        .expect_err("the call cannot be controlled at the service the host named");

    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|words| words.contains("voice service other than")),
        "{refused}"
    );
    assert!(
        scene.stand_in.control().report().upgrades.is_empty()
            && scene.stand_in.upgrades_turned_away() == 0,
        "no socket was opened at the service the host named"
    );
    let ended = scene
        .state_where("the end", |state| {
            state["ended"]["cause"] == "foreign_service"
        })
        .await;
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    assert!(scene.platform.count("stop") >= 1);
    assert_eq!(
        scene.stand_in.count("/api/voice/sessions/call-1/close"),
        1,
        "the host closed the call it created"
    );
    scene.host.stop().await;
}

/// Native code that does not return from a stop never holds the host's revocation: the host is
/// asked all the same, and the person is told that the media may not have stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_native_code_never_returns_does_not_hold_the_revocation() {
    let timings = Timings {
        local_within: Duration::from_millis(300),
        ..quick()
    };
    let scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;
    scene.platform.never_return_from_a_stop();

    let closure = scene
        .call("voice_stop", json!({ "voiceSessionId": null }))
        .expect("the call ends");

    assert_eq!(
        closure["closed_locally"], false,
        "native code did not return"
    );
    assert_eq!(
        closure["fence"]["kind"], "not_owed",
        "the host revoked the grant"
    );
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    scene.host.stop().await;
}

/// A page that is loaded again holds nothing of the call it left, and finds it where it is kept:
/// the state names the call, and a stop that names none ends the call this device holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_that_is_loaded_again_finds_the_call_and_ends_it() {
    let scene = scene().await;
    let started = scene.start().await;
    let voice_session_id =
        started["value"]["outcome"]["started"]["session"]["voice_session_id"].clone();

    // A page that starts anew asks what the device holds.
    let found = scene.state();
    assert_eq!(found["running"], true);
    assert_eq!(found["session"]["voice_session_id"], voice_session_id);
    assert_eq!(found["session"]["answer_sdp"], "");

    let closure = scene
        .call("voice_stop", json!({ "voiceSessionId": null }))
        .expect("the call ends");
    assert_eq!(closure["closed_locally"], true);
    assert_eq!(scene.state()["running"], false);
    scene.host.stop().await;
}

/// Native code that stops answering the owner's signs of life is not holding a call the owner can
/// still end: after a few signs unanswered the call is ended, with the host asked to revoke.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_code_that_stops_answering_ends_the_call() {
    let scene = scene().await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;

    scene.platform.refuse_signs_as(FailureKind::Unavailable);

    let ended = scene
        .state_where("the end", |state| {
            state["ended"]["cause"] == "native_silent"
        })
        .await;
    assert!(scene.platform.count("alive") >= 3);
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    scene.host.stop().await;
}

/// The account is signed out during the call: the call is not carried on under no account, and is
/// ended in full.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signing_out_during_a_call_ends_it() {
    let scene = scene().await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;

    scene.tokens.sign_out().await.expect("the phone signs out");

    let ended = scene
        .state_where("the end", |state| {
            state["ended"]["cause"] == "account_changed"
        })
        .await;
    assert_eq!(ended["ended"]["host"]["kind"], "revoked");
    assert!(scene.platform.count("stop") >= 1);
    scene.host.stop().await;
}

/// The host connection is lost during the call. The call goes on, and the model is told by a fixed
/// sentence. When a connection to the host is made again, the host's refusal to say that the call
/// is still its own (this one names a session the host never held) is not taken for its return:
/// the screen is told so in words, still says the host is lost, and the model is told nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_is_lost_is_told_to_the_model_and_a_refusal_is_not_its_return() {
    let scene = scene().await;
    scene.start().await;
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    let instructions = |scene: &Scene| {
        scene
            .stand_in
            .control()
            .report()
            .sent
            .iter()
            .filter(|sent| sent.command == "instructions")
            .count()
    };
    assert_eq!(instructions(&scene), 1, "told once what this version does");

    // The connection to the host ends.
    scene
        .phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("a connection")
        .session()
        .close();

    scene
        .stand_in
        .control()
        .until("the sentence for a lost host", |report| {
            report
                .sent
                .iter()
                .filter(|sent| sent.command == "instructions")
                .count()
                >= 2
        })
        .await;
    let refused = scene
        .state_where("the host's refusal", |state| state["warning"].is_string())
        .await;
    assert_eq!(refused["host"], "lost", "a refusal is not a return");
    assert_eq!(refused["running"], true, "the call went on");
    assert_eq!(
        instructions(&scene),
        2,
        "the model was told once of the loss"
    );
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.host.stop().await;
}
