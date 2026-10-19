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
//! | The native session ending revokes the call's grant in the host's store before the service finalises the call | `ending_the_native_session_revokes_the_voice_grant_before_the_service_finalises_the_call` |
//! | A stop that never returns does not hold the host's revocation | `a_stop_native_code_never_returns_does_not_hold_the_revocation` |
//! | The host's revocation does not wait for native code's stop | `the_hosts_revocation_does_not_wait_for_native_code_to_stop_the_media` |
//! | A stop that names the call during its setup reaches its owner | `a_stop_that_names_the_call_during_its_setup_ends_that_call` |
//! | A stop that names another call ends nothing that is held | `a_stop_that_names_another_call_ends_nothing_that_is_held` |
//! | A start whose answer was lost continues under the answer a repeat brings | `a_start_whose_answer_is_lost_continues_under_the_answer_a_repeat_brings` |
//! | A start the host never answers is unknown, stays owed, and a stop during the repeats revokes what they find | `a_start_the_host_never_answers_is_unknown_and_stays_owed`, `a_stop_during_the_repeats_stops_the_media_and_revokes_what_the_repeats_find` |
//! | A host that is forgotten, a host that is changed and a device the host revokes each end the call | `forgetting_the_host_ends_the_call_and_owes_the_revocation`, `choosing_another_host_ends_the_call`, `a_device_the_host_revokes_loses_the_call_it_holds` |
//! | A call the host cannot be told about is closed at the service over its own route | `a_call_the_host_cannot_be_told_about_is_closed_at_the_service_over_its_own_route` |
//! | An owner that fails ends the call it held, in full | `an_owner_that_fails_ends_the_call_it_held_in_full` |
//! | A file of what a call left owed that the system refuses to read at first is read again when the host is reached, and is not written over before | `a_record_the_system_refused_to_read_is_read_again_when_the_host_is_reached`, `a_record_the_system_refused_to_read_is_not_written_over_and_is_taken_up_with_what_this_launch_added` |
//! | What a launch owes and forgets while the record cannot be read is taken up after what the file held, and the file's note is forgotten when this launch's control attached | `a_record_the_system_refused_to_read_is_taken_up_in_order_with_what_this_launch_owes_and_forgot` |
//! | A named stop that finds the host revoked the grant settles the entry a file held that was unread until the unlock | `a_named_stop_after_the_unlock_settles_the_entry_the_file_held` |
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
use companion_tauri::voice::{Calls, Kept, Service, Timings};
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

/// The time now, in milliseconds since the epoch.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_millis(),
    )
    .expect("a moment that fits")
}

/// A moment in milliseconds as the page is given it, whether it arrives as a number or a string.
fn milliseconds(value: &serde_json::Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .unwrap_or_else(|| panic!("not a moment: {value}"))
}

/// The document an operator writes to name the voice service.
fn document_naming(origin: &str) -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = Nullable::some(origin.to_owned());
    document
}

/// The voice service at `origin`, reached the way the application reaches it.
fn service_at(origin: &str) -> Service {
    Service {
        origin: origin.to_owned(),
        http: Arc::new(
            HttpService::with(
                kr_protocol::service::GatewayOrigin::new(origin).expect("an origin"),
                HttpDeadlines::default(),
                managed_response_limits(),
            )
            .expect("a transport"),
        ),
        connector: ControlConnector::platform().expect("a connector"),
    }
}

/// Everything one test holds.
struct Scene {
    /// The daemon, until a test stops it.
    host: Option<Host>,
    stand_in: StandIn,
    platform: Arc<ScriptedCalls>,
    phone: Phone,
    tokens: Arc<SignedInAccount>,
    service: Arc<PhoneService>,
    session: String,
}

impl Scene {
    fn host(&self) -> &Host {
        self.host.as_ref().expect("the host is running")
    }

    /// Stops the daemon, once.
    async fn stop_host(&mut self) {
        if let Some(host) = self.host.take() {
            host.stop().await;
        }
    }

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
        kr_protocol::service::GatewayOrigin::new(stand_in.origin()).expect("an origin"),
        Arc::new(NoCarrier),
        Arc::new(|_| {}),
    ));
    let platform = ScriptedCalls::new();
    let data = tempfile::tempdir().expect("a directory");
    let calls = Calls::on_phone(
        Arc::clone(&platform) as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(account_origin.unwrap_or_else(|| stand_in.origin())),
        timings,
        Kept::at(data.path()),
    );

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
        host: Some(host),
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
    let mut scene = scene().await;

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
    scene.stop_host().await;
}

/// A device with no account token for the voice scope could not control a call, and the service
/// closes a call nobody controls, so nothing is created or asked: no call is opened on the device
/// and the host is not asked to start one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_no_voice_token_starts_nothing() {
    let mut scene = scene_with(quick(), None, None).await;
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
    let state = scene.state();
    assert_eq!(state["running"], false);
    // A screen loaded again finds how the start ended, in the words its asker was given.
    assert_eq!(state["ended"]["cause"], "not_started", "{state}");
    assert_eq!(state["ended"]["words"], refused["message"], "{state}");
    scene.stop_host().await;
}

/// A token that has run out is replaced before the start, so a start never finds out at the
/// control that its token is old, and the control presents the one the refresh issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_token_is_refreshed_before_the_start_and_the_control_presents_the_new_one() {
    let mut scene = scene_with(quick(), Some(phone_grant(PHONE_TOKEN, 1)), None).await;
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
    scene.stop_host().await;
}

/// A device whose account is not the one the call was started under finds the service has no such
/// call for it: the call is ended in full (the media, the host's grant, the service), the person
/// is told why in words, and a warning stands before the next start without blocking it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_of_another_account_ends_the_call_and_a_warning_stands_before_the_next() {
    let mut scene = scene().await;
    scene.stand_in.treat_as_another_account(PHONE_TOKEN);
    assert_eq!(scene.state()["warning"], serde_json::Value::Null);

    let started = scene.start().await;
    assert!(started["value"]["outcome"]["started"].is_object());

    // The device is busy with a call until it has finished ending it: it says so by what it is
    // doing, and another start is refused until then.
    let ended = scene
        .state_where("a call that ended", |state| {
            state["ended"]["cause"] == "no_such_call" && state["setting_up"] == false
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
    scene.stop_host().await;
}

/// A control whose token the service does not accept, after the host created the call, closes the
/// call: the media stops, the host revokes the grant and closes the call at the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_control_that_is_not_authorised_closes_the_call_the_host_started() {
    let mut scene = scene().await;
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
    scene.stop_host().await;
}

/// The notification's stop is native code's own end of the call. No page is looking, and the call
/// is ended in full all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_notifications_stop_ends_the_call_with_no_page() {
    let mut scene = scene().await;
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
    scene.stop_host().await;
}

/// KR-REQ-15.14: ending the native session revokes the call's voice grant at once, in the host's own
/// store, whatever the voice service has done about the call. Native code ends the call by itself.
/// The service holds both ways the call is closed at it: the host's close over HTTP and the phone's
/// close over its control, and answers neither. The grant is revoked by the time the host's close
/// has reached the service, so nothing of the call has been finalised when the authority ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ending_the_native_session_revokes_the_voice_grant_before_the_service_finalises_the_call() {
    let mut scene = scene().await;
    let started = scene.start().await;
    let grant_id: kr_protocol::ids::GrantId = serde_json::from_value(
        started["value"]["outcome"]["started"]["session"]["grant_id"].clone(),
    )
    .expect("the grant the call runs under");
    let revoked_in_the_hosts_store = |scene: &Scene| {
        scene
            .host()
            .controller()
            .sharing()
            .grants()
            .record(grant_id)
            .expect("the store answers")
            .expect("the record is there")
            .revoked_at_ms
            .is_some()
    };
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;
    assert!(
        !revoked_in_the_hosts_store(&scene),
        "the call's grant stands while the call runs"
    );

    scene.stand_in.hold_closes();
    scene.stand_in.control().hold_closures(true);
    scene.platform.tell(CallEvent::Ended);

    // The host has told the service the call is over, with its own token, and the service holds
    // that close; the control's closure is held too, so nothing has been finalised. The grant is
    // revoked all the same.
    let hosts_token = format!("Bearer {}", voice_support::HOST_TOKEN);
    tokio::time::timeout(WATCHDOG, async {
        while !scene.stand_in.seen().iter().any(|request| {
            request.path == "/api/voice/sessions/call-1/close"
                && request.authorization.as_deref() == Some(hosts_token.as_str())
        }) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the host told the service the call ended");
    assert!(
        revoked_in_the_hosts_store(&scene),
        "the grant is revoked in the host's store while the service has answered neither close"
    );

    scene.stand_in.control().hold_closures(false);
    scene.stand_in.release_closes();
    let ended = scene
        .state_where("the end", |state| state["ended"]["cause"] == "native_ended")
        .await;
    assert_eq!(ended["running"], false);
    scene.stop_host().await;
}

/// A connection that fails ends the call the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_connection_ends_the_call_with_no_page() {
    let mut scene = scene().await;
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
    assert_eq!(
        ended["ended"]["closed_locally"], true,
        "native code ended the call itself, so its media is stopped: {ended}"
    );
    scene.stop_host().await;
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
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
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
    scene.stop_host().await;
}

/// A sign of life that native code answers as a call that has ended ends the call, whether or not
/// its news said so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_of_life_native_code_refuses_as_ended_ends_the_call() {
    let mut scene = scene().await;
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
    scene.stop_host().await;
}

/// The provider announces a delegation, and this version acts on nothing a person says: the model
/// is told once that nothing was done, whatever the control says again, and the page is given a
/// row that says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegation_is_answered_to_the_model_that_nothing_was_done_once() {
    let mut scene = scene().await;
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
    // The news of the second socket is read in order, so once a delegation announced on it is
    // answered the device has read what the socket listed at its attachment, d-1 among it.
    scene.stand_in.control().announce("d-2", 2400);
    scene
        .state_where("the second delegation answered", |state| {
            state["delegations"][1]["told"] == true
        })
        .await;
    let answered = |delegation: &str| {
        scene
            .stand_in
            .control()
            .report()
            .sent
            .iter()
            .filter(|sent| sent.delegation.as_deref() == Some(delegation))
            .count()
    };
    assert_eq!(answered("d-1"), 1, "the model was told once");
    assert_eq!(answered("d-2"), 1);
    assert_eq!(
        scene.state()["delegations"].as_array().map(Vec::len),
        Some(2)
    );
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.stop_host().await;
}

/// A delegation the voice service lists when the control attaches was announced before this device
/// was listening, and the service gives no offset for it: the row has none, rather than saying it
/// was asked at the start of the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegation_listed_when_the_control_attaches_has_no_offset() {
    let mut scene = scene().await;
    scene.stand_in.control().list(vec!["d-0".to_owned()]);
    scene.start().await;

    let row = scene
        .state_where("the listed delegation answered", |state| {
            state["delegations"][0]["told"] == true
        })
        .await;

    assert_eq!(row["delegations"][0]["delegation_id"], "d-0");
    assert!(row["delegations"][0]["offset_ms"].is_null(), "{row}");
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.stop_host().await;
}

/// Muting the microphone is native code's, and the service is told as advice to the provider.
/// Silencing the model's voice is native code's alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn muting_the_microphone_silences_it_here_and_tells_the_service() {
    let mut scene = scene().await;
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
    scene.stop_host().await;
}

/// The host decides where a call's control is, and the account's token goes only where the
/// account is signed in. A host that names another service gets none: no socket is opened at the
/// service it named, the call is ended in full, and the person is told why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_names_another_voice_service_gets_no_token() {
    // The phone's account is signed in at a service that is not the one the host names.
    let mut scene = scene_with(
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
    scene.stop_host().await;
}

/// The host is asked to revoke while native code is still stopping the media: its revocation is not
/// held behind the stop, and the stop is not held behind the host. The service has been told the
/// call is over while native code has not returned, and the person's answer comes when both are
/// done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hosts_revocation_does_not_wait_for_native_code_to_stop_the_media() {
    let mut scene = scene().await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;
    scene.platform.hold("stop");
    let _holding = scene.platform.release_when_done("stop");

    let stopping = scene
        .phone
        .companion
        .start_call("voice_stop", json!({ "voiceSessionId": null }));
    tokio::time::timeout(WATCHDOG, async {
        while scene.stand_in.count("/api/voice/sessions/call-1/close") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the host revoked and told the service while native code was still stopping");
    assert!(
        !stopping.is_finished(),
        "native code has not returned from its stop"
    );

    scene.platform.release("stop");
    let closure = stopping
        .await
        .expect("the stop ran")
        .expect("the call ends");
    assert_eq!(closure["closed_locally"], true);
    assert_eq!(closure["fence"]["kind"], "not_owed");
    scene.stop_host().await;
}

/// Native code that does not return from a stop never holds the host's revocation: the host is
/// asked all the same, and the person is told that the media may not have stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_native_code_never_returns_does_not_hold_the_revocation() {
    let timings = Timings {
        local_within: Duration::from_millis(300),
        ..quick()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
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
    scene.stop_host().await;
}

/// A page that is loaded again holds nothing of the call it left, and finds it where it is kept:
/// the state names the call, and a stop that names none ends the call this device holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_that_is_loaded_again_finds_the_call_and_ends_it() {
    let mut scene = scene().await;
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
    scene.stop_host().await;
}

/// Native code that stops answering the owner's signs of life is not holding a call the owner can
/// still end: after a few signs unanswered the call is ended, with the host asked to revoke.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_code_that_stops_answering_ends_the_call() {
    let mut scene = scene().await;
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
    scene.stop_host().await;
}

/// The account is signed out during the call: the call is not carried on under no account, and is
/// ended in full.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signing_out_during_a_call_ends_it() {
    let mut scene = scene().await;
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
    scene.stop_host().await;
}

/// The host connection is lost during the call. The call goes on, and the model is told by a fixed
/// sentence. When a connection to the host is made again, the host's refusal to say that the call
/// is still its own (this one names a session the host never held) is not taken for its return:
/// the screen is told so in words, still says the host is lost, and the model is told nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_is_lost_is_told_to_the_model_and_a_refusal_is_not_its_return() {
    let mut scene = scene().await;
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
    scene.stop_host().await;
}

/// A page that names the call while it is still being set up reaches the call's owner: the call is
/// given up before native code is permitted, and the media never carries the person's voice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_that_names_the_call_during_its_setup_ends_that_call() {
    let mut scene = scene().await;
    let prepared = scene.prepared().await;
    scene.platform.hold("permit");
    let _holding = scene.platform.release_when_done("permit");
    let starting = scene
        .phone
        .companion
        .start_call("voice_start", scene.start_request(&prepared));
    tokio::time::timeout(WATCHDOG, async {
        while scene.platform.count("permit") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native code was asked to permit the call");

    // The host has created the call, and the screen can read which call it is.
    let setting_up = scene.state();
    let voice_session_id = setting_up["session"]["voice_session_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the state names the call being set up: {setting_up}"))
        .to_owned();
    assert_eq!(setting_up["running"], false, "{setting_up}");

    let closure = scene
        .call("voice_stop", json!({ "voiceSessionId": voice_session_id }))
        .expect("the call is given up");

    assert_eq!(closure["closed_locally"], true);
    assert_eq!(
        closure["fence"]["kind"], "not_owed",
        "the host revoked: {closure}"
    );
    assert!(scene.platform.permitted_for().is_none(), "never permitted");
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    let refused = starting
        .await
        .expect("the start ran")
        .expect_err("a call given up is not a call started");
    assert_eq!(refused["code"], "RESOURCE_UNAVAILABLE", "{refused}");
    assert_eq!(scene.state()["running"], false);
    scene.platform.release("permit");
    scene.stop_host().await;
}

/// A stop that names a call this device does not hold is the host's to answer: it ends nothing of
/// the call that is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_that_names_another_call_ends_nothing_that_is_held() {
    let mut scene = scene().await;
    scene.start().await;
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;

    let other = kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid()).to_string();
    let closure = scene
        .call("voice_stop", json!({ "voiceSessionId": other }))
        .expect("the host is asked about the call it was named");

    assert_eq!(closure["closed_locally"], false);
    assert_eq!(scene.state()["running"], true, "the held call goes on");
    assert_eq!(scene.platform.count("stop"), 0);
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.stop_host().await;
}

/// Timings for a start whose answer is cut at once, so the device asks again.
/// A screen that is loaded again while the device is making a call, before the host has said
/// whether it made one, finds a device that is setting a call up, with no call to name. The screen
/// ends what the device is making without naming it: the media stops and the stop is answered at
/// once, while the host is still answering the start, and the call the host then turns out to have
/// made is ended in full.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_screen_loaded_again_while_a_call_is_being_made_finds_it_and_ends_it() {
    let timings = Timings {
        host_within: Duration::from_secs(3),
        ..quick()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    scene.platform.hold("open");
    let _holding = scene.platform.release_when_done("open");
    scene.stand_in.hold_creations();
    let prepared = scene.prepared().await;
    let starting = scene
        .phone
        .companion
        .start_call("voice_start", scene.start_request(&prepared));
    tokio::time::timeout(WATCHDOG, async {
        while scene.platform.count("open") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native code was asked to open the call");

    // The microphone question is still being asked: nothing runs, and there is no call to name.
    let asking = scene.state();
    assert_eq!(asking["setting_up"], true, "{asking}");
    assert_eq!(asking["running"], false, "{asking}");
    assert!(asking["session"].is_null(), "{asking}");

    scene.platform.release("open");
    tokio::time::timeout(WATCHDOG, async {
        while scene.stand_in.count("/api/voice/sessions") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the host asked the service for the call");
    let waiting = scene.state();
    assert_eq!(waiting["setting_up"], true, "{waiting}");
    assert_eq!(
        waiting["ending"], false,
        "nothing is being ended yet: {waiting}"
    );
    assert!(
        waiting["session"].is_null(),
        "the host has not said whether it made a call: {waiting}"
    );

    let closure = tokio::time::timeout(
        WATCHDOG,
        scene
            .phone
            .companion
            .start_call("voice_stop", json!({ "voiceSessionId": null })),
    )
    .await
    .expect("the stop is answered while the host is still answering the start")
    .expect("the stop ran")
    .expect("the stop is answered");
    assert_eq!(closure["closed_locally"], true, "{closure}");
    assert!(scene.platform.count("stop") >= 1, "the media stopped");
    // The device is still busy with the call the host may have made, and says it is ending it: a
    // screen loaded now offers no start and no second end, and a second end is told why.
    let ending = scene.state();
    assert_eq!(ending["setting_up"], true, "{ending}");
    assert_eq!(ending["ending"], true, "{ending}");
    let again = scene
        .call("voice_stop", json!({ "voiceSessionId": null }))
        .expect_err("there is nothing more to ask of a call that is being ended");
    assert!(
        again["message"]
            .as_str()
            .is_some_and(|words| words.contains("already ending")),
        "{again}"
    );

    // The host finishes the call it was making, and the call is ended in full.
    scene.stand_in.release_creations();
    starting
        .await
        .expect("the start ran")
        .expect_err("a call given up is not a call started");
    let ended = scene
        .state_where("the call the host made, ended", |state| {
            state["setting_up"] == false && state["ended"]["host"]["kind"] == "revoked"
        })
        .await;
    assert_eq!(ended["ended"]["cause"], "requested", "{ended}");
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    scene.stop_host().await;
}

/// The device's open fails after native code made the call, and the person's stop was already
/// waiting. The stop is told what became of the media: native code did not return from its stop, so
/// the media is not known to be stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_waiting_during_a_failed_open_is_told_whether_the_media_stopped() {
    let timings = Timings {
        local_within: Duration::from_millis(1500),
        ..quick()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    scene.platform.hold("open");
    let _holding = scene.platform.release_when_done("open");
    scene.platform.fail_the_open_after_making_the_call();
    scene.platform.never_return_from_a_stop();
    let prepared = scene.prepared().await;
    let starting = scene
        .phone
        .companion
        .start_call("voice_start", scene.start_request(&prepared));
    tokio::time::timeout(WATCHDOG, async {
        while scene.platform.count("open") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native code was asked to open the call");

    // The open fails; the owner stops what native code made, and that stop does not return.
    scene.platform.release("open");
    tokio::time::timeout(WATCHDOG, async {
        while scene.platform.count("stop") == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the owner stopped the call native code made");
    let closure = tokio::time::timeout(
        WATCHDOG,
        scene
            .phone
            .companion
            .start_call("voice_stop", json!({ "voiceSessionId": null })),
    )
    .await
    .expect("the stop is answered")
    .expect("the stop ran")
    .expect("the stop is answered");

    assert_eq!(
        closure["closed_locally"], false,
        "native code did not return from its stop: {closure}"
    );
    starting
        .await
        .expect("the start ran")
        .expect_err("a call that could not be opened is not a call started");
    // A screen loaded again finds how the start ended, and that the media is not known to be
    // stopped.
    let state = scene.state();
    assert_eq!(state["ended"]["cause"], "not_started", "{state}");
    assert_eq!(state["ended"]["closed_locally"], false, "{state}");
    scene.stop_host().await;
}

/// The device's open fails after native code made the call, and what native code holds cannot be
/// read, so the call it may hold cannot be stopped. A stop that waited is told the media is not
/// known to be stopped, as it is when native code does not return from its own stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_waiting_during_a_failed_open_whose_state_cannot_be_read_is_told_it_is_unconfirmed()
{
    let mut scene = scene().await;
    scene.platform.hold("open");
    let _holding = scene.platform.release_when_done("open");
    scene.platform.fail_the_open_after_making_the_call();
    scene.platform.fail_reads_of_what_is_held();
    let prepared = scene.prepared().await;
    let starting = scene
        .phone
        .companion
        .start_call("voice_start", scene.start_request(&prepared));
    tokio::time::timeout(WATCHDOG, async {
        while scene.platform.count("open") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native code was asked to open the call");
    let stopping = scene
        .phone
        .companion
        .start_call("voice_stop", json!({ "voiceSessionId": null }));
    // The stop is queued behind the open the owner is waiting for.
    tokio::time::sleep(Duration::from_millis(200)).await;
    scene.platform.release("open");

    let closure = tokio::time::timeout(WATCHDOG, stopping)
        .await
        .expect("the stop is answered")
        .expect("the stop ran")
        .expect("the stop is answered");

    assert_eq!(
        closure["closed_locally"], false,
        "what native code holds could not be read: {closure}"
    );
    starting
        .await
        .expect("the start ran")
        .expect_err("a call that could not be opened is not a call started");
    scene.stop_host().await;
}

fn asking_again() -> Timings {
    Timings {
        start_within: Duration::ZERO,
        repeat_delays: [Duration::from_millis(20); 3],
        host_within: Duration::from_secs(3),
        ..quick()
    }
}

/// The host's answer to a start never arrives, as a connection that ends between the host's
/// reading and its answer would leave it. The device asks again under the same action, the host
/// answers from what it kept, and the call goes on as the one that was started: one creation at
/// the service, one opening of the call here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_whose_answer_is_lost_continues_under_the_answer_a_repeat_brings() {
    let mut scene = scene_with(asking_again(), Some(phone_grant(PHONE_TOKEN, 3600)), None).await;

    let started = scene.start().await;

    assert!(
        started["value"]["outcome"]["started"].is_object(),
        "the call the host made is the call that runs: {started}"
    );
    scene
        .state_where("a running call", |state| {
            state["running"] == true && state["control"] == "connected"
        })
        .await;
    assert_eq!(scene.stand_in.count("/api/voice/sessions"), 1);
    assert_eq!(scene.platform.count("open"), 1);
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.stop_host().await;
}

/// The host never says whether it made the call. The person is told so, with the action the start
/// was sent under, the media is stopped, and the revocation the host may be owed stays on the
/// screen after the next call opens, until the moment the call would have closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_the_host_never_answers_is_unknown_and_stays_owed() {
    let timings = Timings {
        host_within: Duration::from_millis(300),
        ..asking_again()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    scene.stand_in.hold_creations();

    let asked_at = now_ms();
    let started = scene.start().await;

    assert!(
        started["value"].is_null(),
        "no call was reported: {started}"
    );
    let action_id = started["action_id"]
        .as_str()
        .expect("the start names its action")
        .to_owned();
    let state = scene.state();
    assert_eq!(state["running"], false);
    assert_eq!(state["ended"]["cause"], "start_unknown", "{state}");
    assert_eq!(state["ended"]["closed_locally"], true);
    assert_eq!(state["ended"]["host"]["kind"], "not_told");
    // The service may hold a call this device cannot name, so it is not "not needed".
    assert_eq!(state["ended"]["broker"], "unknown", "{state}");
    assert!(scene.platform.count("stop") >= 1, "the media is stopped");
    assert_eq!(state["owed"][0]["kind"], "start_unknown", "{state}");
    assert_eq!(state["owed"][0]["action_id"], action_id.as_str());
    // The host could still admit the request until its action window ended, which is later than
    // the time it was sent at, so a call it made ends later than a record counted from the send
    // would say: the window's remaining validity (five minutes less the time since it was issued),
    // the call's length and the clock allowance.
    assert!(
        milliseconds(&state["owed"][0]["until_ms"]) >= asked_at + 240_000 + 600_000 + 120_000,
        "{state}"
    );

    // The record outlives the next call's opening, whatever that call comes to.
    scene.stand_in.release_creations();
    let prepared = scene.prepared().await;
    let _ = scene.call("voice_start", scene.start_request(&prepared));
    let later = scene.state();
    assert_eq!(later["owed"][0]["action_id"], action_id.as_str(), "{later}");
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.stop_host().await;
}

/// The person presses stop while the device is still asking the host what became of its start. The
/// media stops at once and the stop is answered, and the device goes on asking: when the host turns
/// out to have made the call, the call is ended in full and the host's grant is revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_during_the_repeats_stops_the_media_and_revokes_what_the_repeats_find() {
    let timings = Timings {
        start_within: Duration::ZERO,
        repeat_delays: [
            Duration::from_millis(50),
            Duration::from_millis(50),
            Duration::from_secs(4),
        ],
        host_within: Duration::from_millis(300),
        ..quick()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    scene.stand_in.hold_creations();
    let prepared = scene.prepared().await;
    let starting = scene
        .phone
        .companion
        .start_call("voice_start", scene.start_request(&prepared));
    tokio::time::timeout(WATCHDOG, async {
        while scene.stand_in.count("/api/voice/sessions") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the host asked the service for the call");

    let closure = scene
        .call("voice_stop", json!({ "voiceSessionId": null }))
        .expect("the stop is answered at once");
    assert_eq!(closure["closed_locally"], true);
    assert!(
        closure["host_failure"].is_object(),
        "the host has not said whether it made the call: {closure}"
    );
    assert!(scene.platform.count("stop") >= 1, "the media stopped");

    // The host finishes the call it was making, and a repeat finds it.
    scene.stand_in.release_creations();
    starting
        .await
        .expect("the start ran")
        .expect_err("a call given up is not a call started");
    let ended = scene
        .state_where("the call the repeats found, ended", |state| {
            state["ended"]["host"]["kind"] == "revoked"
        })
        .await;
    assert_eq!(ended["ended"]["cause"], "requested", "{ended}");
    assert_eq!(ended["ended"]["closed_locally"], true);
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    assert!(scene.platform.permitted_for().is_none(), "never permitted");
    scene.stop_host().await;
}

/// The person forgets the host the call belongs to, while the call runs and the host cannot be
/// reached. This device no longer holds the pairing, so the call is ended, and what it could not
/// tell the host is owed: the grant may be live until the moment the call was to close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forgetting_the_host_ends_the_call_and_owes_the_revocation() {
    let timings = Timings {
        host_within: Duration::from_secs(3),
        ..quick()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    let started = scene.start().await;
    let voice_session_id =
        started["value"]["outcome"]["started"]["session"]["voice_session_id"].clone();
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    let reference = scene
        .call("pairing_view", json!({}))
        .expect("the pairing screen")["hosts"][0]["reference"]
        .clone();
    // The voice service confirms the closure late, as a busy one does: the end is reported while the
    // device waits for it, and the closure is shown a moment after.
    scene
        .stand_in
        .control()
        .confirm_closures_after(Duration::from_secs(2));
    // The host goes away, and the person forgets it before it is back.
    scene.stop_host().await;
    scene
        .state_where("a host that is lost", |state| state["host"] == "lost")
        .await;

    scene
        .call("hosts_forget", json!({ "reference": reference }))
        .expect("the host is forgotten");

    let ended = scene
        .state_where("the end", |state| {
            state["ended"]["cause"] == "host_forgotten"
        })
        .await;
    assert_eq!(ended["running"], false);
    assert!(scene.platform.count("stop") >= 1);
    assert_eq!(ended["ended"]["host"]["kind"], "not_told", "{ended}");
    assert_eq!(ended["owed"][0]["kind"], "revocation", "{ended}");
    assert_eq!(
        ended["owed"][0]["voice_session_id"], voice_session_id,
        "{ended}"
    );
    // The entry says which host it is owed to, by the reference the page lists that host by.
    assert_eq!(ended["owed"][0]["host_reference"], reference, "{ended}");
    assert!(
        ended["owed"][0]["host_name"]
            .as_str()
            .is_some_and(|name| !name.is_empty()),
        "{ended}"
    );
    // It stands until the moment the host's grant ends by itself, with room for a clock that is not
    // this device's own: the host's closing time is the host's reading.
    let closes = milliseconds(&started["value"]["outcome"]["started"]["session"]["closes_at_ms"]);
    assert_eq!(
        milliseconds(&ended["owed"][0]["until_ms"]),
        closes + 120_000,
        "{ended}"
    );
    // The host cannot tell the voice service, so the device does, by the call's own control. The end
    // is reported while the service's closure is awaited, so the closure is waited for.
    scene
        .state_where("the closure at the service", |state| {
            state["ended"]["broker"] == "closed"
        })
        .await;
    assert!(commands_sent(&scene).contains(&"close".to_owned()));
}

/// The host created the call, and cannot be told it is over: it is gone before the device finishes
/// setting the call up. The call is ended all the same, the revocation is owed, and the voice
/// service is told over its own route, with the account's token, because nothing else can: no
/// control was opened for the call and the host cannot tell it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_the_host_cannot_be_told_about_is_closed_at_the_service_over_its_own_route() {
    let timings = Timings {
        host_within: Duration::from_secs(3),
        ..quick()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    scene.platform.hold("permit");
    let _holding = scene.platform.release_when_done("permit");
    scene.platform.refuse_the_permit();
    let prepared = scene.prepared().await;
    let starting = scene
        .phone
        .companion
        .start_call("voice_start", scene.start_request(&prepared));
    tokio::time::timeout(WATCHDOG, async {
        while scene.platform.count("permit") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("native code was asked to permit the call");
    scene.stop_host().await;

    scene.platform.release("permit");

    starting
        .await
        .expect("the start ran")
        .expect_err("a call that could not be permitted is not a call started");
    let ended = scene
        .state_where("the end", |state| {
            state["ended"]["broker"] == "closed_over_http"
        })
        .await;
    assert_eq!(ended["ended"]["host"]["kind"], "not_told", "{ended}");
    assert_eq!(ended["owed"][0]["kind"], "revocation", "{ended}");
    assert_eq!(
        scene.stand_in.count("/api/voice/sessions/call-1/close"),
        1,
        "the service was told over its own route"
    );
}

/// The person chooses another host to browse while a call runs. The call belongs to the host that
/// made it, and a device does not carry a call for one host while it acts on another: the call is
/// ended, and the host it belongs to is asked to revoke.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn choosing_another_host_ends_the_call() {
    let mut scene = scene().await;
    let owner = DeviceKeys::generate().expect("owner keys");
    let other = Host::start(&owner).await;
    pair(&scene.phone, &other, &owner, &[ActionRight::SessionView]).await;
    scene.start().await;
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    let view = scene
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let another = view["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .find(|row| row["in_use"] == false)
        .and_then(|row| row["reference"].as_str())
        .expect("the host not in use")
        .to_owned();

    scene
        .call("hosts_use", json!({ "reference": another }))
        .expect("the other host is chosen");

    let ended = scene
        .state_where("the end", |state| state["ended"]["cause"] == "host_changed")
        .await;
    assert_eq!(ended["running"], false);
    assert_eq!(ended["ended"]["host"]["kind"], "revoked", "{ended}");
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    other.stop().await;
    scene.stop_host().await;
}

/// The identity `host` gave the one phone paired with it.
fn the_phone_of(host: &Host) -> kr_protocol::ids::DeviceId {
    let owner = host.owner.as_ref().map(|owner| owner.device_id);
    host.controller()
        .devices()
        .devices()
        .expect("the device directory answers")
        .into_iter()
        .find(|record| record.is_paired() && owner != Some(record.device_id))
        .expect("the paired phone")
        .device_id
}

/// The host revokes the phone while its call runs. Revocation is the host's act, so the host ends
/// what the device holds: its grant is withdrawn and the call is closed at the service, which
/// closes the control, and the phone ends the call by its ordinary path, with the media stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_the_host_revokes_loses_the_call_it_holds() {
    let mut scene = scene().await;
    scene.stand_in.end_the_control_when_a_call_is_closed();
    scene.start().await;
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;

    let mut client = scene.host().client().await;
    let _: kr_protocol::sharing::RevocationResult = net_support::pairing::mutate(
        scene.host().environment_id,
        &mut client,
        kr_protocol::method::Method::DeviceRevoke,
        &kr_protocol::sharing::DeviceRevokeParams {
            device_id: the_phone_of(scene.host()),
        },
    )
    .await
    .expect("the host revokes the phone");

    let ended = scene
        .state_where("the end", |state| {
            state["running"] == false && state["ended"].is_object()
        })
        .await;
    assert_eq!(ended["ended"]["cause"], "service_closed", "{ended}");
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    assert!(scene.platform.count("stop") >= 1, "the media stopped");
    scene.stop_host().await;
}

/// The host revokes a phone whose call the voice service is slow to close. The revocation is
/// answered while the service still holds the close, because the host ends what the device held on
/// a task of its own after the fence: a service that answers slowly holds neither the fence nor
/// the revocation's answer. The close that was still going on when the revocation was answered has
/// not failed by then (a revocation that waited for it would have been answered after the close
/// gave up and was reported as unclosed), and the call ends by the service's own closing, as it
/// does when the service is quick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_service_does_not_hold_the_answer_to_the_host_revoking_a_device() {
    let mut scene = scene().await;
    scene.stand_in.end_the_control_when_a_call_is_closed();
    scene.start().await;
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    scene.stand_in.hold_closes();
    let unclosed = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&unclosed);
    scene
        .host()
        .controller()
        .voice()
        .coordinator()
        .report_unclosed_calls_to(Arc::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
        }));

    let mut client = scene.host().client().await;
    let revoking = tokio::time::timeout(
        WATCHDOG,
        net_support::pairing::mutate::<_, kr_protocol::sharing::RevocationResult>(
            scene.host().environment_id,
            &mut client,
            kr_protocol::method::Method::DeviceRevoke,
            &kr_protocol::sharing::DeviceRevokeParams {
                device_id: the_phone_of(scene.host()),
            },
        ),
    )
    .await;
    // However it went, the service is let go of, so that nothing is left held.
    scene.stand_in.release_closes();
    revoking
        .expect("the revocation is answered while the service still holds the close")
        .expect("the host revokes the phone");
    assert_eq!(
        unclosed.load(Ordering::SeqCst),
        0,
        "the revocation was answered after the close gave up"
    );

    let ended = scene
        .state_where("the end", |state| {
            state["running"] == false && state["ended"].is_object()
        })
        .await;
    assert_eq!(ended["ended"]["cause"], "service_closed", "{ended}");
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    assert_eq!(unclosed.load(Ordering::SeqCst), 0, "the close succeeded");
    scene.stop_host().await;
}

/// Where a host reach that fails the way a bug does fails.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FailsAt {
    /// The first look at the pairing, which the owner takes at each tick of a running call.
    Pairing,
    /// The first reach for a connection to the host, which the owner takes when it asks what
    /// became of a start.
    Reaching,
    /// The first look at the host a call belongs to, which the owner takes before it asks
    /// native code for anything; it fails while `told` is not set, as the others do not.
    InUse,
}

/// A host reach that fails the way a bug does: the first time it is asked for what `at` names, once
/// it is told to (and for `InUse`, before it is told to), it panics, in the task that owns the
/// call.
struct FailsWhenTold {
    inner: companion_tauri::voice::AppReach<tauri::test::MockRuntime>,
    told: AtomicUsize,
    at: FailsAt,
}

impl companion_tauri::voice::HostReach for FailsWhenTold {
    fn in_use(
        &self,
    ) -> Result<companion_tauri::voice::CallHost, companion_tauri::error::CommandError> {
        assert!(
            self.at != FailsAt::InUse || self.told.load(Ordering::SeqCst) != 0,
            "the owner fails"
        );
        self.inner.in_use()
    }

    fn session_to<'a>(
        &'a self,
        host: &'a kr_client::pairing::paired::PairedHost,
        avoiding: Option<&'a Arc<kr_client::Session>>,
    ) -> companion_tauri::voice::Reaching<'a, Arc<kr_client::Session>> {
        assert!(
            self.at != FailsAt::Reaching || self.told.load(Ordering::SeqCst) == 0,
            "the owner fails"
        );
        self.inner.session_to(host, avoiding)
    }

    fn pairing(
        &self,
        host: &kr_client::pairing::paired::PairedHost,
    ) -> companion_tauri::voice::Pairing {
        assert!(
            self.at != FailsAt::Pairing || self.told.load(Ordering::SeqCst) == 0,
            "the owner fails"
        );
        self.inner.pairing(host)
    }

    fn another_host_in_use(&self, host: &kr_client::pairing::paired::PairedHost) -> bool {
        self.inner.another_host_in_use(host)
    }
}

/// What a start asks for, as the page asks for it.
fn request_of(scene: &Scene, prepared: &serde_json::Value) -> companion_tauri::voice::StartRequest {
    companion_tauri::voice::StartRequest {
        session_ids: vec![scene.session.parse().expect("a session")],
        duration_seconds: 600,
        reasoning_budget_minor: None,
        prepared: serde_json::from_value(prepared["prepared"].clone()).expect("a digest"),
        expected_rate_version: prepared["managed"]["rate"]["version"]
            .as_str()
            .map(str::to_owned),
        subject: companion_tauri::target::Subject::default(),
    }
}

/// A reach to the scene's host that fails where `at` says: once `told` is set, or, for `InUse`,
/// while it is not.
fn failing_reach(scene: &Scene, at: FailsAt, told: usize) -> Arc<FailsWhenTold> {
    Arc::new(FailsWhenTold {
        inner: companion_tauri::voice::AppReach::new(scene.phone.companion.app.handle().clone()),
        told: AtomicUsize::new(told),
        at,
    })
}

/// The task that owns a call fails. The call is not left running with nobody to end it: the
/// supervisor stops the media, asks the host to revoke the grant, closes the call at the service,
/// and says in the record that the owner failed. The next call starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_that_fails_ends_the_call_it_held_in_full() {
    let mut scene = scene().await;
    let prepared = scene.prepared().await;
    let reach = failing_reach(&scene, FailsAt::Pairing, 0);
    let calls = scene.phone.companion.app.state::<Calls>();
    let started = calls
        .start(
            request_of(&scene, &prepared),
            Arc::clone(&reach) as Arc<dyn companion_tauri::voice::HostReach>,
            Arc::clone(&scene.tokens),
        )
        .await
        .expect("a call starts");
    assert!(matches!(
        started,
        companion_tauri::voice::Started::Result(_)
    ));
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;

    reach.told.store(1, Ordering::SeqCst);

    let ended = scene
        .state_where("the owner's failure", |state| {
            state["ended"]["cause"] == "owner_failed" && state["setting_up"] == false
        })
        .await;
    assert_eq!(ended["running"], false);
    assert!(scene.platform.count("stop") >= 1, "the media is stopped");
    assert_eq!(ended["ended"]["host"]["kind"], "revoked", "{ended}");
    assert_eq!(ended["ended"]["closed_locally"], true);
    assert_eq!(scene.stand_in.count("/api/voice/sessions/call-1/close"), 1);
    // The slot is free: the next call starts.
    let again = scene.start().await;
    assert!(again["value"]["outcome"]["started"].is_object(), "{again}");
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.stop_host().await;
}

/// The owner fails after native code ended the call by itself: native code answers the stop that
/// ends the call as a call that has ended already, and that is a call whose media is stopped, as
/// the owner's own end reads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_that_fails_counts_a_call_native_code_already_ended_as_stopped() {
    let mut scene = scene().await;
    let prepared = scene.prepared().await;
    let reach = failing_reach(&scene, FailsAt::Pairing, 0);
    let calls = scene.phone.companion.app.state::<Calls>();
    calls
        .start(
            request_of(&scene, &prepared),
            Arc::clone(&reach) as Arc<dyn companion_tauri::voice::HostReach>,
            Arc::clone(&scene.tokens),
        )
        .await
        .expect("a call starts");
    scene
        .state_where("a running call", |state| state["running"] == true)
        .await;
    scene.platform.answer_a_stop_as_ended();

    reach.told.store(1, Ordering::SeqCst);

    let ended = scene
        .state_where("the owner's failure", |state| {
            state["ended"]["cause"] == "owner_failed"
        })
        .await;
    assert_eq!(ended["ended"]["closed_locally"], true, "{ended}");
    scene.stop_host().await;
}

/// The owner fails while it asks the host what became of a start whose answer was lost. The host
/// may have made a call, so the supervisor stops the media and keeps the start as owed, under the
/// action it was sent under, as the owner would have.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_that_fails_while_asking_what_became_of_a_start_leaves_the_start_owed() {
    let mut scene = scene_with(asking_again(), Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    scene.stand_in.hold_creations();
    let prepared = scene.prepared().await;
    let reach = failing_reach(&scene, FailsAt::Reaching, 1);
    let calls = scene.phone.companion.app.state::<Calls>();

    let refused = calls
        .start(
            request_of(&scene, &prepared),
            Arc::clone(&reach) as Arc<dyn companion_tauri::voice::HostReach>,
            Arc::clone(&scene.tokens),
        )
        .await;

    assert!(refused.is_err(), "the owner failed before it could answer");
    let ended = scene
        .state_where("the owner's failure", |state| {
            state["ended"]["cause"] == "owner_failed"
        })
        .await;
    assert!(scene.platform.count("stop") >= 1, "the media is stopped");
    // The host was not heard to answer, so it is not a host that was never asked, and the service
    // may hold a call this device cannot name.
    assert_eq!(ended["ended"]["host"]["kind"], "not_told", "{ended}");
    assert_eq!(ended["ended"]["broker"], "unknown", "{ended}");
    assert_eq!(ended["owed"][0]["kind"], "start_unknown", "{ended}");
    assert!(
        ended["owed"][0]["action_id"]
            .as_str()
            .is_some_and(|action| !action.is_empty()),
        "{ended}"
    );
    scene.stand_in.release_creations();
    scene.stop_host().await;
}

/// The owner fails before it has kept anything to finish: no call was named to it, and it wrote no
/// end. The supervisor writes one, so that a screen that reads the device after the slot is free
/// finds that the call stopped working, and that nothing is known of the media, and the next call
/// starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_that_fails_before_it_keeps_anything_still_leaves_an_end() {
    let mut scene = scene().await;
    let prepared = scene.prepared().await;
    let reach = failing_reach(&scene, FailsAt::InUse, 0);
    let calls = scene.phone.companion.app.state::<Calls>();

    let refused = calls
        .start(
            request_of(&scene, &prepared),
            Arc::clone(&reach) as Arc<dyn companion_tauri::voice::HostReach>,
            Arc::clone(&scene.tokens),
        )
        .await;

    assert!(refused.is_err(), "the owner failed before it could answer");
    let ended = scene
        .state_where("the owner's failure", |state| {
            state["ended"]["cause"] == "owner_failed" && state["setting_up"] == false
        })
        .await;
    assert_eq!(ended["ended"]["closed_locally"], false, "{ended}");
    // The slot is free: the next call starts.
    let again = scene.start().await;
    assert!(again["value"]["outcome"]["started"].is_object(), "{again}");
    let _ = scene.call("voice_stop", json!({ "voiceSessionId": null }));
    scene.stop_host().await;
}

/// The host refuses the start itself, with a refusal that carries its protocol code in the words
/// the client library writes. A screen that reads the device afterwards is told the host's words and
/// not the code, as the screen's own start is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_the_host_refuses_is_recorded_in_its_words_and_without_its_code() {
    let mut scene = scene().await;
    let prepared = scene.prepared().await;
    let mut request = scene.start_request(&prepared);
    request["sessionIds"] =
        json!([kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()).to_string()]);

    let answer = scene.call("voice_start", request);

    let state = scene.state();
    assert_eq!(state["ended"]["cause"], "not_started", "{answer:?} {state}");
    let words = state["ended"]["words"].as_str().expect("words");
    assert!(!words.is_empty(), "{state}");
    for code in [
        "PERMISSION_DENIED: ",
        "INVALID_ARGUMENT: ",
        "RESOURCE_UNAVAILABLE: ",
    ] {
        assert!(!words.starts_with(code), "{words}");
    }
    scene.stop_host().await;
}

/// The device's open fails, and while it cleans up what native code may hold, the device says it is
/// ending, not making a call: the screen is not offered an end that the cleanup has already begun.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_open_says_it_is_ending_while_it_cleans_up() {
    let mut scene = scene().await;
    scene.platform.hold("held");
    let _holding = scene.platform.release_when_done("held");
    scene.platform.fail_the_open_after_making_the_call();
    let prepared = scene.prepared().await;
    let starting = scene
        .phone
        .companion
        .start_call("voice_start", scene.start_request(&prepared));
    tokio::time::timeout(WATCHDOG, async {
        while scene.platform.count("held") == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the owner asked native code what it holds");

    let cleaning = scene.state();

    assert_eq!(cleaning["setting_up"], true, "{cleaning}");
    assert_eq!(cleaning["ending"], true, "{cleaning}");
    scene.platform.release("held");
    starting
        .await
        .expect("the start ran")
        .expect_err("a call that could not be opened is not a call started");
    scene.stop_host().await;
}

/// Waits until the kept file, read as it is on disk, satisfies `until`, and returns it. Read raw: a
/// write that has not finished has a staged file that `Kept::read` would take away.
async fn kept_file_where(
    directory: &std::path::Path,
    until: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            if let Ok(bytes) = std::fs::read(directory.join("voice-kept.json"))
                && let Ok(file) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && until(&file)
            {
                return file;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the kept file never held what was waited for")
}

/// The note that the voice service had no such call for this account outlives the process: a
/// device launched again finds it standing for the same host, account and service, and not for
/// another.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_note_that_the_service_had_no_such_call_survives_a_launch() {
    let mut scene = scene().await;
    scene.stand_in.treat_as_another_account(PHONE_TOKEN);
    scene.start().await;
    scene
        .state_where("a call that ended with the note", |state| {
            state["ended"]["cause"] == "no_such_call" && state["warning"].is_string()
        })
        .await;
    let generation = match scene.tokens.status() {
        Ok(kr_client::services::account::AccountStatus::SignedIn { generation, .. }) => {
            Some(generation)
        }
        other => panic!("the phone is signed in: {other:?}"),
    };
    // The note is in the file once the write that follows the ending has finished.
    kept_file_where(scene.phone.data.path(), |file| !file["note"].is_null()).await;
    let relaunched = Calls::on_phone(
        ScriptedCalls::new() as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        quick(),
        Kept::at(scene.phone.data.path()),
    );

    let same = relaunched.note_key(
        Some(scene.host().environment_id.to_string()),
        generation.clone(),
    );
    let other = relaunched.note_key(Some("another-environment".to_owned()), generation);

    assert!(
        relaunched.state(same.as_ref()).warning.is_some(),
        "the note stands for the same host, account and service"
    );
    assert!(
        relaunched.state(other.as_ref()).warning.is_none(),
        "and for no other"
    );
    scene.stop_host().await;
}

/// A revocation this device could not tell its host outlives the process, with the host's name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_owed_to_a_host_survives_a_launch() {
    let timings = Timings {
        host_within: Duration::from_secs(2),
        ..quick()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    let started = scene.start().await;
    let voice_session_id =
        started["value"]["outcome"]["started"]["session"]["voice_session_id"].clone();
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    // The host does not answer the stop in time: it waits for the service to close the call.
    scene.stand_in.hold_closes();
    let closure = scene
        .call("voice_stop", json!({ "voiceSessionId": null }))
        .expect("the stop is answered");
    scene.stand_in.release_closes();
    assert!(closure["host_failure"].is_object(), "{closure}");
    scene
        .state_where("a revocation owed", |state| {
            state["owed"][0]["kind"] == "revocation"
        })
        .await;
    kept_file_where(scene.phone.data.path(), |file| {
        file["owed"].as_array().is_some_and(|owed| owed.len() == 1)
    })
    .await;

    let relaunched = Calls::on_phone(
        ScriptedCalls::new() as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        quick(),
        Kept::at(scene.phone.data.path()),
    );

    let state = relaunched.state(None);
    assert_eq!(state.owed.len(), 1, "{state:?}");
    assert_eq!(
        serde_json::to_value(&state.owed[0].voice_session_id).expect("a value"),
        voice_session_id
    );
    assert!(!state.owed[0].host_name.is_empty());
    // The entry names the host it is owed to, as the owner wrote it, so a device launched again can
    // ask that host.
    let connection = scene
        .phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("the phone is connected");
    let companion_tauri::connection::Standing::Paired { host, .. } = connection.standing() else {
        panic!("the phone is a paired device");
    };
    assert_eq!(
        state.owed[0].host,
        Some((host.host_device_id, connection.environment_id()))
    );
    scene.stop_host().await;
}

/// A stop that names a voice session this device holds no call for asks the host about it, and the
/// host that revokes the grant settles the entry owed to it for that session, and no other host's:
/// another host may hold a voice session of the same identifier, and what is owed to it is not
/// what this host answered for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_named_stop_settles_the_entry_owed_to_the_host_that_revoked_and_no_other() {
    let mut scene = scene().await;
    scene.stand_in.end_the_control_when_a_call_is_closed();
    let started = scene.start().await;
    let live: kr_protocol::ids::VoiceSessionId = started["value"]["outcome"]["started"]["session"]
        ["voice_session_id"]
        .as_str()
        .expect("a voice session")
        .parse()
        .expect("an identifier");
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    let connection = scene
        .phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("the phone is connected");
    let companion_tauri::connection::Standing::Paired { host, .. } = connection.standing() else {
        panic!("the phone is a paired device");
    };
    let owed_to = |host: (kr_protocol::ids::DeviceId, kr_protocol::ids::EnvironmentId)| {
        companion_tauri::voice::OwedView {
            kind: "revocation".to_owned(),
            words: "The host did not answer.".to_owned(),
            action_id: None,
            voice_session_id: Some(live.to_string()),
            until_ms: now_ms() + 1_800_000,
            host_reference: "a-host".to_owned(),
            host_name: "A host".to_owned(),
            host: Some(host),
        }
    };
    let this_host = (host.host_device_id, connection.environment_id());
    let another_host = (
        kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
        kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
    );
    let directory = scene.phone.data.path().join("relaunch-named");
    Kept::at(&directory)
        .write(&companion_tauri::voice::KeptVoice {
            owed: vec![owed_to(another_host), owed_to(this_host)],
            note: None,
        })
        .expect("the file is written");
    // A device launched again holds no call, so the stop that names the voice session is the host's
    // to answer alone.
    let relaunched = Calls::on_phone(
        ScriptedCalls::new() as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        quick(),
        Kept::at(&directory),
    );
    assert_eq!(relaunched.state(None).owed.len(), 2);
    let reach = companion_tauri::voice::AppReach::new(scene.phone.companion.app.handle().clone());

    let closed = relaunched
        .stop(Some(live), &reach)
        .await
        .expect("the host is asked");

    assert!(
        matches!(closed.host, companion_tauri::voice::HostEnd::Revoked { .. }),
        "{closed:?}"
    );
    let left = relaunched.state(None);
    assert_eq!(left.owed.len(), 1, "{left:?}");
    assert_eq!(left.owed[0].host, Some(another_host));
    // What was settled is settled in the file too.
    let file = kept_file_where(&directory, |file| {
        file["owed"].as_array().is_some_and(|owed| owed.len() == 1)
    })
    .await;
    assert_eq!(file["owed"][0]["voice_session_id"], live.to_string());
    // The entry that is left is the other host's: both were owed for the same voice session.
    assert_eq!(
        file["owed"][0]["host_device_id"],
        serde_json::to_value(another_host.0).expect("a value")
    );
    scene.stop_host().await;
}

/// A host that is reached again is asked once more for each revocation it is owed, from what the file
/// kept of its identity, and only a host that revokes the grant settles one. A host that refuses has
/// not said that the grant is gone: the host refuses a stop of a call it holds, too, when the stop is
/// not admitted, so the revocation stays owed until the grant ends by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_host_that_revokes_the_grant_settles_what_it_was_owed() {
    let mut scene = scene().await;
    scene.stand_in.end_the_control_when_a_call_is_closed();
    let started = scene.start().await;
    let live: kr_protocol::ids::VoiceSessionId = started["value"]["outcome"]["started"]["session"]
        ["voice_session_id"]
        .as_str()
        .expect("a voice session")
        .parse()
        .expect("an identifier");
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    let connection = scene
        .phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("the phone is connected");
    let companion_tauri::connection::Standing::Paired { host, .. } = connection.standing() else {
        panic!("the phone is a paired device");
    };
    // Two revocations are owed to the host: one for a voice session it does not hold, asked first,
    // and one for the call it holds, which only a revocation settles.
    let unknown = kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid());
    let owed = |id: kr_protocol::ids::VoiceSessionId| companion_tauri::voice::OwedView {
        kind: "revocation".to_owned(),
        words: "The host did not answer.".to_owned(),
        action_id: None,
        voice_session_id: Some(id.to_string()),
        until_ms: now_ms() + 1_800_000,
        host_reference: "a-host".to_owned(),
        host_name: "A host".to_owned(),
        host: Some((host.host_device_id, connection.environment_id())),
    };
    let directory = scene.phone.data.path().join("relaunch");
    Kept::at(&directory)
        .write(&companion_tauri::voice::KeptVoice {
            owed: vec![owed(unknown), owed(live)],
            note: None,
        })
        .expect("the file is written");
    let relaunched = Calls::on_phone(
        ScriptedCalls::new() as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        quick(),
        Kept::at(&directory),
    );
    assert_eq!(relaunched.state(None).owed.len(), 2);

    relaunched.host_reached(
        host.host_device_id,
        connection.environment_id(),
        connection.session(),
    );

    tokio::time::timeout(WATCHDOG, async {
        while relaunched.state(None).owed.len() != 1 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the host revoked the grant it held and the entry was settled");
    let left = relaunched.state(None);
    assert_eq!(
        left.owed[0].voice_session_id.as_deref(),
        Some(unknown.to_string().as_str()),
        "the host that holds no such voice session did not settle its entry"
    );
    // What was settled is settled in the file too.
    let file = kept_file_where(&directory, |file| {
        file["owed"].as_array().is_some_and(|owed| owed.len() == 1)
    })
    .await;
    assert_eq!(file["owed"][0]["voice_session_id"], unknown.to_string());
    // The call the host held ended with its revocation. The phone's own end then asks the host about
    // a voice session it no longer holds and is refused, which does not say the grant is gone: the
    // refusal is owed, with the host's own words behind a lead-in that says what happened.
    let ended = scene
        .state_where("the call the host revoked, ended", |state| {
            state["running"] == false && state["ended"].is_object()
        })
        .await;
    assert_eq!(ended["ended"]["host"]["kind"], "refused", "{ended}");
    let owed_for_live = ended["owed"]
        .as_array()
        .and_then(|owed| {
            owed.iter()
                .find(|each| each["voice_session_id"] == live.to_string())
        })
        .unwrap_or_else(|| panic!("a refusal is owed: {ended}"));
    assert!(
        owed_for_live["words"]
            .as_str()
            .is_some_and(|words| words.starts_with("The host refused the stop: ")),
        "{owed_for_live}"
    );
    scene.stop_host().await;
}

/// Makes the kept file one the system refuses to read, as a phone's is before its first unlock: the
/// file is put aside, and a link that leads back to itself stands where it was, which cannot be
/// opened by anyone.
#[cfg(unix)]
fn lock_the_kept_file(directory: &std::path::Path) {
    let file = directory.join("voice-kept.json");
    std::fs::rename(&file, directory.join("voice-kept.locked")).expect("the file is put aside");
    std::os::unix::fs::symlink(&file, &file).expect("a link stands where the file was");
}

/// The unlock: the file can be read again. What stood where it was must still be the link, or the
/// file that could not be read was written over.
#[cfg(unix)]
fn unlock_the_kept_file(directory: &std::path::Path) {
    let file = directory.join("voice-kept.json");
    assert!(
        std::fs::symlink_metadata(&file)
            .expect("the file is there")
            .file_type()
            .is_symlink(),
        "the file that could not be read was written over"
    );
    std::fs::remove_file(&file).expect("the link goes");
    std::fs::rename(directory.join("voice-kept.locked"), &file).expect("the file is back");
}

/// What this device owes the host `host`, for the voice session `voice_session_id`.
#[cfg(unix)]
fn owed_to(
    host: (kr_protocol::ids::DeviceId, kr_protocol::ids::EnvironmentId),
    voice_session_id: kr_protocol::ids::VoiceSessionId,
) -> companion_tauri::voice::OwedView {
    companion_tauri::voice::OwedView {
        kind: "revocation".to_owned(),
        words: "The host did not answer.".to_owned(),
        action_id: None,
        voice_session_id: Some(voice_session_id.to_string()),
        until_ms: now_ms() + 1_800_000,
        host_reference: "a-host".to_owned(),
        host_name: "A host".to_owned(),
        host: Some(host),
    }
}

/// A phone that iOS starts before its first unlock cannot read the file of what a call left owed,
/// and a file that cannot be read is not an empty one. The device says nothing is owed only until
/// the file can be read; when the host is reached after the unlock it reads the file again first,
/// and asks the host for what it holds, without another launch.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_the_system_refused_to_read_is_read_again_when_the_host_is_reached() {
    let mut scene = scene().await;
    scene.stand_in.end_the_control_when_a_call_is_closed();
    let started = scene.start().await;
    let live: kr_protocol::ids::VoiceSessionId = started["value"]["outcome"]["started"]["session"]
        ["voice_session_id"]
        .as_str()
        .expect("a voice session")
        .parse()
        .expect("an identifier");
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    let connection = scene
        .phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("the phone is connected");
    let companion_tauri::connection::Standing::Paired { host, .. } = connection.standing() else {
        panic!("the phone is a paired device");
    };
    let this_host = (host.host_device_id, connection.environment_id());
    // Two revocations are owed to the host: one for a voice session it does not hold, which stays
    // owed, and one for the call it holds, which its revocation settles.
    let unknown = kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid());
    let directory = scene.phone.data.path().join("relaunch-locked");
    Kept::at(&directory)
        .write(&companion_tauri::voice::KeptVoice {
            owed: vec![owed_to(this_host, unknown), owed_to(this_host, live)],
            note: None,
        })
        .expect("the file is written");
    lock_the_kept_file(&directory);

    let relaunched = Calls::on_phone(
        ScriptedCalls::new() as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        quick(),
        Kept::at(&directory),
    );
    assert!(
        relaunched.state(None).owed.is_empty(),
        "nothing can be told of a file that cannot be read"
    );

    unlock_the_kept_file(&directory);
    relaunched.host_reached(
        host.host_device_id,
        connection.environment_id(),
        connection.session(),
    );

    // The host was asked for what the file held, and revoked the grant of the call it holds.
    scene
        .state_where("the call the host revoked, ended", |state| {
            state["running"] == false && state["ended"].is_object()
        })
        .await;
    let file = kept_file_where(&directory, |file| {
        file["owed"].as_array().is_some_and(|owed| owed.len() == 1)
    })
    .await;
    assert_eq!(file["owed"][0]["voice_session_id"], unknown.to_string());
    scene.stop_host().await;
}

/// What this launch owes or notes while the file cannot be read is kept in memory, not written over
/// the file; once the file can be read, what it holds comes first, a note this launch made is the
/// newer and stands, and the whole is written back, so that nothing an earlier launch left owed is
/// lost to a write that came first.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_the_system_refused_to_read_is_not_written_over_and_is_taken_up_with_what_this_launch_added()
 {
    let mut scene = scene().await;
    scene.stand_in.treat_as_another_account(PHONE_TOKEN);
    let prepared = scene.prepared().await;
    let connection = scene
        .phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("the phone is connected");
    let companion_tauri::connection::Standing::Paired { host, .. } = connection.standing() else {
        panic!("the phone is a paired device");
    };
    let this_host = (host.host_device_id, connection.environment_id());
    let earlier = kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid());
    let directory = scene.phone.data.path().join("relaunch-locked-written");
    Kept::at(&directory)
        .write(&companion_tauri::voice::KeptVoice {
            owed: vec![owed_to(this_host, earlier)],
            note: None,
        })
        .expect("the file is written");
    lock_the_kept_file(&directory);

    let relaunched = Calls::on_phone(
        Arc::clone(&scene.platform) as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        quick(),
        Kept::at(&directory),
    );
    // This launch's call finds the service has no such call for the account, which it notes, and
    // which is written to the file as the call ends.
    let reach = Arc::new(companion_tauri::voice::AppReach::new(
        scene.phone.companion.app.handle().clone(),
    )) as Arc<dyn companion_tauri::voice::HostReach>;
    relaunched
        .start(
            request_of(&scene, &prepared),
            reach,
            Arc::clone(&scene.tokens),
        )
        .await
        .expect("a call starts");
    let generation = match scene.tokens.status() {
        Ok(kr_client::services::account::AccountStatus::SignedIn { generation, .. }) => {
            Some(generation)
        }
        other => panic!("the phone is signed in: {other:?}"),
    };
    let key = relaunched.note_key(Some(scene.host().environment_id.to_string()), generation);
    let ended = tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = relaunched.state(key.as_ref());
            if state
                .ended
                .as_ref()
                .is_some_and(|ended| ended.cause == "no_such_call")
                && !state.setting_up
            {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the call ended with the note");
    assert!(ended.warning.is_some(), "the note stands in memory");
    assert!(
        ended.owed.is_empty(),
        "nothing is told of a file that cannot be read"
    );

    // The unlock checks that nothing was written over the file; the next use reads it.
    unlock_the_kept_file(&directory);
    let state = relaunched.state(key.as_ref());
    assert_eq!(state.owed.len(), 1, "{state:?}");
    assert_eq!(
        state.owed[0].voice_session_id.as_deref(),
        Some(earlier.to_string().as_str())
    );
    assert!(state.warning.is_some(), "the note this launch made stands");
    let file = kept_file_where(&directory, |file| {
        file["owed"].as_array().is_some_and(|owed| owed.len() == 1) && !file["note"].is_null()
    })
    .await;
    assert_eq!(file["owed"][0]["voice_session_id"], earlier.to_string());
    scene.stop_host().await;
}

/// What this launch owes while the file cannot be read comes after what the file held, and is
/// written with it; a note the file holds is forgotten when this launch's control attached, which
/// is newer than the file: the earlier launch's note does not come back with the unlock.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_the_system_refused_to_read_is_taken_up_in_order_with_what_this_launch_owes_and_forgot()
 {
    let timings = Timings {
        host_within: Duration::from_secs(3),
        ..quick()
    };
    let mut scene = scene_with(timings, Some(phone_grant(PHONE_TOKEN, 3600)), None).await;
    let prepared = scene.prepared().await;
    let connection = scene
        .phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("the phone is connected");
    let companion_tauri::connection::Standing::Paired { host, .. } = connection.standing() else {
        panic!("the phone is a paired device");
    };
    let this_host = (host.host_device_id, connection.environment_id());
    let generation = match scene.tokens.status() {
        Ok(kr_client::services::account::AccountStatus::SignedIn { generation, .. }) => {
            Some(generation)
        }
        other => panic!("the phone is signed in: {other:?}"),
    };
    let environment = Some(scene.host().environment_id.to_string());
    let key = Calls::on_phone(
        ScriptedCalls::new() as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        quick(),
        Kept::nowhere(),
    )
    .note_key(environment, generation)
    .expect("a key");

    // An earlier launch left a revocation owed and a note that the service had no such call.
    let earlier = kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid());
    let directory = scene.phone.data.path().join("relaunch-locked-order");
    Kept::at(&directory)
        .write(&companion_tauri::voice::KeptVoice {
            owed: vec![owed_to(this_host, earlier)],
            note: Some(key.clone()),
        })
        .expect("the file is written");
    lock_the_kept_file(&directory);

    let relaunched = Calls::on_phone(
        Arc::clone(&scene.platform) as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        timings,
        Kept::at(&directory),
    );
    let reach = Arc::new(companion_tauri::voice::AppReach::new(
        scene.phone.companion.app.handle().clone(),
    )) as Arc<dyn companion_tauri::voice::HostReach>;
    relaunched
        .start(
            request_of(&scene, &prepared),
            Arc::clone(&reach),
            Arc::clone(&scene.tokens),
        )
        .await
        .expect("a call starts");
    let running = tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = relaunched.state(Some(&key));
            if state.control == "connected" {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the control attached");
    let this_call = running
        .session
        .as_ref()
        .expect("a call runs")
        .voice_session_id
        .to_string();

    // The host goes away, so the end of the call cannot tell it: the revocation is owed.
    scene.stop_host().await;
    let closed = relaunched
        .stop(None, reach.as_ref())
        .await
        .expect("the call is stopped");
    assert!(
        matches!(closed.host, companion_tauri::voice::HostEnd::NotTold { .. }),
        "{closed:?}"
    );
    let locked = relaunched.state(Some(&key));
    // What this launch owes is told at once; what the file holds is not known yet.
    assert_eq!(locked.owed.len(), 1, "{locked:?}");
    assert_eq!(
        locked.owed[0].voice_session_id.as_deref(),
        Some(this_call.as_str())
    );
    assert!(locked.warning.is_none(), "the file's note is not read yet");

    unlock_the_kept_file(&directory);
    let state = relaunched.state(Some(&key));
    let owed: Vec<_> = state
        .owed
        .iter()
        .map(|each| each.voice_session_id.clone().unwrap_or_default())
        .collect();
    assert_eq!(
        owed,
        vec![earlier.to_string(), this_call.clone()],
        "what the file held, then what this launch owes"
    );
    assert!(
        state.warning.is_none(),
        "the control that attached since forgot the note the file held"
    );
    let file = kept_file_where(&directory, |file| {
        file["owed"].as_array().is_some_and(|owed| owed.len() == 2) && file["note"].is_null()
    })
    .await;
    assert_eq!(file["owed"][0]["voice_session_id"], earlier.to_string());
    assert_eq!(file["owed"][1]["voice_session_id"], this_call);
}

/// A stop that names a voice session the host holds, made after the file's unlock and before anything
/// else reads the record, settles the entry the file held for it: the entry is taken up first, and
/// then removed, in memory and in the file.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_named_stop_after_the_unlock_settles_the_entry_the_file_held() {
    let mut scene = scene().await;
    scene.stand_in.end_the_control_when_a_call_is_closed();
    let started = scene.start().await;
    let live: kr_protocol::ids::VoiceSessionId = started["value"]["outcome"]["started"]["session"]
        ["voice_session_id"]
        .as_str()
        .expect("a voice session")
        .parse()
        .expect("an identifier");
    scene
        .state_where("an attached control", |state| {
            state["control"] == "connected"
        })
        .await;
    let connection = scene
        .phone
        .companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("the phone is connected");
    let companion_tauri::connection::Standing::Paired { host, .. } = connection.standing() else {
        panic!("the phone is a paired device");
    };
    let this_host = (host.host_device_id, connection.environment_id());
    let directory = scene.phone.data.path().join("relaunch-locked-named");
    Kept::at(&directory)
        .write(&companion_tauri::voice::KeptVoice {
            owed: vec![owed_to(this_host, live)],
            note: None,
        })
        .expect("the file is written");
    lock_the_kept_file(&directory);
    let relaunched = Calls::on_phone(
        ScriptedCalls::new() as Arc<dyn companion_platform::call::CallPlatform>,
        service_at(scene.stand_in.origin()),
        quick(),
        Kept::at(&directory),
    );
    unlock_the_kept_file(&directory);
    let reach = companion_tauri::voice::AppReach::new(scene.phone.companion.app.handle().clone());

    // Nothing has read the record since the launch: the stop is the first use.
    let closed = relaunched
        .stop(Some(live), &reach)
        .await
        .expect("the host is asked");

    assert!(
        matches!(closed.host, companion_tauri::voice::HostEnd::Revoked { .. }),
        "{closed:?}"
    );
    kept_file_where(&directory, |file| {
        file["owed"].as_array().is_some_and(Vec::is_empty)
    })
    .await;
    assert!(relaunched.state(None).owed.is_empty());
    scene.stop_host().await;
}
