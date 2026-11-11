//! The checks a debug build runs for a whole call on a phone, against a host a harness started.
//!
//! The harness is a real daemon and a stand-in for the voice service on the machine the phone
//! runs on. A script puts a request in the application's data directory that names the stand-in's
//! origin, a token the stand-in's control accepts for the phone's account, and a direct invitation
//! to the daemon. The application pairs with the daemon from that invitation, the person allows
//! voice, and a call is started through the commands the page uses: native code opens the call and
//! makes the offer, the daemon creates the call at the stand-in, native code applies the answer
//! and is permitted, and the control attaches.
//!
//! A run is in one of three modes. By default the answer leads nowhere, so the connection fails,
//! native code ends the call, and the checks read the end: the device stopped the media, the
//! daemon revoked the grant and the stand-in was told the call was over. In the outage mode the
//! answer is a peer's in this same application, so the call connects and carries audio: the checks
//! read the counters of what each end received, wait for the script to take the voice service away,
//! and then exercise what must keep working without it (the microphone's mute, the speaker's
//! silence and a stop that does not wait for the service) and read the end, in which the service's
//! closure is reported as not confirmed. A direction whose audio the machine cannot measure, as a
//! simulator with no microphone cannot for the send direction, is reported as not measured.
//!
//! In the delegating mode the call hands spoken requests to a real host, and the probe plays the
//! person and the provider through the peer and the stand-in ([`delegating`]): one call is one leg.
//!
//! The request holds an invitation's secret and an account token for a stand-in, both thrown away
//! with the run, and is read once and removed.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use companion_platform::call::{CallPlatform, CaptureState, Media};
use kr_client::services::account::{
    AccountIdentity, AccountService, AccountToken, AccountUsage, AuthorisationGrant, Client,
    Exchanged, IssuedGrant, PendingAuthorisation, RefreshToken, Refreshed, SignedInAccount,
    StoredGrant,
};
use kr_client::services::voice_control::ControlConnector;
use kr_client::services::{HttpDeadlines, HttpService, ServiceFuture, managed_response_limits};
use kr_crypto::store::MemoryStore;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager as _, Runtime};
use tokio::sync::watch;

use super::delegating::{self, Driver, Leg, PeerDriver};
use super::{Check, Checks};
use crate::account::carrier::{Boxed, Carrier, Ending, Plan, Unavailable};
use crate::account::{Account, AccountSlot};
use crate::commands;
use crate::state::AppState;
use crate::target::Subject;
use crate::voice::Service;

/// How long pairing is given, from the invitation to a pairing that is made.
const PAIR_WITHIN: Duration = Duration::from_secs(90);

/// How long the connection to the paired host is given.
const CONNECT_WITHIN: Duration = Duration::from_secs(60);

/// How long a started call is given to show as running with its control attached.
const RUN_WITHIN: Duration = Duration::from_secs(30);

/// How long a call whose connection leads nowhere is given to end: the provider's connection
/// fails after about half a minute, and native code ends the call when it does.
const END_WITHIN: Duration = Duration::from_secs(180);

/// How long the voice service is given to be told the call is over, after the call has ended.
const FINALISED_WITHIN: Duration = Duration::from_secs(30);

/// The look between two reads of the call's state.
const LOOK: Duration = Duration::from_millis(250);

/// How long a call that is connected is given, by default, to show the audio it carried in each
/// direction.
const MEDIA_SECONDS: u64 = 60;

/// How long the call is given to read the voice service as unreachable after the script took it
/// away.
const UNREACHABLE_WITHIN: Duration = Duration::from_secs(90);

/// How long the voice service is given to be reported as not confirmed when it is gone: the host
/// tries it, and gives it up.
const UNCONFIRMED_WITHIN: Duration = Duration::from_secs(180);

/// How long the media is given to carry packets again after the service is gone and the local
/// controls have run: a counter that has not moved by then did not go on.
const MEDIA_GOES_ON_WITHIN: Duration = Duration::from_secs(5);

/// The audio packets a direction must have carried, about a second of them, for the call to be
/// said to carry audio that way.
const AUDIO_FLOOR: u64 = 50;

/// The samples the speaker side must have taken, about a fifth of a second at 48 kHz, for the call
/// to be said to have played audio out.
const PLAYED_FLOOR: u64 = 9_600;

/// What a run is for.
#[derive(serde::Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The answer leads nowhere, and native code ends the call when its connection fails.
    #[default]
    NativeFailure,
    /// The answer is a peer's: the call carries audio and then the voice service goes away.
    Outage,
    /// The answer is a peer's and the call stays up until the person ends it from its
    /// notification on the phone's lock screen, which the script that runs the device drives.
    LockScreen,
    /// The answer is a peer's, the call hands spoken requests to the host, and the probe plays one
    /// leg of what the gate does with them.
    Delegating,
}

/// What a harness run is given: where the stand-in voice service is, the token its control accepts
/// for the phone's account, and an invitation to the host to pair with.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Harness {
    /// The stand-in's origin, which the host names to the phone as its voice service.
    pub origin: String,
    /// The access token the phone's account holds, which the stand-in's control accepts.
    pub token: String,
    /// The direct invitation's text.
    pub invitation: String,
    /// What the run is for.
    #[serde(default)]
    pub mode: Mode,
    /// How many seconds a connected call is given to show its audio, in the outage mode.
    #[serde(default = "media_seconds")]
    pub media_seconds: u64,
    /// Which leg the delegating mode plays.
    #[serde(default)]
    pub leg: Leg,
    /// The sessions the host holds for the run, which the delegating mode's call is allowed to
    /// reach. Empty where the run reads no session.
    #[serde(default)]
    pub session_ids: Vec<String>,
}

const fn media_seconds() -> u64 {
    MEDIA_SECONDS
}

impl Harness {
    /// The account the phone is signed in to for this run: the stand-in's origin, and a grant
    /// holding the run's token, kept in memory.
    #[must_use]
    pub fn account(&self) -> AccountSlot {
        let (origin, token) = (self.origin.clone(), self.token.clone());
        AccountSlot::new(Box::new(move || {
            let (origin, token) = (origin.clone(), token.clone());
            Box::pin(async move { signed_in(&origin, &token).await })
        }))
    }

    /// The voice service at the stand-in's origin, reached the way the application reaches the
    /// managed one.
    ///
    /// # Errors
    ///
    /// Returns why the transport cannot be set up.
    pub fn service(&self) -> Result<Service, String> {
        let gateway = kr_protocol::service::GatewayOrigin::new(&self.origin)
            .map_err(|error| error.to_string())?;
        let http = HttpService::with(gateway, HttpDeadlines::default(), managed_response_limits())
            .map_err(|error| error.to_string())?;
        Ok(Service::new(
            self.origin.clone(),
            Arc::new(http),
            ControlConnector::platform().map_err(|error| error.to_string())?,
        ))
    }
}

/// An account service that issues the run's token and nothing else.
#[derive(Debug)]
struct RunAccounts {
    token: String,
}

impl RunAccounts {
    fn grant(&self) -> IssuedGrant {
        IssuedGrant {
            access_token: AccountToken::new(self.token.clone()).expect("a token"),
            expires_in_seconds: 3600,
            refresh_token: RefreshToken::new("harness-refresh-token").expect("a token"),
            scopes: ["openid", "profile", "email", "offline_access", "voice"]
                .map(str::to_owned)
                .to_vec(),
            subject: "account-1".to_owned(),
        }
    }
}

impl AccountService for RunAccounts {
    fn exchange<'a>(&'a self, _grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        Box::pin(async { Ok(Exchanged::Issued(self.grant())) })
    }

    fn refresh<'a>(&'a self, _stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        Box::pin(async { Ok(Refreshed::Rotated(self.grant())) })
    }

    fn revoke<'a>(&'a self, _refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn identity<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity> {
        Box::pin(async {
            Ok(AccountIdentity {
                subject: "account-1".to_owned(),
                email: None,
                name: None,
            })
        })
    }

    fn usage<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage> {
        Box::pin(async { Ok(AccountUsage::default()) })
    }
}

/// A phone that signs in nowhere: the call is what is under test, not the ceremony.
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

async fn signed_in(origin: &str, token: &str) -> Result<Arc<Account>, String> {
    let service = Arc::new(RunAccounts {
        token: token.to_owned(),
    });
    let tokens = Arc::new(SignedInAccount::new(
        Arc::clone(&service) as Arc<dyn AccountService>,
        Arc::new(MemoryStore::new()),
        Client::Mobile,
    ));
    tokens
        .keep(service.grant(), "harness")
        .await
        .map_err(|error| error.to_string())?;
    let origin =
        kr_protocol::service::GatewayOrigin::new(origin).map_err(|error| error.to_string())?;
    let deletion = crate::account::deletion::never_deleting(&origin, &tokens);
    Ok(Arc::new(Account::new(
        tokens,
        service,
        origin,
        Arc::new(NoCarrier),
        Arc::new(|_| {}),
        deletion,
    )))
}

/// The time now, in milliseconds since the Unix epoch, to set a run's steps beside the voice service's
/// own record of when its requests came.
fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}

/// Looks until `look` finds something or `within` passes.
pub(super) async fn until<T, Fut: Future<Output = Option<T>>>(
    within: Duration,
    mut look: impl FnMut() -> Fut,
) -> Option<T> {
    let end = Instant::now() + within;
    loop {
        if let Some(found) = look().await {
            return Some(found);
        }
        if Instant::now() >= end {
            return None;
        }
        tokio::time::sleep(LOOK).await;
    }
}

/// The state of the call this device holds, as the page reads it.
pub(super) async fn call_state<R: Runtime>(app: &AppHandle<R>) -> Value {
    match commands::voice_call_state(app.state(), app.state(), app.state()).await {
        Ok(state) => serde_json::to_value(state).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

/// Where the pairing attempt has got to, as a word, and why when it ended.
fn attempt(device: &crate::device::Device) -> (String, String) {
    let state = serde_json::to_value(device.view().state).unwrap_or(Value::Null);
    let word = state["state"].as_str().unwrap_or("unknown").to_owned();
    let why = state["failure"]["kind"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (word, why)
}

/// Pairs with the host the invitation names. False when no pairing is made and the call cannot go
/// on.
pub(super) async fn pair<R: Runtime>(
    app: &AppHandle<R>,
    invitation: &str,
    checks: &mut Checks<'_>,
) -> bool {
    let state = app.state::<AppState>();
    let device = match state.device() {
        Ok(device) => device,
        Err(error) => {
            checks.push(Check::found(
                "paired",
                false,
                format!("no device: {error:?}"),
            ));
            return false;
        }
    };
    let read = match device.read(invitation) {
        Ok(read) => read,
        Err(failure) => {
            checks.push(Check::found(
                "paired",
                false,
                format!("the invitation was not read: {:?}", failure.kind),
            ));
            return false;
        }
    };
    let intake = device.begin_intake();
    let _ = device.hold_for(intake, read);
    if let Err(error) = device.start_held() {
        checks.push(Check::found("paired", false, format!("{error:?}")));
        return false;
    }
    let ended = until(PAIR_WITHIN, || async {
        let (word, why) = attempt(&device);
        matches!(word.as_str(), "paired" | "ended").then_some((word, why))
    })
    .await;
    let (word, why) =
        ended.unwrap_or_else(|| (attempt(&device).0, "not within the time".to_owned()));
    let ok = word == "paired";
    checks.push(Check::found("paired", ok, format!("{word} {why}")));
    ok
}

/// Waits for the connection to the paired host.
pub(super) async fn connect<R: Runtime>(app: &AppHandle<R>, checks: &mut Checks<'_>) -> bool {
    let connected = until(CONNECT_WITHIN, || async {
        app.state::<AppState>()
            .connection_state()
            .connected
            .then_some(())
    })
    .await
    .is_some();
    checks.push(Check::found(
        "connected to the host",
        connected,
        format!("{:?}", app.state::<AppState>().connection_state().reason),
    ));
    connected
}

/// Allows voice for a session, reads what a call would be and starts one, the way the page does.
/// The call's voice session is returned when the host made it.
async fn start<R: Runtime>(
    app: &AppHandle<R>,
    session_ids: &[String],
    checks: &mut Checks<'_>,
) -> Option<String> {
    let session = session_ids
        .first()
        .cloned()
        .unwrap_or_else(|| kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()).to_string());
    let environment = app.state::<AppState>().connection_state().environment_id;
    let allowed = commands::voice_allow(
        app.state(),
        Subject::default(),
        json!({ "session_ids": [session], "actions": null, "environment_id": environment }),
    )
    .await;
    checks.push(Check::found(
        "voice is allowed",
        allowed.is_ok(),
        allowed
            .as_ref()
            .err()
            .map_or_else(String::new, |e| format!("{e:?}")),
    ));
    allowed.ok()?;

    let prepared = commands::voice_prepare(
        app.state(),
        json!({ "session_ids": [session], "selected": [] }),
    )
    .await;
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            checks.push(Check::found(
                "a call is prepared",
                false,
                format!("{error:?}"),
            ));
            return None;
        }
    };
    let digest = serde_json::from_value(prepared["prepared"].clone());
    let Ok(digest) = digest else {
        checks.push(Check::found(
            "a call is prepared",
            false,
            "no digest of what a call would be",
        ));
        return None;
    };
    checks.push(Check::found(
        "a call is prepared",
        true,
        format!("what a call would be was read; at {}", now_ms()),
    ));

    let (began, began_ms) = (Instant::now(), now_ms());
    // What the connection to the host did while the start waited, one word per change.
    let watched = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let watcher = {
        let (app, watched) = (app.clone(), std::sync::Arc::clone(&watched));
        tokio::spawn(async move {
            let mut last = None;
            loop {
                let state = app.state::<AppState>().connection_state();
                let word = format!("connected {} {:?}", state.connected, state.reason);
                if last.as_ref() != Some(&word) {
                    watched
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(format!("{}s {word}", began.elapsed().as_secs()));
                    last = Some(word);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    };
    let started = commands::voice_start(
        app.clone(),
        app.state(),
        app.state(),
        Subject::default(),
        vec![session],
        600,
        None,
        digest,
        prepared["managed"]["rate"]["version"]
            .as_str()
            .map(str::to_owned),
    )
    .await;
    watcher.abort();
    let connection = watched
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .join("; ");
    let started = match started.map(|started| serde_json::to_value(started).unwrap_or(Value::Null))
    {
        Ok(started) => started,
        Err(error) => {
            checks.push(Check::found(
                "the host started the call",
                false,
                format!("{error:?}"),
            ));
            return None;
        }
    };
    let made = &started["value"]["outcome"]["started"]["session"];
    let id = made["voice_session_id"].as_str().map(str::to_owned);
    let started_ok = id.is_some() && made["answer_sdp"] == "";
    checks.push(Check::found(
        "the host started the call",
        started_ok,
        if started_ok {
            format!(
                "the host made the call and kept the provider's answer from the page; the start began at {began_ms} and took {} s; the connection to the host: {connection}",
                began.elapsed().as_secs()
            )
        } else {
            // What the host answered, without the provider's answer or any credential.
            let mut answer = started.clone();
            if let Some(session) = answer.pointer_mut("/value/outcome/started/session") {
                session["answer_sdp"] = Value::Null;
            }
            let text = answer.to_string();
            format!(
                "the start began at {began_ms} and took {} s; the connection to the host: {connection}; the host answered {}",
                began.elapsed().as_secs(),
                text.chars().take(600).collect::<String>()
            )
        },
    ));
    id
}

/// What the call showed while it ran, one line per change, each with the seconds since the start.
struct Trace {
    from: Instant,
    seen: std::sync::Mutex<(String, Vec<String>)>,
}

impl Trace {
    fn new() -> Self {
        Self {
            from: Instant::now(),
            seen: std::sync::Mutex::default(),
        }
    }

    fn see(&self, state: &Value) {
        let word = format!(
            "running {} setting_up {} capture {} control {}",
            state["running"], state["setting_up"], state["capture"], state["control"]
        );
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if word != seen.0 {
            seen.1
                .push(format!("{}s {word}", self.from.elapsed().as_secs()));
            seen.0 = word;
        }
    }

    fn text(&self) -> String {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1
            .join("; ")
    }
}

/// How the call a run reads to its end is meant to end.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HowItEnds {
    /// Its connection fails, and native code ends it.
    ConnectionFails,
    /// The person ends it from its notification on the phone's lock screen.
    LockScreen,
}

/// Whether the microphone was muted, at each change, with the time of the change in milliseconds
/// since the Unix epoch: the order in which the person's taps on the notification reached the call.
/// The times are those of the looks, so the widest gap between two looks is kept beside them: a
/// change is known to have happened no earlier than a gap before the look that saw it.
#[derive(Default)]
struct MuteTrail(std::sync::Mutex<MuteLooks>);

#[derive(Default)]
struct MuteLooks {
    changes: Vec<(bool, u128)>,
    last_look: Option<u128>,
    widest_gap_ms: u128,
}

impl MuteTrail {
    fn see(&self, muted: bool) {
        let now = now_ms();
        let mut seen = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(last) = seen.last_look {
            seen.widest_gap_ms = seen.widest_gap_ms.max(now.saturating_sub(last));
        }
        seen.last_look = Some(now);
        if seen.changes.last().map(|(was, _)| *was) != Some(muted) {
            seen.changes.push((muted, now));
        }
    }

    fn text(&self) -> String {
        let seen = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changes = seen
            .changes
            .iter()
            .map(|(muted, at)| format!("{}@{at}", if *muted { "muted" } else { "open" }))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{changes}; widest gap {} ms", seen.widest_gap_ms)
    }

    fn muted_once(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .changes
            .iter()
            .any(|(muted, _)| *muted)
    }
}

/// Reads a started call to its end and checks what the end did.
async fn end<R: Runtime>(
    app: &AppHandle<R>,
    platform: &dyn CallPlatform,
    voice_session_id: &str,
    ending: HowItEnds,
    checks: &mut Checks<'_>,
) {
    let trace = Trace::new();
    let looked = &trace;
    let mutes = MuteTrail::default();
    let muted = &mutes;
    let running = until(RUN_WITHIN, || async move {
        let state = call_state(app).await;
        looked.see(&state);
        (state["running"] == true && state["control"] == "connected").then_some(state)
    })
    .await;
    checks.push(Check::found(
        "the call runs with its control attached",
        running
            .as_ref()
            .is_some_and(|state| state["session"]["voice_session_id"] == voice_session_id),
        trace.text(),
    ));
    match platform.held().await {
        Ok(held) => checks.push(Check::found(
            "native code holds the call",
            held.call.is_some(),
            format!(
                "capture {:?}, muted {}",
                held.capture, held.microphone_muted
            ),
        )),
        Err(failure) => checks.push(Check::found(
            "native code holds the call",
            false,
            failure.message,
        )),
    }

    if ending == HowItEnds::LockScreen {
        // The script that runs the device reads this line as its cue: the call is up, so the
        // notification is posted, and the screen can be locked.
        checks.push(Check::found(
            "the call waits for the lock screen",
            running.is_some(),
            "the call is up and waits for the person's taps on its notification",
        ));
    }
    let ended = until(END_WITHIN, || async move {
        let state = call_state(app).await;
        looked.see(&state);
        if ending == HowItEnds::LockScreen
            && let Ok(held) = platform.held().await
            && held.call.is_some()
        {
            muted.see(held.microphone_muted);
        }
        (state["running"] == false && state["ended"].is_object()).then_some(state)
    })
    .await;
    let cause = ended
        .as_ref()
        .and_then(|state| state["ended"]["cause"].as_str())
        .unwrap_or("none");
    match ending {
        HowItEnds::ConnectionFails => checks.push(Check::found(
            "native code ends a call whose connection fails",
            matches!(cause, "native_failed" | "native_ended"),
            format!("cause {cause}; {}", trace.text()),
        )),
        HowItEnds::LockScreen => {
            checks.push(Check::found(
                "the call ends from its notification on the lock screen",
                cause == "native_ended",
                format!("cause {cause}; {}", trace.text()),
            ));
            checks.push(Check::found(
                "the microphone followed the taps on the lock screen",
                mutes.muted_once(),
                mutes.text(),
            ));
        }
    }
    let Some(ended) = ended else {
        return;
    };
    checks.push(Check::found(
        "the media stopped on this device",
        ended["ended"]["closed_locally"] == true,
        format!("closed_locally {}", ended["ended"]["closed_locally"]),
    ));
    checks.push(Check::found(
        "the host revoked the grant",
        ended["ended"]["host"]["kind"] == "revoked",
        format!("host {}", ended["ended"]["host"]["kind"]),
    ));
    let finalised = until(FINALISED_WITHIN, || async {
        let state = call_state(app).await;
        let broker = state["ended"]["broker"]
            .as_str()
            .unwrap_or("pending")
            .to_owned();
        (broker != "pending").then_some(broker)
    })
    .await;
    checks.push(Check::found(
        "the voice service was told the call is over",
        finalised
            .as_deref()
            .is_some_and(|broker| broker.starts_with("closed")),
        format!(
            "service {}",
            finalised.as_deref().unwrap_or("still pending")
        ),
    ));
    match platform.held().await {
        Ok(held) => checks.push(Check::found(
            "nothing held after the end",
            held.call.is_none(),
            format!("{held:?}"),
        )),
        Err(failure) => checks.push(Check::found(
            "nothing held after the end",
            false,
            failure.message,
        )),
    }
}

/// What a direction's audio counter shows, as a check. `unmeasured` says why a count below the
/// floor is no evidence of anything, when it is not: a direction whose source this machine has no
/// hardware for.
fn counter_check(
    name: &'static str,
    what: &str,
    floor: u64,
    value: Option<u64>,
    unmeasured: Option<String>,
) -> Check {
    match (value, unmeasured) {
        (Some(count), _) if count >= floor => {
            Check::found(name, true, format!("{what} {count}, floor {floor}"))
        }
        (Some(count), Some(why)) => {
            Check::not_measured(name, format!("{what} {count}, floor {floor}; {why}"))
        }
        (Some(count), None) => Check::found(name, false, format!("{what} {count}, floor {floor}")),
        (None, _) => Check::not_measured(name, format!("native code reported no {what}")),
    }
}

/// Reads the call's media from native code: what it carried and what the microphone is doing.
async fn media_of(platform: &dyn CallPlatform) -> Option<(Option<Media>, CaptureState)> {
    let held = platform.held().await.ok()?;
    Some((held.media, held.capture))
}

/// The audio packets the call has received, as native code counts them.
async fn packets_received(platform: &dyn CallPlatform) -> Option<u64> {
    media_of(platform)
        .await
        .and_then(|(media, _)| media)
        .and_then(|media| media.packets_received)
}

/// Whether the audio of all three kinds has crossed its floor.
fn all_crossed(media: &Media) -> bool {
    media.packets_received.is_some_and(|n| n >= AUDIO_FLOOR)
        && media.packets_sent.is_some_and(|n| n >= AUDIO_FLOOR)
        && media.played_samples.is_some_and(|n| n >= PLAYED_FLOOR)
}

/// Runs a call whose answer is a peer's: audio in both directions is read from the counters, the
/// script takes the voice service away, what must work without it is exercised, and the end is
/// read.
async fn outage<R: Runtime>(
    app: &AppHandle<R>,
    platform: &dyn CallPlatform,
    voice_session_id: &str,
    media_within: Duration,
    checks: &mut Checks<'_>,
) {
    let trace = Trace::new();
    let looked = &trace;
    let running = until(RUN_WITHIN, || async move {
        let state = call_state(app).await;
        looked.see(&state);
        (state["running"] == true && state["control"] == "connected").then_some(state)
    })
    .await;
    let runs = running
        .as_ref()
        .is_some_and(|state| state["session"]["voice_session_id"] == voice_session_id);
    checks.push(Check::found(
        "the call runs with its control attached",
        runs,
        trace.text(),
    ));
    if !runs {
        return;
    }
    match platform.held().await {
        Ok(held) => checks.push(Check::found(
            "native code holds the call",
            held.call.is_some(),
            format!(
                "capture {:?}, muted {}",
                held.capture, held.microphone_muted
            ),
        )),
        Err(failure) => checks.push(Check::found(
            "native code holds the call",
            false,
            failure.message,
        )),
    }

    // The audio each end received, read from the counters until all of them cross their floors.
    let last = std::sync::Mutex::new(None);
    let kept = &last;
    let _ = until(media_within, || async move {
        let reading = media_of(platform).await;
        let crossed = reading
            .as_ref()
            .and_then(|(media, _)| media.as_ref())
            .is_some_and(all_crossed);
        *kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = reading;
        crossed.then_some(())
    })
    .await;
    let reading = last
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let capture = reading.as_ref().map(|(_, capture)| *capture);
    let media = reading.and_then(|(media, _)| media);
    let silent_microphone = (capture != Some(CaptureState::Capturing))
        .then(|| format!("capture {capture:?}, so nothing was heard to send"));
    checks.push(counter_check(
        "audio reaches the call from the peer",
        "audio packets received",
        AUDIO_FLOOR,
        media.as_ref().and_then(|media| media.packets_received),
        None,
    ));
    checks.push(counter_check(
        "audio leaves the call for the peer",
        "audio packets sent",
        AUDIO_FLOOR,
        media.as_ref().and_then(|media| media.packets_sent),
        silent_microphone,
    ));
    checks.push(counter_check(
        "the call takes audio to the speaker side",
        "samples played",
        PLAYED_FLOOR,
        media.as_ref().and_then(|media| media.played_samples),
        None,
    ));
    // The figure, an estimate: from the entry of the start to this application's receipt of the
    // news that audio was played out. It is last of the media checks, and the script takes the
    // voice service away when it reads it.
    let figure = until(Duration::from_secs(10), || async {
        call_state(app).await["first_audio_ms"].as_u64()
    })
    .await;
    // Audio that arrived and samples that were played, with no news of audio played out, is a
    // detector that failed to tell: that is a failure. With either of the two unmeasured or under
    // its floor, the figure is only not measured.
    let played = media.as_ref().is_some_and(|media| {
        media.packets_received.is_some_and(|n| n >= AUDIO_FLOOR)
            && media.played_samples.is_some_and(|n| n >= PLAYED_FLOOR)
    });
    checks.push(match figure {
        Some(ms) => Check::found(
            "the first audio played out",
            true,
            format!(
                "figure first_audio_ms={ms}; from the entry of the start to the receipt of the news"
            ),
        ),
        None if played => Check::found(
            "the first audio played out",
            false,
            "native code told of no audio played out, though audio arrived and samples were played",
        ),
        None => Check::not_measured(
            "the first audio played out",
            "native code told of no audio played out",
        ),
    });

    // The script takes the voice service away. The call tells the person it cannot reach it.
    let unreachable = until(UNREACHABLE_WITHIN, || async {
        (call_state(app).await["control"] == "unreachable").then_some(())
    })
    .await
    .is_some();
    checks.push(Check::found(
        "the control reads unreachable when the service is gone",
        unreachable,
        trace.text(),
    ));

    // What works without the service: the microphone's mute and the speaker's silence are local.
    let mut local = Vec::new();
    for (what, name) in [
        (
            crate::commands::VoiceMute::Microphone,
            "the microphone mutes with the service gone",
        ),
        (
            crate::commands::VoiceMute::Playback,
            "the speaker is silenced with the service gone",
        ),
    ] {
        let done = commands::voice_set_muted(app.state(), what, true).await;
        let held = platform.held().await;
        let (ok, detail) = match (done, held) {
            (Ok(_), Ok(held)) => {
                let kept = match what {
                    crate::commands::VoiceMute::Microphone => held.microphone_muted,
                    crate::commands::VoiceMute::Playback => !held.playing,
                };
                (kept && held.call.is_some(), format!("held {held:?}"))
            }
            (Err(error), _) => (false, format!("{error:?}")),
            (_, Err(failure)) => (false, failure.message),
        };
        local.push((name, ok, detail));
    }
    for (name, ok, detail) in local {
        checks.push(Check::found(name, ok, detail));
    }
    // The media's baseline is taken now, with the service gone and the mute and the silence done,
    // so that packets that arrived before them do not count towards the media going on after them.
    let before = packets_received(platform).await;
    let after = match before {
        Some(before) => {
            let grown = until(MEDIA_GOES_ON_WITHIN, || async move {
                packets_received(platform).await.filter(|now| *now > before)
            })
            .await;
            match grown {
                Some(grown) => Some(grown),
                None => packets_received(platform).await,
            }
        }
        None => None,
    };
    checks.push(match (before, after) {
        (Some(before), Some(after)) => Check::found(
            "the media stays connected with the service gone",
            after > before,
            format!("audio packets received {before} then {after}"),
        ),
        _ => Check::not_measured(
            "the media stays connected with the service gone",
            "native code reported no audio packets received",
        ),
    });

    // The stop does not wait for the service: the media stops here, the host revokes, and the
    // service's closure is reported as not confirmed.
    let stopped = commands::voice_stop(app.clone(), app.state(), None).await;
    checks.push(Check::found(
        "a stop with the service gone returns",
        stopped.is_ok(),
        stopped
            .as_ref()
            .err()
            .map_or_else(String::new, |error| format!("{error:?}")),
    ));
    let ended = until(END_WITHIN, || async {
        let state = call_state(app).await;
        (state["running"] == false && state["ended"].is_object()).then_some(state)
    })
    .await;
    let Some(ended) = ended else {
        checks.push(Check::found(
            "the media stopped on this device",
            false,
            "the call never showed its end",
        ));
        return;
    };
    checks.push(Check::found(
        "the media stopped on this device",
        ended["ended"]["closed_locally"] == true,
        format!("closed_locally {}", ended["ended"]["closed_locally"]),
    ));
    checks.push(Check::found(
        "the host revoked the grant",
        ended["ended"]["host"]["kind"] == "revoked",
        format!("host {}", ended["ended"]["host"]["kind"]),
    ));
    let settled = until(UNCONFIRMED_WITHIN, || async {
        let state = call_state(app).await;
        let broker = state["ended"]["broker"]
            .as_str()
            .unwrap_or("pending")
            .to_owned();
        (broker != "pending").then_some(broker)
    })
    .await;
    checks.push(Check::found(
        "the closure of the call at the service is not confirmed",
        settled.as_deref() == Some("not_confirmed"),
        format!("service {}", settled.as_deref().unwrap_or("still pending")),
    ));
    match platform.held().await {
        Ok(held) => checks.push(Check::found(
            "nothing held after the end",
            held.call.is_none(),
            format!("{held:?}"),
        )),
        Err(failure) => checks.push(Check::found(
            "nothing held after the end",
            false,
            failure.message,
        )),
    }
}

/// Runs a whole call from the invitation to the call's end, and says what each step did. The
/// checks that follow a step that failed are not made: a check that did not run is not reported
/// as passed. `report` is given each check as it is made.
pub async fn call_check<R: Runtime>(
    app: &AppHandle<R>,
    platform: &dyn CallPlatform,
    harness: &Harness,
    report: &mut (dyn FnMut(&Check) + Send),
) -> Vec<Check> {
    let driver = match harness.mode {
        Mode::Delegating => app
            .path()
            .app_data_dir()
            .map_err(|error| error.to_string())
            .and_then(|data| PeerDriver::from_files(&data, harness)),
        Mode::NativeFailure | Mode::Outage | Mode::LockScreen => {
            Err("this mode plays no leg".to_owned())
        }
    };
    call_check_with(
        app,
        platform,
        harness,
        driver
            .as_ref()
            .map(|driver| driver as &dyn Driver)
            .map_err(String::as_str),
        report,
    )
    .await
}

/// As [`call_check`], with the driver a delegating run plays its leg through, or why there is none.
pub async fn call_check_with<R: Runtime>(
    app: &AppHandle<R>,
    platform: &dyn CallPlatform,
    harness: &Harness,
    driver: Result<&dyn Driver, &str>,
    report: &mut (dyn FnMut(&Check) + Send),
) -> Vec<Check> {
    let (invitation, mode) = (harness.invitation.as_str(), harness.mode);
    let mut checks = Checks {
        all: Vec::new(),
        report,
    };
    if mode == Mode::Delegating {
        // The shipped configuration answers every delegation that nothing was done; every other leg
        // is the gate's, which only a debug build can switch on, for the calls made from now on.
        let session = delegating::session_of(harness);
        checks.push(Check::found(
            "the host named a session to read",
            session.is_ok(),
            session.as_ref().err().copied().unwrap_or_default(),
        ));
        if session.is_err() {
            return checks.all;
        }
        if harness.leg != Leg::Production {
            app.state::<crate::voice::Calls>()
                .accept_host_delegations(true);
        }
    }
    if pair(app, invitation, &mut checks).await
        && connect(app, &mut checks).await
        && let Some(voice_session_id) = start(app, &harness.session_ids, &mut checks).await
    {
        match mode {
            Mode::NativeFailure => {
                end(
                    app,
                    platform,
                    &voice_session_id,
                    HowItEnds::ConnectionFails,
                    &mut checks,
                )
                .await;
            }
            Mode::LockScreen => {
                end(
                    app,
                    platform,
                    &voice_session_id,
                    HowItEnds::LockScreen,
                    &mut checks,
                )
                .await;
            }
            Mode::Outage => {
                let media = Duration::from_secs(harness.media_seconds);
                outage(app, platform, &voice_session_id, media, &mut checks).await;
            }
            Mode::Delegating => {
                delegating_call(
                    app,
                    platform,
                    &voice_session_id,
                    harness.leg,
                    driver,
                    &mut checks,
                )
                .await;
            }
        }
    }
    checks.all
}

/// Runs a call that hands spoken requests to the host: it is read running, one leg is played, and
/// the person ends it, with the voice service up, and the end is read.
async fn delegating_call<R: Runtime>(
    app: &AppHandle<R>,
    platform: &dyn CallPlatform,
    voice_session_id: &str,
    leg: Leg,
    driver: Result<&dyn Driver, &str>,
    checks: &mut Checks<'_>,
) {
    let trace = Trace::new();
    let looked = &trace;
    let running = until(RUN_WITHIN, || async move {
        let state = call_state(app).await;
        looked.see(&state);
        (state["running"] == true && state["control"] == "connected").then_some(state)
    })
    .await;
    let runs = running
        .as_ref()
        .is_some_and(|state| state["session"]["voice_session_id"] == voice_session_id);
    checks.push(Check::found(
        "the call runs with its control attached",
        runs,
        trace.text(),
    ));
    if !runs {
        return;
    }
    match platform.held().await {
        Ok(held) => checks.push(Check::found(
            "native code holds the call",
            held.call.is_some(),
            format!(
                "capture {:?}, muted {}",
                held.capture, held.microphone_muted
            ),
        )),
        Err(failure) => checks.push(Check::found(
            "native code holds the call",
            false,
            failure.message,
        )),
    }
    match driver {
        Ok(driver) => delegating::run(app, platform, driver, leg, checks).await,
        Err(why) => checks.push(Check::found("the peer's files are read", false, why)),
    }

    // The person ends the call with the voice service up, as in a call that ran its course.
    let stopped = commands::voice_stop(app.clone(), app.state(), None).await;
    checks.push(Check::found(
        "the person ends the call",
        stopped.is_ok(),
        stopped
            .as_ref()
            .err()
            .map_or_else(String::new, |error| format!("{error:?}")),
    ));
    let ended = until(END_WITHIN, || async {
        let state = call_state(app).await;
        (state["running"] == false && state["ended"].is_object()).then_some(state)
    })
    .await;
    let Some(ended) = ended else {
        checks.push(Check::found(
            "the media stopped on this device",
            false,
            "the call never showed its end",
        ));
        return;
    };
    checks.push(Check::found(
        "the media stopped on this device",
        ended["ended"]["closed_locally"] == true,
        format!("closed_locally {}", ended["ended"]["closed_locally"]),
    ));
    checks.push(Check::found(
        "the host revoked the grant",
        ended["ended"]["host"]["kind"] == "revoked",
        format!("host {}", ended["ended"]["host"]["kind"]),
    ));
    let finalised = until(FINALISED_WITHIN, || async {
        let state = call_state(app).await;
        let broker = state["ended"]["broker"]
            .as_str()
            .unwrap_or("pending")
            .to_owned();
        (broker != "pending").then_some(broker)
    })
    .await;
    checks.push(Check::found(
        "the voice service was told the call is over",
        finalised
            .as_deref()
            .is_some_and(|broker| broker.starts_with("closed")),
        format!(
            "service {}",
            finalised.as_deref().unwrap_or("still pending")
        ),
    ));
    let words = ended["ended"]["words"].as_str().unwrap_or_default();
    checks.push(Check::found(
        "the end names no request that may have been carried out",
        !words.contains("may or may not"),
        words,
    ));
    match platform.held().await {
        Ok(held) => checks.push(Check::found(
            "nothing held after the end",
            held.call.is_none(),
            format!("{held:?}"),
        )),
        Err(failure) => checks.push(Check::found(
            "nothing held after the end",
            false,
            failure.message,
        )),
    }
}
