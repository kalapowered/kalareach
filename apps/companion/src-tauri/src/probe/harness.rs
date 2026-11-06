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
//! A run is in one of two modes. By default the answer leads nowhere, so the connection fails,
//! native code ends the call, and the checks read the end: the device stopped the media, the
//! daemon revoked the grant and the stand-in was told the call was over. In the outage mode the
//! answer is a peer's in this same application, so the call connects and carries audio: the checks
//! read the counters of what each end received, wait for the script to take the voice service away,
//! and then exercise what must keep working without it (the microphone's mute, the speaker's
//! silence and a stop that does not wait for the service) and read the end, in which the service's
//! closure is reported as not confirmed. A direction whose audio the machine cannot measure, as a
//! simulator with no microphone cannot for the send direction, is reported as not measured.
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

/// Looks until `look` finds something or `within` passes.
async fn until<T, Fut: Future<Output = Option<T>>>(
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
async fn call_state<R: Runtime>(app: &AppHandle<R>) -> Value {
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
async fn start<R: Runtime>(app: &AppHandle<R>, checks: &mut Checks<'_>) -> Option<String> {
    let session = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()).to_string();
    let allowed = commands::voice_allow(
        app.state(),
        Subject::default(),
        json!({ "session_ids": [session], "actions": null }),
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
        "what a call would be was read",
    ));

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
    checks.push(Check::found(
        "the host started the call",
        id.is_some() && made["answer_sdp"] == "",
        "the host made the call and kept the provider's answer from the page",
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

/// Reads a started call to its end and checks what the end did.
async fn end<R: Runtime>(
    app: &AppHandle<R>,
    platform: &dyn CallPlatform,
    voice_session_id: &str,
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

    let ended = until(END_WITHIN, || async move {
        let state = call_state(app).await;
        looked.see(&state);
        (state["running"] == false && state["ended"].is_object()).then_some(state)
    })
    .await;
    let cause = ended
        .as_ref()
        .and_then(|state| state["ended"]["cause"].as_str())
        .unwrap_or("none");
    checks.push(Check::found(
        "native code ends a call whose connection fails",
        matches!(cause, "native_failed" | "native_ended"),
        format!("cause {cause}; {}", trace.text()),
    ));
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
    checks.push(match figure {
        Some(ms) => Check::found(
            "the first audio played out",
            true,
            format!(
                "figure first_audio_ms={ms}; from the entry of the start to the receipt of the news"
            ),
        ),
        None => Check::not_measured(
            "the first audio played out",
            "native code told of no audio played out",
        ),
    });
    let before = media.as_ref().and_then(|media| media.packets_received);

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
    let after = media_of(platform)
        .await
        .and_then(|(media, _)| media)
        .and_then(|media| media.packets_received);
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
    let (invitation, mode) = (harness.invitation.as_str(), harness.mode);
    let mut checks = Checks {
        all: Vec::new(),
        report,
    };
    if pair(app, invitation, &mut checks).await
        && connect(app, &mut checks).await
        && let Some(voice_session_id) = start(app, &mut checks).await
    {
        match mode {
            Mode::NativeFailure => end(app, platform, &voice_session_id, &mut checks).await,
            Mode::Outage => {
                let media = Duration::from_secs(harness.media_seconds);
                outage(app, platform, &voice_session_id, media, &mut checks).await;
            }
        }
    }
    checks.all
}
