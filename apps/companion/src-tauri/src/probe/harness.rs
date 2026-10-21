//! The checks a debug build runs for a whole call on a phone, against a host a harness started.
//!
//! The harness is a real daemon and a stand-in for the voice service on the machine the phone
//! runs on. A script puts a request in the application's data directory that names the stand-in's
//! origin, a token the stand-in's control accepts for the phone's account, and a direct invitation
//! to the daemon. The application pairs with the daemon from that invitation, the person allows
//! voice, and a call is started through the commands the page uses: native code opens the call and
//! makes the offer, the daemon creates the call at the stand-in, native code applies the answer
//! and is permitted, and the control attaches. The answer leads nowhere, so the connection fails,
//! native code ends the call, and the checks read the end: the device stopped the media, the
//! daemon revoked the grant and the stand-in was told the call was over.
//!
//! The request holds an invitation's secret and an account token for a stand-in, both thrown away
//! with the run, and is read once and removed.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use companion_platform::call::CallPlatform;
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
        Ok(Service {
            origin: self.origin.clone(),
            http: Arc::new(http),
            connector: ControlConnector::platform().map_err(|error| error.to_string())?,
        })
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
    Ok(Arc::new(Account::new(
        tokens,
        service,
        kr_protocol::service::GatewayOrigin::new(origin).map_err(|error| error.to_string())?,
        Arc::new(NoCarrier),
        Arc::new(|_| {}),
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
async fn pair<R: Runtime>(app: &AppHandle<R>, invitation: &str, checks: &mut Checks<'_>) -> bool {
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
async fn connect<R: Runtime>(app: &AppHandle<R>, checks: &mut Checks<'_>) -> bool {
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

/// Runs a whole call from the invitation to the call's end, and says what each step did. The
/// checks that follow a step that failed are not made: a check that did not run is not reported
/// as passed. `report` is given each check as it is made.
pub async fn call_check<R: Runtime>(
    app: &AppHandle<R>,
    platform: &dyn CallPlatform,
    invitation: &str,
    report: &mut (dyn FnMut(&Check) + Send),
) -> Vec<Check> {
    let mut checks = Checks {
        all: Vec::new(),
        report,
    };
    if pair(app, invitation, &mut checks).await
        && connect(app, &mut checks).await
        && let Some(voice_session_id) = start(app, &mut checks).await
    {
        end(app, platform, &voice_session_id, &mut checks).await;
    }
    checks.all
}
