//! A phone turns notifications on for the hosts it is paired with.
//!
//! The device is this crate's own backend paired with real in-process hosts. The native half (the
//! system's permission, the provider's token, the record the receiver answers a challenge into, the
//! limited key store), the notification service's gateway and the host's side of the registration
//! call (`HostLink`, which records what it was handed) are what a test has no phone, no Google and
//! no push-capable host for, so each is a small script; the phone's sequencing, its record and its
//! pairing records are the product's. What the devices' legs show of the receivers, of the real
//! gateway and of what a host takes is shown there; what these hold is the order and the keys the
//! application's core uses, and what it hands its registrar.
//!
//! Each case names the requirement row its own assertions show, in its own comment. The cases
//! that name none hold a defect that happened and can happen again.

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_platform::notify::{Permission, PreviewKeys};
use companion_platform::push::{PendingRegistration, PendingState};
use companion_tauri::device::Device;
use companion_tauri::push::{
    AskFuture, ConnectionRegistrar, HostLine, LineFuture, LineStop, Native, PushDesk, PushFuture,
    PushState, PushView, Reach, Registrar, Wiring,
};
use kr_client::pairing::paired::PairedHost;
use kr_client::services::ServiceFuture;
use kr_client::services::relay::{ServiceHttp, ServiceHttpAnswer};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, SecretName, SecretStore, load_notification_preview_key};
use kr_protocol::ids::DeviceKeyRevision;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::push::{DevicePushRegisterParams, DevicePushRegisterResult};
use kr_protocol::rights::ActionRight;
use net_support::Host;
use serde_json::{Value, json};
use support::{WATCHDOG, pair, phone_paired_with};

const VECTORS: &str = include_str!("../../../../fixtures/push/push.json");

tokio::task_local! {
    /// Set around a call of the desk by a test that wants the page's callback to fail inside that
    /// call, and nowhere else.
    static CALLBACK_FAILS_HERE: bool;
}

const FIRST_TOKEN: &str = "fZ9k-test-registration-token:APA91bExample";
const SECOND_TOKEN: &str = "gH2m-another-registration-token:APA91bExample";

/// How many times the receiver's record is read before the script has answered the challenge in it.
const READS_BEFORE_THE_ANSWER: usize = 2;

/// What the phone's native half has been asked, and what it holds.
struct Receiver {
    state: Mutex<ReceiverState>,
}

struct ReceiverState {
    permission: Permission,
    /// What the system answers when it is asked: a person who agrees makes the permission granted,
    /// and one who refuses leaves it as it was.
    when_asked: Permission,
    /// How many times the system was asked, and how many times the permission was read.
    asked: usize,
    permission_reads: usize,
    /// Whether a question about the permission is never answered, as when the application ends
    /// in the middle of it.
    permission_hangs: bool,
    /// Whether the question about the permission ends the task that asked it.
    permission_panics: bool,
    /// The reads of the permission, by their number, that wait to be released: the answer is the
    /// one the platform gave when it was asked, and reaches the asker when the test lets it.
    permission_held: BTreeSet<usize>,
    permission_released: BTreeSet<usize>,
    /// The number of the filing of the preview keys (the first is 1) that waits to be let go, and
    /// whether it has been let go.
    keys_hold: Option<usize>,
    keys_released: bool,
    /// How many filings of the preview keys have been asked.
    keys_asked: usize,
    /// Whether a filing of the preview keys fails.
    keys_fail: bool,
    /// How many of the next filings of the preview keys fail, and whether a filing that fails has
    /// first put the set it was handed where the receivers read it, as a store that fails part way
    /// does.
    keys_fail_next: usize,
    keys_partly_applied: bool,
    /// The reads of the token, by their number, that wait to be released in the same way.
    token_held: BTreeSet<usize>,
    token_released: BTreeSet<usize>,
    /// How many reads of the token have been asked, and how many of them were told the token is
    /// out of reach.
    token_reads: usize,
    /// How many reads of the token are answered with a token before the platform says there is none.
    token_readable_for: Option<usize>,
    /// The provider's token, once the provider has made one.
    token: Option<String>,
    /// Reads of the token that say there is none yet, before there is one.
    reads_without_a_token: usize,
    pending: Option<PendingRegistration>,
    reads_of_pending: usize,
    /// Whether the challenge is answered when it has been waited for, or held until released.
    answering: bool,
    /// A registration was written while another one's challenge was still waiting.
    overlapped: bool,
    /// What the receivers hold now, and every set they were handed, in the order they were handed.
    keys_now: Option<PreviewKeys>,
    keys_history: Vec<PreviewKeys>,
}

impl Receiver {
    fn new(token: &str) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ReceiverState {
                permission: Permission::Granted,
                when_asked: Permission::Granted,
                asked: 0,
                permission_reads: 0,
                permission_hangs: false,
                permission_panics: false,
                permission_held: BTreeSet::new(),
                permission_released: BTreeSet::new(),
                keys_hold: None,
                keys_released: false,
                keys_asked: 0,
                keys_fail: false,
                keys_fail_next: 0,
                keys_partly_applied: false,
                token_held: BTreeSet::new(),
                token_released: BTreeSet::new(),
                token_reads: 0,
                token_readable_for: None,
                token: Some(token.to_owned()),
                reads_without_a_token: 0,
                pending: None,
                reads_of_pending: 0,
                answering: true,
                overlapped: false,
                keys_now: None,
                keys_history: Vec::new(),
            }),
        })
    }

    fn with(&self, change: impl FnOnce(&mut ReceiverState)) {
        change(&mut self.state.lock().expect("the receiver"));
    }

    /// The provider gives the installation `token`.
    fn token_is(&self, token: &str) {
        self.with(|state| state.token = Some(token.to_owned()));
    }
}

impl Native for Receiver {
    fn permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async move {
            let (number, answer, hangs, panics) = {
                let mut state = self.state.lock().expect("the receiver");
                state.permission_reads += 1;
                (
                    state.permission_reads,
                    state.permission,
                    state.permission_hangs,
                    state.permission_panics,
                )
            };
            assert!(!panics, "the task that asked about the permission ends");
            if hangs {
                std::future::pending::<()>().await;
            }
            // The answer is the one the platform had when it was asked, whenever it arrives.
            loop {
                {
                    let state = self.state.lock().expect("the receiver");
                    if !state.permission_held.contains(&number)
                        || state.permission_released.contains(&number)
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(answer)
        })
    }

    fn ask_permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("the receiver");
            state.asked += 1;
            if state.when_asked == Permission::Granted {
                state.permission = Permission::Granted;
            }
            Ok(state.when_asked)
        })
    }

    fn token(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async move {
            let (number, answer) = {
                let mut state = self.state.lock().expect("the receiver");
                state.token_reads += 1;
                let number = state.token_reads;
                if state.reads_without_a_token > 0 {
                    state.reads_without_a_token -= 1;
                    return Ok(None);
                }
                if state.token_readable_for.is_some_and(|reads| number > reads) {
                    return Ok(None);
                }
                (number, state.token.clone())
            };
            // The answer is the token the provider held when it was asked, whenever it arrives.
            loop {
                {
                    let state = self.state.lock().expect("the receiver");
                    if !state.token_held.contains(&number) || state.token_released.contains(&number)
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok(answer)
        })
    }

    fn pending_set<'a>(&'a self, record: &'a PendingRegistration) -> PushFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("the receiver");
            if state
                .pending
                .as_ref()
                .is_some_and(|held| held.state == PendingState::Pending)
            {
                state.overlapped = true;
            }
            state.pending = Some(record.clone());
            state.reads_of_pending = 0;
            Ok(())
        })
    }

    fn pending_get(&self) -> PushFuture<'_, Option<PendingRegistration>> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("the receiver");
            state.reads_of_pending += 1;
            // The receiver answers a challenge the gateway sent once it has been waited for.
            if state.answering
                && state.reads_of_pending >= READS_BEFORE_THE_ANSWER
                && let Some(held) = state.pending.as_mut()
                && held.state == PendingState::Pending
            {
                held.state = PendingState::Answered;
            }
            Ok(state.pending.clone())
        })
    }

    fn preview_keys<'a>(&'a self, keys: &'a PreviewKeys) -> PushFuture<'a, ()> {
        Box::pin(async move {
            let held = {
                let mut state = self.state.lock().expect("the receiver");
                state.keys_asked += 1;
                state.keys_hold == Some(state.keys_asked)
            };
            // A held filing is handed over when the test lets it go, and not before.
            while held && !self.state.lock().expect("the receiver").keys_released {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let mut state = self.state.lock().expect("the receiver");
            if state.keys_fail || state.keys_fail_next > 0 {
                state.keys_fail_next = state.keys_fail_next.saturating_sub(1);
                if state.keys_partly_applied {
                    state.keys_now = Some(keys.clone());
                }
                return Err("the receivers' store refused the keys".to_owned());
            }
            state.keys_now = Some(keys.clone());
            state.keys_history.push(keys.clone());
            Ok(())
        })
    }

    fn route(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async move { Ok(None) })
    }
}

/// What the host was sent, and where the script waits.
#[derive(Default)]
struct Registered {
    /// The hosts the phone opened a connection to.
    connected: Vec<kr_protocol::ids::DeviceId>,
    /// How each run reached its host, in the order the runs asked.
    reaches: Vec<Reach>,
    /// The host, and the sender record the credential it was handed is for.
    credentials: Vec<(kr_protocol::ids::DeviceId, Value)>,
    /// The host, and the preview key it was told of.
    keys: Vec<(
        kr_protocol::ids::DeviceId,
        kr_protocol::scalars::NotificationPreviewKey,
    )>,
    /// Whether the connection waits to be let through, and whether the host's answer to the
    /// registration does.
    hold_connection: bool,
    hold_answer: bool,
    /// What the registration ends in instead of the host's answer.
    register_stops: Option<LineStop>,
    /// What a connection to the host fails with, when it does.
    connect_fails: Option<String>,
}

/// Waits for as long as `held` says of the script that a step is held.
async fn while_held(script: &Mutex<Registered>, held: impl Fn(&Registered) -> bool) {
    loop {
        let now = held(&script.lock().expect("what was handed"));
        if !now {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The host's side, as a script: a connection, and the two changes made over it.
struct HostLink(Arc<Mutex<Registered>>);

impl Registrar for HostLink {
    fn connect<'a>(
        &'a self,
        host: &'a PairedHost,
        reach: Reach,
    ) -> PushFuture<'a, Box<dyn HostLine + 'a>> {
        Box::pin(async move {
            let fails = {
                let mut script = self.0.lock().expect("what was handed");
                script.reaches.push(reach);
                script.connected.push(host.host_device_id);
                script.connect_fails.clone()
            };
            if let Some(words) = fails {
                return Err(words);
            }
            while_held(&self.0, |script| script.hold_connection).await;
            Ok(Box::new(Line {
                script: Arc::clone(&self.0),
                host: host.host_device_id,
                device: host.device_id.to_string(),
            }) as Box<dyn HostLine + 'a>)
        })
    }
}

struct Line {
    script: Arc<Mutex<Registered>>,
    host: kr_protocol::ids::DeviceId,
    /// The host's identifier for this phone.
    device: String,
}

/// The host's answer to a registration, as the vectors record it, for the phone named `device`.
fn registration_answer(device: &str) -> DevicePushRegisterResult {
    let records = vectors()["records"].clone();
    serde_json::from_value(json!({
        "device_id": device,
        "installation_id": records["installation_binding"]["installation_id"],
        "sender_record_id": records["sender_record"]["binding"]["sender_record_id"],
        "credential_expires_at_ms": "1769817600000",
    }))
    .expect("a result")
}

impl HostLine for Line {
    fn register(
        &mut self,
        params: DevicePushRegisterParams,
    ) -> LineFuture<'_, DevicePushRegisterResult> {
        Box::pin(async move {
            let stop = {
                let mut script = self.script.lock().expect("what was handed");
                script.credentials.push((
                    self.host,
                    json!({
                        "sender_record_id": params.credential.sender_record_id.to_string(),
                        "previews_enabled": params.previews_enabled,
                    }),
                ));
                script.register_stops.clone()
            };
            while_held(&self.script, |script| script.hold_answer).await;
            match stop {
                Some(stop) => Err(stop),
                None => Ok(registration_answer(&self.device)),
            }
        })
    }

    fn update_preview_key(
        &mut self,
        preview_key: kr_protocol::scalars::NotificationPreviewKey,
        _revision: DeviceKeyRevision,
    ) -> LineFuture<'_, ()> {
        Box::pin(async move {
            self.script
                .lock()
                .expect("what was handed")
                .keys
                .push((self.host, preview_key));
            Ok(())
        })
    }
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the push vectors")
}

/// The notification service, as a script: it takes a proposal and says it sent the challenge, and
/// issues the credential the vectors record. It keeps the tokens it was proposed.
struct Gateway {
    proposed: Mutex<Vec<String>>,
    /// Whether the answer to an authorisation request is held until released, and how many such
    /// requests have reached the gateway.
    issue: Mutex<Issue>,
}

#[derive(Default)]
struct Issue {
    held: bool,
    reached: usize,
}

impl Gateway {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            proposed: Mutex::new(Vec::new()),
            issue: Mutex::new(Issue::default()),
        })
    }

    /// Holds (or lets go) the answers to authorisation requests.
    fn hold_issue(&self, held: bool) {
        self.issue.lock().expect("the issue script").held = held;
    }

    fn issue_requests(&self) -> usize {
        self.issue.lock().expect("the issue script").reached
    }
}

impl fmt::Debug for Gateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Gateway")
    }
}

impl ServiceHttp for Gateway {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer> {
        let sent: Value = serde_json::from_slice(body).expect("a request");
        let records = vectors()["records"].clone();
        let is_issue = url.ends_with("/api/push/sender/issue");
        let answer = if is_issue {
            json!({ "ok": true, "data": {
                "record": records["sender_record"],
                "credential": records["delivery_credential"],
            }})
        } else {
            let proposal = &sent["body"]["installation_register"]["request"]["propose"]["proposal"];
            self.proposed.lock().expect("the proposals").push(
                proposal["registration_token"]
                    .as_str()
                    .expect("a token")
                    .to_owned(),
            );
            json!({ "ok": true, "data": {
                "state": "pending",
                "registration_id": proposal["registration_id"],
                "challenge_expires_at_ms": "1767225900000",
                "challenge_sent": true,
            }})
        };
        Box::pin(async move {
            if is_issue {
                self.issue.lock().expect("the issue script").reached += 1;
                // The answer reaches the phone when the test lets it go.
                loop {
                    let held = self.issue.lock().expect("the issue script").held;
                    if !held {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            Ok(ServiceHttpAnswer {
                status: 200,
                body: serde_json::to_vec(&answer).expect("an answer"),
            })
        })
    }
}

/// The desk over a phone paired with `hosts`, with the scripts in the native half's and the
/// gateway's places.
struct Desk {
    desk: Arc<PushDesk>,
    receiver: Arc<Receiver>,
    gateway: Arc<Gateway>,
    registered: Arc<Mutex<Registered>>,
    device: Arc<Device>,
    /// What the desk's clock is ahead of the real one, so that a test can let time pass.
    clock_ahead_ms: Arc<AtomicU64>,
    /// How many times the desk told the page that what it shows changed.
    changes: Arc<AtomicUsize>,
    /// Kept so the phone's records outlive the test.
    _phone: support::Phone,
}

impl Desk {
    fn view(&self) -> PushView {
        self.desk.view()
    }

    /// The references of the paired hosts, oldest first.
    fn references(&self) -> Vec<String> {
        let mut views = self.view().hosts;
        views.reverse();
        views.into_iter().map(|host| host.reference).collect()
    }

    /// Waits until the first host's words contain `wanted`.
    async fn until_words(&self, wanted: &str) {
        let words = || self.view().hosts[0].words.clone();
        tokio::time::timeout(WATCHDOG, async {
            while !words().contains(wanted) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the words never said {wanted:?}: they say {:?}", words()));
    }

    /// Waits until `holds` says of the hosts' states what is wanted.
    async fn until(&self, holds: impl Fn(&[PushState]) -> bool) -> Vec<PushState> {
        states_until(&self.desk, holds).await
    }

    /// Lets a minute and more pass for the desk's clock.
    fn let_time_pass(&self) {
        self.clock_ahead_ms
            .fetch_add(2 * 60 * 1000, Ordering::SeqCst);
    }
}

/// Waits until `holds` says of the hosts' states what is wanted.
async fn states_until(desk: &PushDesk, holds: impl Fn(&[PushState]) -> bool) -> Vec<PushState> {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let states: Vec<PushState> = desk.view().hosts.iter().map(|host| host.state).collect();
            if holds(&states) {
                return states;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the hosts did not come to the state wanted: {:?}",
            desk.view()
                .hosts
                .iter()
                .map(|host| (host.state, host.words.clone()))
                .collect::<Vec<_>>()
        )
    })
}

/// Waits until `holds`, which is a condition of what the scripts have recorded.
async fn eventually(what: &str, holds: impl Fn() -> bool) {
    tokio::time::timeout(WATCHDOG, async {
        while !holds() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("it never came about: {what}"));
}

/// What the gateway was proposed, in order.
fn proposed(gateway: &Gateway) -> Vec<String> {
    gateway.proposed.lock().expect("the proposals").clone()
}

/// A look at where notifications stand, as the application makes at its start, when it comes to the
/// front and when the network changes.
async fn look(desk: &Arc<PushDesk>) {
    desk.refresh().await.expect("a look");
}

async fn desk(hosts: &[&Host], owner: &DeviceKeys, receiver: Arc<Receiver>) -> Desk {
    desk_reaching(hosts, owner, receiver, |_, script| {
        Arc::new(HostLink(Arc::clone(script))) as Arc<dyn Registrar>
    })
    .await
}

/// A desk over a phone paired with `hosts`, whose registrar `registrar` makes from the phone's
/// device and the script it records into.
async fn desk_reaching(
    hosts: &[&Host],
    owner: &DeviceKeys,
    receiver: Arc<Receiver>,
    registrar: impl FnOnce(&Arc<Device>, &Arc<Mutex<Registered>>) -> Arc<dyn Registrar>,
) -> Desk {
    let phone = phone_paired_with(hosts[0], owner, &[ActionRight::SessionView]).await;
    for other in &hosts[1..] {
        pair(&phone, other, owner, &[ActionRight::SessionView]).await;
    }
    let device = phone.companion.device();
    let registered = Arc::new(Mutex::new(Registered::default()));
    let opened = open_with(
        phone.data.path(),
        &device,
        &receiver,
        registrar(&device, &registered),
    );
    Desk {
        desk: opened.desk,
        receiver,
        gateway: opened.gateway,
        registered,
        device,
        clock_ahead_ms: opened.clock_ahead_ms,
        changes: opened.changes,
        _phone: phone,
    }
}

/// A desk opened over the record in `data`, with a gateway of its own and a clock that can be set
/// ahead: what the application opens each time it starts.
struct Opened {
    desk: Arc<PushDesk>,
    gateway: Arc<Gateway>,
    clock_ahead_ms: Arc<AtomicU64>,
    /// How many times the desk told the page that what it shows changed.
    changes: Arc<AtomicUsize>,
}

impl Opened {
    /// Lets a minute and more pass for the desk's clock.
    fn let_time_pass(&self) {
        self.clock_ahead_ms
            .fetch_add(2 * 60 * 1000, Ordering::SeqCst);
    }
}

fn open_over(
    data: &Path,
    device: &Arc<Device>,
    receiver: &Arc<Receiver>,
    registered: &Arc<Mutex<Registered>>,
) -> Opened {
    open_with(
        data,
        device,
        receiver,
        Arc::new(HostLink(Arc::clone(registered))),
    )
}

fn open_with(
    data: &Path,
    device: &Arc<Device>,
    receiver: &Arc<Receiver>,
    registrar: Arc<dyn Registrar>,
) -> Opened {
    let gateway = Gateway::new();
    let http = Arc::clone(&gateway);
    let clock_ahead_ms = Arc::new(AtomicU64::new(0));
    let ahead = Arc::clone(&clock_ahead_ms);
    let changes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&changes);
    let desk = PushDesk::open(
        data,
        Arc::clone(device),
        Arc::clone(receiver) as Arc<dyn Native>,
        registrar,
        Wiring {
            http: Arc::new(move |_| Ok(Arc::clone(&http) as Arc<dyn ServiceHttp>)),
            clock: Arc::new(move || kr_ipc::now_ms().get() + ahead.load(Ordering::SeqCst)),
        },
        move || {
            counted.fetch_add(1, Ordering::SeqCst);
            // Where a test asks the page's callback to fail in its own task, as a panic in the page
            // does. The desk's runs are tasks of their own, which the scope does not reach.
            assert!(
                !CALLBACK_FAILS_HERE
                    .try_with(|fails| *fails)
                    .unwrap_or(false),
                "the page's callback failed"
            );
        },
    )
    .expect("the desk opens");
    Opened {
        desk,
        gateway,
        clock_ahead_ms,
        changes,
    }
}

/// KR-REQ-16.08: the host the person asked for ends up holding a credential the gateway issued for
/// it, and the page's row says the notifications are on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_the_person_asked_for_is_handed_the_credential_the_gateway_issued() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);

    assert_eq!(
        phone.view().hosts[0].state,
        PushState::Off,
        "nothing before the person asks"
    );
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;

    let handed = phone.registered.lock().expect("what was handed");
    assert_eq!(
        handed.credentials.len(),
        1,
        "the host was handed one registration"
    );
    assert_eq!(
        handed.credentials[0].1["sender_record_id"],
        vectors()["records"]["sender_record"]["binding"]["sender_record_id"],
        "under the authorisation the gateway issued"
    );
    assert_eq!(
        phone
            .gateway
            .proposed
            .lock()
            .expect("the proposals")
            .as_slice(),
        [FIRST_TOKEN],
        "the gateway was proposed the token the provider gave"
    );
}

/// KR-REQ-16.08: a registration the phone stopped itself, as it does for an account that has left,
/// is shown in the phone's own words; only a host's refusal or silence is shown as the host not
/// taking the phone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_the_phone_made_itself_is_not_shown_as_the_host_refusing() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);

    let own = "Sign in again: the account on this phone changed.";
    phone.registered.lock().expect("the script").register_stops =
        Some(LineStop::Phone(own.to_owned()));
    phone.desk.enable(&reference).expect("the person asks");
    phone
        .until(|states| states == [PushState::NeedsAttention])
        .await;
    assert_eq!(phone.view().hosts[0].words, own);

    let refusal = "the host did not answer in time";
    phone.registered.lock().expect("the script").register_stops =
        Some(LineStop::Host(refusal.to_owned()));
    phone
        .desk
        .enable(&reference)
        .expect("the person asks again");
    phone.until_words("The host did not take this phone").await;
    assert!(
        phone.view().hosts[0].words.ends_with(refusal),
        "{:?}",
        phone.view().hosts[0].words
    );
}

/// KR-REQ-16.11: what the receivers hold is this phone's preview seed, the one the host was told the
/// public half of, under that key's identifier, and the public key of the host that seals to it,
/// under the identifier its previews name it by. The authorisation key's seed is not what is filed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_keys_filed_for_the_receivers_are_the_preview_key_the_host_was_told_of_and_the_hosts() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;

    let filed = held_keys(&phone).expect("the receivers were handed keys");
    assert_eq!(filed.recipients.len(), 1, "one seed was filed");
    let recipient = &filed.recipients[0];
    // The seed that was filed, read back as the receivers read their key.
    let store = MemoryStore::new();
    let name = SecretName::device_key(
        companion_platform::secrets::DEVICE_SCOPE,
        KeyPurpose::NotificationPreview,
    )
    .expect("a name");
    store.set(&name, &recipient.seed).expect("the seed is kept");
    let derived = load_notification_preview_key(&store, companion_platform::secrets::DEVICE_SCOPE)
        .expect("the key loads")
        .expect("a key");
    let handed = phone.registered.lock().expect("what was handed");
    assert_eq!(
        derived.public(),
        &handed.keys[0].1,
        "the seed filed is the one the host's preview key is made from"
    );
    assert_eq!(
        &recipient.id,
        derived.key_id().as_bytes(),
        "under that key's identifier"
    );
    // The host's key, under the identifier its sealed previews name it by.
    let paired = phone
        .device
        .pairing()
        .hosts
        .list()
        .expect("the paired hosts")
        .remove(0);
    let key = paired.host_keys.notification_preview;
    assert_eq!(filed.senders.len(), 1, "one host's key was filed");
    assert_eq!(filed.senders[0].key, *key.as_bytes());
    assert_eq!(
        &filed.senders[0].id,
        kr_protocol::pairing::key_id(KeyPurpose::NotificationPreview, key.as_bytes()).as_bytes()
    );
    // The control: the installation's authorisation seed is another secret, which the phone holds
    // and the application's secure store gives back, and it is not what is filed.
    let authorisation = phone
        .device
        .identity()
        .secrets
        .get(
            &SecretName::device_key(
                companion_platform::secrets::DEVICE_SCOPE,
                KeyPurpose::Authorisation,
            )
            .expect("a name"),
        )
        .expect("the store answers")
        .expect("the phone holds an authorisation seed");
    assert_ne!(
        authorisation.expose(),
        recipient.seed.as_slice(),
        "the authorisation seed is not what is filed"
    );
}

/// What the receivers hold now.
fn held_keys(phone: &Desk) -> Option<PreviewKeys> {
    phone
        .receiver
        .state
        .lock()
        .expect("the receiver")
        .keys_now
        .clone()
}

/// KR-REQ-16.08: the phone keeps one record of the registration it waits for and the gateway one
/// pending attempt, so two hosts asked together are registered one after the other. Neither is told
/// that a newer registration replaced it, and each is handed the credential the gateway issued.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hosts_that_ask_together_register_one_after_the_other() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let phone = desk(&[&first, &second], &owner, Receiver::new(FIRST_TOKEN)).await;
    assert_eq!(phone.view().hosts.len(), 2);
    for reference in phone.references() {
        phone.desk.enable(&reference).expect("the person asks");
    }
    phone
        .until(|states| states == [PushState::On, PushState::On])
        .await;

    assert!(
        !phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .overlapped,
        "a registration was written while another's challenge was still waiting"
    );
    let handed = phone.registered.lock().expect("what was handed");
    let hosts: BTreeSet<_> = handed.credentials.iter().map(|each| each.0).collect();
    assert_eq!(hosts.len(), 2, "each host was handed a credential");
    for each in &handed.credentials {
        assert_eq!(
            each.1["sender_record_id"],
            vectors()["records"]["sender_record"]["binding"]["sender_record_id"],
            "the credential the gateway issued"
        );
    }
}

/// KR-REQ-16.16: a token the system changes while a host is registering is not lost. The run that
/// began with the old token ends, and the host is registered again with the new one, with nothing
/// asked of the person.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_that_changes_while_a_host_registers_is_registered_again_when_that_run_ends() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    receiver.with(|state| state.answering = false);
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::Working]).await;
    // The run is waiting for its challenge to be answered, as the provider changes the token.
    tokio::time::timeout(WATCHDOG, async {
        while phone
            .gateway
            .proposed
            .lock()
            .expect("the proposals")
            .is_empty()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the first token was proposed");
    phone.receiver.token_is(SECOND_TOKEN);
    look(&phone.desk).await;

    // The challenge is answered; the run ends, and the new token is what the host is registered with.
    phone.receiver.with(|state| state.answering = true);
    tokio::time::timeout(WATCHDOG, async {
        while phone.gateway.proposed.lock().expect("the proposals").len() < 2 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the new token was proposed once the first run had ended");
    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(
        phone
            .gateway
            .proposed
            .lock()
            .expect("the proposals")
            .as_slice(),
        [FIRST_TOKEN, SECOND_TOKEN]
    );
}

/// The provider makes a registration token a moment after the person agrees, so the sequence waits
/// for it and does not stop with "no token yet" at the first look.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_that_arrives_a_moment_after_the_permission_is_waited_for() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    receiver.with(|state| state.reads_without_a_token = 3);
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(
        phone
            .gateway
            .proposed
            .lock()
            .expect("the proposals")
            .as_slice(),
        [FIRST_TOKEN]
    );
}

/// The system's permission question is asked when the person chooses to turn
/// notifications on, and by nothing else. A person who refused once leaves the permission unread
/// as granted or denied on some phones, and the look the application makes at its start, when it
/// comes to the front or when the network changes finds a host that stopped for it: that look
/// reads the permission and puts no dialog on the screen the person is on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_look_the_application_makes_by_itself_never_asks_the_system_for_permission() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    receiver.with(|state| {
        state.permission = Permission::Unknown;
        state.when_asked = Permission::Denied;
    });
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    let asked = |phone: &Desk| phone.receiver.state.lock().expect("the receiver").asked;
    phone.desk.enable(&reference).expect("the person asks");
    phone.until_words("off for this app").await;
    assert_eq!(asked(&phone), 1, "the person's own choice asked the system");

    // Time passes, and the application looks again by itself.
    phone.let_time_pass();
    look(&phone.desk).await;
    phone.until_words("not allowed for this app yet").await;
    assert_eq!(
        asked(&phone),
        1,
        "a look the application made by itself asked the system again"
    );

    // The person chooses again, and only then is the system asked once more.
    phone
        .desk
        .enable(&reference)
        .expect("the person asks again");
    phone.until_words("off for this app").await;
    assert_eq!(asked(&phone), 2);
}

/// KR-REQ-16.16: a token the provider gave while the application was not running is registered at
/// the next look. A host is on only while the digest its registration proposed is the digest of the
/// token the provider holds, so what the application missed is found by comparing and does not
/// depend on anything the platform remembered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_the_provider_gave_while_the_application_was_not_running_is_registered_at_the_next_look()
 {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;

    // The application ends, and the provider gives another token while it is gone.
    let restarted = open_over(
        phone._phone.data.path(),
        &phone.device,
        &Receiver::new(SECOND_TOKEN),
        &phone.registered,
    );
    assert_eq!(restarted.desk.view().hosts[0].state, PushState::On);
    look(&restarted.desk).await;
    states_until(&restarted.desk, |states| states == [PushState::On]).await;
    assert_eq!(
        proposed(&restarted.gateway),
        [SECOND_TOKEN],
        "the token the provider holds is the one registered"
    );
}

/// KR-REQ-16.16: a change found while a host's run is under way is not lost when the application
/// ends. The run that proposed the old token ends well, and the host does not become on with it: it
/// stays working while the run goes round again, so an application that ends in the repeat's first
/// question to the platform leaves the host needing the retry, and the next start registers the
/// token the provider holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_found_while_a_run_is_under_way_is_not_lost_when_the_application_ends() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    receiver.with(|state| state.answering = false);
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    eventually("the first token was proposed", || {
        proposed(&phone.gateway) == [FIRST_TOKEN]
    })
    .await;

    // The provider gives another token and the application looks. Then the challenge is answered,
    // and the run is held at the first question of its repeat.
    phone.receiver.token_is(SECOND_TOKEN);
    look(&phone.desk).await;
    let reads = phone
        .receiver
        .state
        .lock()
        .expect("the receiver")
        .permission_reads;
    phone.receiver.with(|state| {
        state.permission_hangs = true;
        state.answering = true;
    });
    eventually("the run went round again", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .permission_reads
            > reads
    })
    .await;

    let restarted = open_over(
        phone._phone.data.path(),
        &phone.device,
        &Receiver::new(SECOND_TOKEN),
        &phone.registered,
    );
    assert_eq!(
        restarted.desk.view().hosts[0].state,
        PushState::NeedsAttention,
        "the host is on with the token the run proposed, which the provider no longer holds"
    );
    restarted.let_time_pass();
    look(&restarted.desk).await;
    states_until(&restarted.desk, |states| states == [PushState::On]).await;
    assert_eq!(proposed(&restarted.gateway), [SECOND_TOKEN]);
}

/// KR-REQ-16.16: two hosts are on, the provider gives another token, and the application ends in
/// the look that found it, with both runs under way. Both hosts are then marked, as one write, and
/// the next start registers both with the token the provider holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_application_ending_in_the_look_that_found_a_new_token_loses_it_for_neither_host() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let phone = desk(&[&first, &second], &owner, Receiver::new(FIRST_TOKEN)).await;
    for reference in phone.references() {
        phone.desk.enable(&reference).expect("the person asks");
    }
    phone
        .until(|states| states == [PushState::On, PushState::On])
        .await;

    // The runs the look starts hang at their first question to the platform, as they do when the
    // application ends in them.
    phone.receiver.token_is(SECOND_TOKEN);
    phone.receiver.with(|state| state.permission_hangs = true);
    look(&phone.desk).await;
    assert_eq!(
        phone
            .view()
            .hosts
            .iter()
            .map(|each| each.state)
            .collect::<Vec<_>>(),
        [PushState::Working, PushState::Working],
        "both hosts were marked, and a run holds each"
    );

    let restarted = open_over(
        phone._phone.data.path(),
        &phone.device,
        &Receiver::new(SECOND_TOKEN),
        &phone.registered,
    );
    assert_eq!(
        restarted
            .desk
            .view()
            .hosts
            .iter()
            .map(|each| each.state)
            .collect::<Vec<_>>(),
        [PushState::NeedsAttention, PushState::NeedsAttention],
        "a host is still shown as on with a token the gateway does not know"
    );
    restarted.let_time_pass();
    look(&restarted.desk).await;
    states_until(&restarted.desk, |states| {
        states == [PushState::On, PushState::On]
    })
    .await;
    assert_eq!(
        proposed(&restarted.gateway),
        [SECOND_TOKEN, SECOND_TOKEN],
        "each host registered the token the provider holds"
    );
}

/// A token that changes and changes back before any look is the token each registration proposed,
/// so there is nothing to register and nothing is marked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_that_changed_and_changed_back_is_not_registered_again() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;

    phone.receiver.token_is(SECOND_TOKEN);
    phone.receiver.token_is(FIRST_TOKEN);
    look(&phone.desk).await;
    // A host that a look marks is working before the look returns.
    assert_eq!(phone.view().hosts[0].state, PushState::On);
    assert_eq!(proposed(&phone.gateway), [FIRST_TOKEN]);
}

/// A run that proposed one token while the provider has gone back to the other is not the
/// registration of the token it holds: the host does not become on with it, and the run goes round
/// again with the token it holds now.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_that_changed_back_while_a_run_proposed_the_other_is_registered_again() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(SECOND_TOKEN);
    receiver.with(|state| state.answering = false);
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    eventually("the other token was proposed", || {
        proposed(&phone.gateway) == [SECOND_TOKEN]
    })
    .await;

    phone.receiver.token_is(FIRST_TOKEN);
    phone.receiver.with(|state| state.answering = true);
    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(proposed(&phone.gateway), [SECOND_TOKEN, FIRST_TOKEN]);
}

/// A record written before the digest was kept has none, and is registered again at the next look:
/// a host is on only while a digest says which token it proposed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_with_no_digest_is_registered_again_at_the_next_look() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;

    // The record as an earlier build wrote it: without the digest.
    let file = phone._phone.data.path().join("push").join("push.json");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("the record")).expect("a record");
    for kept in record["hosts"].as_object_mut().expect("hosts").values_mut() {
        kept.as_object_mut().expect("a host").remove("registered");
    }
    std::fs::write(&file, serde_json::to_vec(&record).expect("a record")).expect("written");

    let restarted = open_over(
        phone._phone.data.path(),
        &phone.device,
        &Receiver::new(FIRST_TOKEN),
        &phone.registered,
    );
    assert_eq!(restarted.desk.view().hosts[0].state, PushState::On);
    look(&restarted.desk).await;
    eventually("the host was registered again", || {
        proposed(&restarted.gateway) == [FIRST_TOKEN]
    })
    .await;
    states_until(&restarted.desk, |states| states == [PushState::On]).await;

    // The digest is kept now: the next start finds nothing to register.
    let again = open_over(
        phone._phone.data.path(),
        &phone.device,
        &Receiver::new(FIRST_TOKEN),
        &phone.registered,
    );
    look(&again.desk).await;
    assert_eq!(again.desk.view().hosts[0].state, PushState::On);
    assert!(proposed(&again.gateway).is_empty());
}

/// A host that is forgotten while its run is under way is not made again by that run, and a host
/// paired again is taken up afresh: the old run holds no claim, so it hands nothing to the host and
/// writes nothing, and the new run registers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_forgotten_while_its_run_is_waiting_is_not_made_again_by_that_run() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    receiver.with(|state| state.answering = false);
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    eventually("the token was proposed", || {
        proposed(&phone.gateway) == [FIRST_TOKEN]
    })
    .await;

    let paired = phone
        .device
        .pairing()
        .hosts
        .list()
        .expect("the paired hosts")
        .remove(0);
    phone.desk.forgotten(paired.host_device_id);
    assert_eq!(phone.view().hosts[0].state, PushState::Off);
    // Paired again, the person turns it on, and the challenge of the old run is answered.
    phone
        .desk
        .enable(&reference)
        .expect("the person asks again");
    phone.receiver.with(|state| state.answering = true);
    phone.until(|states| states == [PushState::On]).await;

    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN, FIRST_TOKEN],
        "the host was taken up afresh"
    );
    assert_eq!(
        phone
            .registered
            .lock()
            .expect("what was handed")
            .credentials
            .len(),
        1,
        "the run of the forgotten host handed nothing to the host"
    );
}

/// A run whose task ends without finishing, as a panic ends it, does not leave the host showing
/// that it is working for ever: it leaves the retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_that_ends_without_finishing_leaves_the_retry_and_not_working() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    receiver.with(|state| state.permission_panics = true);
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone
        .until(|states| states == [PushState::NeedsAttention])
        .await;
}

/// A list of paired hosts that cannot be read is an error and not an empty list: a look on it
/// marks nothing, and the next look, once it can be read, registers the token the provider holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_of_paired_hosts_that_cannot_be_read_marks_nothing() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;

    phone.receiver.token_is(SECOND_TOKEN);
    let file = find(phone._phone.data.path(), "hosts.json").expect("the paired hosts' file");
    let kept = std::fs::read(&file).expect("the paired hosts");
    std::fs::write(&file, b"{ not a list").expect("spoiled");
    assert!(
        phone.desk.refresh().await.is_err(),
        "a list that cannot be read is no list"
    );
    std::fs::write(&file, kept).expect("mended");

    look(&phone.desk).await;
    phone.until(|states| states == [PushState::On]).await;
    eventually("the token was registered", || {
        proposed(&phone.gateway) == [FIRST_TOKEN, SECOND_TOKEN]
    })
    .await;
}

/// The file called `name` under `directory`, wherever the phone keeps it.
fn find(directory: &Path, name: &str) -> Option<std::path::PathBuf> {
    for entry in std::fs::read_dir(directory).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find(&path, name) {
                return Some(found);
            }
        } else if path.file_name().is_some_and(|each| each == name) {
            return Some(path);
        }
    }
    None
}

/// A run that cannot read the token again when it has made its registration has no evidence that
/// the host is registered with the token the provider holds, and does not turn the host on: it
/// stops for a retry, and the retry that follows registers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_that_cannot_read_the_token_at_its_end_does_not_turn_the_host_on() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    // The first read of the token is the run's own, to propose it; the next is its comparison.
    receiver.with(|state| state.token_readable_for = Some(1));
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone
        .until(|states| states == [PushState::NeedsAttention])
        .await;
    assert_eq!(proposed(&phone.gateway), [FIRST_TOKEN]);

    phone.receiver.with(|state| state.token_readable_for = None);
    phone.let_time_pass();
    look(&phone.desk).await;
    phone.until(|states| states == [PushState::On]).await;
}

/// A token that the provider changed while a run's last read of it was on its way is not hidden by
/// the answer that arrives late: the look that saw the new token is kept, and the run goes round
/// again with it and does not turn the host on with the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_answer_to_a_runs_last_read_does_not_hide_a_change_a_look_saw() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    // The run's second read of the token, the comparison, is held on its way.
    receiver.with(|state| {
        state.token_held.insert(2);
    });
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    eventually("the comparison read was asked", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .token_reads
            >= 2
    })
    .await;

    // The provider changes the token and the application looks, while the run's answer is still on
    // its way. The look finds the host held by its run.
    phone.receiver.token_is(SECOND_TOKEN);
    look(&phone.desk).await;
    phone.receiver.with(|state| {
        state.token_released.insert(2);
    });

    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN, SECOND_TOKEN],
        "the run went round again with the token the look saw"
    );
}

/// The run of a host that was forgotten is ended where it waits, and does not use the consent the
/// person gave when they turned the host on again: the new run asks once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_run_of_a_forgotten_host_does_not_use_the_consent_of_the_run_that_replaced_it() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    receiver.with(|state| {
        state.permission = Permission::Unknown;
        // Each run's first read of the permission waits to be let go.
        state.permission_held.extend([1, 2]);
    });
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    eventually("the first run read the permission", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .permission_reads
            >= 1
    })
    .await;
    let paired = phone
        .device
        .pairing()
        .hosts
        .list()
        .expect("the paired hosts")
        .remove(0);
    phone.desk.forgotten(paired.host_device_id);
    phone
        .desk
        .enable(&reference)
        .expect("the person asks again");
    eventually("the second run read the permission", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .permission_reads
            >= 2
    })
    .await;

    // The first run is ended where it waits, though its answer has not come: a run holds the desk
    // for as long as its task lives, so only the test's handle and the second run's are left. Only
    // then is the second run's answer let go.
    eventually("the first run ended where it waited", || {
        Arc::strong_count(&phone.desk) <= 3
    })
    .await;
    phone.receiver.with(|state| {
        state.permission_released.insert(2);
    });
    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(
        phone.receiver.state.lock().expect("the receiver").asked,
        1,
        "the system was asked once, by the run that was given consent"
    );
}

/// Looks whose answers reach the desk out of order do not hide a change: the look that read the
/// token first answers last, with the old token, and it does not take the place of what the look
/// that read the new token showed. The run, whose own late answer is the old token too, goes round
/// again with the new one and does not turn the host on with the old.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_look_whose_older_answer_arrives_last_does_not_hide_a_change_another_look_saw() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    // The reads of the token are numbered as they are asked: the run's proposal (1), its comparison
    // (2), the first look (3) and the second look (4). The comparison and the first look are held.
    receiver.with(|state| {
        state.token_held.extend([2, 3]);
    });
    let phone = desk(&[&host], &owner, receiver).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    let reads = || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .token_reads
    };
    eventually("the comparison read was asked", || reads() >= 2).await;
    let first = Arc::clone(&phone.desk);
    let first_look = tokio::spawn(async move { first.refresh().await });
    eventually("the first look read the token", || reads() >= 3).await;

    // The provider changes the token, and a second look reads the new one and is answered at once.
    phone.receiver.token_is(SECOND_TOKEN);
    look(&phone.desk).await;
    // The older answers arrive after it: the first look's, then the run's.
    phone.receiver.with(|state| {
        state.token_released.insert(3);
    });
    first_look
        .await
        .expect("the first look ended")
        .expect("a look");
    phone.receiver.with(|state| {
        state.token_released.insert(2);
    });

    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN, SECOND_TOKEN],
        "the run went round again with the token the second look saw"
    );
}

/// The steps of a run that wait on something outside the phone, after the last of which the host
/// has been told everything.
#[derive(Clone, Copy)]
enum Step {
    /// The gateway's answer to the request for the host's authorisation.
    GatewayIssue,
    /// The connection to the host.
    Connection,
    /// The host's answer to the registration.
    HostAnswer,
}

/// Starts the sequence for the one host, holds it at `step`, lets `forgets` do what the person did,
/// lets the step go, and waits for the run to end. The desk is returned for what the host was sent.
///
/// `forgets` says whether what the person did ended the run where it waits, as the desk forgetting
/// the host does: then the run has ended before the step is let go, and not only after.
async fn the_host_is_forgotten_while(
    step: Step,
    forgets: impl FnOnce(&Desk, &PairedHost) -> bool,
) -> Desk {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let hold = |held: bool| match step {
        Step::GatewayIssue => phone.gateway.hold_issue(held),
        Step::Connection => {
            phone
                .registered
                .lock()
                .expect("what was sent")
                .hold_connection = held;
        }
        Step::HostAnswer => phone.registered.lock().expect("what was sent").hold_answer = held,
    };
    hold(true);
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    eventually("the run is at the step", || match step {
        Step::GatewayIssue => phone.gateway.issue_requests() == 1,
        Step::Connection => {
            phone
                .registered
                .lock()
                .expect("what was sent")
                .connected
                .len()
                == 1
        }
        Step::HostAnswer => {
            phone
                .registered
                .lock()
                .expect("what was sent")
                .credentials
                .len()
                == 1
        }
    })
    .await;

    let paired = phone
        .device
        .pairing()
        .hosts
        .list()
        .expect("the paired hosts")
        .remove(0);
    let ended_where_it_waited = forgets(&phone, &paired);
    // A run holds the desk for as long as its task lives, so only the test's handle is left when
    // the run has ended.
    if ended_where_it_waited {
        eventually("the run ended where it waited", || {
            Arc::strong_count(&phone.desk) == 1
        })
        .await;
    }
    hold(false);
    eventually("the run ended", || Arc::strong_count(&phone.desk) == 1).await;
    phone
}

/// What the host was sent: how many connections, registrations and preview keys.
fn sent(phone: &Desk) -> (usize, usize, usize) {
    let script = phone.registered.lock().expect("what was sent");
    (
        script.connected.len(),
        script.credentials.len(),
        script.keys.len(),
    )
}

/// The person forgets the host (the application's record of it goes with the run's claim) while
/// the gateway issues the host's authorisation, which it does once the host is connected to: the
/// host is told nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_forgotten_while_the_gateway_issues_for_it_is_told_nothing() {
    let phone = the_host_is_forgotten_while(Step::GatewayIssue, |phone, paired| {
        phone.desk.forgotten(paired.host_device_id);
        true
    })
    .await;
    assert_eq!(sent(&phone), (1, 0, 0));
}

/// Forgetting a host removes the pairing before the desk drops its claim; a run that wakes between
/// the two is not wanted either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_unpaired_while_the_gateway_issues_for_it_is_told_nothing() {
    let phone = the_host_is_forgotten_while(Step::GatewayIssue, |phone, paired| {
        phone
            .device
            .forget_host(paired.host_device_id)
            .expect("the pairing is forgotten");
        false
    })
    .await;
    assert_eq!(sent(&phone), (1, 0, 0));
}

/// KR-REQ-16.08: the gateway issues the authorisation for a host once the host has been reached.
/// An issue replaces the credential the host holds at once, so a host that cannot be reached keeps
/// the one it has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_cannot_be_reached_is_not_issued_an_authorisation() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.registered.lock().expect("the script").connect_fails =
        Some("the host did not answer in time".to_owned());
    phone.desk.enable(&reference).expect("the person asks");
    phone
        .until(|states| states == [PushState::NeedsAttention])
        .await;
    assert!(
        phone.view().hosts[0]
            .words
            .starts_with("The host did not take this phone as a destination"),
        "{:?}",
        phone.view().hosts[0].words
    );
    assert_eq!(
        phone.gateway.issue_requests(),
        0,
        "the gateway issued nothing for a host that was not reached"
    );

    phone.registered.lock().expect("the script").connect_fails = None;
    phone
        .desk
        .enable(&reference)
        .expect("the person asks again");
    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(phone.gateway.issue_requests(), 1);
}

/// The person forgets the host while the connection to it is made: it is connected to, and told
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_forgotten_while_it_is_connected_to_is_told_nothing() {
    let phone = the_host_is_forgotten_while(Step::Connection, |phone, paired| {
        phone.desk.forgotten(paired.host_device_id);
        true
    })
    .await;
    assert_eq!(sent(&phone), (1, 0, 0));
}

/// The person forgets the host while it answers the registration: the preview key is not sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_forgotten_while_it_answers_the_registration_is_sent_no_preview_key() {
    let phone = the_host_is_forgotten_while(Step::HostAnswer, |phone, paired| {
        phone.desk.forgotten(paired.host_device_id);
        true
    })
    .await;
    assert_eq!(sent(&phone), (1, 1, 0));
}

/// A run that waits for its turn at the phone's one registration slot, and whose host is forgotten
/// while it waits, proposes nothing to the gateway when its turn comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_forgotten_while_it_waits_for_its_turn_proposes_nothing() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let receiver = Receiver::new(FIRST_TOKEN);
    // The first host's challenge is not answered, so it keeps the slot.
    receiver.with(|state| state.answering = false);
    let phone = desk(&[&first, &second], &owner, receiver).await;
    let references = phone.references();
    phone.desk.enable(&references[0]).expect("the person asks");
    eventually("the first token was proposed", || {
        proposed(&phone.gateway) == [FIRST_TOKEN]
    })
    .await;
    phone.desk.enable(&references[1]).expect("the person asks");
    // The second host is the newest, which the page lists first: its run says it is waiting for the
    // slot once it has passed every check before it.
    phone
        .until_words("Waiting for the notification service")
        .await;
    // The second host's run waits for the slot. Its host is forgotten, and the first run finishes.
    let second_host = phone
        .device
        .host_by_reference(&references[1])
        .expect("the second host");
    phone.desk.forgotten(second_host.host_device_id);
    phone.receiver.with(|state| state.answering = true);

    // Only the test's own handle is left when both runs have ended.
    eventually("both runs ended", || Arc::strong_count(&phone.desk) == 1).await;
    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN],
        "the run that was not wanted proposed nothing"
    );
}

/// The files the phone set aside because it could not read them.
fn set_aside(data: &Path) -> Vec<std::path::PathBuf> {
    let mut found: Vec<_> = std::fs::read_dir(data.join("push"))
        .expect("the directory")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("push.unreadable-"))
        })
        .collect();
    found.sort();
    found
}

/// A record that cannot be read, damaged or written by a build this one does not know, holds each
/// host's authorisation identifier. It is moved aside whole, and the hosts paired then are marked
/// lost: they show as needing the person, across restarts, until the person turns each on again.
/// A look leaves them alone, and a host paired later is off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_that_cannot_be_read_is_set_aside_and_its_hosts_are_marked_lost() {
    let unreadable: [(&str, &[u8]); 2] = [
        ("damaged", b"{\"version\": 1, \"hosts\": {"),
        ("another version", br#"{"version":2,"hosts":{}}"#),
    ];
    for (kind, bytes) in unreadable {
        let owner = DeviceKeys::generate().expect("keys");
        let first = Host::start(&owner).await;
        let second = Host::start(&owner).await;
        let third = Host::start(&owner).await;
        let receiver = Receiver::new(FIRST_TOKEN);
        let phone = desk(&[&first, &second], &owner, Arc::clone(&receiver)).await;
        let references = phone.references();
        phone.desk.enable(&references[0]).expect("the person asks");
        phone
            .until(|states| states == [PushState::Off, PushState::On])
            .await;
        let data = phone._phone.data.path();
        let record = data.join("push").join("push.json");
        kr_ipc::paths::write_owner_only_file(&record, bytes).expect("the record is spoiled");

        let open = || open_over(data, &phone.device, &receiver, &phone.registered);
        let states = |opened: &Opened| {
            opened
                .desk
                .view()
                .hosts
                .iter()
                .map(|each| each.state)
                .collect::<Vec<_>>()
        };
        let restarted = open();
        assert_eq!(
            states(&restarted),
            [PushState::NeedsAttention, PushState::NeedsAttention],
            "{kind}: neither host is shown as off"
        );
        let aside = set_aside(data);
        assert_eq!(aside.len(), 1, "{kind}: the record was set aside");
        assert_eq!(
            std::fs::read(&aside[0]).expect("the file set aside"),
            bytes,
            "{kind}: whole"
        );
        let kept = std::fs::read(&record).expect("the marks were kept");
        drop(restarted);

        // The marks outlast the start that made them, and the record is set aside once.
        let again = open();
        assert_eq!(
            states(&again),
            [PushState::NeedsAttention, PushState::NeedsAttention],
            "{kind}: after another start"
        );
        assert_eq!(set_aside(data), aside, "{kind}: set aside once");
        // A look leaves them alone, however long they have waited: it starts no run, and writes
        // nothing.
        again.let_time_pass();
        look(&again.desk).await;
        assert_eq!(
            Arc::strong_count(&again.desk),
            1,
            "{kind}: a look started a run"
        );
        assert_eq!(std::fs::read(&record).expect("the record"), kept);

        // A host paired after the loss is off, and the person starts one host over.
        pair(&phone._phone, &third, &owner, &[ActionRight::SessionView]).await;
        assert_eq!(
            states(&again),
            [
                PushState::Off,
                PushState::NeedsAttention,
                PushState::NeedsAttention
            ],
            "{kind}: a host paired later"
        );
        again
            .desk
            .enable(&references[0])
            .expect("the person asks again");
        states_until(&again.desk, |states| {
            states == [PushState::Off, PushState::NeedsAttention, PushState::On]
        })
        .await;
        drop(again);

        // That one stays on across a start, the other is still lost, and the old record is as it was.
        assert_eq!(
            states(&open()),
            [PushState::Off, PushState::NeedsAttention, PushState::On],
            "{kind}: a host started over and one not"
        );
        assert_eq!(
            std::fs::read(&aside[0]).expect("the file set aside"),
            bytes,
            "{kind}: still whole"
        );
    }
}

/// A phone with one host turned on, whose record is then replaced by `bytes`. The host is returned
/// to keep it running.
async fn a_phone_whose_record_was_spoiled(bytes: &[u8]) -> (Host, Desk) {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;
    let record = phone._phone.data.path().join("push").join("push.json");
    kr_ipc::paths::write_owner_only_file(&record, bytes).expect("the record is spoiled");
    (host, phone)
}

/// The desk, opened again over the phone's record.
fn reopened(phone: &Desk) -> Opened {
    open_over(
        phone._phone.data.path(),
        &phone.device,
        &phone.receiver,
        &phone.registered,
    )
}

/// A start that ends after it set the record aside and before it wrote the marks leaves no record
/// and one set aside: the next start marks the hosts then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_ended_after_setting_the_record_aside_marks_the_hosts_at_the_next() {
    let (_host, phone) = a_phone_whose_record_was_spoiled(b"{ not a record").await;
    let data = phone._phone.data.path();
    let record = data.join("push").join("push.json");
    drop(reopened(&phone));
    assert_eq!(set_aside(data).len(), 1);
    std::fs::remove_file(&record).expect("the marks are lost with the end of the start");

    let restarted = reopened(&phone);
    assert_eq!(
        restarted.desk.view().hosts[0].state,
        PushState::NeedsAttention
    );
    assert!(record.exists(), "the marks were written");
    assert_eq!(set_aside(data).len(), 1, "set aside once");
}

/// A start that cannot read the paired hosts cannot say which to mark: the record stays where it
/// is, and the next start that can read them sets it aside and marks them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_that_could_not_read_the_paired_hosts_leaves_the_record_for_the_next() {
    let (_host, phone) = a_phone_whose_record_was_spoiled(b"{ not a record").await;
    let data = phone._phone.data.path();
    let file = find(data, "hosts.json").expect("the paired hosts' file");
    let kept = std::fs::read(&file).expect("the paired hosts");
    std::fs::write(&file, b"{ not a list").expect("spoiled");
    drop(reopened(&phone));
    assert!(set_aside(data).is_empty(), "it was left where it is");
    std::fs::write(&file, kept).expect("mended");

    let restarted = reopened(&phone);
    assert_eq!(
        restarted.desk.view().hosts[0].state,
        PushState::NeedsAttention
    );
    assert_eq!(set_aside(data).len(), 1, "now it was set aside");
}

/// A lost host the person started over is an ordinary host again: a try that stops is tried again
/// by a look, and is not left to the person for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_host_the_person_started_over_is_tried_again_like_any_other() {
    let (_host, phone) = a_phone_whose_record_was_spoiled(b"{ not a record").await;
    let restarted = reopened(&phone);
    let reference = phone.references().remove(0);
    // The run's own read of the token for the registration is answered, the one for its comparison is not.
    phone.receiver.with(|state| {
        state.token_readable_for = Some(state.token_reads + 1);
    });
    restarted
        .desk
        .enable(&reference)
        .expect("the person asks again");
    eventually("the run ended", || Arc::strong_count(&restarted.desk) == 1).await;
    let view = restarted.desk.view();
    assert_eq!(view.hosts[0].state, PushState::NeedsAttention);
    assert!(
        view.hosts[0].words.contains("notification token"),
        "it stopped for want of the token, and is no longer lost: {}",
        view.hosts[0].words
    );

    phone.receiver.with(|state| state.token_readable_for = None);
    restarted.let_time_pass();
    look(&restarted.desk).await;
    states_until(&restarted.desk, |states| states == [PushState::On]).await;
}

/// Whether this account ignores file permissions, as one that owns the machine does: a case that
/// takes access away has nothing to show for it, and says so.
#[cfg(unix)]
fn ignores_permissions(path: &Path, case: &str) -> bool {
    if std::fs::read(path).is_ok() || std::fs::read_dir(path).is_ok() {
        eprintln!("{case}: skipped, this account reads what it was refused");
        return true;
    }
    false
}

/// A record that the system fails to read may be fine at the next start: it is left where it is,
/// nothing is written until a start can read it, no host is started in the meantime, and the page
/// says to start the application again.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_the_system_fails_to_read_is_left_in_place_and_not_written_over() {
    use std::os::unix::fs::PermissionsExt as _;

    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;
    let data = phone._phone.data.path();
    let record = data.join("push").join("push.json");
    let original = std::fs::read(&record).expect("the record");
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o000))
        .expect("the record is made unreadable");
    if ignores_permissions(&record, "a_record_the_system_fails_to_read") {
        return;
    }

    let restarted = reopened(&phone);
    assert_eq!(
        restarted.desk.view().hosts[0].state,
        PushState::NeedsAttention
    );
    assert!(set_aside(data).is_empty(), "it was left where it is");
    // Neither turning the host on nor forgetting it changes the record.
    restarted
        .desk
        .enable(&reference)
        .expect("the person asks again");
    let paired = phone
        .device
        .host_by_reference(&reference)
        .expect("the host");
    restarted.desk.forgotten(paired.host_device_id);
    // Forgetting hands the receivers their keys again, which holds the desk for a moment; no run
    // is left holding it, and the host still needs the person.
    eventually("no run holds the desk", || {
        Arc::strong_count(&restarted.desk) == 1
    })
    .await;
    let shown = restarted.desk.view().hosts.remove(0);
    assert_eq!(
        shown.state,
        PushState::NeedsAttention,
        "no run was started for the host, and it still says to start the application again"
    );
    assert!(
        shown
            .words
            .contains("Close the application and open it again"),
        "{:?}",
        shown.words
    );

    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600))
        .expect("the record is made readable");
    assert_eq!(
        std::fs::read(&record).expect("the record"),
        original,
        "nothing was written over it"
    );
}

/// A record that was read and is not one this build knows, and that cannot be moved aside, is left
/// where it is and is not written over, even when the directory can be written to again.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_that_could_not_be_set_aside_is_not_written_over() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_host, phone) = a_phone_whose_record_was_spoiled(b"{ not a record").await;
    let data = phone._phone.data.path();
    let directory = data.join("push");
    let record = directory.join("push.json");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
        .expect("the directory is made unwritable");
    if std::fs::write(directory.join("probe"), b"").is_ok() {
        eprintln!(
            "a_record_that_could_not_be_set_aside: skipped, this account writes where it was refused"
        );
        return;
    }

    let restarted = reopened(&phone);
    assert_eq!(
        restarted.desk.view().hosts[0].state,
        PushState::NeedsAttention
    );
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is made writable again");
    let reference = phone.references().remove(0);
    restarted
        .desk
        .enable(&reference)
        .expect("the person asks again");
    assert_eq!(Arc::strong_count(&restarted.desk), 1, "no run was started");
    assert_eq!(
        std::fs::read(&record).expect("the record"),
        b"{ not a record",
        "nothing was written over it"
    );
    assert!(set_aside(data).is_empty());
}

/// A run the person starts reaches its host as asked, and one a look starts reaches it as a visit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_reaches_its_host_as_the_person_asked_and_a_look_as_a_visit() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;

    phone.receiver.token_is(SECOND_TOKEN);
    look(&phone.desk).await;
    eventually("the look's run registered the new token", || {
        proposed(&phone.gateway) == [FIRST_TOKEN, SECOND_TOKEN]
    })
    .await;
    phone.until(|states| states == [PushState::On]).await;
    eventually("both runs ended", || Arc::strong_count(&phone.desk) == 1).await;
    assert_eq!(
        phone.registered.lock().expect("what was sent").reaches,
        [Reach::Asked, Reach::Visit]
    );
}

/// The relay two hosts share, and the services that tell their endpoints apart.
const SHARED_RELAY: &str = "https://relay.push.test";

/// Where one host's notifications stand, by the reference the page names it with.
fn state_of(phone: &Desk, reference: &str) -> PushState {
    phone
        .view()
        .hosts
        .into_iter()
        .find(|host| host.reference == reference)
        .expect("a paired host")
        .state
}

/// A host on `SHARED_RELAY` that resolves through the resolver at `port`.
async fn on_the_shared_relay(owner: &DeviceKeys, port: u16) -> Host {
    Host::start_with_endpoint(
        owner,
        support::on_relay(SHARED_RELAY, &format!("http://127.0.0.1:{port}/pkarr")),
    )
    .await
}

/// The product's registrar, with a test's hand on the connection it opens: it records how each run
/// reached its host and holds the line open, endpoint hold and all, until the test lets it go.
struct Watched {
    real: ConnectionRegistrar,
    script: Arc<Mutex<Registered>>,
}

impl Registrar for Watched {
    fn beside_the_host_in_use<'a>(&'a self, host: &'a PairedHost) -> AskFuture<'a> {
        self.real.beside_the_host_in_use(host)
    }

    fn connect<'a>(
        &'a self,
        host: &'a PairedHost,
        reach: Reach,
    ) -> PushFuture<'a, Box<dyn HostLine + 'a>> {
        Box::pin(async move {
            self.script
                .lock()
                .expect("what was sent")
                .reaches
                .push(reach);
            let line = self.real.connect(host, reach).await?;
            self.script
                .lock()
                .expect("what was sent")
                .connected
                .push(host.host_device_id);
            while_held(&self.script, |script| script.hold_connection).await;
            Ok(Box::new(WatchedLine {
                real: line,
                script: Arc::clone(&self.script),
                host: host.host_device_id,
                device: host.device_id.to_string(),
            }) as Box<dyn HostLine + 'a>)
        })
    }
}

/// The product's line to a host, with a host that does not answer the registration for as long as
/// the test says (the request has gone out, and the line waits), and then answers it as the vectors
/// record. The preview key goes over the real connection.
struct WatchedLine<'a> {
    real: Box<dyn HostLine + 'a>,
    script: Arc<Mutex<Registered>>,
    host: kr_protocol::ids::DeviceId,
    device: String,
}

impl HostLine for WatchedLine<'_> {
    fn register(
        &mut self,
        params: DevicePushRegisterParams,
    ) -> LineFuture<'_, DevicePushRegisterResult> {
        Box::pin(async move {
            self.script
                .lock()
                .expect("what was sent")
                .credentials
                .push((self.host, json!({})));
            while_held(&self.script, |script| script.hold_answer).await;
            let _ = params;
            Ok(registration_answer(&self.device))
        })
    }

    fn update_preview_key(
        &mut self,
        preview_key: kr_protocol::scalars::NotificationPreviewKey,
        revision: DeviceKeyRevision,
    ) -> LineFuture<'_, ()> {
        self.real.update_preview_key(preview_key, revision)
    }
}

/// A desk over the product's registrar, for a phone paired with `hosts` in the order given.
async fn desk_over_the_product_registrar(hosts: &[&Host], owner: &DeviceKeys) -> Desk {
    desk_reaching(
        hosts,
        owner,
        Receiver::new(FIRST_TOKEN),
        |device, script| {
            Arc::new(Watched {
                real: ConnectionRegistrar(Arc::clone(device)),
                script: Arc::clone(script),
            }) as Arc<dyn Registrar>
        },
    )
    .await
}

/// Whether a host answers over a connection to it, which it does only while the endpoint the
/// connection was made through is open.
async fn answers(connection: &companion_tauri::connection::Connection) -> bool {
    let read: Result<kr_protocol::hostinfo::HostInfoResult, _> = tokio::time::timeout(
        WATCHDOG,
        connection
            .session()
            .read(kr_protocol::method::Method::HostInfo, &json!({})),
    )
    .await
    .expect("the host answers or the connection ends");
    read.is_ok()
}

/// The host takes this phone's preview key at `revision` over the product's own line, as a
/// rotation would send it.
async fn the_host_takes_revision(phone: &Desk, host: &PairedHost, revision: u64) {
    let registrar = ConnectionRegistrar(Arc::clone(&phone.device));
    let mut line = registrar
        .connect(host, Reach::Asked)
        .await
        .expect("the line to the host");
    let key = *kr_crypto::keys::NotificationPreviewKeyPair::generate()
        .expect("a key")
        .public();
    line.update_preview_key(key, DeviceKeyRevision::new(revision))
        .await
        .expect("the host takes the revision");
}

/// A phone whose host took a higher revision of its preview key is not refused at its next
/// connection: every way of connecting offers the revision the records hold, read at that
/// connection and not taken from a copy of the host's record made before the update. The copies
/// are the ones that outlive an update: the loop that keeps the host in use, the second connection
/// a connection opens from itself, and a connection opened from a record made earlier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phone_whose_host_took_a_higher_revision_is_not_refused_at_its_next_connection() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk_over_the_product_registrar(&[&host], &owner).await;
    let before = phone
        .device
        .host_by_reference(&phone.references()[0])
        .expect("the paired host");
    let opened_before = companion_tauri::connection::Connection::paired(&phone.device, &before)
        .await
        .expect("connected at the first revision");
    assert!(answers(&opened_before).await);

    the_host_takes_revision(&phone, &before, 2).await;

    let held = phone
        .device
        .pairing()
        .hosts
        .by_device(before.host_device_id)
        .expect("readable")
        .expect("the host");
    assert_eq!(held.device_key_revision.get(), 2, "the phone kept it");
    let from_the_old_copy = companion_tauri::connection::Connection::paired(&phone.device, &before)
        .await
        .expect("a connection made from a record made before the update is not refused");
    assert!(answers(&from_the_old_copy).await);
    let from_itself = opened_before
        .another()
        .await
        .expect("the connection opened before the update opens another");
    assert!(answers(&from_itself).await);
}

/// A revision behind the one the host holds is refused, and the phone's record does not go back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_behind_the_one_the_host_holds_is_refused_and_the_phones_record_stays() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk_over_the_product_registrar(&[&host], &owner).await;
    let paired = phone
        .device
        .host_by_reference(&phone.references()[0])
        .expect("the paired host");
    the_host_takes_revision(&phone, &paired, 2).await;

    let current = paired.clone();
    let registrar = ConnectionRegistrar(Arc::clone(&phone.device));
    let mut line = registrar
        .connect(&current, Reach::Asked)
        .await
        .expect("the line, offering the revision the host holds");
    let key = *kr_crypto::keys::NotificationPreviewKeyPair::generate()
        .expect("a key")
        .public();
    line.update_preview_key(key, DeviceKeyRevision::new(1))
        .await
        .expect_err("a revision behind the host's is refused");
    let held = || {
        phone
            .device
            .pairing()
            .hosts
            .by_device(paired.host_device_id)
            .expect("readable")
            .expect("the host")
            .device_key_revision
            .get()
    };
    assert_eq!(held(), 2, "the phone's record does not go back");
}

/// A visit to another host on the relay a run is using cannot close the endpoint the run holds,
/// whether the person started the run or a look did: the host in use is on no relay, the run's
/// host and the visited host share one and differ in the services the endpoint uses, so reaching
/// either closes the endpoint the other was reached through unless it is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_visit_beside_a_run_cannot_close_the_endpoint_the_run_holds() {
    let owner = DeviceKeys::generate().expect("keys");
    let in_use = Host::start(&owner).await;
    let running = on_the_shared_relay(&owner, 9).await;
    let visited = on_the_shared_relay(&owner, 10).await;
    let phone = desk_over_the_product_registrar(&[&in_use, &running, &visited], &owner).await;
    let references = phone.references();
    let host = |number: usize| {
        phone
            .device
            .host_by_reference(&references[number])
            .expect("a paired host")
    };
    phone
        .device
        .use_host(host(0).host_device_id)
        .expect("the host in use");
    let visited_host = host(2);
    let holding = |held: bool| {
        phone
            .registered
            .lock()
            .expect("what was sent")
            .hold_connection = held;
    };
    let connections = || {
        phone
            .registered
            .lock()
            .expect("what was sent")
            .connected
            .len()
    };

    // The person asks, and the run is held with its connection open.
    holding(true);
    phone.desk.enable(&references[1]).expect("the person asks");
    eventually("the run connected", || connections() == 1).await;
    assert!(
        companion_tauri::connection::Connection::visited(&phone.device, &visited_host)
            .await
            .is_err(),
        "a visit closed the endpoint a run asked for holds"
    );
    holding(false);
    eventually("the run ended", || Arc::strong_count(&phone.desk) == 1).await;
    assert_eq!(
        state_of(&phone, &references[1]),
        PushState::On,
        "the run the person started beside the host in use ends with the host on"
    );

    // A look starts the run, and the same holds.
    phone.receiver.token_is(SECOND_TOKEN);
    phone.let_time_pass();
    holding(true);
    look(&phone.desk).await;
    eventually("the look's run connected", || connections() == 2).await;
    assert!(
        companion_tauri::connection::Connection::visited(&phone.device, &visited_host)
            .await
            .is_err(),
        "a visit closed the endpoint a run a look started holds"
    );
    holding(false);
    eventually("the run ended", || Arc::strong_count(&phone.desk) == 1).await;
    assert_eq!(
        phone.registered.lock().expect("what was sent").reaches,
        [Reach::Asked, Reach::Visit]
    );
    assert_eq!(state_of(&phone, &references[1]), PushState::On);

    // Once the runs have ended the endpoint is free, and the visited host is reached.
    let visit = companion_tauri::connection::Connection::visited(&phone.device, &visited_host)
        .await
        .expect("a visit once no run holds the endpoint");
    assert!(answers(&visit).await, "the visited host answers");
}

/// A look's run holds the endpoint of its host while it is connected. That stops other visits and
/// not the person: choosing another host on the same relay closes the endpoint the run holds, and
/// the chosen host answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_look_that_holds_a_host_does_not_stop_the_person_choosing_a_host_on_its_relay() {
    let owner = DeviceKeys::generate().expect("keys");
    let in_use = Host::start(&owner).await;
    let running = on_the_shared_relay(&owner, 9).await;
    let chosen = on_the_shared_relay(&owner, 10).await;
    let phone = desk_over_the_product_registrar(&[&in_use, &running, &chosen], &owner).await;
    let references = phone.references();
    let host = |number: usize| {
        phone
            .device
            .host_by_reference(&references[number])
            .expect("a paired host")
    };
    phone
        .device
        .use_host(host(0).host_device_id)
        .expect("the host in use");
    phone.desk.enable(&references[1]).expect("the person asks");
    eventually("the first run ended", || {
        state_of(&phone, &references[1]) == PushState::On && Arc::strong_count(&phone.desk) == 1
    })
    .await;

    // A look finds the host due, and its run holds the host's endpoint open.
    phone.receiver.token_is(SECOND_TOKEN);
    phone
        .registered
        .lock()
        .expect("what was sent")
        .hold_connection = true;
    look(&phone.desk).await;
    eventually("the look's run connected", || {
        phone
            .registered
            .lock()
            .expect("what was sent")
            .connected
            .len()
            == 2
    })
    .await;

    let connection = companion_tauri::connection::Connection::paired(&phone.device, &host(2))
        .await
        .expect("the person's choice of a host is not stopped by a look's hold");
    assert!(answers(&connection).await, "the chosen host answers");

    phone
        .registered
        .lock()
        .expect("what was sent")
        .hold_connection = false;
    eventually("the look's run ended", || {
        Arc::strong_count(&phone.desk) == 1
    })
    .await;
}

/// A run a look starts for a host that is not in use never closes the endpoint the host in use is
/// reached through, though the two hosts share a relay and differ in the services their endpoints
/// use: it stops before it asks the gateway or the host anything, and says why, and the host in use
/// keeps answering. A run the person starts is the person's own choice and may take the relay, and
/// ends with the host on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_look_never_cuts_off_the_host_in_use_for_a_host_beside_it() {
    let owner = DeviceKeys::generate().expect("keys");
    let in_use = on_the_shared_relay(&owner, 9).await;
    let beside = on_the_shared_relay(&owner, 10).await;
    let phone = desk_over_the_product_registrar(&[&in_use, &beside], &owner).await;
    let references = phone.references();
    let host = |number: usize| {
        phone
            .device
            .host_by_reference(&references[number])
            .expect("a paired host")
    };
    phone
        .device
        .use_host(host(0).host_device_id)
        .expect("the host in use");

    // The person turns notifications on for the host beside the host in use.
    phone.desk.enable(&references[1]).expect("the person asks");
    eventually("the run ended", || {
        phone
            .registered
            .lock()
            .expect("what was sent")
            .reaches
            .len()
            == 1
            && Arc::strong_count(&phone.desk) == 1
    })
    .await;
    assert_eq!(
        state_of(&phone, &references[1]),
        PushState::On,
        "the person's own run takes the relay and ends with the host on"
    );

    // The host in use is connected, and a look finds the host beside it due.
    let connection = companion_tauri::connection::Connection::paired(&phone.device, &host(0))
        .await
        .expect("the host in use");
    assert!(answers(&connection).await, "the host in use answers");
    phone.receiver.token_is(SECOND_TOKEN);
    look(&phone.desk).await;
    phone
        .until_words("same relay as the host you are using")
        .await;
    eventually("the look's run ended", || {
        Arc::strong_count(&phone.desk) == 1
    })
    .await;

    assert!(
        answers(&connection).await,
        "the run for the host beside it closed the endpoint the host in use is reached through"
    );
    assert_eq!(
        phone.registered.lock().expect("what was sent").reaches,
        [Reach::Asked],
        "the look's run made no connection"
    );
    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN],
        "the look's run asked the gateway nothing"
    );
    assert_eq!(phone.gateway.issue_requests(), 1);
    assert_eq!(
        state_of(&phone, &references[1]),
        PushState::NeedsAttention,
        "the host beside it is left for the person"
    );
}

/// A host the person forgets while it has not answered the registration, and never does, does not
/// keep the endpoint it was reached through: the run ends where it waits, with its connection and
/// the hold on the endpoint, and another host on the same relay connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forgotten_host_that_never_answers_does_not_keep_the_relay_it_was_reached_through() {
    let owner = DeviceKeys::generate().expect("keys");
    let in_use = Host::start(&owner).await;
    let silent = on_the_shared_relay(&owner, 9).await;
    let other = on_the_shared_relay(&owner, 10).await;
    let phone = desk_over_the_product_registrar(&[&in_use, &silent, &other], &owner).await;
    let references = phone.references();
    let host = |number: usize| {
        phone
            .device
            .host_by_reference(&references[number])
            .expect("a paired host")
    };
    phone
        .device
        .use_host(host(0).host_device_id)
        .expect("the host in use");
    let (silent_host, other_host) = (host(1), host(2));
    phone.registered.lock().expect("what was sent").hold_answer = true;

    // The host has the registration and does not answer.
    phone.desk.enable(&references[1]).expect("the person asks");
    eventually("the registration was sent", || {
        phone
            .registered
            .lock()
            .expect("what was sent")
            .credentials
            .len()
            == 1
    })
    .await;
    assert!(
        companion_tauri::connection::Connection::paired(&phone.device, &other_host)
            .await
            .is_err(),
        "the endpoint is held while the host is waited for"
    );

    // The person forgets it, as the application does: the pairing, then the desk.
    phone
        .device
        .forget_host(silent_host.host_device_id)
        .expect("the pairing is forgotten");
    phone.desk.forgotten(silent_host.host_device_id);

    tokio::time::timeout(WATCHDOG, async {
        while companion_tauri::connection::Connection::paired(&phone.device, &other_host)
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("another host on the relay connects once the forgotten host's run has ended");
    eventually("the run ended", || Arc::strong_count(&phone.desk) == 1).await;
    phone.registered.lock().expect("what was sent").hold_answer = false;
}

/// The keys are filed before the host's endpoint is held, and no host waits behind the platform's
/// filing: while they are filed, another host on the same relay connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_endpoint_of_a_host_is_not_held_while_the_preview_keys_are_filed() {
    let owner = DeviceKeys::generate().expect("keys");
    let in_use = Host::start(&owner).await;
    let running = on_the_shared_relay(&owner, 9).await;
    let other = on_the_shared_relay(&owner, 10).await;
    let phone = desk_over_the_product_registrar(&[&in_use, &running, &other], &owner).await;
    let references = phone.references();
    let host = |number: usize| {
        phone
            .device
            .host_by_reference(&references[number])
            .expect("a paired host")
    };
    phone
        .device
        .use_host(host(0).host_device_id)
        .expect("the host in use");
    let other_host = host(2);
    phone.receiver.with(|state| state.keys_hold = Some(1));

    phone.desk.enable(&references[1]).expect("the person asks");
    eventually("the run is filing the keys", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .keys_asked
            >= 1
    })
    .await;
    companion_tauri::connection::Connection::paired(&phone.device, &other_host)
        .await
        .expect("another host on the relay connects while the key is filed");

    phone.receiver.with(|state| state.keys_released = true);
    phone.until(|states| states[1] == PushState::On).await;
}

/// KR-REQ-16.11: the receivers hold the host's key before the host is told to seal anything to this
/// phone: a notification that arrives the moment the host has the registration is opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_receivers_hold_a_hosts_key_before_the_host_is_registered() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    phone
        .registered
        .lock()
        .expect("what was handed")
        .hold_answer = true;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    eventually("the host has been handed the registration", || {
        !phone
            .registered
            .lock()
            .expect("what was handed")
            .credentials
            .is_empty()
    })
    .await;
    let held = held_keys(&phone).expect("the receivers were handed keys before the registration");
    assert_eq!(held.senders.len(), 1, "the host's key is among them");
    phone
        .registered
        .lock()
        .expect("what was handed")
        .hold_answer = false;
    phone.until(|states| states == [PushState::On]).await;
}

/// KR-REQ-16.11: a host the person forgets is taken out of what the receivers hold, and the seed
/// with the last of them: a receiver opens a preview only for a host this phone is still paired with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_receivers_hold_the_keys_of_the_paired_hosts_and_nothing_of_a_forgotten_one() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let phone = desk(&[&first, &second], &owner, Receiver::new(FIRST_TOKEN)).await;
    for reference in phone.references() {
        phone.desk.enable(&reference).expect("the person asks");
        phone
            .until(|states| !states.contains(&PushState::Working))
            .await;
    }
    phone
        .until(|states| states.iter().all(|state| *state == PushState::On))
        .await;
    let both = held_keys(&phone).expect("the receivers were handed keys");
    assert_eq!(both.senders.len(), 2);
    assert_eq!(both.recipients.len(), 1);

    let paired = phone
        .device
        .pairing()
        .hosts
        .list()
        .expect("the paired hosts");
    for (position, host) in paired.iter().enumerate() {
        phone
            .device
            .forget_host(host.host_device_id)
            .expect("the pairing is forgotten");
        phone.desk.forgotten(host.host_device_id);
        let remaining = 1 - position;
        eventually("the receivers follow the forgotten host", || {
            held_keys(&phone).is_some_and(|keys| keys.senders.len() == remaining)
        })
        .await;
    }
    let none = held_keys(&phone).expect("the receivers were handed the empty set");
    assert!(
        none.recipients.is_empty(),
        "no seed is held for a phone with no host that may use it"
    );
}

/// KR-REQ-16.11: the keys are built and handed over under one hold, so a set built before a newer
/// one is never filed after it: a host forgotten while an earlier filing is still being handed over
/// is out of what the receivers end up holding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_set_of_keys_is_never_filed_after_a_newer_one() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let third = Host::start(&owner).await;
    let phone = desk(
        &[&first, &second, &third],
        &owner,
        Receiver::new(FIRST_TOKEN),
    )
    .await;
    for reference in phone.references() {
        phone.desk.enable(&reference).expect("the person asks");
        phone
            .until(|states| !states.contains(&PushState::Working))
            .await;
    }
    phone
        .until(|states| states.iter().all(|state| *state == PushState::On))
        .await;
    let paired = phone
        .device
        .pairing()
        .hosts
        .list()
        .expect("the paired hosts");

    // The first host is unpaired elsewhere; a look builds the set without it and is handed over
    // slowly. The person forgets the second meanwhile, which builds a newer set.
    let asked = phone
        .receiver
        .state
        .lock()
        .expect("the receiver")
        .keys_asked;
    phone.receiver.with(|state| {
        state.keys_hold = Some(asked + 1);
        state.keys_released = false;
    });
    phone
        .device
        .forget_host(paired[0].host_device_id)
        .expect("the pairing is forgotten");
    let slow_look = {
        let desk = Arc::clone(&phone.desk);
        tokio::spawn(async move { desk.refresh().await })
    };
    eventually("the look is handing its set over", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .keys_asked
            == asked + 1
    })
    .await;
    phone
        .device
        .forget_host(paired[1].host_device_id)
        .expect("the pairing is forgotten");
    phone.desk.forgotten(paired[1].host_device_id);
    phone.receiver.with(|state| state.keys_released = true);
    slow_look.await.expect("the look ended").expect("a look");

    eventually("the receivers hold the newer set", || {
        held_keys(&phone).is_some_and(|keys| keys.senders.len() == 1)
    })
    .await;
    let history = phone
        .receiver
        .state
        .lock()
        .expect("the receiver")
        .keys_history
        .clone();
    assert_eq!(
        history.last().map(|keys| keys.senders.len()),
        Some(1),
        "the last set handed over is the newer one: {history:?}"
    );
}

/// KR-REQ-16.11: a list of paired hosts that cannot be read is not an empty one: a look on it hands
/// the receivers nothing, instead of taking every host's previews away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_of_paired_hosts_that_cannot_be_read_leaves_the_receivers_keys_as_they_are() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;
    let before = phone
        .receiver
        .state
        .lock()
        .expect("the receiver")
        .keys_asked;
    let held = held_keys(&phone).expect("the receivers were handed keys");
    assert_eq!(held.senders.len(), 1);

    let file = find(phone._phone.data.path(), "hosts.json").expect("the paired hosts' file");
    let kept = std::fs::read(&file).expect("the paired hosts");
    std::fs::write(&file, b"{ not a list").expect("spoiled");
    assert!(
        phone.desk.refresh().await.is_err(),
        "a list that cannot be read is no list"
    );
    std::fs::write(&file, kept).expect("mended");

    assert_eq!(
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .keys_asked,
        before,
        "nothing was handed over on a list that could not be read"
    );
    assert_eq!(held_keys(&phone), Some(held));
}

/// A phone with one host whose notifications are on.
async fn a_phone_with_notifications_on() -> (Host, Desk, String) {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;
    (host, phone, reference)
}

/// What the host was handed, registration by registration: whether previews were asked for.
fn previews_asked(phone: &Desk) -> Vec<bool> {
    phone
        .registered
        .lock()
        .expect("what was handed")
        .credentials
        .iter()
        .map(|(_, handed)| handed["previews_enabled"].as_bool().expect("a choice"))
        .collect()
}

/// KR-REQ-16.11: turning previews off takes the host's key out of what the receivers hold before
/// the host is told, tells the host, and asks the provider for nothing: no token is proposed and no
/// challenge is waited for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turning_previews_off_takes_the_hosts_key_out_before_the_host_is_told() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    assert_eq!(held_keys(&phone).expect("keys").senders.len(), 1);
    phone.registered.lock().expect("the script").hold_connection = true;

    let view = phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect("the person chooses");

    assert!(!view.hosts[0].previews, "the choice is recorded at once");
    assert!(
        held_keys(&phone).expect("keys").senders.is_empty(),
        "the receivers hold no key of the host before it is told"
    );
    eventually("the run reached the host", || {
        phone.registered.lock().expect("the script").connected.len() == 2
    })
    .await;
    assert_eq!(previews_asked(&phone), [true], "the host is not told yet");

    phone.registered.lock().expect("the script").hold_connection = false;
    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(previews_asked(&phone), [true, false]);
    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN],
        "no token was proposed again"
    );
    assert!(held_keys(&phone).expect("keys").senders.is_empty());
}

/// KR-REQ-16.11: turning previews on files the host's key before the host is told to seal them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turning_previews_on_files_the_hosts_key_before_the_host_is_told() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect("off");
    phone.until(|states| states == [PushState::On]).await;
    eventually("the host was told", || {
        previews_asked(&phone) == [true, false]
    })
    .await;
    phone.registered.lock().expect("the script").hold_connection = true;

    phone.desk.set_previews(&reference, true).await.expect("on");

    assert_eq!(
        held_keys(&phone).expect("keys").senders.len(),
        1,
        "the receivers hold the host's key before the host is told"
    );
    assert_eq!(
        previews_asked(&phone),
        [true, false],
        "the host is not told yet"
    );
    phone.registered.lock().expect("the script").hold_connection = false;
    eventually("the host was told", || {
        previews_asked(&phone) == [true, false, true]
    })
    .await;
    phone.until(|states| states == [PushState::On]).await;
}

/// KR-REQ-16.11: a host that cannot be told leaves the row needing the person, the choice stays
/// recorded and no key is filed for the host, and Try again runs the whole sequence with the choice
/// that was recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_the_host_could_not_be_told_stays_recorded_and_try_again_sends_it() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    let refusal =
        "RATE_LIMITED: this device has changed its choice of previews too often; try again later";
    phone.registered.lock().expect("the script").register_stops =
        Some(LineStop::Host(refusal.to_owned()));

    phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect("off");
    phone
        .until(|states| states == [PushState::NeedsAttention])
        .await;
    assert!(!phone.view().hosts[0].previews, "the choice stays recorded");
    assert!(
        phone.view().hosts[0].words.ends_with(refusal),
        "the row says what the host said: {:?}",
        phone.view().hosts[0].words
    );
    assert!(held_keys(&phone).expect("keys").senders.is_empty());

    // A host that needs the person is not told again by a second choice: the choice is recorded,
    // and Try again sends it.
    let reaches = phone.registered.lock().expect("the script").reaches.len();
    phone
        .desk
        .set_previews(&reference, true)
        .await
        .expect("on again");
    assert!(
        phone.view().hosts[0].previews,
        "the second choice is recorded"
    );
    assert_eq!(
        phone.registered.lock().expect("the script").reaches.len(),
        reaches,
        "no run was started for a host that needs the person"
    );
    assert_eq!(phone.view().hosts[0].state, PushState::NeedsAttention);
    phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect("off again");

    phone.registered.lock().expect("the script").register_stops = None;
    phone.desk.enable(&reference).expect("Try again");
    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN, FIRST_TOKEN],
        "Try again runs the whole sequence"
    );
    assert_eq!(
        previews_asked(&phone).last(),
        Some(&false),
        "with the recorded choice"
    );
}

/// KR-REQ-16.11: a token that changed while the host was told of the choice is registered again,
/// as it is after any run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_that_changed_while_the_host_was_told_of_a_choice_is_registered() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    phone.registered.lock().expect("the script").hold_answer = true;
    phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect("off");
    eventually("the host was handed the registration", || {
        previews_asked(&phone).len() == 2
    })
    .await;
    phone.receiver.token_is(SECOND_TOKEN);
    phone.registered.lock().expect("the script").hold_answer = false;

    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(proposed(&phone.gateway), [FIRST_TOKEN, SECOND_TOKEN]);
}

/// KR-REQ-16.11: a token that cannot be read when the host has been told of a choice stops the run
/// needing the person, as it does after any run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_that_cannot_be_read_after_a_choice_stops_the_run_needing_the_person() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    phone
        .receiver
        .with(|state| state.token_readable_for = Some(state.token_reads));

    phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect("off");
    phone
        .until(|states| states == [PushState::NeedsAttention])
        .await;
    phone
        .until_words("could not read its notification token")
        .await;
}

/// KR-REQ-16.11: a choice made while a run holds the host is read by that run when it tells the host,
/// and goes round again when the choice changed after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_made_while_a_run_tells_the_host_is_told_after_it() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.registered.lock().expect("the script").hold_answer = true;
    phone.desk.enable(&reference).expect("the person asks");
    eventually("the host was handed the registration", || {
        previews_asked(&phone).len() == 1
    })
    .await;

    phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect("off");
    phone.registered.lock().expect("the script").hold_answer = false;

    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(previews_asked(&phone), [true, false]);
    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN],
        "one proposal: the second pass was the host's only"
    );
}

/// An earlier record, written before the choice existed, reads as previews on, and the host is told
/// so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_earlier_record_with_no_choice_reads_as_previews_on() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    let file = find(phone._phone.data.path(), "push.json").expect("the record");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("the record")).expect("json");
    for host in record["hosts"].as_object_mut().expect("hosts").values_mut() {
        host.as_object_mut().expect("a host").remove("previews");
        host.as_object_mut()
            .expect("a host")
            .remove("told_previews");
    }
    std::fs::write(&file, serde_json::to_vec(&record).expect("json")).expect("an earlier record");

    let restarted = reopened(&phone);
    assert!(
        restarted.desk.view().hosts[0].previews,
        "an earlier record reads as on"
    );
    restarted.desk.enable(&reference).expect("Try again");
    states_until(&restarted.desk, |states| states == [PushState::On]).await;
    assert_eq!(previews_asked(&phone).last(), Some(&true));
}

/// A look finds a host that is on and was last told another choice than the one recorded, and tells
/// it, at most once a minute, with no token proposed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_look_tells_a_host_the_choice_it_was_not_told() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    let file = find(phone._phone.data.path(), "push.json").expect("the record");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("the record")).expect("json");
    for host in record["hosts"].as_object_mut().expect("hosts").values_mut() {
        host["previews"] = json!(false);
        host["told_previews"] = json!(true);
    }
    std::fs::write(&file, serde_json::to_vec(&record).expect("json")).expect("a choice not told");

    let restarted = reopened(&phone);
    assert!(!restarted.desk.view().hosts[0].previews);
    look(&restarted.desk).await;
    assert_eq!(
        previews_asked(&phone),
        [true],
        "a look within a minute of the write waits"
    );
    restarted.let_time_pass();
    look(&restarted.desk).await;
    states_until(&restarted.desk, |states| states == [PushState::On]).await;
    eventually("the host was told", || {
        previews_asked(&phone) == [true, false]
    })
    .await;
    assert_eq!(
        proposed(&restarted.gateway),
        Vec::<String>::new(),
        "no token was proposed"
    );
    let _ = reference;
}

/// What the page has been told so far: how many times the desk said that what it shows changed.
fn told(phone: &Desk) -> usize {
    phone.changes.load(Ordering::SeqCst)
}

/// A look that cannot read the notification token cannot say that a host which is on still has the
/// token it was registered with: it shows the host as needing the person, starts no run, tells the
/// page once, and the next look that reads a token shows it on again without registering it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_look_that_cannot_read_the_token_does_not_leave_a_host_shown_as_on() {
    let (_host, phone, _reference) = a_phone_with_notifications_on().await;
    let before = told(&phone);
    phone
        .receiver
        .with(|state| state.token_readable_for = Some(state.token_reads));

    look(&phone.desk).await;

    assert_eq!(phone.view().hosts[0].state, PushState::NeedsAttention);
    assert!(
        phone.view().hosts[0]
            .words
            .contains("could not check its notification token"),
        "{:?}",
        phone.view().hosts[0].words
    );
    assert_eq!(told(&phone), before + 1, "the page was told");
    look(&phone.desk).await;
    assert_eq!(told(&phone), before + 1, "nothing new to tell the page");
    assert_eq!(
        phone.registered.lock().expect("what was sent").reaches,
        [Reach::Asked],
        "no run was started"
    );

    phone.receiver.with(|state| state.token_readable_for = None);
    look(&phone.desk).await;
    assert_eq!(phone.view().hosts[0].state, PushState::On);
    assert_eq!(told(&phone), before + 2, "the page was told it is on again");
    assert_eq!(
        proposed(&phone.gateway),
        [FIRST_TOKEN],
        "the same token is not registered again"
    );
}

/// A host left unconfirmed by a look that could not read the token is registered by the next look
/// that reads a different one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_left_unconfirmed_is_registered_when_the_next_look_finds_another_token() {
    let (_host, phone, _reference) = a_phone_with_notifications_on().await;
    phone
        .receiver
        .with(|state| state.token_readable_for = Some(state.token_reads));
    look(&phone.desk).await;
    assert_eq!(phone.view().hosts[0].state, PushState::NeedsAttention);

    phone.receiver.with(|state| state.token_readable_for = None);
    phone.receiver.token_is(SECOND_TOKEN);
    look(&phone.desk).await;
    phone.until(|states| states == [PushState::On]).await;
    assert_eq!(proposed(&phone.gateway), [FIRST_TOKEN, SECOND_TOKEN]);
}

/// A desk opened while the paired hosts could not be read cannot write a record, so a host it never
/// heard of is not one it can turn on: once the list can be read the host shows as needing the
/// person, with the words that say to start the application again, and turning it on starts nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_a_blocked_desk_never_heard_of_shows_the_restart_words_once_the_list_is_readable() {
    let (_host, phone) = a_phone_whose_record_was_spoiled(b"{ not a record").await;
    let file = find(phone._phone.data.path(), "hosts.json").expect("the paired hosts' file");
    let kept = std::fs::read(&file).expect("the paired hosts");
    std::fs::write(&file, b"{ not a list").expect("spoiled");
    let blocked = reopened(&phone);
    std::fs::write(&file, kept).expect("mended");

    let shown = blocked.desk.view().hosts.remove(0);
    assert_eq!(shown.state, PushState::NeedsAttention);
    assert!(
        shown
            .words
            .contains("Close the application and open it again"),
        "{:?}",
        shown.words
    );
    blocked
        .desk
        .enable(&shown.reference)
        .expect("the person asks");
    assert_eq!(Arc::strong_count(&blocked.desk), 1, "no run was started");
}

/// A host whose run the system ended in the middle, `ago_ms` before the application starts again.
async fn a_phone_whose_run_ended_with_the_application(ago_ms: u64) -> (Host, Desk, Opened) {
    let (host, phone, _reference) = a_phone_with_notifications_on().await;
    let file = find(phone._phone.data.path(), "push.json").expect("the record");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("the record")).expect("json");
    let now = kr_ipc::now_ms().get();
    for each in record["hosts"].as_object_mut().expect("hosts").values_mut() {
        each["phase"] = json!("working");
        each["updated_ms"] = json!(now - ago_ms);
    }
    std::fs::write(&file, serde_json::to_vec(&record).expect("json")).expect("an interrupted run");
    let restarted = reopened(&phone);
    (host, phone, restarted)
}

/// KR-REQ-16.08: a run the application's end cut short is tried again by the first look when it was
/// last heard of a minute or more before the start, and waits out the rest of the minute when it was
/// sooner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_cut_short_a_minute_before_the_start_is_tried_again_at_the_first_look() {
    let (_host, phone, restarted) = a_phone_whose_run_ended_with_the_application(90_000).await;
    assert_eq!(
        restarted.desk.view().hosts[0].state,
        PushState::NeedsAttention
    );

    look(&restarted.desk).await;

    states_until(&restarted.desk, |states| states == [PushState::On]).await;
    assert_eq!(
        phone.registered.lock().expect("what was sent").reaches,
        [Reach::Asked, Reach::Visit]
    );
}

/// A run cut short ten seconds before the start waits out the rest of its minute: a look starts
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_cut_short_moments_before_the_start_waits_out_its_minute() {
    let (_host, phone, restarted) = a_phone_whose_run_ended_with_the_application(10_000).await;

    look(&restarted.desk).await;

    assert_eq!(Arc::strong_count(&restarted.desk), 1, "no run was started");
    assert_eq!(
        phone.registered.lock().expect("what was sent").reaches,
        [Reach::Asked]
    );
    assert_eq!(
        restarted.desk.view().hosts[0].state,
        PushState::NeedsAttention
    );
}

/// A failure in the page's callback, in the look that claimed the hosts, does not leave a host
/// working with no run behind it: the runs are started before the page is told, so each host reaches
/// the end the look sent it to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_callback_that_fails_in_the_look_does_not_leave_a_host_working_without_a_run() {
    let owner = DeviceKeys::generate().expect("keys");
    let first = Host::start(&owner).await;
    let second = Host::start(&owner).await;
    let phone = desk(&[&first, &second], &owner, Receiver::new(FIRST_TOKEN)).await;
    for reference in phone.references() {
        phone.desk.enable(&reference).expect("the person asks");
    }
    phone
        .until(|states| states == [PushState::On, PushState::On])
        .await;

    phone.receiver.token_is(SECOND_TOKEN);
    let desk = Arc::clone(&phone.desk);
    let outcome =
        tokio::spawn(CALLBACK_FAILS_HERE.scope(true, async move { desk.refresh().await })).await;
    assert!(
        outcome.is_err_and(|error| error.is_panic()),
        "the callback failed in the look"
    );

    phone
        .until(|states| states == [PushState::On, PushState::On])
        .await;
    assert_eq!(
        proposed(&phone.gateway)
            .iter()
            .filter(|token| *token == SECOND_TOKEN)
            .count(),
        2,
        "each host registered the token the provider holds"
    );
}

/// A host this phone is no longer paired with when the application starts keeps nothing in the
/// record: the start writes the record without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_drops_what_the_record_kept_of_a_host_no_longer_paired() {
    let (_host, phone, _reference) = a_phone_with_notifications_on().await;
    let paired = phone
        .device
        .pairing()
        .hosts
        .list()
        .expect("the paired hosts")
        .remove(0);
    phone
        .device
        .forget_host(paired.host_device_id)
        .expect("the pairing is forgotten");
    let file = find(phone._phone.data.path(), "push.json").expect("the record");
    let kept: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("the record")).expect("json");
    assert_eq!(kept["hosts"].as_object().expect("hosts").len(), 1);

    drop(reopened(&phone));

    let written: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("the record")).expect("json");
    assert!(
        written["hosts"].as_object().expect("hosts").is_empty(),
        "{written}"
    );
}

/// A host nobody asked for notifications has no row to choose on: the choice is left alone, quietly,
/// and the desk goes on answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_made_for_a_host_never_asked_for_notifications_changes_nothing() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);

    // On a task of its own, so that a call that never ends is the watchdog's to stop.
    let desk = Arc::clone(&phone.desk);
    let choosing = tokio::spawn({
        let reference = reference.clone();
        async move { desk.set_previews(&reference, false).await }
    });
    let view = tokio::time::timeout(WATCHDOG, choosing)
        .await
        .expect("the call ends")
        .expect("the call ran")
        .expect("a view");

    assert_eq!(view.hosts[0].state, PushState::Off);
    assert!(held_keys(&phone).is_none(), "nothing was filed");
    assert_eq!(
        phone.view().hosts[0].state,
        PushState::Off,
        "the desk answers"
    );
}

/// KR-REQ-16.11: the host is told previews are off only after the key is out of the receivers'
/// hands. A run that began before the choice, and is at the gateway when it is made, tells the host
/// what it read before the choice; the choice is told after the receivers have let the key go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_that_began_before_the_choice_does_not_tell_the_host_off_ahead_of_the_receivers() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    phone.gateway.hold_issue(true);
    phone.desk.enable(&reference).expect("Try again");
    eventually("the run is at the gateway", || {
        phone.gateway.issue_requests() == 2
    })
    .await;

    // The person turns previews off, and the receivers are slow to let the key go.
    let next = phone
        .receiver
        .state
        .lock()
        .expect("the receiver")
        .keys_asked
        + 1;
    phone.receiver.with(|state| {
        state.keys_hold = Some(next);
        state.keys_released = false;
    });
    let choosing = tokio::spawn({
        let (desk, reference) = (Arc::clone(&phone.desk), reference.clone());
        async move { desk.set_previews(&reference, false).await }
    });
    eventually("the removal is asked of the receivers", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .keys_asked
            == next
    })
    .await;

    // The gateway answers and the run tells the host while the receivers still hold the key.
    phone.gateway.hold_issue(false);
    eventually("the run told the host", || {
        previews_asked(&phone).len() == 2
    })
    .await;
    assert_eq!(
        previews_asked(&phone),
        [true, true],
        "the host was not told off while the receivers held its key"
    );

    phone.receiver.with(|state| state.keys_released = true);
    choosing.await.expect("the call ran").expect("the choice");
    eventually("the host was told off", || {
        previews_asked(&phone) == [true, true, false]
    })
    .await;
    phone.until(|states| states == [PushState::On]).await;
    assert!(held_keys(&phone).expect("keys").senders.is_empty());
}

/// KR-REQ-16.11: a choice whose key cannot be filed is not made. Previews off that left the host's
/// key with the receivers would be off in name only, so the choice is let go with the record, the
/// person is told, and no run starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_whose_key_cannot_be_filed_is_not_made() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    phone.receiver.with(|state| state.keys_fail = true);

    let refused = phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect_err("the choice is refused");

    assert!(
        refused.message.contains("could not file its preview key"),
        "{:?}",
        refused.message
    );
    assert!(phone.view().hosts[0].previews, "the choice was let go");
    assert_eq!(phone.view().hosts[0].state, PushState::On);
    assert_eq!(
        phone.registered.lock().expect("what was sent").reaches,
        [Reach::Asked],
        "no run was started"
    );
    // The receivers are handed the set the record says at the next look, since what they hold is
    // not known after a filing that failed.
    let asked = |phone: &Desk| {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .keys_asked
    };
    let before = asked(&phone);
    phone.receiver.with(|state| state.keys_fail = false);
    look(&phone.desk).await;
    assert!(asked(&phone) > before, "the look filed the set again");
    assert_eq!(held_keys(&phone).expect("keys").senders.len(), 1);
}

/// KR-REQ-16.11: a filing that failed part way may have left the receivers holding some of the new
/// set, so the choice is let go with the set the record says filed again at once: previews that were
/// off do not stay open to a host because an attempt to turn them on stopped half way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_filing_that_failed_part_way_is_followed_by_the_earlier_set_at_once() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    phone
        .desk
        .set_previews(&reference, false)
        .await
        .expect("off");
    phone.until(|states| states == [PushState::On]).await;
    eventually("the host was told off", || {
        previews_asked(&phone) == [true, false]
    })
    .await;
    assert!(held_keys(&phone).expect("keys").senders.is_empty());

    phone.receiver.with(|state| {
        state.keys_fail_next = 1;
        state.keys_partly_applied = true;
    });
    let refused = phone
        .desk
        .set_previews(&reference, true)
        .await
        .expect_err("the choice is refused");

    assert!(
        refused.message.contains("Try again"),
        "{:?}",
        refused.message
    );
    assert!(!phone.view().hosts[0].previews, "the choice was let go");
    assert!(
        held_keys(&phone).expect("keys").senders.is_empty(),
        "the host's key the failed filing left is taken out again before the call ends"
    );
}

/// KR-REQ-16.11: previews turned off reach the host even when the key cannot be taken out of the
/// receivers' hands in the run that tells it: the host stops sealing, and the row says what is left
/// to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn previews_turned_off_reach_the_host_though_the_key_cannot_be_taken_out_in_that_run() {
    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    let file = find(phone._phone.data.path(), "push.json").expect("the record");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("the record")).expect("json");
    for each in record["hosts"].as_object_mut().expect("hosts").values_mut() {
        each["previews"] = json!(false);
    }
    std::fs::write(&file, serde_json::to_vec(&record).expect("json")).expect("a choice kept");
    let restarted = reopened(&phone);
    phone.receiver.with(|state| state.keys_fail = true);

    restarted.desk.enable(&reference).expect("Try again");

    states_until(&restarted.desk, |states| {
        states == [PushState::NeedsAttention]
    })
    .await;
    assert_eq!(
        previews_asked(&phone),
        [true, false],
        "the host was told off"
    );
    let words = restarted.desk.view().hosts[0].words.clone();
    assert!(
        words.contains("could not file its preview key"),
        "{words:?}"
    );
}

/// A choice the record cannot keep is not made: the record is what a restart reads, and an off that
/// only the memory held would be on again at the next start.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_the_record_cannot_keep_is_not_made() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    let directory = phone._phone.data.path().join("push");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
        .expect("the directory is made unwritable");
    if std::fs::write(directory.join("probe"), b"").is_ok() {
        eprintln!(
            "a_choice_the_record_cannot_keep: skipped, this account writes where it was refused"
        );
        return;
    }

    let refused = phone.desk.set_previews(&reference, false).await;

    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is made writable again");
    assert!(refused.is_err(), "the choice is refused");
    assert!(phone.view().hosts[0].previews, "and let go");
    assert_eq!(
        phone.registered.lock().expect("what was sent").reaches,
        [Reach::Asked],
        "no run was started"
    );
}

/// A choice let go after its filing failed is written back to the record, and when that cannot be
/// done the person is told the earlier choice may return: what a restart reads is what the person is
/// told.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_choice_let_go_says_so_when_the_record_cannot_be_written_back() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_host, phone, reference) = a_phone_with_notifications_on().await;
    let next = phone
        .receiver
        .state
        .lock()
        .expect("the receiver")
        .keys_asked
        + 1;
    phone.receiver.with(|state| {
        state.keys_hold = Some(next);
        state.keys_released = false;
    });
    let choosing = tokio::spawn({
        let (desk, reference) = (Arc::clone(&phone.desk), reference.clone());
        async move { desk.set_previews(&reference, false).await }
    });
    eventually("the filing is asked of the receivers", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .keys_asked
            == next
    })
    .await;
    // The record took the choice. It cannot take another write now.
    let directory = phone._phone.data.path().join("push");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
        .expect("the directory is made unwritable");
    if std::fs::write(directory.join("probe"), b"").is_ok() {
        eprintln!("a_choice_let_go_says_so: skipped, this account writes where it was refused");
        phone.receiver.with(|state| state.keys_released = true);
        let _ = choosing.await;
        return;
    }

    phone.receiver.with(|state| {
        state.keys_fail = true;
        state.keys_released = true;
    });
    let refused = choosing
        .await
        .expect("the call ran")
        .expect_err("the choice is refused");

    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is made writable again");
    assert!(
        refused.message.contains("put back"),
        "the person is told the earlier choice may not be what is kept: {:?}",
        refused.message
    );
    assert!(phone.view().hosts[0].previews, "and the choice was let go");
}
