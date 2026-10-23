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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_platform::notify::Permission;
use companion_platform::push::{PendingRegistration, PendingState};
use companion_tauri::device::Device;
use companion_tauri::push::{Native, PushDesk, PushFuture, PushState, PushView, Registrar, Wiring};
use kr_client::pairing::paired::PairedHost;
use kr_client::services::ServiceFuture;
use kr_client::services::relay::{ServiceHttp, ServiceHttpAnswer};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{MemoryStore, SecretName, SecretStore, load_notification_preview_key};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::push::{DevicePushRegisterParams, DevicePushRegisterResult};
use kr_protocol::rights::ActionRight;
use net_support::Host;
use serde_json::{Value, json};
use support::{WATCHDOG, pair, phone_paired_with};

const VECTORS: &str = include_str!("../../../../fixtures/push/push.json");

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
    /// How many reads of the permission have answered.
    permission_answered: usize,
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
    /// What was filed for the extension: the key identifier and the seed.
    filed: Vec<([u8; 32], Vec<u8>)>,
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
                permission_answered: 0,
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
                filed: Vec::new(),
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
                    let mut state = self.state.lock().expect("the receiver");
                    if !state.permission_held.contains(&number)
                        || state.permission_released.contains(&number)
                    {
                        state.permission_answered += 1;
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

    fn limited_key<'a>(
        &'a self,
        recipient_key_id: &'a [u8; 32],
        seed: &'a [u8],
    ) -> PushFuture<'a, ()> {
        Box::pin(async move {
            self.state
                .lock()
                .expect("the receiver")
                .filed
                .push((*recipient_key_id, seed.to_vec()));
            Ok(())
        })
    }

    fn route(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async move { Ok(None) })
    }
}

/// What the host was handed.
#[derive(Default)]
struct Registered {
    /// The host, the sender record the credential is for and the preview key it was told of.
    handed: Vec<(
        kr_protocol::ids::DeviceId,
        Value,
        kr_protocol::scalars::NotificationPreviewKey,
    )>,
}

struct HostLink(Arc<Mutex<Registered>>);

impl Registrar for HostLink {
    fn register<'a>(
        &'a self,
        host: &'a PairedHost,
        params: DevicePushRegisterParams,
        preview_key: kr_protocol::scalars::NotificationPreviewKey,
    ) -> PushFuture<'a, DevicePushRegisterResult> {
        Box::pin(async move {
            self.0.lock().expect("what was handed").handed.push((
                host.host_device_id,
                json!({ "sender_record_id": params.credential.sender_record_id.to_string() }),
                preview_key,
            ));
            let records = vectors()["records"].clone();
            Ok(serde_json::from_value(json!({
                "device_id": host.device_id.to_string(),
                "installation_id": records["installation_binding"]["installation_id"],
                "sender_record_id": records["sender_record"]["binding"]["sender_record_id"],
                "credential_expires_at_ms": "1769817600000",
            }))
            .expect("a result"))
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
        let answer = if url.ends_with("/api/push/sender/issue") {
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
    /// Whether the application ends at its next page callback: the callback is the product's own
    /// seam, at a point with no wait in it where a process can end.
    ends: Arc<AtomicBool>,
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
    let phone = phone_paired_with(hosts[0], owner, &[ActionRight::SessionView]).await;
    for other in &hosts[1..] {
        pair(&phone, other, owner, &[ActionRight::SessionView]).await;
    }
    let device = phone.companion.device();
    let registered = Arc::new(Mutex::new(Registered::default()));
    let ends = Arc::new(AtomicBool::new(false));
    let opened = open_over(
        phone.data.path(),
        &device,
        &receiver,
        &registered,
        Arc::clone(&ends),
    );
    Desk {
        desk: opened.desk,
        receiver,
        gateway: opened.gateway,
        registered,
        device,
        clock_ahead_ms: opened.clock_ahead_ms,
        ends,
        _phone: phone,
    }
}

/// A desk opened over the record in `data`, with a gateway of its own and a clock that can be set
/// ahead: what the application opens each time it starts.
struct Opened {
    desk: Arc<PushDesk>,
    gateway: Arc<Gateway>,
    clock_ahead_ms: Arc<AtomicU64>,
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
    ends: Arc<AtomicBool>,
) -> Opened {
    let gateway = Arc::new(Gateway {
        proposed: Mutex::new(Vec::new()),
    });
    let http = Arc::clone(&gateway);
    let clock_ahead_ms = Arc::new(AtomicU64::new(0));
    let ahead = Arc::clone(&clock_ahead_ms);
    let desk = PushDesk::open(
        data,
        Arc::clone(device),
        Arc::clone(receiver) as Arc<dyn Native>,
        Arc::new(HostLink(Arc::clone(registered))),
        Wiring {
            http: Arc::new(move |_| Ok(Arc::clone(&http) as Arc<dyn ServiceHttp>)),
            clock: Arc::new(move || kr_ipc::now_ms().get() + ahead.load(Ordering::SeqCst)),
        },
        move || assert!(!ends.load(Ordering::SeqCst), "the application ends"),
    )
    .expect("the desk opens");
    Opened {
        desk,
        gateway,
        clock_ahead_ms,
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
        handed.handed.len(),
        1,
        "the host was handed one registration"
    );
    assert_eq!(
        handed.handed[0].1["sender_record_id"],
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

/// KR-REQ-16.11: what is filed for the notification extension is the preview key's seed, the one
/// the host was told the public half of, under that key's identifier. The authorisation key's seed
/// is not what is filed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_key_filed_for_the_notification_extension_is_the_preview_key_the_host_was_told_of() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let phone = desk(&[&host], &owner, Receiver::new(FIRST_TOKEN)).await;
    let reference = phone.references().remove(0);
    phone.desk.enable(&reference).expect("the person asks");
    phone.until(|states| states == [PushState::On]).await;

    let filed = phone
        .receiver
        .state
        .lock()
        .expect("the receiver")
        .filed
        .clone();
    assert_eq!(filed.len(), 1, "one key was filed");
    let (key_id, seed) = &filed[0];
    // The seed that was filed, read back as the notification extension reads its key.
    let store = MemoryStore::new();
    let name = SecretName::device_key(
        companion_platform::secrets::DEVICE_SCOPE,
        KeyPurpose::NotificationPreview,
    )
    .expect("a name");
    store.set(&name, seed).expect("the seed is kept");
    let derived = load_notification_preview_key(&store, companion_platform::secrets::DEVICE_SCOPE)
        .expect("the key loads")
        .expect("a key");
    let handed = phone.registered.lock().expect("what was handed");
    assert_eq!(
        derived.public(),
        &handed.handed[0].2,
        "the seed filed is the one the host's preview key is made from"
    );
    assert_eq!(
        key_id,
        derived.key_id().as_bytes(),
        "under that key's identifier"
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
        seed.as_slice(),
        "the authorisation seed is not what is filed"
    );
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
    let hosts: BTreeSet<_> = handed.handed.iter().map(|each| each.0).collect();
    assert_eq!(hosts.len(), 2, "each host was handed a credential");
    for each in &handed.handed {
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
        Arc::new(AtomicBool::new(false)),
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
        Arc::new(AtomicBool::new(false)),
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
/// the look that found it, right after that look has written what it found and before anything
/// else. Both hosts are then marked, as one write, and the next start registers both with the token
/// the provider holds.
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

    phone.receiver.token_is(SECOND_TOKEN);
    phone.ends.store(true, Ordering::SeqCst);
    let desk = Arc::clone(&phone.desk);
    let outcome = tokio::spawn(async move { desk.refresh().await }).await;
    assert!(
        outcome.is_err_and(|error| error.is_panic()),
        "the look ended where the application does"
    );

    let restarted = open_over(
        phone._phone.data.path(),
        &phone.device,
        &Receiver::new(SECOND_TOKEN),
        &phone.registered,
        Arc::new(AtomicBool::new(false)),
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

    // The record as an earlier build wrote it.
    let file = phone._phone.data.path().join("push").join("push.json");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(&file).expect("the record")).expect("a record");
    for kept in record["hosts"].as_object_mut().expect("hosts").values_mut() {
        assert!(
            kept.as_object_mut()
                .expect("a host")
                .remove("registered")
                .is_some(),
            "the record keeps the digest of the token it proposed"
        );
    }
    std::fs::write(&file, serde_json::to_vec(&record).expect("a record")).expect("written");

    let restarted = open_over(
        phone._phone.data.path(),
        &phone.device,
        &Receiver::new(FIRST_TOKEN),
        &phone.registered,
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(restarted.desk.view().hosts[0].state, PushState::On);
    look(&restarted.desk).await;
    states_until(&restarted.desk, |states| states == [PushState::On]).await;
    assert_eq!(proposed(&restarted.gateway), [FIRST_TOKEN]);
    let kept = std::fs::read_to_string(&file).expect("the record");
    assert!(kept.contains("\"registered\""), "{kept}");
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
            .handed
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

/// The run of a host that was forgotten does not use the consent the person gave when they turned
/// the host on again: it ends without asking the system anything, and the new run asks once.
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

    // The first run's answer arrives first, and is let finish before the second run's does.
    phone.receiver.with(|state| {
        state.permission_released.insert(1);
    });
    eventually("the first run's answer reached it", || {
        phone
            .receiver
            .state
            .lock()
            .expect("the receiver")
            .permission_answered
            >= 1
    })
    .await;
    // The second run's answer is let go next. It notices that at its next look at the gate, which
    // is later than the first run needs to take what it takes, a few steps with nothing awaited.
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
