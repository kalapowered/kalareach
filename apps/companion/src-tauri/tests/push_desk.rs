//! A phone turns notifications on for the hosts it is paired with.
//!
//! The device is this crate's own backend paired with real in-process hosts. The native half (the
//! system's permission, the provider's token, the record the receiver answers a challenge into, the
//! limited key store) and the notification service's gateway are the two things a test has no
//! phone and no Google for, so each is a small script; the phone's sequencing, its record and its
//! pairing records are the product's. What the devices' legs show of the receivers and of the real
//! gateway is shown there; what these hold is the order and the keys the application's core uses.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-16.08 | `a_host_the_person_asked_for_is_handed_the_credential_the_gateway_issued` |
//! | KR-REQ-16.11 | `the_key_filed_for_the_notification_extension_is_the_preview_key_the_host_was_told_of` |
//! | KR-REQ-16.06 | `two_hosts_that_ask_together_register_one_after_the_other` |
//! | KR-REQ-16.16 | `a_token_that_changes_while_a_host_registers_is_registered_again_when_that_run_ends` |
//! | KR-REQ-16.06 | `a_token_that_arrives_a_moment_after_the_permission_is_waited_for` |
//! | KR-REQ-16.06 | `a_look_the_application_makes_by_itself_never_asks_the_system_for_permission` |

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// The provider's token, once the provider has made one.
    token: Option<String>,
    /// Reads of the token that say there is none yet, before there is one.
    reads_without_a_token: usize,
    changed: bool,
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
                token: Some(token.to_owned()),
                reads_without_a_token: 0,
                changed: false,
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

    fn token_changed_to(&self, token: &str) {
        self.with(|state| {
            state.token = Some(token.to_owned());
            state.changed = true;
        });
    }
}

impl Native for Receiver {
    fn permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async move {
            let mut state = self.state.lock().expect("the receiver");
            state.permission_reads += 1;
            Ok(state.permission)
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
            let mut state = self.state.lock().expect("the receiver");
            if state.reads_without_a_token > 0 {
                state.reads_without_a_token -= 1;
                return Ok(None);
            }
            Ok(state.token.clone())
        })
    }

    fn token_changed(&self) -> PushFuture<'_, bool> {
        Box::pin(async move {
            Ok(std::mem::take(
                &mut self.state.lock().expect("the receiver").changed,
            ))
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
        tokio::time::timeout(WATCHDOG, async {
            loop {
                let states: Vec<PushState> =
                    self.view().hosts.iter().map(|host| host.state).collect();
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
                self.view()
                    .hosts
                    .iter()
                    .map(|host| (host.state, host.words.clone()))
                    .collect::<Vec<_>>()
            )
        })
    }
}

async fn desk(hosts: &[&Host], owner: &DeviceKeys, receiver: Arc<Receiver>) -> Desk {
    let phone = phone_paired_with(hosts[0], owner, &[ActionRight::SessionView]).await;
    for other in &hosts[1..] {
        pair(&phone, other, owner, &[ActionRight::SessionView]).await;
    }
    let device = phone.companion.device();
    let gateway = Arc::new(Gateway {
        proposed: Mutex::new(Vec::new()),
    });
    let registered = Arc::new(Mutex::new(Registered::default()));
    let http = Arc::clone(&gateway);
    let clock_ahead_ms = Arc::new(AtomicU64::new(0));
    let ahead = Arc::clone(&clock_ahead_ms);
    let desk = PushDesk::open(
        phone.data.path(),
        Arc::clone(&device),
        Arc::clone(&receiver) as Arc<dyn Native>,
        Arc::new(HostLink(Arc::clone(&registered))),
        Wiring {
            http: Arc::new(move |_| Ok(Arc::clone(&http) as Arc<dyn ServiceHttp>)),
            clock: Arc::new(move || kr_ipc::now_ms().get() + ahead.load(Ordering::SeqCst)),
        },
        || {},
    )
    .expect("the desk opens");
    Desk {
        desk,
        receiver,
        gateway,
        registered,
        device,
        clock_ahead_ms,
        _phone: phone,
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
    // The control: the installation's authorisation key is another key, and is not what is filed.
    let authorisation = phone
        .device
        .identity()
        .keys
        .authorisation
        .public()
        .as_bytes()
        .to_vec();
    assert_ne!(derived.public().as_bytes().to_vec(), authorisation);
}

/// KR-REQ-16.06: the phone keeps one record of the registration it waits for and the gateway one
/// pending attempt, so two hosts asked together are registered one after the other. Neither is told
/// that a newer registration replaced it, and both end up on.
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
    phone.receiver.token_changed_to(SECOND_TOKEN);
    phone.desk.refresh().await;

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

/// KR-REQ-16.06: the provider makes a registration token a moment after the person agrees, so the
/// sequence waits for it and does not stop with "no token yet" at the first look.
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

/// KR-REQ-16.06: the system's permission question is asked when the person chooses to turn
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
    phone
        .clock_ahead_ms
        .fetch_add(2 * 60 * 1000, Ordering::SeqCst);
    phone.desk.refresh().await;
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
