//! A phone that was paired with a host pairs with it again.
//!
//! The daemon is kr-controller's in-process host, with its test support included by path, and the
//! device is this crate's own backend on the mock runtime: it pairs through the commands the page
//! calls, forgets the host the way the page's forget question does, and pairs again with a new
//! invitation that the host's owner issues and confirms. The host's record of the phone ended by a
//! revocation or by the end of its grant, or it did not end at all: what the phone is shown and
//! what the host keeps are read at each step.
//!
//! Every wait of a case is a condition with a bound and a message of its own, and every result of
//! a step is asserted before its value is taken: a failing case ends at an assertion that names
//! what did not happen.

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use companion_platform::notify::{Permission, PreviewKeys};
use companion_platform::push::{PendingRegistration, PendingState};
use companion_tauri::push::{
    HostLine, LineFuture, Native, PushDesk, PushFuture, PushState, Reach, Registrar,
    RegistrationRead, Wiring,
};
use kr_client::pairing::paired::PairedHost;
use kr_client::services::ServiceFuture;
use kr_client::services::relay::{ServiceHttp, ServiceHttpAnswer};
use kr_protocol::push::{DevicePushRegisterParams, DevicePushRegisterResult};

use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::ids::{ActionId, DeviceId, InvitationId};
use kr_protocol::invitation::{InviteEntry, InviteGrantKind};
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::rights::ActionRight;
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, Moved, proposal};
use serde_json::{Value, json};
use support::{Phone, WATCHDOG, phone_paired_with};

/// What happened to a phone's attempt to pair again.
#[derive(Debug)]
enum Outcome {
    /// A command of the page's refused the attempt before it began.
    Refused(Value),
    /// The attempt ended in a failure of this kind.
    Ended(String),
    /// The attempt ended in a pairing.
    Paired,
}

fn viewer() -> ProposedGrant {
    proposal(&[ActionRight::SessionView])
}

/// A grant that lasts past the two days the cases that move the clocks take them on.
fn grant_past_the_moved_clocks() -> ProposedGrant {
    let mut grant = viewer();
    grant.expiry = kr_protocol::grant::GrantExpiry::At {
        expires_at_ms: kr_protocol::scalars::TimestampMs::new(
            kr_ipc::now_ms().get() + 3 * 24 * 60 * 60 * 1000,
        ),
    };
    grant
}

/// Waits for `future` for at most [`WATCHDOG`], and ends the case with `what` when it does not
/// finish.
async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(WATCHDOG, future).await {
        Ok(output) => output,
        Err(_) => panic!("{what} did not finish within {WATCHDOG:?}"),
    }
}

/// Waits until `check` holds, for at most [`WATCHDOG`].
async fn until(what: &str, check: impl Fn() -> bool) {
    let end = Instant::now() + WATCHDOG;
    while !check() {
        assert!(
            Instant::now() < end,
            "{what} did not happen within {WATCHDOG:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The result of a step, or the end of the case with the step's name and what refused it.
fn took<T, E: std::fmt::Debug>(step: &str, result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{step} was refused: {error:?}"),
    }
}

fn registry(host: &Host) -> rusqlite::Connection {
    let connection = took(
        "opening the host's registry",
        rusqlite::Connection::open(host.registry_database()),
    );
    took(
        "setting the registry's wait",
        connection.busy_timeout(Duration::from_secs(30)),
    );
    connection
}

/// Every column of one device's row at the host, as stored.
fn row_of(host: &Host, device_id: DeviceId) -> Vec<rusqlite::types::Value> {
    let connection = registry(host);
    let mut statement = took(
        "reading the host's device rows",
        connection.prepare("SELECT * FROM network_devices WHERE device_id = ?1"),
    );
    let columns = statement.column_count();
    took(
        "reading the device's row",
        statement.query_row([device_id.get().as_bytes().as_slice()], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        }),
    )
}

/// Whether the end of the device's grant is on record at the host.
fn expiry_on_record(host: &Host, device_id: DeviceId) -> bool {
    took(
        "reading the end of the grant",
        registry(host).query_row(
            "SELECT expired_at_ms IS NOT NULL FROM network_devices WHERE device_id = ?1",
            [device_id.get().as_bytes().as_slice()],
            |row| row.get::<_, bool>(0),
        ),
    )
}

/// The identifiers of the records the host lists as paired devices other than its owner device.
fn listed_phones(host: &Host) -> Vec<DeviceId> {
    let owner = host.owner.as_ref().map(|owner| owner.device_id);
    let records = took(
        "reading the host's device directory",
        host.controller().devices().devices(),
    );
    records
        .into_iter()
        .filter(|record| record.is_paired() && owner != Some(record.device_id))
        .map(|record| record.device_id)
        .collect()
}

fn record_of(host: &Host, device_id: DeviceId) -> DeviceRecord {
    let records = took(
        "reading the host's device directory",
        host.controller().devices().devices(),
    );
    let found = records
        .into_iter()
        .find(|record| record.device_id == device_id);
    assert!(found.is_some(), "the host holds a record {device_id:?}");
    found.expect("asserted above")
}

/// The reference the pairing screen gives the one host this phone lists.
fn the_listed_host(phone: &Phone) -> String {
    let view = took(
        "the pairing screen",
        phone.companion.call("pairing_view", json!({})),
    );
    let hosts = view["hosts"].as_array().cloned().unwrap_or_default();
    assert_eq!(hosts.len(), 1, "the phone lists one host: {view}");
    let reference = hosts[0]["reference"].as_str().map(str::to_owned);
    assert!(
        reference.is_some(),
        "the listed host has a reference: {view}"
    );
    reference.expect("asserted above")
}

fn listed_host_count(phone: &Phone) -> usize {
    let view = took(
        "the pairing screen",
        phone.companion.call("pairing_view", json!({})),
    );
    view["hosts"].as_array().map_or(usize::MAX, Vec::len)
}

/// Waits until the phone's connection to its host is (or is not) up.
async fn connection(phone: &Phone, connected: bool) {
    let what = if connected {
        "the phone connecting to its host"
    } else {
        "the phone's connection to its host ending"
    };
    until(what, || {
        phone
            .companion
            .call("connection_state", json!({}))
            .is_ok_and(|state| state["connected"] == connected)
    })
    .await;
}

/// Waits until the pairing screen's attempt is in one of `states`, and returns the attempt.
async fn attempt_in(phone: &Phone, states: &[&str]) -> Value {
    let end = Instant::now() + WATCHDOG;
    loop {
        let view = phone.companion.call("pairing_view", json!({}));
        if let Ok(view) = &view
            && states
                .iter()
                .any(|wanted| view["state"]["state"] == *wanted)
        {
            return view["state"].clone();
        }
        assert!(
            Instant::now() < end,
            "the attempt did not reach one of {states:?} within {WATCHDOG:?}: the screen says {view:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn outcome_of(attempt: &Value) -> Outcome {
    match attempt["state"].as_str() {
        Some("paired") => Outcome::Paired,
        Some("ended") => Outcome::Ended(
            attempt["failure"]["kind"]
                .as_str()
                .unwrap_or("<no kind>")
                .to_owned(),
        ),
        other => panic!("the attempt is neither paired nor ended: {other:?} in {attempt}"),
    }
}

/// The phone is given a new invitation that the host's owner issued, takes it up, and the owner
/// confirms it when the phone asks for that. Returns what the attempt came to.
async fn pair_again(
    phone: &Phone,
    host: &Host,
    owner: &DeviceKeys,
    grant: ProposedGrant,
) -> Outcome {
    attempt(phone, host, owner, grant).await.0
}

/// As [`pair_again`], with the identifier of the invitation the attempt used.
async fn attempt(
    phone: &Phone,
    host: &Host,
    owner: &DeviceKeys,
    grant: ProposedGrant,
) -> (Outcome, InvitationId) {
    let mut client = host.client().await;
    let signer = Signer::OwnerDevice(owner);
    let invited = took(
        "the owner issuing an invitation",
        within(
            "the invitation",
            calls::invite_direct(
                host.environment_id,
                &mut client,
                InviteGrantKind::SessionInvitation,
                &grant,
                &signer,
            ),
        )
        .await,
    );
    let InviteEntry::Direct { qr_text } = &invited.entry else {
        panic!("a direct invitation was issued: {:?}", invited.entry);
    };
    // The screen still shows how the last attempt ended until the person returns it to its start,
    // as the page's "Done" does: the new attempt is read from a screen that holds nothing.
    took(
        "returning the pairing screen to its start",
        phone.companion.call("pairing_stop", json!({})),
    );
    until("the pairing screen holding no attempt", || {
        phone
            .companion
            .call("pairing_view", json!({}))
            .is_ok_and(|view| {
                view["state"]["state"] != "paired" && view["state"]["state"] != "ended"
            })
    })
    .await;
    phone.paste.copy(qr_text.as_str(), false);
    let id = invited.invitation_id;
    if let Err(error) = phone.companion.call("pairing_paste", json!({})) {
        return (Outcome::Refused(error), id);
    }
    if let Err(error) = phone.companion.call("pairing_start_read", json!({})) {
        return (Outcome::Refused(error), id);
    }
    let reached = attempt_in(phone, &["awaiting_approval", "paired", "ended"]).await;
    if reached["state"] != "awaiting_approval" {
        return (outcome_of(&reached), id);
    }
    took(
        "the owner confirming the phone",
        within(
            "the confirmation",
            calls::confirm_candidate(
                host.environment_id,
                &mut client,
                invited.invitation_id,
                &signer,
            ),
        )
        .await,
    );
    (
        outcome_of(&attempt_in(phone, &["paired", "ended"]).await),
        id,
    )
}

/// The phone forgets the one host it lists, as the page's forget question does.
fn forget(phone: &Phone) {
    let reference = the_listed_host(phone);
    took(
        "forgetting the host",
        phone
            .companion
            .call("hosts_forget", json!({ "reference": reference })),
    );
    assert_eq!(
        listed_host_count(phone),
        0,
        "the phone lists no host once it forgot it"
    );
}

/// As [`forget`], with the notifications told that the host is forgotten, as the application
/// tells them.
fn forget_notifying(phone: &Phone, push: &Push) {
    let paired = took(
        "reading the paired hosts",
        phone.companion.device().pairing().hosts.list(),
    );
    assert_eq!(paired.len(), 1, "the phone is paired with one host");
    forget(phone);
    push.desk.forgotten(paired[0].host_device_id);
}

/// What the notifications must show once the phone paired again and the person turned them on
/// again: the host was handed a credential for an authorisation that was not asked for before the
/// forget, under the identifier of the new record, and the old authorisation was not asked for
/// again.
async fn assert_new_authorisation(
    push: &Push,
    host: &Host,
    first: DeviceId,
    old: &str,
    asked_before: &[String],
) {
    let (new, device) = push.turn_on().await;
    assert_ne!(new, old, "the host was handed a new authorisation");
    let asked = push.asked();
    assert!(
        asked.len() > asked_before.len(),
        "the gateway was asked for an authorisation after the forget: {asked:?}"
    );
    for id in &asked[asked_before.len()..] {
        assert!(
            !asked_before.contains(id),
            "the old authorisation was asked for again: {id} in {asked:?}"
        );
    }
    assert!(
        asked[asked_before.len()..].contains(&new),
        "the credential is for an authorisation the gateway was asked for: {new} in {asked:?}"
    );
    assert_ne!(device, first, "the registration is under the new record");
    assert_eq!(
        vec![device],
        listed_phones(host),
        "the registration is under the record the host lists"
    );
}

/// What a phone that pairs again must show once it did: one host listed, the phone connected to
/// it, a record of its own at the host under a new identifier, and the ended record as it was.
async fn assert_paired_again(
    phone: &Phone,
    host: &Host,
    first: DeviceId,
    first_row: &[rusqlite::types::Value],
) {
    until("the phone listing the host once", || {
        listed_host_count(phone) == 1
    })
    .await;
    connection(phone, true).await;
    let listed = listed_phones(host);
    assert_eq!(
        listed.len(),
        1,
        "the host lists one record of the phone: {listed:?}"
    );
    assert_ne!(listed[0], first, "the record has an identifier of its own");
    assert_eq!(
        row_of(host, first),
        first_row,
        "the ended record is as it was"
    );
}

/// The phone, paired with a host that holds it as a viewer, and the record the host made of it.
async fn paired_phone(host: &Host, owner: &DeviceKeys) -> (Phone, DeviceId) {
    let phone = within(
        "the first pairing",
        phone_paired_with(host, owner, &[ActionRight::SessionView]),
    )
    .await;
    let listed = listed_phones(host);
    assert_eq!(listed.len(), 1, "the host lists the phone: {listed:?}");
    (phone, listed[0])
}

/// A phone that forgot a host that still lists it is told that, and never that the host cannot be
/// reached; the host's record is as it was. Without the forget, the phone stops itself first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phone_that_forgot_a_host_that_still_lists_it_is_told_so() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let (phone, first) = paired_phone(&host, &owner).await;
    let listed = row_of(&host, first);

    // The control: the phone still holds its record of the host and stops itself.
    let (control, unused) = attempt(&phone, &host, &owner, viewer()).await;
    let stopped = match &control {
        Outcome::Ended(kind) => kind.as_str(),
        Outcome::Refused(error) => error["kind"].as_str().unwrap_or("<no kind>"),
        Outcome::Paired => "paired",
    };
    assert_eq!(
        stopped, "already_paired",
        "without the forget the phone stops at its own record: {control:?}"
    );
    assert_eq!(
        row_of(&host, first),
        listed,
        "the host's record is as it was"
    );
    assert_eq!(
        listed_host_count(&phone),
        1,
        "the phone still lists the host"
    );
    // The phone never used that invitation: the owner withdraws it before issuing the next.
    let mut client = host.client().await;
    took(
        "the owner withdrawing the unused invitation",
        within(
            "the withdrawal",
            calls::cancel(host.environment_id, &mut client, unused, false),
        )
        .await,
    );

    forget(&phone);
    let outcome = pair_again(&phone, &host, &owner, viewer()).await;
    match &outcome {
        Outcome::Ended(kind) => {
            assert_ne!(
                kind, "host_unreachable",
                "a host that lists the phone is not shown as unreachable"
            );
            assert_eq!(
                kind, "host_still_lists_device",
                "the phone is told the host still lists it"
            );
        }
        other => panic!("the attempt should end in a failure: {other:?}"),
    }
    assert_eq!(
        row_of(&host, first),
        listed,
        "the host's record is as it was"
    );
    assert_eq!(
        listed_phones(&host),
        vec![first],
        "the host lists the one record"
    );
    assert_eq!(
        listed_host_count(&phone),
        0,
        "the phone still lists no host"
    );
    host.stop().await;
}

/// The host revokes the phone's record; the phone forgets the host and pairs again with a new
/// invitation that an owner device confirms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phone_its_host_revoked_forgets_the_host_and_pairs_again() {
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner).await;
    let (phone, first) = paired_phone(&host, &owner).await;
    connection(&phone, true).await;
    let push = open_push(&phone);
    let (old_sender, _) = push.turn_on().await;
    let asked_before = push.asked();
    assert_eq!(
        asked_before,
        vec![old_sender.clone()],
        "one authorisation was asked for"
    );

    let barrier = took(
        "the owner revoking the phone",
        within("the revocation", host.network().revoke_device(first)).await,
    );
    assert!(
        barrier.holds(),
        "the revocation's barrier holds: {barrier:?}"
    );
    connection(&phone, false).await;
    let revoked = row_of(&host, first);

    forget_notifying(&phone, &push);
    let outcome = pair_again(&phone, &host, &owner, viewer()).await;
    assert!(
        matches!(outcome, Outcome::Paired),
        "the phone pairs again: {outcome:?}"
    );
    assert_paired_again(&phone, &host, first, &revoked).await;
    assert_new_authorisation(&push, &host, first, &old_sender, &asked_before).await;
    host.stop().await;
}

/// As the case above, for a record whose grant ran out and is on record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_phone_whose_grant_ran_out_forgets_the_host_and_pairs_again() {
    let (moved, clocks) = Moved::new();
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start_on_clocks(&owner, clocks).await;
    let (phone, first) = paired_phone(&host, &owner).await;
    // The phone is connected, which anchors its grant in this boot; the grant runs out and the
    // host's watch over the connection records the end.
    connection(&phone, true).await;
    let push = open_push(&phone);
    let (old_sender, _) = push.turn_on().await;
    let asked_before = push.asked();
    moved.past_the_grant();
    until("the end of the grant being on record", || {
        expiry_on_record(&host, first)
    })
    .await;
    let ran_out = row_of(&host, first);

    forget_notifying(&phone, &push);
    let outcome = pair_again(&phone, &host, &owner, grant_past_the_moved_clocks()).await;
    assert!(
        matches!(outcome, Outcome::Paired),
        "the phone pairs again: {outcome:?}"
    );
    assert_paired_again(&phone, &host, first, &ran_out).await;
    assert_new_authorisation(&push, &host, first, &old_sender, &asked_before).await;
    host.stop().await;
}

/// As the case above, for a grant that is due and whose end nobody read or recorded: the host
/// finds it at the binding and records it there, and the pairing succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_that_ran_out_unread_is_recorded_when_the_phone_pairs_again() {
    let (moved, clocks) = Moved::new();
    let owner = DeviceKeys::generate().expect("keys");
    let host = Host::start_on_clocks(&owner, clocks).await;
    let (phone, first) = paired_phone(&host, &owner).await;
    connection(&phone, true).await;
    let push = open_push(&phone);
    let (old_sender, _) = push.turn_on().await;
    let asked_before = push.asked();
    // The phone forgets the host while it is connected, which ends the connection, and the host
    // counts no connection of the record before the clocks move: nothing reads the end of the
    // grant.
    forget_notifying(&phone, &push);
    let record = record_of(&host, first);
    until("the host counting no connection of the record", || {
        host.connections_of(&record) == 0
    })
    .await;
    moved.past_the_grant();
    assert!(
        !expiry_on_record(&host, first),
        "the end of the grant is not on record before the phone pairs again"
    );
    let unread = row_of(&host, first);

    let outcome = pair_again(&phone, &host, &owner, grant_past_the_moved_clocks()).await;
    assert!(
        matches!(outcome, Outcome::Paired),
        "the phone pairs again: {outcome:?}"
    );
    assert!(
        expiry_on_record(&host, first),
        "the end of the grant is on record"
    );
    assert_ne!(row_of(&host, first), unread, "the binding wrote the end");
    assert_eq!(listed_phones(&host).len(), 1, "the host lists one record");
    assert_ne!(listed_phones(&host)[0], first);
    until("the phone listing the host once", || {
        listed_host_count(&phone) == 1
    })
    .await;
    connection(&phone, true).await;
    assert_new_authorisation(&push, &host, first, &old_sender, &asked_before).await;
    host.stop().await;
}

// ---------------------------------------------------------------------------------------------
// The phone's notifications: the native half, the gateway and the host's side of a registration
// are small scripts, as in the push desk's own suite; the phone's sequencing, its record and its
// pairing records are the product's.

const TOKEN: &str = "fZ9k-test-registration-token:APA91bExample";
const VECTORS: &str = include_str!("../../../../fixtures/push/push.json");

/// How many times the receiver's record is read before the script has answered the challenge in it.
const READS_BEFORE_THE_ANSWER: usize = 2;

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the push vectors")
}

/// The first value of `key` anywhere in `value`.
fn first_value_of(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(map) => map
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| map.values().find_map(|inner| first_value_of(inner, key))),
        Value::Array(items) => items.iter().find_map(|inner| first_value_of(inner, key)),
        _ => None,
    }
}

/// The phone's native half: the permission is granted, the provider has a token, and the receiver
/// answers the challenge in its record once the record has been waited for.
#[derive(Default)]
struct Receiver {
    pending: Mutex<Option<PendingRegistration>>,
    reads: Mutex<usize>,
}

impl Native for Receiver {
    fn permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async { Ok(Permission::Granted) })
    }

    fn ask_permission(&self) -> PushFuture<'_, Permission> {
        Box::pin(async { Ok(Permission::Granted) })
    }

    fn token(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async { Ok(Some(TOKEN.to_owned())) })
    }

    fn pending_set<'a>(&'a self, record: &'a PendingRegistration) -> PushFuture<'a, ()> {
        Box::pin(async move {
            *self.pending.lock().expect("the receiver") = Some(record.clone());
            *self.reads.lock().expect("the receiver") = 0;
            Ok(())
        })
    }

    fn pending_get(&self) -> PushFuture<'_, Option<PendingRegistration>> {
        Box::pin(async move {
            let reads = {
                let mut reads = self.reads.lock().expect("the receiver");
                *reads += 1;
                *reads
            };
            let mut pending = self.pending.lock().expect("the receiver");
            if reads >= READS_BEFORE_THE_ANSWER
                && let Some(held) = pending.as_mut()
                && held.state == PendingState::Pending
            {
                held.state = PendingState::Answered;
            }
            Ok(pending.clone())
        })
    }

    fn preview_keys<'a>(&'a self, _keys: &'a PreviewKeys) -> PushFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn route(&self) -> PushFuture<'_, Option<String>> {
        Box::pin(async { Ok(None) })
    }
}

/// The notification service, as a script: it takes a proposal and says it sent the challenge, and
/// issues the authorisation that it was asked for, as a gateway does, with the credential the
/// vectors record. It keeps the identifier of every authorisation it was asked to issue.
#[derive(Default)]
struct Gateway {
    asked: Mutex<Vec<String>>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        let sent: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let records = vectors()["records"].clone();
        let answer = if let Some(origin) = url.strip_suffix("/api/push/sender/issue") {
            let sender = first_value_of(&sent, "sender_record_id");
            self.asked
                .lock()
                .expect("the asked authorisations")
                .push(sender.clone().unwrap_or_else(|| "<none asked>".to_owned()));
            let mut record = records["sender_record"].clone();
            record["binding"]["gateway_origin"] = json!(origin);
            let mut credential = records["delivery_credential"].clone();
            credential["gateway_origin"] = json!(origin);
            if let Some(sender) = sender {
                record["binding"]["sender_record_id"] = json!(sender);
                credential["sender_record_id"] = json!(sender);
            }
            json!({ "ok": true, "data": { "record": record, "credential": credential }})
        } else {
            let proposal = &sent["body"]["installation_register"]["request"]["propose"]["proposal"];
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
                body: serde_json::to_vec(&answer).unwrap_or_default(),
            })
        })
    }
}

/// What the host was handed: for each registration, the host, the identifier the host holds for
/// the phone, and the identifier of the authorisation in the credential.
#[derive(Default)]
struct Handed {
    registrations: Vec<(DeviceId, DeviceId, String)>,
}

struct HostLink(Arc<Mutex<Handed>>);

impl Registrar for HostLink {
    fn can_ask(&self, _host: DeviceId, _action: ActionId) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        host: &'a PairedHost,
        _reach: Reach,
    ) -> PushFuture<'a, Box<dyn HostLine + 'a>> {
        Box::pin(async move {
            Ok(Box::new(Line {
                handed: Arc::clone(&self.0),
                host: host.host_device_id,
                device: host.device_id,
            }) as Box<dyn HostLine + 'a>)
        })
    }
}

struct Line {
    handed: Arc<Mutex<Handed>>,
    host: DeviceId,
    device: DeviceId,
}

impl HostLine for Line {
    fn read_registration(&mut self, _action: ActionId) -> LineFuture<'_, RegistrationRead> {
        Box::pin(async {
            Ok(RegistrationRead::Undecided(
                "the host cannot say".to_owned(),
            ))
        })
    }

    fn register(
        &mut self,
        _action: ActionId,
        params: DevicePushRegisterParams,
    ) -> LineFuture<'_, DevicePushRegisterResult> {
        Box::pin(async move {
            self.handed
                .lock()
                .expect("what was handed")
                .registrations
                .push((
                    self.host,
                    self.device,
                    params.credential.sender_record_id.to_string(),
                ));
            let records = vectors()["records"].clone();
            Ok(took(
                "the host's answer to a registration",
                serde_json::from_value(json!({
                    "device_id": self.device.to_string(),
                    "installation_id": records["installation_binding"]["installation_id"],
                    "sender_record_id": params.credential.sender_record_id.to_string(),
                    "credential_expires_at_ms": "1769817600000",
                })),
            ))
        })
    }

    fn update_preview_key(
        &mut self,
        _preview_key: kr_protocol::scalars::NotificationPreviewKey,
        _revision: kr_protocol::ids::DeviceKeyRevision,
    ) -> LineFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// The phone's notifications over its records, with the gateway and the host's side scripted.
struct Push {
    desk: Arc<PushDesk>,
    gateway: Arc<Gateway>,
    handed: Arc<Mutex<Handed>>,
}

fn open_push(phone: &Phone) -> Push {
    let gateway = Arc::new(Gateway::default());
    let http = Arc::clone(&gateway);
    let handed = Arc::new(Mutex::new(Handed::default()));
    let origin = took(
        "the official gateway's origin",
        kr_protocol::service::GatewayOrigin::new(kr_client::services::account::ACCOUNT_ORIGIN),
    );
    let desk = PushDesk::open(
        phone.data.path(),
        phone.companion.device(),
        Arc::new(Receiver::default()) as Arc<dyn Native>,
        Arc::new(HostLink(Arc::clone(&handed))) as Arc<dyn Registrar>,
        Wiring {
            origin,
            gateway: companion_tauri::push::gateway_over(Arc::new(move |_| {
                Ok(Arc::clone(&http) as Arc<dyn ServiceHttp>)
            })),
            clock: Arc::new(|| kr_ipc::now_ms().get()),
            keys_within: Duration::from_secs(20),
        },
        |_view| {},
    );
    Push {
        desk,
        gateway,
        handed,
    }
}

impl Push {
    /// The person turns notifications on for the one host the phone lists, and the host is handed
    /// a credential. Returns the identifier of the authorisation in the credential and the
    /// identifier the host holds for the phone.
    async fn turn_on(&self) -> (String, DeviceId) {
        let hosts = self.desk.view().hosts;
        assert_eq!(hosts.len(), 1, "the phone lists one host: {hosts:?}");
        let before = self
            .handed
            .lock()
            .expect("what was handed")
            .registrations
            .len();
        let asked = self.desk.enable(&hosts[0].reference, None);
        assert!(
            asked.is_ok(),
            "the person asks for notifications: {asked:?}"
        );
        until("notifications being on for the host", || {
            self.desk
                .view()
                .hosts
                .iter()
                .map(|host| host.state)
                .collect::<Vec<_>>()
                == [PushState::On]
        })
        .await;
        let handed = self.handed.lock().expect("what was handed");
        assert!(
            handed.registrations.len() > before,
            "the host was handed a registration"
        );
        let (_, device, sender) = handed
            .registrations
            .last()
            .cloned()
            .expect("a registration");
        (sender, device)
    }

    /// The identifiers of the authorisations the gateway was asked to issue, in order.
    fn asked(&self) -> Vec<String> {
        self.gateway
            .asked
            .lock()
            .expect("the asked authorisations")
            .clone()
    }
}
