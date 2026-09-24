//! A settings collection's membership, as a device lives it: real keys, signed key records, the
//! device's own key store on the file seam, and a scripted service and hosts.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-18.05, settings-sync part (the library path) | `a_production_device_receives_its_key_through_its_own_wrap_and_keeps_it_in_its_store`, `nothing_is_sealed_to_a_device_its_host_has_not_committed` |
//! | KR-REQ-20.11, sync-collection half | `removing_a_device_gives_the_rest_a_key_it_cannot_open`, `every_new_epoch_has_a_freshly_drawn_key`, `publication_stays_fenced_from_a_recorded_removal_until_its_record_is_installed` |
//!
//! Every directory a test uses is a temporary one on the internal disk, and every secret store is
//! the owner-only directory the file seam opens there: nothing here touches a keychain.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use kr_client::ClientError;
use kr_client::services::ServiceFuture;
use kr_client::sync::StoredCollectionKeys;
use kr_client::sync::membership::{
    CollectionRef, Device, DeviceDirectory, Ended, HostAnswers, HostDevice, HostReport,
    KeyRecordService, KeyRecords, MembershipError, Outcome, PLAN_LIFETIME_MS, Plan, PlanRefusal,
    PlannedOperation, RecordAt, Refreshed, RekeyAnswer, RekeyFence, RekeyStatus, Settlement, Step,
    SyncMembership,
};
use kr_crypto::envelope::{
    CollectionRecipient, CollectionRecordDraft, check_genesis, check_successor,
    issue_collection_key_record, open_collection_key,
};
use kr_crypto::keys::{DeviceKeys, key_id};
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_protocol::collection_keys::CollectionKeyRecord;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{SyncCollectionId, SyncKeyEpoch, SyncKeyRecordRevision};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{AuthorisationKey, TimestampMs, Uuid};
use kr_protocol::service::installation_id;

/* -------------------------------------------------------------------------- */
/* The scripted service                                                        */
/* -------------------------------------------------------------------------- */

/// What the service recorded about one `rekey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receipt {
    Applied(u64),
    Refused(u64),
    Fenced { never_ran: bool },
}

/// What happens to the next `rekey` the service is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fate {
    /// It is taken and answered.
    Answer,
    /// It is taken, and the answer is lost on its way back.
    LoseAnswer,
    /// It is lost on its way to the service.
    LoseRequest,
    /// It is in flight until the test lets the service take it.
    Hold,
}

/// A request in flight.
#[derive(Clone, Debug)]
struct Flight {
    collection: CollectionRef,
    request: Uuid,
    record: CollectionKeyRecord,
    caller: AuthorisationKey,
}

/// The honest service, with the faults a test asks for.
#[derive(Debug, Default)]
struct ServiceState {
    chains: BTreeMap<CollectionRef, Vec<CollectionKeyRecord>>,
    receipts: BTreeMap<[u8; 16], Receipt>,
    /// Requests whose receipts passed the service's retention.
    past_horizon: BTreeSet<[u8; 16]>,
    fates: VecDeque<Fate>,
    held: Vec<Flight>,
    /// How often each request identity was sent.
    sends: BTreeMap<[u8; 16], u32>,
    /// Answers a hostile service gives the next reads of records.
    forged: VecDeque<KeyRecords>,
}

impl ServiceState {
    /// Takes one request: an exact retry is answered from its receipt, and a request past the
    /// service's retention runs no more.
    fn take(&mut self, flight: &Flight) -> Receipt {
        let key = *flight.request.as_bytes();
        if let Some(receipt) = self.receipts.get(&key) {
            return *receipt;
        }
        let chain = self.chains.entry(flight.collection).or_default();
        let newest = chain
            .last()
            .map_or(0, |record| record.payload.revision.get());
        if self.past_horizon.contains(&key) {
            return Receipt::Refused(newest);
        }
        let caller_id = key_id(KeyPurpose::Authorisation, flight.caller.as_bytes());
        let issued_by_caller = flight.record.payload.issuer_key_id == caller_id;
        let valid = match chain.last() {
            None => {
                issued_by_caller
                    && check_genesis(&flight.record).is_ok()
                    && flight.record.payload.home == installation_id(&flight.caller)
                    && flight.record.payload.collection_id == flight.collection.collection_id
            }
            Some(last) => {
                issued_by_caller
                    && last.member(&flight.caller).is_some()
                    && check_successor(last, &flight.record).is_ok()
            }
        };
        let receipt = if valid {
            chain.push(flight.record.clone());
            Receipt::Applied(flight.record.payload.revision.get())
        } else {
            Receipt::Refused(newest)
        };
        self.receipts.insert(key, receipt);
        receipt
    }

    /// Whether a caller is a member of the collection's newest record: the service answers a
    /// non-member exactly as a missing collection.
    fn admits(&self, collection: &CollectionRef, caller: &AuthorisationKey) -> bool {
        self.chains
            .get(collection)
            .and_then(|chain| chain.last())
            .is_some_and(|newest| newest.member(caller).is_some())
    }
}

/// The world every device of one test shares: the service and the hosts.
#[derive(Clone, Debug, Default)]
struct World {
    service: Arc<Mutex<ServiceState>>,
    hosts: Arc<Hosts>,
}

impl World {
    fn state(&self) -> std::sync::MutexGuard<'_, ServiceState> {
        self.service.lock().expect("an unpoisoned service")
    }

    fn fate(&self, fate: Fate) {
        self.state().fates.push_back(fate);
    }

    /// The service's retention passes a request's receipt.
    fn expire(&self, request: Uuid) {
        let mut state = self.state();
        state.receipts.remove(request.as_bytes());
        state.past_horizon.insert(*request.as_bytes());
    }

    /// Lets the service take every request in flight.
    fn deliver_held(&self) {
        let mut state = self.state();
        let held = std::mem::take(&mut state.held);
        for flight in held {
            state.take(&flight);
        }
    }

    /// The records of a collection, as the service holds them.
    fn chain(&self, collection: &CollectionRef) -> Vec<CollectionKeyRecord> {
        self.state()
            .chains
            .get(collection)
            .cloned()
            .unwrap_or_default()
    }

    fn newest(&self, collection: &CollectionRef) -> CollectionKeyRecord {
        self.chain(collection).last().cloned().expect("a record")
    }

    /// A record another member's device issued and the service accepted.
    fn append(&self, collection: &CollectionRef, record: CollectionKeyRecord) {
        let mut state = self.state();
        let chain = state.chains.entry(*collection).or_default();
        let last = chain.last().expect("a chain to follow");
        check_successor(last, &record).expect("an honest service accepts only a successor");
        chain.push(record);
    }

    fn sends(&self, request: Uuid) -> u32 {
        self.state()
            .sends
            .get(request.as_bytes())
            .copied()
            .unwrap_or(0)
    }

    fn forge_next(&self, answer: KeyRecords) {
        self.state().forged.push_back(answer);
    }
}

/// One device's view of the service: its requests are signed by its authorisation key.
#[derive(Debug)]
struct ServiceView {
    world: World,
    caller: AuthorisationKey,
}

fn lost() -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::StorageUnavailable,
        "the answer did not arrive",
    ))
}

impl KeyRecordService for ServiceView {
    fn records_after<'a>(
        &'a self,
        collection: &'a CollectionRef,
        after: u64,
    ) -> ServiceFuture<'a, KeyRecords> {
        let mut state = self.world.state();
        let answer = if let Some(forged) = state.forged.pop_front() {
            forged
        } else if state.admits(collection, &self.caller) {
            KeyRecords::Records(
                state.chains[collection]
                    .iter()
                    .filter(|record| record.payload.revision.get() > after)
                    .cloned()
                    .collect(),
            )
        } else {
            KeyRecords::Absent
        };
        Box::pin(std::future::ready(Ok(answer)))
    }

    fn record_at<'a>(
        &'a self,
        collection: &'a CollectionRef,
        revision: u64,
    ) -> ServiceFuture<'a, RecordAt> {
        let state = self.world.state();
        let answer = if state.admits(collection, &self.caller) {
            state.chains[collection]
                .iter()
                .find(|record| record.payload.revision.get() == revision)
                .cloned()
                .map_or(RecordAt::Missing, RecordAt::Record)
        } else {
            RecordAt::Absent
        };
        Box::pin(std::future::ready(Ok(answer)))
    }

    fn rekey<'a>(
        &'a self,
        collection: &'a CollectionRef,
        request_id: Uuid,
        _signed_at_ms: u64,
        record: &'a CollectionKeyRecord,
    ) -> ServiceFuture<'a, RekeyAnswer> {
        let mut state = self.world.state();
        *state.sends.entry(*request_id.as_bytes()).or_default() += 1;
        let fate = state.fates.pop_front().unwrap_or(Fate::Answer);
        let flight = Flight {
            collection: *collection,
            request: request_id,
            record: record.clone(),
            caller: self.caller,
        };
        let answer = match fate {
            Fate::LoseRequest => Err(lost()),
            Fate::Hold => {
                state.held.push(flight);
                Err(lost())
            }
            Fate::Answer | Fate::LoseAnswer => {
                let receipt = state.take(&flight);
                match (fate, receipt) {
                    (Fate::LoseAnswer, _) => Err(lost()),
                    (_, Receipt::Applied(revision)) => Ok(RekeyAnswer::Applied { revision }),
                    (_, Receipt::Refused(revision)) => Ok(RekeyAnswer::Refused { revision }),
                    (_, Receipt::Fenced { .. }) => Err(ClientError::Host(ProtocolError::new(
                        ErrorCode::IdConflict,
                        "the request is fenced",
                    ))),
                }
            }
        };
        Box::pin(std::future::ready(answer))
    }

    fn rekey_status<'a>(
        &'a self,
        _collection: &'a CollectionRef,
        request_id: Uuid,
    ) -> ServiceFuture<'a, RekeyStatus> {
        let state = self.world.state();
        let status = match state.receipts.get(request_id.as_bytes()) {
            Some(Receipt::Applied(revision)) => RekeyStatus::Applied {
                revision: *revision,
            },
            Some(Receipt::Refused(revision)) => RekeyStatus::Refused {
                revision: *revision,
            },
            Some(Receipt::Fenced { never_ran }) => RekeyStatus::Fenced {
                never_ran: *never_ran,
            },
            None => RekeyStatus::Unknown,
        };
        Box::pin(std::future::ready(Ok(status)))
    }

    fn rekey_fence<'a>(
        &'a self,
        _collection: &'a CollectionRef,
        request_id: Uuid,
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, RekeyFence> {
        let mut state = self.world.state();
        let key = *request_id.as_bytes();
        let fence = match state.receipts.get(&key) {
            Some(Receipt::Applied(revision)) => RekeyFence::Applied {
                revision: *revision,
            },
            Some(Receipt::Refused(revision)) => RekeyFence::Refused {
                revision: *revision,
            },
            Some(Receipt::Fenced { never_ran }) => RekeyFence::Fenced {
                never_ran: *never_ran,
            },
            None => {
                let never_ran = !state.past_horizon.contains(&key);
                state.receipts.insert(key, Receipt::Fenced { never_ran });
                // A request still in flight never runs once it is fenced.
                state.held.retain(|flight| flight.request != request_id);
                RekeyFence::Fenced { never_ran }
            }
        };
        Box::pin(std::future::ready(Ok(fence)))
    }
}

/* -------------------------------------------------------------------------- */
/* The scripted hosts                                                          */
/* -------------------------------------------------------------------------- */

/// What this device's hosts answer: one report per host, or silence.
#[derive(Debug, Default)]
struct Hosts {
    reports: Mutex<Vec<HostReport>>,
    silent: Mutex<bool>,
}

impl Hosts {
    fn reports(&self) -> std::sync::MutexGuard<'_, Vec<HostReport>> {
        self.reports.lock().expect("unpoisoned hosts")
    }

    /// The first host commits a device's pairing, as the owner approved it.
    fn commit(&self, device: Device, manages_host: bool) {
        let mut reports = self.reports();
        if reports.is_empty() {
            reports.push(HostReport::default());
        }
        reports[0]
            .devices
            .retain(|known| known.authorisation != device.authorisation);
        reports[0].devices.push(HostDevice {
            authorisation: device.authorisation,
            stored_envelope: device.stored_envelope,
            manages_host,
            revoked: false,
        });
    }

    /// One host reports a device revoked.
    fn revoke_at(&self, host: usize, device: Device) {
        let mut reports = self.reports();
        while reports.len() <= host {
            reports.push(HostReport::default());
        }
        let report = &mut reports[host];
        report
            .devices
            .retain(|known| known.authorisation != device.authorisation);
        report.devices.push(HostDevice {
            authorisation: device.authorisation,
            stored_envelope: device.stored_envelope,
            manages_host: true,
            revoked: true,
        });
    }

    fn revoke(&self, device: Device) {
        self.revoke_at(0, device);
    }

    fn silence(&self, silent: bool) {
        *self.silent.lock().expect("unpoisoned hosts") = silent;
    }
}

#[derive(Debug)]
struct HostsView(Arc<Hosts>);

impl DeviceDirectory for HostsView {
    fn answers(&self) -> ServiceFuture<'_, Option<HostAnswers>> {
        let answer = if *self.0.silent.lock().expect("unpoisoned hosts") {
            None
        } else {
            Some(HostAnswers {
                reports: self.0.reports().clone(),
            })
        };
        Box::pin(std::future::ready(Ok(answer)))
    }
}

/* -------------------------------------------------------------------------- */
/* Devices                                                                     */
/* -------------------------------------------------------------------------- */

const SCOPE: &str = "kalareach-membership-test";

fn now() -> TimestampMs {
    TimestampMs::new(1_780_000_000_000)
}

/// One device: its keys, its own directories and its membership.
struct Node {
    keys: DeviceKeys,
    root: tempfile::TempDir,
    world: World,
    membership: SyncMembership,
}

impl Node {
    fn new(world: &World) -> Self {
        let keys = DeviceKeys::generate().expect("device keys");
        let root = tempfile::tempdir().expect("a directory on the internal disk");
        let membership = open_membership(world, &keys, &root);
        Self {
            keys,
            root,
            world: world.clone(),
            membership,
        }
    }

    /// The process stops and starts again: everything the membership file does not hold is lost.
    fn restart(&mut self) {
        self.membership = open_membership(&self.world, &self.keys, &self.root);
    }

    fn device(&self) -> Device {
        Device::from_keys(&self.keys)
    }

    fn auth(&self) -> AuthorisationKey {
        *self.keys.authorisation.public()
    }

    /// The key this device's store holds for one epoch, read through a second handle.
    fn held(&self, collection: &CollectionRef, epoch: u64) -> Option<SymmetricKey> {
        let store = StoredCollectionKeys::of(
            open_store_in(&self.root.path().join("secrets")).expect("the same store"),
            SCOPE,
        );
        store
            .held(&collection.collection_id.to_string(), epoch)
            .expect("a readable store")
    }

    async fn step(&mut self) -> Step {
        self.membership.step(now()).await.expect("a step")
    }

    async fn refresh(&mut self) -> Refreshed {
        self.membership.refresh().await.expect("a refresh")
    }

    async fn reconcile(&mut self) -> Vec<Step> {
        self.membership
            .reconcile(now())
            .await
            .expect("a reconciliation")
    }

    fn publishes(&self) -> bool {
        self.membership.publishes().expect("a readable membership")
    }

    fn installed(&self) -> Option<(u64, u64)> {
        self.membership
            .members()
            .expect("a readable membership")
            .and_then(|status| status.installed)
    }

    fn outcomes(&self) -> Vec<Outcome<Device>> {
        self.membership.outcomes().expect("readable outcomes")
    }

    fn removals(&self) -> Vec<Device> {
        self.membership
            .members()
            .expect("a readable membership")
            .map(|status| status.removals)
            .unwrap_or_default()
    }

    fn out(&self) -> bool {
        self.membership
            .members()
            .expect("a readable membership")
            .is_some_and(|status| status.out)
    }

    /// The standing candidate's request identity.
    fn candidate_request(&self) -> Option<Uuid> {
        self.membership
            .members()
            .expect("a readable membership")
            .and_then(|status| status.candidate)
            .map(|candidate| candidate.request)
    }
}

fn open_membership(world: &World, keys: &DeviceKeys, root: &tempfile::TempDir) -> SyncMembership {
    let secrets = StoredCollectionKeys::open(
        StoreSelection::File,
        "kalareach-membership-test",
        &root.path().join("secrets"),
        SCOPE,
    )
    .expect("the file seam");
    SyncMembership::open(
        root.path().join("membership"),
        keys,
        secrets,
        Arc::new(ServiceView {
            world: world.clone(),
            caller: *keys.authorisation.public(),
        }),
        Arc::new(HostsView(Arc::clone(&world.hosts))),
    )
    .expect("a membership store")
}

fn collection_id(seed: u8) -> SyncCollectionId {
    SyncCollectionId::new(Uuid::from_bytes([seed; 16]))
}

/// A device starts a collection and installs its own first record; every other device is
/// committed at the hosts and joins, confirmed on both sides.
async fn collection_of(world: &World, owner: &mut Node, others: &mut [&mut Node]) -> CollectionRef {
    let collection = owner
        .membership
        .start(collection_id(0x5e), now())
        .await
        .expect("a new collection");
    world.hosts.commit(owner.device(), true);
    for other in others.iter() {
        world.hosts.commit(other.device(), true);
    }
    owner.reconcile().await;
    assert_eq!(owner.installed(), Some((0, 1)));
    for other in others.iter_mut() {
        share(owner, other).await;
    }
    collection
}

/// The owner shares the collection with another device, confirmed on both.
async fn share(owner: &mut Node, recipient: &mut Node) {
    let collection = owner
        .membership
        .members()
        .expect("a membership")
        .expect("a collection")
        .collection;
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&recipient.auth(), now())
        .expect("a committed device");
    assert_eq!(
        owner.membership.authorise(&plan, now()).expect("a plan"),
        Ended::Done
    );
    owner.reconcile().await;
    let join = recipient
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    recipient
        .membership
        .join(&join, now())
        .await
        .expect("a join");
    recipient.reconcile().await;
    assert!(recipient.publishes(), "the recipient installed the record");
}

/// Issues a record as another device would, with any members, epoch and key it chooses.
fn issue(
    issuer: &Node,
    previous: &CollectionKeyRecord,
    members: &[Device],
    epoch: u64,
    key: &SymmetricKey,
) -> CollectionKeyRecord {
    let draft = CollectionRecordDraft {
        collection_id: previous.payload.collection_id,
        home: previous.payload.home,
        key_epoch: SyncKeyEpoch::new(epoch),
        revision: SyncKeyRecordRevision::new(previous.payload.revision.get() + 1),
        previous: Some(previous.digest().expect("a digest")),
        issued_at_ms: now(),
        members: members
            .iter()
            .map(|device| CollectionRecipient {
                authorisation: device.authorisation,
                stored_envelope: device.stored_envelope,
            })
            .collect(),
    };
    issue_collection_key_record(
        &issuer.keys.authorisation,
        &issuer.keys.stored_envelope,
        &draft,
        key,
    )
    .expect("a record")
}

/// The key a record carries for one of its members.
fn key_in(record: &CollectionKeyRecord, member: &Node) -> SymmetricKey {
    let entry = record.member(&member.auth()).expect("listed");
    let issuer = record.issuer().expect("an issuer");
    open_collection_key(
        &member.keys.stored_envelope,
        &issuer.stored_envelope,
        &entry.wrap,
        &entry.wrap.context,
    )
    .expect("the member's own wrap opens")
}

/// The epoch of the key a record carries.
fn epoch_of(record: &CollectionKeyRecord) -> u64 {
    record.payload.key_epoch.get()
}

fn fresh() -> SymmetricKey {
    Secret::random().expect("a key")
}

fn lists(record: &CollectionKeyRecord, node: &Node) -> bool {
    record.member(&node.auth()).is_some()
}

/// Steps until nothing is left, refreshing where the reconciler asks for a fetch, and returns
/// every step with whether publication was open after it.
async fn run(node: &mut Node) -> Vec<(Step, bool)> {
    let mut seen = Vec::new();
    for _ in 0..64 {
        let step = node.step().await;
        seen.push((step, node.publishes()));
        match step {
            Step::Nothing => break,
            Step::FetchNeeded | Step::Settled(Settlement::Refused { .. }) => {
                node.refresh().await;
            }
            _ => {}
        }
    }
    seen
}

/* -------------------------------------------------------------------------- */
/* Receiving a key                                                             */
/* -------------------------------------------------------------------------- */

/// KR-REQ-18.05: a device that joins receives the key through its own wrap in the record, and
/// keeps it in its own store.
#[tokio::test]
async fn a_production_device_receives_its_key_through_its_own_wrap_and_keeps_it_in_its_store() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut device = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut device]).await;

    let newest = world.newest(&collection);
    assert!(lists(&newest, &device));
    let from_wrap = key_in(&newest, &device);
    let held = device
        .held(&collection, 1)
        .expect("the key in the device's store");
    assert_eq!(held.expose(), from_wrap.expose());
    assert_eq!(
        owner
            .held(&collection, 1)
            .expect("the owner's key")
            .expose(),
        held.expose(),
        "the owner holds the key the device received"
    );
    assert!(
        device.held(&collection, 0).is_none(),
        "nothing from before it joined"
    );
    assert!(device.publishes());
    assert_eq!(device.installed(), Some((1, 2)));
}

/// Nothing is sealed to a device its host has not committed: the keys an addition wraps to come
/// from the hosts' reports alone, and a device they do not report committed cannot be planned.
#[tokio::test]
async fn nothing_is_sealed_to_a_device_its_host_has_not_committed() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut []).await;

    // A device whose pairing no host committed, as a bundle before approval.
    let bundle = Node::new(&world);
    assert!(matches!(
        owner.membership.plan_share(&bundle.auth(), now()),
        Err(MembershipError::NotCommitted)
    ));
    // A device a host lists without the right to manage it.
    let viewer = Node::new(&world);
    world.hosts.commit(viewer.device(), false);
    owner.refresh().await;
    assert!(matches!(
        owner.membership.plan_share(&viewer.auth(), now()),
        Err(MembershipError::NotCommitted)
    ));
    // A device the host committed with another stored-envelope key than the one it presents is
    // added under the host's key.
    let device = Node::new(&world);
    let committed_envelope = *DeviceKeys::generate()
        .expect("keys")
        .stored_envelope
        .public();
    world.hosts.commit(
        Device {
            authorisation: device.auth(),
            stored_envelope: committed_envelope,
        },
        true,
    );
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&device.auth(), now())
        .expect("a committed device");
    let PlannedOperation::Share {
        device: planned, ..
    } = plan.operation
    else {
        panic!("a share");
    };
    assert_eq!(planned.stored_envelope, committed_envelope);
    owner.membership.authorise(&plan, now()).expect("confirmed");
    owner.reconcile().await;
    let newest = world.newest(&collection);
    let entry = newest.member(&device.auth()).expect("added");
    assert_eq!(entry.stored_envelope, committed_envelope);
    assert_ne!(entry.stored_envelope, *device.keys.stored_envelope.public());
}

/// Check 3: a record whose issuer any host reports revoked is refused, even while another host
/// still reports it paired.
#[tokio::test]
async fn a_record_from_an_issuer_any_host_reports_revoked_is_refused() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;

    let newest = world.newest(&collection);
    let newcomer = Node::new(&world);
    let key = fresh();
    let epoch = epoch_of(&newest) + 1;
    let record = issue(
        &other,
        &newest,
        &[owner.device(), other.device(), newcomer.device()],
        epoch,
        &key,
    );
    let revision = record.payload.revision.get();
    world.append(&collection, record);
    // The first host still reports the issuer paired; a second reports it revoked.
    world.hosts.revoke_at(1, other.device());

    owner.refresh().await;
    let steps = run(&mut owner).await;
    assert!(
        owner
            .held(&collection, epoch)
            .is_none_or(|held| held.expose() != key.expose()),
        "its key never reaches the store"
    );
    assert!(
        steps
            .iter()
            .all(|(step, _)| *step != Step::Installed { revision }),
        "the record is never installed"
    );
    // The device the hosts disagree about is rotated out.
    let final_record = world.newest(&collection);
    assert!(!lists(&final_record, &other));
    assert!(owner.publishes());
}

/// Check 3: a record from an issuer the hosts list without the right to manage them is refused.
#[tokio::test]
async fn a_record_from_a_non_owner_issuer_is_refused() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;

    // The other device's grant loses the right to manage its host.
    world.hosts.commit(other.device(), false);
    let newest = world.newest(&collection);
    let key = fresh();
    let epoch = epoch_of(&newest) + 1;
    let record = issue(
        &other,
        &newest,
        &[owner.device(), other.device()],
        epoch,
        &key,
    );
    world.append(&collection, record);

    owner.refresh().await;
    run(&mut owner).await;
    assert!(
        owner
            .held(&collection, epoch)
            .is_none_or(|held| held.expose() != key.expose())
    );
    let final_record = world.newest(&collection);
    assert_eq!(epoch_of(&final_record), epoch + 1, "rotated away from it");
    assert!(!lists(&final_record, &other));
}

/// A device never accepts a revision at or below the one it holds: an answer that replays an
/// older record is a chain it cannot follow.
#[tokio::test]
async fn a_record_older_than_the_one_held_is_refused() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;
    let chain = world.chain(&collection);
    let installed = owner.installed();

    world.forge_next(KeyRecords::Records(vec![chain[0].clone()]));
    assert_eq!(owner.refresh().await, Refreshed::BrokenChain);
    assert_eq!(owner.installed(), installed, "nothing older is installed");
    assert!(!owner.publishes());
    assert!(owner.out(), "it accepts nothing and waits for a rejoin");
}

/// A newer record that does not follow the held one, even one a paired device signed validly,
/// needs the owner's confirmed rejoin; nothing from it is installed.
#[tokio::test]
async fn a_newer_record_without_a_chain_from_the_held_one_needs_a_confirmed_rejoin() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;

    // A paired device that is not a member signs a record claiming to follow the newest.
    let stranger = Node::new(&world);
    world.hosts.commit(stranger.device(), true);
    let newest = world.newest(&collection);
    let epoch = epoch_of(&newest) + 1;
    let forged = issue(
        &stranger,
        &newest,
        &[owner.device(), stranger.device()],
        epoch,
        &fresh(),
    );
    world.forge_next(KeyRecords::Records(vec![forged]));
    assert_eq!(owner.refresh().await, Refreshed::BrokenChain);
    assert!(owner.held(&collection, epoch).is_none());
    assert!(!owner.publishes());
    // Nothing moves until the owner confirms the rejoin on this device: the keys it held go,
    // one epoch a step.
    assert_eq!(owner.step().await, Step::ForgotKeys { epoch: 0 });
    assert_eq!(owner.step().await, Step::ForgotKeys { epoch: 1 });
    assert_eq!(owner.step().await, Step::Nothing);
    assert!(owner.held(&collection, 0).is_none() && owner.held(&collection, 1).is_none());
    let plan = owner
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    owner
        .membership
        .join(&plan, now())
        .await
        .expect("the rejoin");
    owner.reconcile().await;
    assert!(owner.publishes());
    assert_eq!(
        owner.installed(),
        Some((1, 2)),
        "the honest chain, checked as a new member"
    );
}

/* -------------------------------------------------------------------------- */
/* Keys at each epoch                                                          */
/* -------------------------------------------------------------------------- */

/// Every new epoch's key is drawn fresh: no two epochs share one.
#[tokio::test]
async fn every_new_epoch_has_a_freshly_drawn_key() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut first = Node::new(&world);
    let mut second = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut first, &mut second]).await;

    owner.membership.remove(&first.auth()).expect("a removal");
    owner.reconcile().await;
    owner.membership.remove(&second.auth()).expect("a removal");
    owner.reconcile().await;

    // Two additions and two removals: four new epochs after the first, each with its own key.
    let keys: Vec<SymmetricKey> = (0..5)
        .map(|epoch| owner.held(&collection, epoch).expect("every epoch's key"))
        .collect();
    for (index, key) in keys.iter().enumerate() {
        for other in &keys[index + 1..] {
            assert_ne!(key.expose(), other.expose(), "two epochs share a key");
        }
    }
    assert_eq!(owner.installed(), Some((4, 5)));
}

/// An addition takes the next epoch and a freshly drawn key, wrapped for every member, the new one
/// included: the key in use is wrapped only for the devices the installed record lists, so an
/// addition that never applies exposes no key anybody writes with.
#[tokio::test]
async fn an_addition_wraps_a_fresh_key_at_the_next_epoch() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut []).await;
    let before = owner.held(&collection, 0).expect("the first key");

    let mut device = Node::new(&world);
    world.hosts.commit(device.device(), true);
    share(&mut owner, &mut device).await;
    let newest = world.newest(&collection);
    assert_eq!(epoch_of(&newest), 1);
    let added = key_in(&newest, &device);
    assert_eq!(key_in(&newest, &owner).expose(), added.expose());
    assert_ne!(added.expose(), before.expose(), "not the key in use");
    assert_eq!(
        device
            .held(&collection, 1)
            .expect("the new member's key")
            .expose(),
        added.expose()
    );
}

/// KR-REQ-20.11, the sync-collection half: removing a device gives the others a fresh key at the
/// next epoch that the removed device has no wrap of; what it held stays with it, and no
/// retroactive secrecy is claimed.
#[tokio::test]
async fn removing_a_device_gives_the_rest_a_key_it_cannot_open() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut stays = Node::new(&world);
    let mut leaves = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut stays, &mut leaves]).await;
    let joined = epoch_of(&world.newest(&collection));
    let old = leaves.held(&collection, joined).expect("the key it had");

    owner.membership.remove(&leaves.auth()).expect("a removal");
    owner.reconcile().await;
    stays.reconcile().await;
    leaves.reconcile().await;

    let newest = world.newest(&collection);
    let epoch = epoch_of(&newest);
    assert_eq!(epoch, joined + 1);
    assert!(!lists(&newest, &leaves), "no wrap for the removed device");
    let new_key = stays
        .held(&collection, epoch)
        .expect("the rest hold the new key");
    assert_eq!(
        owner
            .held(&collection, epoch)
            .expect("the owner too")
            .expose(),
        new_key.expose()
    );
    assert_ne!(new_key.expose(), old.expose());
    assert!(leaves.held(&collection, epoch).is_none());
    assert!(leaves.out(), "the removed device is out");
    // What it had is not taken back: the removed device's store forgets it only because it
    // left, and the old key it held was the one it already had.
    assert_eq!(
        old.expose(),
        owner.held(&collection, joined).expect("kept").expose()
    );
}

/* -------------------------------------------------------------------------- */
/* The owner's plans                                                           */
/* -------------------------------------------------------------------------- */

/// A plan is consumed once, for its own operation: a swapped plan, a cancelled one, a reused one
/// and an expired one are all refused.
#[tokio::test]
async fn a_plan_commits_once_for_its_own_operation() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut []).await;
    let first = Node::new(&world);
    let second = Node::new(&world);
    world.hosts.commit(first.device(), true);
    world.hosts.commit(second.device(), true);
    owner.refresh().await;

    // Substitution: the WebView hands back the plan for another device.
    let plan = owner
        .membership
        .plan_share(&first.auth(), now())
        .expect("a plan");
    let mut swapped = plan;
    if let PlannedOperation::Share { device, .. } = &mut swapped.operation {
        *device = second.device();
    }
    assert!(matches!(
        owner.membership.authorise(&swapped, now()),
        Err(MembershipError::Plan(PlanRefusal::Substituted))
    ));
    let mut redigested = swapped;
    redigested.digest = kr_protocol::scalars::Digest256::from_bytes([7; 32]);
    assert!(matches!(
        owner.membership.authorise(&redigested, now()),
        Err(MembershipError::Plan(PlanRefusal::Substituted))
    ));
    // The plan itself commits once.
    assert_eq!(
        owner.membership.authorise(&plan, now()).expect("confirmed"),
        Ended::Done
    );
    assert!(matches!(
        owner.membership.authorise(&plan, now()),
        Err(MembershipError::Plan(PlanRefusal::Unknown))
    ));
    // Cancelled.
    let cancelled = owner
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    owner.membership.cancel(&cancelled);
    assert!(matches!(
        owner.membership.join(&cancelled, now()).await,
        Err(MembershipError::Plan(PlanRefusal::Unknown))
    ));
    // Expired.
    let expiring = owner
        .membership
        .plan_share(&second.auth(), now())
        .expect("a plan");
    let later = TimestampMs::new(now().get() + PLAN_LIFETIME_MS);
    assert!(matches!(
        owner.membership.authorise(&expiring, later),
        Err(MembershipError::Plan(PlanRefusal::Expired))
    ));
    assert!(matches!(
        owner.membership.authorise(&expiring, now()),
        Err(MembershipError::Plan(PlanRefusal::Unknown))
    ));
    // A join plan does not authorise an addition.
    let join = owner
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    assert!(matches!(
        owner.membership.authorise(&join, now()),
        Err(MembershipError::Plan(PlanRefusal::Substituted))
    ));
}

/// A removal needs no ceremony: the owner's use of a member is enough to take rights away, and a
/// rotation for a device a host reports revoked needs none either. An addition cannot happen
/// without a confirmed plan.
#[tokio::test]
async fn a_removal_needs_no_new_ceremony_and_an_addition_does() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut first = Node::new(&world);
    let mut second = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut first, &mut second]).await;

    owner
        .membership
        .remove(&first.auth())
        .expect("no plan needed");
    owner.reconcile().await;
    world.hosts.revoke(second.device());
    owner.reconcile().await;
    let newest = world.newest(&collection);
    assert!(!lists(&newest, &first) && !lists(&newest, &second));

    // The only way to add is a confirmed plan.
    let third = Node::new(&world);
    world.hosts.commit(third.device(), true);
    owner.refresh().await;
    let forged = Plan {
        id: Uuid::from_bytes([9; 16]),
        operation: PlannedOperation::Share {
            collection,
            epoch: 2,
            device: third.device(),
        },
        expires_at_ms: TimestampMs::new(now().get() + 1000),
        digest: kr_protocol::scalars::Digest256::from_bytes([0; 32]),
    };
    assert!(matches!(
        owner.membership.authorise(&forged, now()),
        Err(MembershipError::Plan(PlanRefusal::Unknown))
    ));
}

/// A member never removes itself: it would draw the next key. Another member removes it.
#[tokio::test]
async fn a_member_cannot_remove_itself() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut []).await;
    assert!(matches!(
        owner.membership.remove(&owner.auth()),
        Err(MembershipError::CannotRemoveSelf)
    ));
    assert!(owner.removals().is_empty());
    assert_eq!(world.chain(&collection).len(), 1);
}

/* -------------------------------------------------------------------------- */
/* The reconciler                                                              */
/* -------------------------------------------------------------------------- */

/// Publication is fenced from the moment a removal is recorded until a record without the device
/// is installed, at every crash point on the way.
#[tokio::test]
async fn publication_stays_fenced_from_a_recorded_removal_until_its_record_is_installed() {
    // One run for each point a crash can fall at: before the first step, and after each step.
    let mut crash_points = 0;
    for crash_at in 0..16 {
        let world = World::default();
        let mut owner = Node::new(&world);
        let mut stays = Node::new(&world);
        let mut leaves = Node::new(&world);
        let collection = collection_of(&world, &mut owner, &mut [&mut stays, &mut leaves]).await;

        owner.membership.remove(&leaves.auth()).expect("a removal");
        assert!(!owner.publishes());
        let mut installed_without = false;
        let mut crashed = false;
        for index in 0..64 {
            if index == crash_at {
                owner.restart();
                crashed = true;
            }
            assert_eq!(
                owner.publishes(),
                installed_without && owner.removals().is_empty(),
                "publication opens only once a record without the device is installed and the removal is done"
            );
            let step = owner.step().await;
            if let Step::Installed { revision } = step {
                let record =
                    &world.chain(&collection)[usize::try_from(revision).expect("small") - 1];
                installed_without = !lists(record, &leaves);
            }
            match step {
                Step::Nothing => break,
                Step::FetchNeeded => {
                    owner.refresh().await;
                }
                _ => {}
            }
        }
        assert!(
            owner.publishes(),
            "the removal completes after a crash at {crash_at}"
        );
        assert!(installed_without);
        assert!(owner.removals().is_empty());
        if !crashed {
            break;
        }
        crash_points += 1;
    }
    assert!(
        crash_points >= 6,
        "every step of the removal was a crash point"
    );
}

/// A removal the owner records while a rotation is under way is carried into the next candidate.
#[tokio::test]
async fn a_removal_arriving_during_a_rotation_is_carried_into_the_next_candidate() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut first = Node::new(&world);
    let mut second = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut first, &mut second]).await;

    owner.membership.remove(&first.auth()).expect("a removal");
    assert_eq!(owner.step().await, Step::Built { built: true });
    assert_eq!(owner.step().await, Step::Dispatched);
    // The second removal arrives while the first rotation is in flight.
    owner.membership.remove(&second.auth()).expect("a removal");
    run(&mut owner).await;
    let newest = world.newest(&collection);
    assert!(!lists(&newest, &first) && !lists(&newest, &second));
    assert!(owner.removals().is_empty());
    assert!(owner.publishes());
    let removed: Vec<Outcome<Device>> = owner
        .outcomes()
        .into_iter()
        .filter(|outcome| {
            matches!(
                outcome,
                Outcome::Removal {
                    ended: Ended::Done,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(removed.len(), 2);
}

/// A record from a member the hosts then revoke wins the race and keeps this device; this device
/// refuses it, rotates the revoked member out, and never installs its key.
#[tokio::test]
async fn a_revoked_winner_that_keeps_this_device_is_rotated_out_and_its_key_never_installed() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut winner = Node::new(&world);
    let mut third = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut winner, &mut third]).await;

    // The winner rotates, keeping this device, and is then revoked.
    let newest = world.newest(&collection);
    let winner_key = fresh();
    let record = issue(
        &winner,
        &newest,
        &[owner.device(), winner.device(), third.device()],
        epoch_of(&newest) + 1,
        &winner_key,
    );
    world.append(&collection, record);
    world.hosts.revoke(winner.device());

    // This device had its own rotation built on the older head; it loses.
    owner.membership.remove(&third.auth()).expect("a removal");
    run(&mut owner).await;
    let final_record = world.newest(&collection);
    assert!(!lists(&final_record, &winner));
    assert!(owner.publishes());
    for epoch in 0..=final_record.payload.key_epoch.get() {
        if let Some(key) = owner.held(&collection, epoch) {
            assert_ne!(
                key.expose(),
                winner_key.expose(),
                "the winner's key is never installed"
            );
        }
    }
}

/// A rotation away from a refused record keeps nothing the refused record added.
#[tokio::test]
async fn a_rotation_away_from_a_refused_record_keeps_nothing_it_added() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut revoked = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut revoked]).await;

    let newest = world.newest(&collection);
    let added = Node::new(&world);
    world.hosts.commit(added.device(), true);
    let key = key_in(&newest, &revoked);
    let record = issue(
        &revoked,
        &newest,
        &[owner.device(), revoked.device(), added.device()],
        epoch_of(&newest),
        &key,
    );
    world.append(&collection, record);
    world.hosts.revoke(revoked.device());

    owner.refresh().await;
    run(&mut owner).await;
    let final_record = world.newest(&collection);
    assert!(
        !lists(&final_record, &added),
        "nothing the refused record added is carried"
    );
    assert!(!lists(&final_record, &revoked));
    assert!(owner.publishes());
}

/// A lost answer is settled by status, and a lost request by the fence, before anything is sent
/// again: every request identity is sent once.
#[tokio::test]
async fn a_lost_rekey_reply_is_settled_by_status_or_fence_before_anything_is_sent_again() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut first = Node::new(&world);
    let mut second = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut first, &mut second]).await;

    // A lost answer: the record applied, and status says so.
    owner.membership.remove(&first.auth()).expect("a removal");
    world.fate(Fate::LoseAnswer);
    assert_eq!(owner.step().await, Step::Built { built: true });
    let request = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    let revision = world.newest(&collection).payload.revision.get();
    assert_eq!(
        owner.step().await,
        Step::Settled(Settlement::Applied { revision })
    );
    assert_eq!(world.sends(request), 1);
    run(&mut owner).await;

    // A lost request: status knows nothing, the fence says it never ran, and a new candidate
    // under a new identity is built and sent once.
    owner.membership.remove(&second.auth()).expect("a removal");
    world.fate(Fate::LoseRequest);
    assert_eq!(owner.step().await, Step::Built { built: true });
    let lost_request = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    assert_eq!(owner.step().await, Step::Settled(Settlement::Fenced));
    run(&mut owner).await;
    assert_eq!(world.sends(lost_request), 1);
    assert!(!lists(&world.newest(&collection), &second));
    assert!(owner.publishes());
}

/// A candidate that loses to another member's record is dropped with its key, which never
/// reaches the store.
#[tokio::test]
async fn a_losing_candidate_key_is_never_installed() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let mut third = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other, &mut third]).await;

    owner.membership.remove(&third.auth()).expect("a removal");
    world.fate(Fate::Hold);
    assert_eq!(owner.step().await, Step::Built { built: true });
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    // The key the candidate carries, read from the request in flight before the service takes it.
    let losing_key = key_in(&world.state().held[0].record, &owner);
    let never_held = |node: &Node| {
        (0..=16).all(|epoch| {
            node.held(&collection, epoch)
                .is_none_or(|key| key.expose() != losing_key.expose())
        })
    };
    // The other member's rotation lands first; the held candidate then loses.
    other.reconcile().await;
    other.membership.remove(&third.auth()).expect("a removal");
    other.reconcile().await;
    world.deliver_held();
    assert!(world.state().held.is_empty());
    for _ in 0..64 {
        let step = owner.step().await;
        assert!(
            never_held(&owner),
            "the losing key reached the store after {step:?}"
        );
        match step {
            Step::Nothing => break,
            Step::FetchNeeded | Step::Settled(Settlement::Refused { .. }) => {
                owner.refresh().await;
            }
            _ => {}
        }
    }
    let newest = world.newest(&collection);
    assert!(!lists(&newest, &third));
    let other_key = key_in(&newest, &owner);
    assert_eq!(
        owner
            .held(&collection, epoch_of(&newest))
            .expect("the winning key")
            .expose(),
        other_key.expose()
    );
    assert!(owner.publishes());
}

/// Two members removing two devices at once: both removals end in the chain.
#[tokio::test]
async fn two_concurrent_removals_both_end_in_the_chain() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let mut first = Node::new(&world);
    let mut second = Node::new(&world);
    let collection = collection_of(
        &world,
        &mut owner,
        &mut [&mut other, &mut first, &mut second],
    )
    .await;
    other.reconcile().await;

    owner.membership.remove(&first.auth()).expect("a removal");
    other.membership.remove(&second.auth()).expect("a removal");
    // Both build on the same head; one wins.
    assert_eq!(owner.step().await, Step::Built { built: true });
    assert_eq!(other.step().await, Step::Built { built: true });
    run(&mut owner).await;
    run(&mut other).await;
    run(&mut owner).await;
    let newest = world.newest(&collection);
    assert!(!lists(&newest, &first) && !lists(&newest, &second));
    assert!(owner.removals().is_empty() && other.removals().is_empty());
}

/// An undispatched candidate is sent after a restart; one marked dispatched and not sent is
/// fenced rather than sent; one sent is settled by status rather than sent again.
#[tokio::test]
async fn an_undispatched_candidate_is_sent_after_a_restart() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut first = Node::new(&world);
    let mut second = Node::new(&world);
    let mut third = Node::new(&world);
    let collection = collection_of(
        &world,
        &mut owner,
        &mut [&mut first, &mut second, &mut third],
    )
    .await;

    // A crash before the dispatch mark: the candidate is dispatched and sent after the restart.
    owner.membership.remove(&first.auth()).expect("a removal");
    assert_eq!(owner.step().await, Step::Built { built: true });
    let request = owner.candidate_request().expect("a candidate");
    owner.restart();
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: true });
    assert_eq!(world.sends(request), 1);
    run(&mut owner).await;

    // A crash after the mark and before the send: never sent; fenced, and a new one built.
    owner.membership.remove(&second.auth()).expect("a removal");
    assert_eq!(owner.step().await, Step::Built { built: true });
    let unsent = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    owner.restart();
    assert_eq!(owner.step().await, Step::Settled(Settlement::Fenced));
    run(&mut owner).await;
    assert_eq!(world.sends(unsent), 0);
    assert!(!lists(&world.newest(&collection), &second));

    // A crash after the send, with the answer not yet taken: settled by status.
    owner.membership.remove(&third.auth()).expect("a removal");
    assert_eq!(owner.step().await, Step::Built { built: true });
    let sent = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: true });
    owner.restart();
    let revision = world.newest(&collection).payload.revision.get();
    assert_eq!(
        owner.step().await,
        Step::Settled(Settlement::Applied { revision })
    );
    run(&mut owner).await;
    assert_eq!(world.sends(sent), 1);
    assert!(owner.publishes());
}

/// An addition whose answer was lost completes after a restart; the device it adds completes too
/// after a restart between storing the key and recording the record as installed.
#[tokio::test]
async fn an_addition_whose_reply_was_lost_completes_after_a_restart() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut []).await;

    let mut device = Node::new(&world);
    world.hosts.commit(device.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&device.auth(), now())
        .expect("a plan");
    owner.membership.authorise(&plan, now()).expect("confirmed");
    world.fate(Fate::LoseAnswer);
    assert_eq!(owner.step().await, Step::Built { built: true });
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    owner.restart();
    run(&mut owner).await;
    assert!(owner.publishes());
    assert!(owner.outcomes().contains(&Outcome::Addition {
        device: device.device(),
        ended: Ended::Done
    }));

    let join = device
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    device.membership.join(&join, now()).await.expect("a join");
    assert_eq!(
        device.step().await,
        Step::Stored {
            epoch: 1,
            revision: 2
        }
    );
    device.restart();
    assert!(device.held(&collection, 1).is_some());
    assert!(!device.publishes());
    assert_eq!(device.step().await, Step::Installed { revision: 2 });
    assert!(device.publishes());
}

/// An addition the owner confirmed survives a removal that arrives before its candidate is sent:
/// the candidate is dropped and the next one carries both.
#[tokio::test]
async fn an_addition_survives_a_removal_that_arrives_before_it_is_sent() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut leaves = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut leaves]).await;

    let device = Node::new(&world);
    world.hosts.commit(device.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&device.auth(), now())
        .expect("a plan");
    owner.membership.authorise(&plan, now()).expect("confirmed");
    assert_eq!(owner.step().await, Step::Built { built: true });
    owner.membership.remove(&leaves.auth()).expect("a removal");
    assert_eq!(owner.step().await, Step::Dropped);
    run(&mut owner).await;
    let newest = world.newest(&collection);
    assert!(lists(&newest, &device));
    assert!(!lists(&newest, &leaves));
    assert_eq!(epoch_of(&newest), 2, "one record carries both");
    assert!(owner.publishes());
}

/// A key a refused issuer opened an epoch with, wrapped again by a later addition from an
/// issuer that passes, is never installed, across a restart and the rotation that removes the
/// refused issuer.
#[tokio::test]
async fn a_refused_issuers_key_wrapped_again_by_a_later_addition_is_never_installed() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut honest = Node::new(&world);
    let mut refused = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut honest, &mut refused]).await;

    let newest = world.newest(&collection);
    let refused_key = fresh();
    let epoch = epoch_of(&newest) + 1;
    let opening = issue(
        &refused,
        &newest,
        &[owner.device(), honest.device(), refused.device()],
        epoch,
        &refused_key,
    );
    world.append(&collection, opening.clone());
    let added = Node::new(&world);
    world.hosts.commit(added.device(), true);
    let rewrapped = issue(
        &honest,
        &opening,
        &[
            owner.device(),
            honest.device(),
            refused.device(),
            added.device(),
        ],
        epoch,
        &refused_key,
    );
    world.append(&collection, rewrapped);
    world.hosts.revoke(refused.device());

    owner.refresh().await;
    assert_eq!(owner.step().await, Step::Built { built: true });
    owner.restart();
    run(&mut owner).await;
    for epoch in 0..=world.newest(&collection).payload.key_epoch.get() {
        if let Some(key) = owner.held(&collection, epoch) {
            assert_ne!(key.expose(), refused_key.expose());
        }
    }
    assert!(owner.held(&collection, epoch).is_none());
    assert!(!lists(&world.newest(&collection), &refused));
    assert!(owner.publishes());
}

/// A removal recorded while an addition of the same device is unsettled is carried out
/// across dispatch, settlement, installation and restarts, and the device stays bound to remove
/// it until an installed record excludes it.
#[tokio::test]
async fn a_removal_recorded_while_an_addition_of_that_device_is_unsettled_is_carried_out() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut []).await;
    let device = Node::new(&world);
    world.hosts.commit(device.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&device.auth(), now())
        .expect("a plan");
    owner.membership.authorise(&plan, now()).expect("confirmed");
    world.fate(Fate::Hold);
    assert_eq!(owner.step().await, Step::Built { built: true });
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    // The owner removes the device while its addition is in flight; the service then applies it.
    owner.membership.remove(&device.auth()).expect("a removal");
    assert!(owner.outcomes().contains(&Outcome::Addition {
        device: device.device(),
        ended: Ended::Cancelled
    }));
    world.deliver_held();
    let revision = world.newest(&collection).payload.revision.get();
    assert_eq!(
        owner.step().await,
        Step::Settled(Settlement::Applied { revision })
    );
    // A crash between the write that cleared the candidate and the ones that install.
    owner.restart();
    assert!(!owner.publishes());
    assert_eq!(owner.step().await, Step::Stored { epoch: 1, revision });
    owner.restart();
    assert!(!owner.publishes());
    assert_eq!(owner.step().await, Step::Installed { revision });
    owner.restart();
    assert!(
        !owner.publishes(),
        "the installed record lists the device the owner removed"
    );
    run(&mut owner).await;
    let newest = world.newest(&collection);
    assert!(!lists(&newest, &device));
    assert_eq!(epoch_of(&newest), 2);
    assert!(owner.publishes());
    assert!(owner.outcomes().contains(&Outcome::Removal {
        device: device.device(),
        ended: Ended::Done
    }));
}

/// Every pending change ends as done, cancelled or refused, is reported, and survives a
/// restart until the screen has shown it.
#[tokio::test]
async fn each_pending_change_ends_as_done_cancelled_or_refused_and_is_reported() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;
    owner
        .membership
        .acknowledge_outcomes(usize::MAX)
        .expect("cleared");

    let first = Node::new(&world);
    let second = Node::new(&world);
    world.hosts.commit(first.device(), true);
    world.hosts.commit(second.device(), true);
    owner.refresh().await;
    // Cancelled: an addition replaced by a removal of the same device.
    let plan = owner
        .membership
        .plan_share(&first.auth(), now())
        .expect("a plan");
    owner.membership.authorise(&plan, now()).expect("confirmed");
    owner.membership.remove(&first.auth()).expect("a removal");
    // Refused: an addition of a device whose removal is pending.
    let plan = owner
        .membership
        .plan_share(&first.auth(), now())
        .expect("a plan");
    assert_eq!(
        owner.membership.authorise(&plan, now()).expect("answered"),
        Ended::Refused
    );
    // Done: the removal (of a device never installed) and an addition.
    run(&mut owner).await;
    let plan = owner
        .membership
        .plan_share(&second.auth(), now())
        .expect("a plan");
    owner.membership.authorise(&plan, now()).expect("confirmed");
    run(&mut owner).await;
    // Refused, because the device leaves: the other member removes it while a removal it asked
    // for is pending.
    owner.membership.remove(&second.auth()).expect("a removal");
    other.refresh().await;
    other.membership.remove(&owner.auth()).expect("a removal");
    other.reconcile().await;
    owner.refresh().await;
    run(&mut owner).await;

    let expected = [
        Outcome::Addition {
            device: first.device(),
            ended: Ended::Cancelled,
        },
        Outcome::Addition {
            device: first.device(),
            ended: Ended::Refused,
        },
        Outcome::Removal {
            device: first.device(),
            ended: Ended::Done,
        },
        Outcome::Addition {
            device: second.device(),
            ended: Ended::Done,
        },
        Outcome::Removal {
            device: second.device(),
            ended: Ended::Refused,
        },
    ];
    for outcome in expected {
        assert!(owner.outcomes().contains(&outcome), "{outcome:?} reported");
    }
    owner.restart();
    let kept = owner.outcomes();
    for outcome in expected {
        assert!(kept.contains(&outcome), "{outcome:?} survives a restart");
    }
    owner
        .membership
        .acknowledge_outcomes(kept.len())
        .expect("shown");
    assert!(owner.outcomes().is_empty());
    let _ = collection;
}

/// The first key lives only in the first record's own wrap until the claim applies and row 4
/// installs it.
#[tokio::test]
async fn the_genesis_key_is_installed_only_through_row_4_after_the_claim_applies() {
    let world = World::default();
    let mut owner = Node::new(&world);
    world.hosts.commit(owner.device(), true);
    let collection = owner
        .membership
        .start(collection_id(0x61), now())
        .await
        .expect("a collection");
    assert!(owner.held(&collection, 0).is_none());
    assert_eq!(owner.step().await, Step::Dispatched);
    assert!(owner.held(&collection, 0).is_none());
    assert_eq!(owner.step().await, Step::Sent { answered: true });
    assert!(owner.held(&collection, 0).is_none());
    assert_eq!(
        owner.step().await,
        Step::Settled(Settlement::Applied { revision: 1 })
    );
    assert!(owner.held(&collection, 0).is_none());
    assert!(!owner.publishes());
    assert_eq!(
        owner.step().await,
        Step::Stored {
            epoch: 0,
            revision: 1
        }
    );
    let stored = owner.held(&collection, 0).expect("the first key");
    assert_eq!(
        stored.expose(),
        key_in(&world.newest(&collection), &owner).expose()
    );
    assert_eq!(owner.step().await, Step::Installed { revision: 1 });
    assert!(owner.publishes());
}

/// A record at an epoch this device holds that wraps another key is refused, and the device
/// rotates away from it.
#[tokio::test]
async fn a_same_epoch_record_wrapping_another_key_is_refused() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;
    let newest = world.newest(&collection);
    let epoch = epoch_of(&newest);
    let held = owner.held(&collection, epoch).expect("the key");

    let added = Node::new(&world);
    world.hosts.commit(added.device(), true);
    let another = fresh();
    let record = issue(
        &other,
        &newest,
        &[owner.device(), other.device(), added.device()],
        epoch,
        &another,
    );
    world.append(&collection, record);
    owner.refresh().await;
    run(&mut owner).await;
    assert_eq!(
        owner.held(&collection, epoch).expect("unchanged").expose(),
        held.expose()
    );
    let final_record = world.newest(&collection);
    assert_eq!(epoch_of(&final_record), epoch + 1, "rotated away");
    assert!(
        !lists(&final_record, &added),
        "nothing the refused record added"
    );
    assert!(owner.publishes());
}

/// A removal is not done while a refused record between the installed record and the head
/// left the device the current key; it is done once a rotation away from it is installed.
#[tokio::test]
async fn a_removal_is_not_done_while_a_refused_record_left_the_device_the_current_key() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut honest = Node::new(&world);
    let mut faulty = Node::new(&world);
    let mut removed = Node::new(&world);
    let collection = collection_of(
        &world,
        &mut owner,
        &mut [&mut honest, &mut faulty, &mut removed],
    )
    .await;

    // The owner removes the device; an honest member's rotation carries it out first.
    owner.membership.remove(&removed.auth()).expect("a removal");
    honest.refresh().await;
    honest
        .membership
        .remove(&removed.auth())
        .expect("a removal");
    honest.reconcile().await;
    let rotated = world.newest(&collection);
    let current_epoch = epoch_of(&rotated);
    let current = key_in(&rotated, &honest);
    // The faulty member wraps the current key for the removed device again, then rotates it out
    // itself, and is revoked.
    let readded = issue(
        &faulty,
        &rotated,
        &[
            owner.device(),
            honest.device(),
            faulty.device(),
            removed.device(),
        ],
        current_epoch,
        &current,
    );
    world.append(&collection, readded.clone());
    let dropped = issue(
        &faulty,
        &readded,
        &[owner.device(), honest.device(), faulty.device()],
        current_epoch + 1,
        &fresh(),
    );
    world.append(&collection, dropped);
    world.hosts.revoke(faulty.device());

    // Inspected after every step: the removal ends as done only once a record at an epoch after
    // the faulty member's is installed, so the key the removed device holds is no longer in use.
    for _ in 0..64 {
        let step = owner.step().await;
        if step == Step::Done {
            let (epoch, _) = owner.installed().expect("installed");
            assert!(
                epoch > current_epoch + 1,
                "done at epoch {epoch}, before a rotation away from the key it holds"
            );
        }
        match step {
            Step::Nothing => break,
            Step::FetchNeeded | Step::Settled(Settlement::Refused { .. }) => {
                owner.refresh().await;
            }
            _ => {}
        }
    }
    let final_record = world.newest(&collection);
    assert!(!lists(&final_record, &removed));
    assert!(!lists(&final_record, &faulty));
    assert!(owner.removals().is_empty());
    assert!(owner.publishes());
    assert!(owner.outcomes().contains(&Outcome::Removal {
        device: removed.device(),
        ended: Ended::Done
    }));
}

/// A device its hosts revoke while its addition is in flight is refused as an addition,
/// removed when the record adding it is settled, and rotated out before publication reopens.
#[tokio::test]
async fn a_device_revoked_while_its_addition_is_in_flight_is_rotated_out_before_publication() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut []).await;
    let device = Node::new(&world);
    world.hosts.commit(device.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&device.auth(), now())
        .expect("a plan");
    owner.membership.authorise(&plan, now()).expect("confirmed");
    world.fate(Fate::Hold);
    assert_eq!(owner.step().await, Step::Built { built: true });
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    world.hosts.revoke(device.device());
    owner.refresh().await;
    assert!(owner.outcomes().contains(&Outcome::Addition {
        device: device.device(),
        ended: Ended::Refused
    }));
    world.deliver_held();
    for _ in 0..64 {
        let step = owner.step().await;
        if owner.publishes() {
            let (_, revision) = owner.installed().expect("installed");
            let record = &world.chain(&collection)[usize::try_from(revision).expect("small") - 1];
            assert!(
                !lists(record, &device),
                "publication open while the installed record lists the revoked device"
            );
        }
        match step {
            Step::Nothing => break,
            Step::FetchNeeded => {
                owner.refresh().await;
            }
            _ => {}
        }
    }
    assert!(owner.publishes());
    assert!(!lists(&world.newest(&collection), &device));
}

/// A record opening a new epoch with a key this device already holds is refused, and the
/// device rotates away from it.
#[tokio::test]
async fn a_new_epoch_reusing_an_earlier_key_is_refused_and_rotated_away() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut faulty = Node::new(&world);
    let mut removed = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut faulty, &mut removed]).await;
    let old = owner.held(&collection, 0).expect("the first key");

    let newest = world.newest(&collection);
    let epoch = epoch_of(&newest) + 1;
    let reusing = issue(
        &faulty,
        &newest,
        &[owner.device(), faulty.device()],
        epoch,
        &old,
    );
    world.append(&collection, reusing);
    owner.refresh().await;
    run(&mut owner).await;
    assert!(
        owner.held(&collection, epoch).is_none(),
        "the reusing record's epoch is never installed"
    );
    let fresh_key = owner
        .held(&collection, epoch + 1)
        .expect("rotated to the epoch after it");
    assert_ne!(fresh_key.expose(), old.expose());
    let final_record = world.newest(&collection);
    assert_eq!(epoch_of(&final_record), epoch + 1);
    assert!(owner.publishes());
}

/// A `rekey` whose receipt expired is settled by the record after its base, whether it
/// applied or not, each with a lost answer and a restart.
#[tokio::test]
async fn a_rekey_whose_receipt_expired_is_settled_by_the_record_after_its_base() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let mut first = Node::new(&world);
    let mut second = Node::new(&world);
    let collection = collection_of(
        &world,
        &mut owner,
        &mut [&mut other, &mut first, &mut second],
    )
    .await;
    other.refresh().await;

    // Applied, answer lost, restart, receipt expired: the record after the base is its own.
    owner.membership.remove(&first.auth()).expect("a removal");
    world.fate(Fate::LoseAnswer);
    assert_eq!(owner.step().await, Step::Built { built: true });
    let applied = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    owner.restart();
    world.expire(applied);
    let revision = world.newest(&collection).payload.revision.get();
    assert_eq!(
        owner.step().await,
        Step::Settled(Settlement::ReadAfterBase {
            revision: Some(revision)
        })
    );
    run(&mut owner).await;
    assert!(!lists(&world.newest(&collection), &first));
    assert!(owner.publishes());
    other.reconcile().await;

    // Not applied: lost on its way, another member's record takes its place, and the receipt it
    // never had has passed the retention. The record after the base is the other member's.
    owner.membership.remove(&second.auth()).expect("a removal");
    world.fate(Fate::LoseRequest);
    assert_eq!(owner.step().await, Step::Built { built: true });
    let lost_request = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    other.membership.remove(&second.auth()).expect("a removal");
    other.reconcile().await;
    owner.restart();
    world.expire(lost_request);
    let theirs = world.newest(&collection).payload.revision.get();
    assert_eq!(
        owner.step().await,
        Step::Settled(Settlement::ReadAfterBase {
            revision: Some(theirs)
        })
    );
    run(&mut owner).await;
    assert_eq!(world.sends(lost_request), 1);
    assert!(!lists(&world.newest(&collection), &second));
    assert!(owner.publishes());
}

/// A record after the installed one that leaves this device out ends its membership, even
/// when a later record lists it again, until the owner confirms a join on it.
#[tokio::test]
async fn a_record_that_leaves_this_device_out_ends_its_membership_until_the_owner_confirms_a_join()
{
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut device = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut device]).await;

    // The owner removes the device, reuses that key in a later epoch, and lists it again.
    let newest = world.newest(&collection);
    let held = epoch_of(&newest);
    let removed_key = fresh();
    let without = issue(&owner, &newest, &[owner.device()], held + 1, &removed_key);
    world.append(&collection, without.clone());
    let reused = issue(&owner, &without, &[owner.device()], held + 2, &removed_key);
    world.append(&collection, reused.clone());
    let again = issue(
        &owner,
        &reused,
        &[owner.device(), device.device()],
        held + 2,
        &removed_key,
    );
    world.append(&collection, again);

    assert_eq!(device.refresh().await, Refreshed::Recorded);
    assert_eq!(device.step().await, Step::Left);
    assert!(device.out());
    assert!(!device.publishes());
    assert_eq!(device.step().await, Step::ForgotKeys { epoch: held });
    assert!(device.held(&collection, held).is_none());
    assert_eq!(device.step().await, Step::Nothing);
    assert_eq!(device.refresh().await, Refreshed::Out);
    assert!(device.held(&collection, held + 2).is_none());

    let plan = device
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    device
        .membership
        .join(&plan, now())
        .await
        .expect("confirmed");
    device.reconcile().await;
    assert!(device.publishes());
    assert_eq!(device.installed(), Some((held + 2, 5)));
}

/// A revocation verified from an authority feed fences publication at once, before any host
/// answers, and the removal it asks for waits for a fetch before it is done.
#[tokio::test]
async fn a_verified_feed_revocation_fences_publication_before_any_host_answers() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut revoked = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut revoked]).await;
    assert!(owner.publishes());

    world.hosts.silence(true);
    owner
        .membership
        .feed_revocation(&revoked.auth())
        .expect("recorded");
    assert!(!owner.publishes(), "fenced when it arrives");
    assert_eq!(owner.refresh().await, Refreshed::NoHostAnswered);
    let steps = run(&mut owner).await;
    assert!(steps.iter().all(|(_, publishes)| !publishes));
    assert!(!lists(&world.newest(&collection), &revoked), "rotated out");
    assert!(
        !owner.removals().is_empty(),
        "done waits for a fetch no host answers"
    );

    world.hosts.silence(false);
    owner.refresh().await;
    run(&mut owner).await;
    assert!(owner.removals().is_empty());
    assert!(owner.publishes());
}

/// The record read to settle a candidate whose receipt expired becomes the head, with
/// the host answers applied to it in the same write.
#[tokio::test]
async fn a_record_read_to_settle_a_candidate_becomes_the_head_with_the_host_answers() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;

    // This device's addition is lost; another member's record re-adds a device the recorded
    // answers fail.
    let device = Node::new(&world);
    world.hosts.commit(device.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&device.auth(), now())
        .expect("a plan");
    owner.membership.authorise(&plan, now()).expect("confirmed");
    world.fate(Fate::LoseRequest);
    assert_eq!(owner.step().await, Step::Built { built: true });
    let lost_request = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    let failing = Node::new(&world);
    let newest = world.newest(&collection);
    let key = key_in(&newest, &other);
    let theirs = issue(
        &other,
        &newest,
        &[owner.device(), other.device(), failing.device()],
        epoch_of(&newest),
        &key,
    );
    world.append(&collection, theirs);
    world.expire(lost_request);

    let revision = world.newest(&collection).payload.revision.get();
    assert_eq!(
        owner.step().await,
        Step::Settled(Settlement::ReadAfterBase {
            revision: Some(revision)
        })
    );
    let status = owner
        .membership
        .members()
        .expect("readable")
        .expect("a collection");
    assert_eq!(status.head, revision, "the record read is the head");
    assert!(
        status.removals.contains(&failing.device()),
        "the answers the head failed are applied in the same write"
    );
    run(&mut owner).await;
    assert!(!lists(&world.newest(&collection), &failing));
    assert!(owner.publishes());
}

/// A change is done only at a head fetched after it was recorded.
#[tokio::test]
async fn a_change_is_done_only_at_a_head_fetched_after_it_was_recorded() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut removed = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut removed]).await;

    owner.membership.remove(&removed.auth()).expect("a removal");
    let mut steps = Vec::new();
    loop {
        let step = owner.step().await;
        steps.push(step);
        if matches!(step, Step::Installed { .. }) {
            break;
        }
    }
    // Installed from its own settled record, not from a fetch: not done yet.
    assert_eq!(owner.step().await, Step::FetchNeeded);
    assert_eq!(owner.removals(), vec![removed.device()]);
    assert!(!owner.publishes());
    owner.refresh().await;
    assert_eq!(owner.step().await, Step::Done);
    assert!(owner.publishes());
    let _ = collection;
}

/// A change the installed head already carries out builds no further candidate while it
/// waits for a fetch.
#[tokio::test]
async fn a_change_the_installed_head_carries_out_builds_no_candidate_while_it_waits_for_a_fetch() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut removed = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut removed]).await;

    owner.membership.remove(&removed.auth()).expect("a removal");
    loop {
        if matches!(owner.step().await, Step::Installed { .. }) {
            break;
        }
    }
    let chain = world.chain(&collection).len();
    for _ in 0..3 {
        assert_eq!(owner.step().await, Step::FetchNeeded);
    }
    assert_eq!(world.chain(&collection).len(), chain, "no further rotation");
    assert!(owner.candidate_request().is_none());
}

/// The write that confirms a join records the host answers and the removals they require,
/// before anything is installed.
#[tokio::test]
async fn a_join_records_the_host_answers_and_the_removals_they_require() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut revoked = Node::new(&world);
    let mut device = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut revoked]).await;
    world.hosts.commit(device.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&device.auth(), now())
        .expect("a plan");
    owner.membership.authorise(&plan, now()).expect("confirmed");
    owner.reconcile().await;

    // Before the device joins, a host revokes a member its join record lists.
    world.hosts.revoke(revoked.device());
    let join = device
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    device
        .membership
        .join(&join, now())
        .await
        .expect("confirmed");
    assert_eq!(
        device.removals(),
        vec![revoked.device()],
        "recorded in the join's write"
    );
    let steps = run(&mut device).await;
    let installed_without = steps
        .iter()
        .position(|(step, _)| matches!(step, Step::Installed { revision } if *revision >= 4));
    let opened = steps.iter().position(|(_, publishes)| *publishes);
    assert!(opened.is_some() && installed_without.is_some());
    assert!(installed_without <= opened);
    assert!(!lists(&world.newest(&collection), &revoked));
}

/// A key reused from before this device's current join is the stated limit and is not
/// detected; a key reused from an epoch it opened since the join always is.
#[tokio::test]
async fn a_reused_key_before_the_current_join_is_the_stated_limit_and_a_current_wrap_never_is() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut device = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut device]).await;
    // The key the device held in the membership it is about to leave.
    let first_epoch = epoch_of(&world.newest(&collection));
    let before_join = device
        .held(&collection, first_epoch)
        .expect("the key of its first membership");

    // The device leaves, the owner rotates, and lists it again at a new epoch reusing the key of
    // the device's earlier membership, from before its new join: the stated limit, accepted.
    let newest = world.newest(&collection);
    let without = issue(
        &owner,
        &newest,
        &[owner.device()],
        first_epoch + 1,
        &fresh(),
    );
    world.append(&collection, without.clone());
    let reusing = issue(
        &owner,
        &without,
        &[owner.device(), device.device()],
        first_epoch + 2,
        &before_join,
    );
    world.append(&collection, reusing.clone());
    device.refresh().await;
    run(&mut device).await;
    assert!(device.out());
    let plan = device
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    device
        .membership
        .join(&plan, now())
        .await
        .expect("confirmed");
    run(&mut device).await;
    assert!(
        device.publishes(),
        "a reuse from before the join is not detected"
    );
    assert_eq!(
        device
            .held(&collection, first_epoch + 2)
            .expect("installed")
            .expose(),
        before_join.expose()
    );

    // A key reused from an epoch the device opened since its join is refused.
    let current = world.newest(&collection);
    let again = issue(
        &owner,
        &current,
        &[owner.device(), device.device()],
        first_epoch + 3,
        &before_join,
    );
    world.append(&collection, again);
    device.refresh().await;
    run(&mut device).await;
    assert!(
        device.held(&collection, first_epoch + 3).is_none(),
        "the reused key is never installed"
    );
    let final_record = world.newest(&collection);
    assert_eq!(epoch_of(&final_record), first_epoch + 4, "rotated away");
    assert!(device.publishes());
}

/* -------------------------------------------------------------------------- */
/* The file, the lock and the order of things                                  */
/* -------------------------------------------------------------------------- */

/// One answer that ends this device's membership is recorded at once, and a candidate it
/// dispatched stays in the file: the steps that follow settle that request first, by its status
/// and its fence, send nothing and move no head, so nothing it sent can still run once the device
/// has left and joined again. Publication stays closed at every step and across a restart.
#[tokio::test]
async fn a_dispatched_candidate_is_settled_after_an_answer_that_ends_the_membership() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut first = Node::new(&world);
    let added = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut first]).await;
    let records_before = world.chain(&collection).len();
    let epoch = epoch_of(&world.newest(&collection));

    // An addition is dispatched and sent, and stays in flight.
    world.hosts.commit(added.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&added.auth(), now())
        .expect("a committed device");
    owner.membership.authorise(&plan, now()).expect("a plan");
    world.fate(Fate::Hold);
    assert_eq!(owner.step().await, Step::Built { built: true });
    let request = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    assert!(!owner.publishes());

    // A hostile service answers once with a chain this device cannot follow: out at once, with
    // the dispatched candidate kept to be settled.
    let installed = owner.installed();
    let replayed = world.chain(&collection)[0].clone();
    world.forge_next(KeyRecords::Records(vec![replayed]));
    assert_eq!(owner.refresh().await, Refreshed::BrokenChain);
    assert!(owner.out() && !owner.publishes());
    assert_eq!(owner.candidate_request(), Some(request));
    assert!(owner.outcomes().contains(&Outcome::Addition {
        device: added.device(),
        ended: Ended::Refused
    }));

    owner.restart();
    assert!(owner.out() && !owner.publishes());
    assert_eq!(owner.candidate_request(), Some(request));
    assert_eq!(owner.refresh().await, Refreshed::Out);
    assert_eq!(owner.step().await, Step::Settled(Settlement::Fenced));
    assert!(owner.out() && !owner.publishes());
    assert_eq!(owner.candidate_request(), None);
    assert!(
        world.state().held.is_empty(),
        "the fence stops the request for good"
    );
    assert_eq!(
        world.sends(request),
        1,
        "a device that is out sends nothing"
    );
    loop {
        let step = owner.step().await;
        assert!(!owner.publishes());
        if step == Step::Nothing {
            break;
        }
        assert!(matches!(step, Step::ForgotKeys { .. }), "{step:?}");
    }
    assert!(owner.held(&collection, epoch).is_none());
    assert_eq!(
        owner.installed(),
        installed,
        "nothing it learnt while out moved a head"
    );

    let plan = owner
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    owner
        .membership
        .join(&plan, now())
        .await
        .expect("the rejoin");
    owner.reconcile().await;
    assert!(owner.publishes());
    assert_eq!(world.sends(request), 1);
    assert_eq!(
        world.chain(&collection).len(),
        records_before,
        "the request that was in flight never ran"
    );
    assert!(!lists(&world.newest(&collection), &added));
}

/// The key of a candidate this device sent that never applied is withdrawn: its wraps may have
/// reached every device it listed, so a record another member issues carrying that key is
/// refused and rotated away, and the removal the owner asked for meanwhile is done only once the
/// rotation's record is installed.
#[tokio::test]
async fn a_record_carrying_the_key_of_a_candidate_that_never_applied_is_refused() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let added = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;
    let epoch = epoch_of(&world.newest(&collection));

    // The owner adds a device; the service hands out the wraps and never applies the request.
    world.hosts.commit(added.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&added.auth(), now())
        .expect("a committed device");
    owner.membership.authorise(&plan, now()).expect("a plan");
    world.fate(Fate::Hold);
    assert_eq!(owner.step().await, Step::Built { built: true });
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    let flight = world.state().held[0].record.clone();
    let withdrawn = key_in(&flight, &other);
    assert_eq!(key_in(&flight, &added).expose(), withdrawn.expose());

    // The owner removes that device, and the request is fenced as never run.
    owner.membership.remove(&added.auth()).expect("a removal");
    assert_eq!(owner.step().await, Step::Settled(Settlement::Fenced));
    assert!(world.state().held.is_empty());

    // Another member issues a valid successor carrying the withdrawn key, without that device.
    let head = world.newest(&collection);
    let reusing = issue(
        &other,
        &head,
        &[owner.device(), other.device()],
        epoch + 1,
        &withdrawn,
    );
    world.append(&collection, reusing);
    assert_eq!(owner.refresh().await, Refreshed::Recorded);
    assert!(!owner.publishes());
    assert_eq!(owner.removals(), vec![added.device()]);

    let seen = run(&mut owner).await;
    let installed_at = seen
        .iter()
        .position(|(step, _)| matches!(step, Step::Installed { .. }))
        .expect("the rotation is installed");
    assert!(
        seen[..installed_at].iter().all(|(_, publishes)| !publishes),
        "{seen:?}"
    );
    let done_at = seen
        .iter()
        .position(|(step, _)| *step == Step::Done)
        .expect("the removal ends");
    assert!(done_at > installed_at, "{seen:?}");
    assert!(
        owner.held(&collection, epoch + 1).is_none(),
        "the withdrawn key is never installed"
    );
    let newest = world.newest(&collection);
    assert_eq!(epoch_of(&newest), epoch + 2, "rotated away");
    assert!(!lists(&newest, &added));
    assert_ne!(
        owner
            .held(&collection, epoch + 2)
            .expect("the rotation's key")
            .expose(),
        withdrawn.expose()
    );
    assert!(owner.outcomes().contains(&Outcome::Removal {
        device: added.device(),
        ended: Ended::Done
    }));
    assert!(owner.removals().is_empty());
    assert!(owner.publishes());
}

/// A gate a test opens.
#[derive(Debug, Default)]
struct Gate {
    open: Mutex<bool>,
    waiting: Mutex<Option<std::task::Waker>>,
}

impl Gate {
    fn open(&self) {
        *self.open.lock().expect("an unpoisoned gate") = true;
        if let Some(waker) = self.waiting.lock().expect("an unpoisoned gate").take() {
            waker.wake();
        }
    }

    async fn wait(&self) {
        std::future::poll_fn(|context| {
            if *self.open.lock().expect("an unpoisoned gate") {
                return std::task::Poll::Ready(());
            }
            *self.waiting.lock().expect("an unpoisoned gate") = Some(context.waker().clone());
            std::task::Poll::Pending
        })
        .await;
    }
}

/// Hosts whose answer waits until the test opens a gate.
#[derive(Debug)]
struct GatedHosts {
    hosts: Arc<Hosts>,
    gate: Arc<Gate>,
}

impl DeviceDirectory for GatedHosts {
    fn answers(&self) -> ServiceFuture<'_, Option<HostAnswers>> {
        Box::pin(async move {
            self.gate.wait().await;
            Ok(Some(HostAnswers {
                reports: self.hosts.reports().clone(),
            }))
        })
    }
}

/// An operation holds the membership across the service calls it waits on, and another handle
/// is told at once that it is busy rather than blocking a thread the first one needs to finish.
#[tokio::test(flavor = "current_thread")]
async fn a_second_handle_is_told_the_membership_is_busy_rather_than_waiting() {
    let world = World::default();
    let mut owner = Node::new(&world);
    collection_of(&world, &mut owner, &mut []).await;

    let gate = Arc::new(Gate::default());
    let secrets = StoredCollectionKeys::open(
        StoreSelection::File,
        "kalareach-membership-test",
        &owner.root.path().join("secrets"),
        SCOPE,
    )
    .expect("the file seam");
    let mut gated = SyncMembership::open(
        owner.root.path().join("membership"),
        &owner.keys,
        secrets,
        Arc::new(ServiceView {
            world: world.clone(),
            caller: owner.auth(),
        }),
        Arc::new(GatedHosts {
            hosts: Arc::clone(&world.hosts),
            gate: Arc::clone(&gate),
        }),
    )
    .expect("a second handle");
    let mut refresh = Box::pin(gated.refresh());
    let waiting = std::future::poll_fn(|context| {
        std::task::Poll::Ready(refresh.as_mut().poll(context).is_pending())
    })
    .await;
    assert!(
        waiting,
        "the refresh waits on its hosts while it holds the membership"
    );
    assert!(matches!(
        owner.membership.members(),
        Err(MembershipError::Busy)
    ));
    assert!(matches!(
        owner.membership.step(now()).await,
        Err(MembershipError::Busy)
    ));
    gate.open();
    assert_eq!(refresh.await.expect("the refresh"), Refreshed::Recorded);
    assert!(owner.membership.members().expect("free again").is_some());
}

/// A share plan names the collection and the epoch it was made at, and they are checked under
/// the same hold that records the addition: once the collection has moved on, it is refused.
#[tokio::test]
async fn a_share_plan_is_refused_once_the_collection_moved_on() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let mut third = Node::new(&world);
    collection_of(&world, &mut owner, &mut [&mut other, &mut third]).await;
    let device = Node::new(&world);
    world.hosts.commit(device.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&device.auth(), now())
        .expect("a plan");

    // Before the owner confirms, another member rotates and this device installs it.
    other.reconcile().await;
    other.membership.remove(&third.auth()).expect("a removal");
    other.reconcile().await;
    owner.reconcile().await;
    assert!(matches!(
        owner.membership.authorise(&plan, now()),
        Err(MembershipError::Plan(PlanRefusal::Stale))
    ));
    let status = owner
        .membership
        .members()
        .expect("readable")
        .expect("a collection");
    assert!(status.addition.is_none(), "nothing was recorded");
}

/// Starting a collection after leaving one forgets the keys of the one it left, one epoch a
/// write, and keeps the outcomes the screen has not shown yet.
#[tokio::test]
async fn starting_a_collection_after_leaving_one_keeps_the_outcomes_and_forgets_the_old_keys() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut device = Node::new(&world);
    let old = collection_of(&world, &mut owner, &mut [&mut device]).await;
    let old_epoch = epoch_of(&world.newest(&old));

    // The device asks for a removal of its own, and is removed before it builds anything.
    device.membership.remove(&owner.auth()).expect("a removal");
    owner.membership.remove(&device.auth()).expect("a removal");
    owner.reconcile().await;
    assert_eq!(device.refresh().await, Refreshed::Left);
    assert!(device.held(&old, old_epoch).is_some(), "not forgotten yet");

    let new = device
        .membership
        .start(collection_id(0x77), now())
        .await
        .expect("a new collection");
    assert_ne!(new, old);
    assert!(
        device.held(&old, old_epoch).is_none(),
        "the old keys went first"
    );
    assert!(device.outcomes().contains(&Outcome::Removal {
        device: owner.device(),
        ended: Ended::Refused
    }));
    device.restart();
    assert!(device.outcomes().contains(&Outcome::Removal {
        device: owner.device(),
        ended: Ended::Refused
    }));
    world.hosts.commit(device.device(), true);
    device.reconcile().await;
    assert!(device.publishes());
}

/// A membership file changed behind this device's back is refused on load, even one whose window
/// is a single record: the device is out and a join awaits the owner.
#[tokio::test]
async fn a_membership_file_changed_behind_the_devices_back_is_refused() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut []).await;
    assert!(owner.publishes());

    // Change one byte of the installed record's signature, the only record the file holds.
    let signature = *world.newest(&collection).signature.as_bytes();
    let path = owner
        .root
        .path()
        .join("membership")
        .join("membership.facts");
    let mut bytes = std::fs::read(&path).expect("the membership file");
    let at = bytes
        .windows(signature.len())
        .position(|window| window == signature)
        .expect("the record's signature in the file");
    bytes[at] ^= 0x01;
    std::fs::write(&path, bytes).expect("written back");

    assert!(owner.out(), "refused, with a join awaiting the owner");
    assert!(!owner.publishes());
}

/// Sends an addition that stays in flight, and returns the request and the record in flight.
async fn an_addition_in_flight(
    world: &World,
    owner: &mut Node,
    added: &Node,
) -> (Uuid, CollectionKeyRecord) {
    world.hosts.commit(added.device(), true);
    owner.refresh().await;
    let plan = owner
        .membership
        .plan_share(&added.auth(), now())
        .expect("a committed device");
    owner.membership.authorise(&plan, now()).expect("a plan");
    world.fate(Fate::Hold);
    assert_eq!(owner.step().await, Step::Built { built: true });
    let request = owner.candidate_request().expect("a candidate");
    assert_eq!(owner.step().await, Step::Dispatched);
    assert_eq!(owner.step().await, Step::Sent { answered: false });
    let flight = world.state().held[0].record.clone();
    (request, flight)
}

/// Changes the membership file behind the device's back: the first run of `from`'s bytes becomes
/// `to`'s.
fn change_file(node: &Node, from: &[u8], to: &[u8]) {
    let path = node.root.path().join("membership").join("membership.facts");
    let mut bytes = std::fs::read(&path).expect("the membership file");
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .expect("the bytes in the file");
    bytes[at..at + from.len()].copy_from_slice(to);
    std::fs::write(&path, bytes).expect("written back");
}

/// A file changed behind the device's back so that it no longer names the request its dispatched
/// candidate was sent under is refused, and the candidate stays: nothing can settle a request
/// nobody can name, so the device sends nothing, forgets its keys, and records no new membership,
/// neither a join nor a new collection, while that request may still run.
#[tokio::test]
async fn a_dispatched_request_a_changed_file_no_longer_names_blocks_a_new_membership() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let added = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;
    let epoch = epoch_of(&world.newest(&collection));
    let (request, _) = an_addition_in_flight(&world, &mut owner, &added).await;

    change_file(&owner, request.as_bytes(), Uuid::NIL.as_bytes());
    owner.restart();
    assert!(owner.out() && !owner.publishes());
    loop {
        let step = owner.step().await;
        assert!(!owner.publishes());
        if step == Step::Nothing {
            break;
        }
        assert!(matches!(step, Step::ForgotKeys { .. }), "{step:?}");
    }
    assert!(owner.held(&collection, epoch).is_none());
    assert_eq!(world.sends(request), 1);
    assert_eq!(
        world.state().held.len(),
        1,
        "the request is still in flight"
    );

    let plan = owner
        .membership
        .plan_join(collection, now())
        .expect("a plan");
    assert!(matches!(
        owner.membership.join(&plan, now()).await,
        Err(MembershipError::UnsettledRequest)
    ));
    assert!(matches!(
        owner.membership.start(collection_id(0x78), now()).await,
        Err(MembershipError::UnsettledRequest)
    ));
    assert!(owner.out());
}

/// A candidate whose recorded key mark was changed behind the device's back, so that it is no
/// longer the mark of the key in the candidate's own wrap, is refused on load: the membership
/// ends, the request is settled while out, and a record another member issues carrying the
/// candidate's key is never installed.
#[tokio::test]
async fn a_candidate_whose_key_mark_was_changed_behind_the_devices_back_ends_the_membership() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let added = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;
    let epoch = epoch_of(&world.newest(&collection));
    let (request, flight) = an_addition_in_flight(&world, &mut owner, &added).await;
    let key = key_in(&flight, &other);

    let mut input = b"kr-collection-key-mark/1".to_vec();
    input.extend_from_slice(key.expose());
    let mark = kr_cbor::sha256(&input);
    let mut changed = mark;
    changed[0] ^= 0x01;
    change_file(&owner, &mark, &changed);
    owner.restart();
    assert!(owner.out() && !owner.publishes());
    assert_eq!(owner.step().await, Step::Settled(Settlement::Fenced));
    assert!(
        world.state().held.is_empty(),
        "the fence stops the request for good"
    );

    let head = world.newest(&collection);
    let reusing = issue(
        &other,
        &head,
        &[owner.device(), other.device()],
        epoch + 1,
        &key,
    );
    world.append(&collection, reusing);
    for (step, publishes) in run(&mut owner).await {
        assert!(!publishes, "{step:?}");
    }
    assert!(owner.held(&collection, epoch + 1).is_none());
    assert!(owner.out());
    assert_eq!(world.sends(request), 1);
}

/// A record whose issuer the hosts report with another stored-envelope key than its record names
/// is never opened for use: check 3 fails, and the device rotates the issuer out.
#[tokio::test]
async fn a_record_whose_issuer_the_hosts_report_with_another_key_is_never_opened() {
    let world = World::default();
    let mut owner = Node::new(&world);
    let mut other = Node::new(&world);
    let collection = collection_of(&world, &mut owner, &mut [&mut other]).await;

    let newest = world.newest(&collection);
    let key = fresh();
    let epoch = epoch_of(&newest) + 1;
    let record = issue(
        &other,
        &newest,
        &[owner.device(), other.device()],
        epoch,
        &key,
    );
    world.append(&collection, record);
    world.hosts.commit(
        Device {
            authorisation: other.auth(),
            stored_envelope: *DeviceKeys::generate()
                .expect("keys")
                .stored_envelope
                .public(),
        },
        true,
    );

    owner.refresh().await;
    run(&mut owner).await;
    for held in 0..=epoch + 1 {
        assert!(
            owner
                .held(&collection, held)
                .is_none_or(|stored| stored.expose() != key.expose())
        );
    }
    assert!(!lists(&world.newest(&collection), &other));
    assert!(owner.publishes());
}
