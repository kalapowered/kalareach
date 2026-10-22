//! Settings sync across devices, against the web service itself: a device taken out while another is
//! away, and two devices that change the same setting.
//!
//! Every other suite holds the sync client to a service written for the test. These legs hold it to
//! the one the web repository serves, with three or two installations that each keep their own keys
//! and stores, share one collection through the membership ceremony, and write through the same
//! clients the application uses. The hosts that vouch for the devices are the one scripted part: a
//! host says which devices it paired, and the service knows nothing of hosts.
//!
//! Neither leg needs an account: settings sync is signed by the installation alone. Both take their
//! origin from [`kr_sync_integration::ORIGIN_VARIABLE`] and run against a local deployment or a
//! deployed one alike; `scripts/e2e-backup.sh` runs them on a local Worker.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-20.11 and KR-REQ-18.05, the settings part: revocation | `a_device_taken_out_while_another_is_away_is_answered_as_missing_and_the_other_seals_again_under_the_new_epoch` |
//! | KR-REQ-20.13 and KR-REQ-18.05, across devices | `two_devices_that_change_a_setting_from_one_revision_keep_both_and_neither_is_chosen_by_a_clock` |
//!
//! # What they leave
//!
//! Against a deployment: the collections the devices made, with the objects they wrote, owned by
//! installations whose keys are discarded with the run. No client operation removes a shared
//! collection's key records, which a collection keeps for its life.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_backup_integration::{DeviceSigner, Watched};
use kr_client::drafts::{
    DraftSealer, DraftStore, DraftSync, DraftTarget, Published as DraftPublished,
};
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_client::services::sync::ManagedSyncService;
use kr_client::services::{ServiceFuture, SyncBackupService, SyncFetched};
use kr_client::sync::membership::{
    CollectionRef, Device, DeviceDirectory, Ended, HostAnswers, HostDevice, HostReport,
    KeyRecordService, Refreshed, SyncMembership,
};
use kr_client::sync::{
    CollectionKeys, Published, Restored, SettingValue, SharedCollectionService,
    StoredCollectionKeys, SyncBody, SyncClient, SyncError, SyncObject, SyncSettings, SyncStore,
    fresh_object_id, fresh_revision,
};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::StoreSelection;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{DeviceId, SessionId, SyncCollectionId, SyncObjectId};
use kr_protocol::scalars::{AuthorisationKey, TimestampMs};
use kr_protocol::sync::SyncObjectKind;
use kr_sync_integration::{Deployment, fresh_uuid, now_ms, proved};

const SCOPE: &str = "kalareach-backup-sync-leg";

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

/* -------------------------------------------------------------------------- */
/* The hosts, and the devices                                                  */
/* -------------------------------------------------------------------------- */

/// What this person's hosts say of their devices: who each paired and lets manage it.
#[derive(Debug, Default)]
struct Hosts {
    devices: Mutex<Vec<HostDevice>>,
}

impl Hosts {
    /// The host pairs a device and lets it manage the host.
    fn commit(&self, device: Device) {
        let mut devices = self.devices.lock().expect("the hosts");
        devices.retain(|known| known.authorisation != device.authorisation);
        devices.push(HostDevice {
            authorisation: device.authorisation,
            stored_envelope: device.stored_envelope,
            manages_host: true,
            revoked: false,
        });
    }
}

#[derive(Debug)]
struct HostsView(Arc<Hosts>);

impl DeviceDirectory for HostsView {
    fn answers(&self) -> ServiceFuture<'_, Option<HostAnswers>> {
        let answers = HostAnswers {
            reports: vec![HostReport {
                devices: self.0.devices.lock().expect("the hosts").clone(),
            }],
            ..HostAnswers::default()
        };
        Box::pin(std::future::ready(Ok(Some(answers))))
    }
}

/// One installation: its keys, its stores, and the service it reaches by its own signature.
struct Node {
    keys: DeviceKeys,
    root: tempfile::TempDir,
    service: Arc<ManagedSyncService>,
    transport: Arc<Watched>,
    membership: SyncMembership,
    device_id: DeviceId,
}

impl Node {
    fn new(deployment: &Deployment, hosts: &Arc<Hosts>) -> Self {
        let keys = DeviceKeys::generate().expect("device keys");
        let root = tempfile::tempdir().expect("a directory on the internal disk");
        let transport = Watched::new(deployment.transport(), None);
        let service = Arc::new(ManagedSyncService::new(
            deployment.origin().clone(),
            Arc::clone(&transport) as Arc<dyn ServiceHttp>,
            Arc::new(DeviceSigner::new(keys.clone())) as Arc<dyn ServiceSigner>,
        ));
        let membership = SyncMembership::open(
            root.path().join("membership"),
            &keys,
            Self::secrets(&root),
            Arc::clone(&service) as Arc<dyn KeyRecordService>,
            Arc::new(HostsView(Arc::clone(hosts))),
        )
        .expect("a membership store");
        hosts.commit(Device::from_keys(&keys));
        Self {
            keys,
            root,
            service,
            transport,
            membership,
            device_id: DeviceId::new(fresh_uuid()),
        }
    }

    fn secrets(root: &tempfile::TempDir) -> StoredCollectionKeys {
        StoredCollectionKeys::open(
            StoreSelection::File,
            SCOPE,
            &root.path().join("secrets"),
            SCOPE,
        )
        .expect("the file seam")
    }

    fn auth(&self) -> AuthorisationKey {
        *self.keys.authorisation.public()
    }

    async fn reconcile(&mut self) {
        self.membership.refresh().await.expect("a refresh");
        self.membership.reconcile(now()).await.expect("reconciled");
    }

    /// The epoch of the record this device has installed, if it has one.
    fn epoch(&self) -> Option<u64> {
        self.membership
            .members()
            .expect("a readable membership")
            .and_then(|status| status.installed)
            .map(|(epoch, _)| epoch)
    }

    fn out(&self) -> bool {
        self.membership
            .members()
            .expect("a readable membership")
            .is_some_and(|status| status.out)
    }

    /// A settings client over `collection`, written under `epoch` and believing what the epochs
    /// from `floor` on sealed, over a store of its own named `store`.
    fn settings(
        &self,
        collection: CollectionRef,
        epoch: u64,
        floor: u64,
        store: &str,
    ) -> (SyncClient, Arc<SharedCollectionService>) {
        let shared = Arc::new(
            SharedCollectionService::new(Arc::clone(&self.service), collection, epoch)
                .believing_from(floor),
        );
        let sealer = shared.sealer(Arc::new(Self::secrets(&self.root)) as Arc<dyn CollectionKeys>);
        let client = SyncClient::new(
            Arc::clone(&shared) as Arc<dyn SyncBackupService>,
            Arc::new(sealer),
            SyncStore::open(self.root.path().join(store)).expect("a store"),
        );
        (client, shared)
    }
}

/// The owner shares the collection with another device, confirmed on both sides.
async fn share(owner: &mut Node, recipient: &mut Node) {
    let collection = owner
        .membership
        .members()
        .expect("a membership")
        .expect("a collection")
        .collection;
    owner.membership.refresh().await.expect("a refresh");
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
}

/// The owner starts a collection and shares it with each of `others`; every device is then brought
/// up to the epoch the last addition made, and the collection is returned.
async fn collection_of(owner: &mut Node, others: &mut [&mut Node]) -> CollectionRef {
    let started = owner
        .membership
        .start(SyncCollectionId::new(fresh_uuid()), now())
        .await
        .expect("a collection is started");
    owner.reconcile().await;
    assert_eq!(owner.epoch(), Some(0), "the first record is installed");
    for other in others.iter_mut() {
        share(owner, other).await;
    }
    owner.reconcile().await;
    for other in others.iter_mut() {
        other.reconcile().await;
        assert_eq!(
            other.epoch(),
            owner.epoch(),
            "every device is at the epoch of the last addition"
        );
    }
    started
}

fn settings_object(
    object_id: SyncObjectId,
    device_id: DeviceId,
    colour: &str,
    at: u64,
) -> SyncObject {
    SyncObject {
        object_id,
        revision: fresh_revision().expect("a revision"),
        device_id,
        updated_at_ms: TimestampMs::new(at),
        body: SyncBody::Settings(SyncSettings {
            values: BTreeMap::from([(
                "colour_mode".to_owned(),
                SettingValue::Text(colour.to_owned()),
            )]),
            pinned_labels: std::collections::BTreeSet::new(),
        }),
        went_over: Vec::new(),
    }
}

fn colour(object: &SyncObject) -> String {
    match &object.body {
        SyncBody::Settings(settings) => match settings.values.get("colour_mode") {
            Some(SettingValue::Text(text)) => text.clone(),
            other => panic!("no colour mode: {other:?}"),
        },
        other => panic!("not settings: {other:?}"),
    }
}

/// Stores a new revision of a settings object and publishes it.
async fn write(
    client: &SyncClient,
    object_id: SyncObjectId,
    device_id: DeviceId,
    colour: &str,
    at: u64,
) -> Result<Published, SyncError> {
    client
        .store()
        .put_object(&settings_object(object_id, device_id, colour, at))
        .expect("the object is kept");
    client.publish(object_id, now()).await
}

fn accepted(published: Published) -> kr_client::services::SyncPosition {
    match published {
        Published::Accepted { position } => position,
        other => panic!("the service accepted the write: {other:?}"),
    }
}

fn refused_with(error: SyncError, code: ErrorCode) -> String {
    match error {
        SyncError::Client(error) => {
            assert_eq!(error.code(), code, "{error}");
            error.to_string()
        }
        other => panic!("a refusal with the code {code:?}, not {other:?}"),
    }
}

/// What the service holds of a settings object, read as `reader` does.
async fn fetch_settings(
    client: &SyncClient,
    object_id: SyncObjectId,
) -> Result<SyncObject, SyncError> {
    match client
        .fetch(SyncObjectKind::Settings, object_id, now())
        .await?
    {
        Restored::Settings { object, .. } => Ok(object),
        other => panic!("settings: {other:?}"),
    }
}

/// How many refused writes the service holds for the person to choose about in `collection`.
async fn copies_waiting(member: &Node, collection: &CollectionRef) -> usize {
    member
        .service
        .compare_shared(collection, &[], true, None)
        .await
        .expect("a comparison")
        .expect("a member")
        .copies
        .len()
}

/* -------------------------------------------------------------------------- */
/* A device taken out                                                          */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.11 and 18.05, across three installations: the owner takes a device out while another is
/// away.
///
/// * The device taken out is answered as for no collection, wherever it asks, and what it had sent
///   before it was taken out is answered from its receipt, exactly as it was, and is not written a
///   second time.
/// * The device that was away writes under the epoch it last knew and meets the retired epoch: the
///   service stores nothing, the client leaves the work outstanding and asks, and is told it never
///   ran. The device then reads the chain, installs the new record it was given a wrap in, and
///   writes again under the new epoch, which is accepted.
/// * What a member sealed before the epoch the collection is at now is refused by name by a reader
///   that believes only the new one, until a member that holds the plaintext seals it again.
///
/// Every answer the service gave is held to naming the history it was in.
#[tokio::test]
async fn a_device_taken_out_while_another_is_away_is_answered_as_missing_and_the_other_seals_again_under_the_new_epoch()
 {
    let Some(deployment) = Deployment::from_environment() else {
        return;
    };
    let hosts = Arc::new(Hosts::default());
    let mut owner = Node::new(&deployment, &hosts);
    let mut leaving = Node::new(&deployment, &hosts);
    let mut away = Node::new(&deployment, &hosts);
    let collection = collection_of(&mut owner, &mut [&mut leaving, &mut away]).await;
    let before = owner.epoch().expect("an installed epoch");

    // All three write a setting of their own, and the owner's is read by the others.
    let owners_object = fresh_object_id().expect("an object");
    let (owner_client, _) = owner.settings(collection, before, before, "owner");
    let (leaving_client, _) = leaving.settings(collection, before, before, "leaving");
    let (away_client, _) = away.settings(collection, before, before, "away");
    accepted(
        write(&owner_client, owners_object, owner.device_id, "dark", 1_000)
            .await
            .expect("the owner writes"),
    );
    accepted(
        write(
            &leaving_client,
            fresh_object_id().expect("an object"),
            leaving.device_id,
            "light",
            1_000,
        )
        .await
        .expect("the device to be taken out writes"),
    );
    accepted(
        write(
            &away_client,
            fresh_object_id().expect("an object"),
            away.device_id,
            "dark",
            1_000,
        )
        .await
        .expect("the device that will be away writes"),
    );
    assert_eq!(
        colour(
            &fetch_settings(&leaving_client, owners_object)
                .await
                .expect("a member reads another member's setting")
        ),
        "dark"
    );

    // The device that is about to be taken out sends one more write whose answer is lost: the
    // service has it, and the device does not know.
    let lost_object = fresh_object_id().expect("an object");
    leaving.transport.lose_the_next_answer();
    let lost = write(
        &leaving_client,
        lost_object,
        leaving.device_id,
        "light",
        2_000,
    )
    .await
    .expect_err("the answer never came back");
    assert!(matches!(lost, SyncError::Client(_)), "{lost:?}");
    assert_eq!(leaving_client.outstanding().expect("a count"), 1);

    // The owner takes the device out while the other is away. The collection moves to a new epoch.
    owner.membership.remove(&leaving.auth()).expect("a removal");
    owner.reconcile().await;
    let after = owner.epoch().expect("an installed epoch");
    assert!(
        after > before,
        "a removal moves the collection to a new epoch"
    );

    // The device taken out is answered as for no collection, whichever way it asks.
    let said = refused_with(
        fetch_settings(&leaving_client, owners_object)
            .await
            .expect_err("a device that was taken out reads nothing"),
        ErrorCode::UnknownSession,
    );
    assert!(!said.is_empty());
    refused_with(
        write(
            &leaving_client,
            fresh_object_id().expect("an object"),
            leaving.device_id,
            "light",
            3_000,
        )
        .await
        .expect_err("a device that was taken out writes nothing"),
        ErrorCode::UnknownSession,
    );
    // What it sent before it learnt it was out is answered from its receipt, once: the owner reads
    // the object it wrote, at the place the lost write took, and asking again moves nothing.
    let (reader, shared) = owner.settings(collection, after, 0, "owner-reads");
    let place = |shared: &Arc<SharedCollectionService>| {
        let shared = Arc::clone(shared);
        async move {
            match shared
                .fetch(&kr_client::sync::sync_collection(
                    SyncObjectKind::Settings,
                    lost_object,
                ))
                .await
                .expect("a read")
            {
                SyncFetched::Held { position, .. } => position,
                SyncFetched::Absent { .. } => panic!("the lost write is held"),
            }
        }
    };
    let landed = place(&shared).await;
    // Two of its writes are outstanding: the one whose answer was lost, and the one the service
    // answered as for no collection, which the client keeps as work it cannot account for.
    assert_eq!(leaving_client.outstanding().expect("a count"), 2);
    let reconciled = leaving_client
        .reconcile_unsettled(now())
        .await
        .expect("the service is asked about both");
    assert_eq!(
        reconciled.settled, 1,
        "the receipt of the write that landed answers for it: {reconciled:?}"
    );
    assert_eq!(
        reconciled.unresolved, 1,
        "the write answered as for no collection has no receipt to ask for: {reconciled:?}"
    );
    assert_eq!(leaving_client.outstanding().expect("a count"), 1);
    assert_eq!(
        place(&shared).await,
        landed,
        "asking about the write that landed gave no second write"
    );
    assert_eq!(
        colour(
            &fetch_settings(&reader, lost_object)
                .await
                .expect("the owner reads the write the lost answer belonged to")
        ),
        "light"
    );

    // Once the device has read the chain it knows it is out, and holds no key to write with.
    leaving.reconcile().await;
    assert!(leaving.out(), "the device knows it was taken out");
    let said = refused_with(
        write(
            &leaving_client,
            fresh_object_id().expect("an object"),
            leaving.device_id,
            "light",
            3_500,
        )
        .await
        .expect_err("a device that knows it is out can seal nothing"),
        ErrorCode::HostNotConfigured,
    );
    assert!(said.contains("does not hold the key"), "{said}");

    // The device that was away writes under the epoch it last knew, which is retired now.
    let away_object = fresh_object_id().expect("an object");
    let error = write(&away_client, away_object, away.device_id, "dark", 4_000)
        .await
        .expect_err("the epoch the device knew is retired");
    refused_with(error, ErrorCode::ResyncRequired);
    assert_eq!(away_client.outstanding().expect("a count"), 1);
    assert!(matches!(
        shared
            .fetch(&kr_client::sync::sync_collection(
                SyncObjectKind::Settings,
                away_object
            ))
            .await
            .expect("a read"),
        SyncFetched::Absent { .. }
    ));
    let settled = away_client
        .reconcile_unsettled(now())
        .await
        .expect("the service accounts for the write");
    assert_eq!(
        away_client.outstanding().expect("a count"),
        0,
        "the write was settled as one that never ran: {settled:?}"
    );

    // The device reads the chain, installs the record it has a wrap in, and writes under the new
    // epoch.
    assert_eq!(
        away.membership.refresh().await.expect("a refresh"),
        Refreshed::Recorded
    );
    away.membership.reconcile(now()).await.expect("reconciled");
    assert_eq!(
        away.epoch(),
        Some(after),
        "the device installed the new record"
    );
    let (current, _) = away.settings(collection, after, 0, "away-current");
    let landed = accepted(
        write(&current, away_object, away.device_id, "dark", 5_000)
            .await
            .expect("a write under the new epoch"),
    );
    assert_eq!(landed.write_sequence, 1, "the first write of this object");

    // What the owner sealed before the new epoch is refused by name to a reader that believes only
    // the new one, until a member that holds the plaintext seals it again.
    let (strict, _) = away.settings(collection, after, after, "away-strict");
    let said = refused_with(
        fetch_settings(&strict, owners_object)
            .await
            .expect_err("sealed before the floor"),
        ErrorCode::HostNotConfigured,
    );
    assert!(
        said.contains(&format!("epoch {before}")) && said.contains(&format!("epoch {after}")),
        "the refusal names the two epochs: {said}"
    );
    let held = fetch_settings(&reader, owners_object)
        .await
        .expect("a member that believes from the first epoch reads it");
    reader
        .store()
        .put_object(&SyncObject {
            revision: fresh_revision().expect("a revision"),
            ..held
        })
        .expect("the object is sealed again");
    accepted(
        reader
            .publish(owners_object, now())
            .await
            .expect("sealed again under the new epoch"),
    );
    assert_eq!(
        colour(
            &fetch_settings(&strict, owners_object)
                .await
                .expect("sealed under the new epoch, it is believed")
        ),
        "dark"
    );

    for node in [&owner, &leaving, &away] {
        node.transport.assert_every_answer_named_its_history();
    }
    proved(
        "revocation",
        &deployment,
        "a device taken out is answered as missing, its earlier write is answered once from its receipt, a device that was away meets the retired epoch and writes again under the new one",
    );
}

/* -------------------------------------------------------------------------- */
/* Two devices                                                                 */
/* -------------------------------------------------------------------------- */

/// KR-REQ-20.13 and 18.05, across two installations: both change one setting from the revision they
/// both hold.
///
/// The service takes whichever write arrives first and refuses the second by comparison, whatever
/// either device's clock says, and the refused device keeps what won beside its own setting for the
/// person to choose, with its own untouched. The leg runs twice, once with the later clock arriving
/// first and once with the earlier. A draft one device publishes is read by the other as a draft
/// beside whatever that device holds: a stored draft the person has still to send, not a request to
/// run anything.
#[tokio::test]
async fn two_devices_that_change_a_setting_from_one_revision_keep_both_and_neither_is_chosen_by_a_clock()
 {
    let Some(deployment) = Deployment::from_environment() else {
        return;
    };
    let hosts = Arc::new(Hosts::default());
    let mut one = Node::new(&deployment, &hosts);
    let mut two = Node::new(&deployment, &hosts);
    let collection = collection_of(&mut one, &mut [&mut two]).await;
    let epoch = one.epoch().expect("an installed epoch");
    let (client_one, _) = one.settings(collection, epoch, epoch, "settings");
    let (client_two, _) = two.settings(collection, epoch, epoch, "settings");

    // Round one: the first device arrives first, and its clock is the later. Round two: the second
    // device arrives first, and its clock is the earlier.
    for (first_is_one, first_clock, second_clock) in
        [(true, 900_000, 100_000), (false, 100_000, 900_000)]
    {
        let (first, second, first_client, second_client) = if first_is_one {
            (&one, &two, &client_one, &client_two)
        } else {
            (&two, &one, &client_two, &client_one)
        };
        // One setting both hold at the same revision.
        let object_id = fresh_object_id().expect("an object");
        accepted(
            write(&client_one, object_id, one.device_id, "dark", 1_000)
                .await
                .expect("the first device writes"),
        );
        let base = fetch_settings(&client_two, object_id)
            .await
            .expect("the second device reads it");
        assert_eq!(colour(&base), "dark");

        // Each changes it from there.
        let winner = accepted(
            write(
                first_client,
                object_id,
                first.device_id,
                "from the first",
                first_clock,
            )
            .await
            .expect("the first to arrive is accepted"),
        );
        let Published::Conflicted {
            copy,
            position,
            other_revision,
        } = write(
            second_client,
            object_id,
            second.device_id,
            "from the second",
            second_clock,
        )
        .await
        .expect("an answer")
        else {
            panic!("the second to arrive is refused by the comparison, whatever its clock says");
        };
        assert_eq!(position, winner, "the service holds the first to arrive");
        let kept = second_client
            .store()
            .conflicts(object_id)
            .expect("the copies")
            .items;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].conflict_id, copy);
        assert_eq!(kept[0].other.revision, other_revision);
        assert_eq!(
            colour(&kept[0].other),
            "from the first",
            "what won is kept beside the refused device's own"
        );
        assert_eq!(
            colour(
                &second_client
                    .store()
                    .object(object_id)
                    .expect("a read")
                    .expect("held")
            ),
            "from the second",
            "the refused device's own setting is as it was"
        );

        // The service keeps the refused write too, until the person chooses.
        let waiting = copies_waiting(&one, &collection).await;
        assert_eq!(waiting, 1, "the refused write waits at the service");
        second_client
            .resolve(copy)
            .await
            .expect("a choice")
            .expect("a copy this device held");
        assert_eq!(
            copies_waiting(&one, &collection).await,
            0,
            "the choice drops the copy"
        );

        // The control: a device that has read what stands writes over it, whatever its clock says,
        // so the refusal was the comparison's and not the order of two clocks.
        fetch_settings(second_client, object_id)
            .await
            .expect("the refused device reads what stands");
        accepted(
            write(
                second_client,
                object_id,
                second.device_id,
                "after reading",
                1,
            )
            .await
            .expect("a device that has read what stands is accepted"),
        );
    }

    // A draft one device publishes is read by the other as a draft, beside nothing of its own, and
    // is not sent anywhere.
    let drafts_one =
        DraftStore::open(one.root.path().join("drafts"), one.device_id).expect("drafts");
    let drafts_two =
        DraftStore::open(two.root.path().join("drafts"), two.device_id).expect("drafts");
    let sealing = |node: &Node| -> Arc<dyn DraftSealer> {
        let shared = SharedCollectionService::new(Arc::clone(&node.service), collection, epoch);
        Arc::new(shared.sealer(Arc::new(Node::secrets(&node.root)) as Arc<dyn CollectionKeys>))
            as Arc<dyn DraftSealer>
    };
    let sync_one = DraftSync::new(
        Arc::new(SharedCollectionService::new(
            Arc::clone(&one.service),
            collection,
            epoch,
        )),
        sealing(&one),
        SyncStore::open(one.root.path().join("drafts-sync")).expect("a store"),
    );
    let sync_two = DraftSync::new(
        Arc::new(SharedCollectionService::new(
            Arc::clone(&two.service),
            collection,
            epoch,
        )),
        sealing(&two),
        SyncStore::open(two.root.path().join("drafts-sync")).expect("a store"),
    );
    let target = DraftTarget::session(SessionId::new(fresh_uuid()));
    let draft = drafts_one
        .create(target.clone(), "run the migration".to_owned(), now())
        .expect("a draft");
    assert!(matches!(
        sync_one
            .publish(&drafts_one, draft.draft_id, draft.revision, now())
            .await
            .expect("an answer"),
        DraftPublished::Accepted { .. }
    ));
    let fetched = sync_two
        .fetch_beside(&drafts_two, draft.draft_id, now())
        .await
        .expect("the other device reads it");
    assert_eq!(fetched.remote.text, "run the migration");
    let held: Vec<_> = drafts_two.list().expect("a listing").drafts;
    assert_eq!(held.len(), 1, "one draft on the second device: the copy");
    assert_eq!(held[0].text, "run the migration");
    assert_eq!(
        held[0].device_id, two.device_id,
        "it is the second device's own"
    );
    assert_eq!(held[0].target, target);
    assert!(
        held[0].conflict_of.0.as_ref() == Some(&draft.draft_id),
        "it says which draft it came from"
    );
    assert_eq!(
        drafts_one.list().expect("a listing").drafts.len(),
        1,
        "the first device's draft is as it was"
    );

    for node in [&one, &two] {
        node.transport.assert_every_answer_named_its_history();
    }
    proved(
        "multi-device",
        &deployment,
        "the first write to arrive wins in both clock orders, the refused device keeps what won beside its own, and a draft reads on the other device as a draft",
    );
}
