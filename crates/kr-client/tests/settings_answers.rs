//! What the settings-sync route answers a device about the collections it keeps, what this crate's
//! client makes of it, and what the stand-in the daemon's and the companion's tests talk to
//! answers, held to one recording.
//!
//! A device writes its own collection with a compare-and-swap against a revision, has the copies
//! of the writes that lost kept for it to choose between, settles a write whose answer was lost by
//! asking about it or fencing it, and shares a collection by claiming it with a key record: from
//! then on a write names the epoch it is sealed under, only the members of the newest record are
//! answered, and a write under an epoch the collection has moved past is retired.
//! `fixtures/service/settings-answers.json` keeps, for each request of one script, the status and
//! the shape of the body a Worker on this machine answered and what the client decoded it to.
//!
//! [`the_stand_in_answers_as_the_worker_did`] runs the script against the stand-in and holds each
//! status, shape and decoded value to the record.
//!
//! The recording is made again when the route's contract changes:
//!
//! ```text
//! node infra/scripts/testing/local-restore.mjs start --state <dir> --name first --port <port>
//! KR_DEPLOYED_ORIGIN=http://127.0.0.1:<port> \
//!   KR_RECORD_SETTINGS_ANSWERS=fixtures/service/settings-answers.json \
//!   KR_WEB_COMMIT=<the web commit> \
//!   cargo test -p kr-client --test settings_answers record -- --ignored
//! ```
//!
//! Settings need no account: an installation's signature is the whole of the proof. What a local
//! Worker cannot be made to do is not in the script: a principal whose settings-sync allowance is
//! spent, and a restore of the deployment. The stand-in's answers for them are read from the
//! Worker's source, and the table in the stand-in crate's documentation names the lines.

use std::sync::Arc;

use kr_client::drafts::draft_collection;
use kr_client::services::sync::KnownRevision;
use kr_client::services::{
    HttpDeadlines, HttpService, Keyed, ManagedSyncService, ServiceHttp, SyncBackupService,
    SyncComparison, SyncExchanged, SyncPosition, SyncRequestFence, SyncRequestStatus, SyncRevision,
    managed_response_limits,
};
use kr_client::sync::membership::{
    CollectionRef, DeviceDirectory, HostAnswers, KeyRecordService, KeyRecords, SyncMembership,
};
use kr_client::sync::{StoredCollectionKeys, sync_collection};
use kr_crypto::envelope::{
    CollectionRecipient, CollectionRecordDraft, issue_collection_key_record,
};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_crypto::store::StoreSelection;
use kr_protocol::collection_keys::CollectionKeyRecord;
use kr_protocol::ids::{
    DraftId, SyncCollectionId, SyncKeyEpoch, SyncKeyRecordRevision, SyncObjectId,
};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_protocol::sync::{
    MAX_SYNC_CONFLICT_COPIES, MAX_SYNC_OBJECT_PLAINTEXT_BYTES, SyncObjectKind,
};
use kr_service_stand_in::ServiceWeb;

mod recording;

use recording::{
    Journal, Recording, debug, decoded, differences, exchange_differences, held_outcomes, recorded,
};

const FIXTURE: &str = include_str!("../../../fixtures/service/settings-answers.json");

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis(),
    )
    .expect("a time in range")
}

fn identity() -> Uuid {
    kr_transport::random::fresh_uuid_v4().expect("an identity")
}

/// A real sealed object, under a key the service never sees, as the bytes a sealer hands over.
fn sealed(plaintext: &[u8]) -> Vec<u8> {
    let object = kr_crypto::envelope::seal_sync_object(&Secret::from_bytes([0x5a; 32]), plaintext)
        .expect("a sealed object");
    kr_cbor::to_canonical_vec(&object).expect("canonical bytes")
}

/// One device: its keys and the client it reaches the service with.
struct Device {
    keys: DeviceKeys,
    service: Arc<ManagedSyncService>,
}

impl Device {
    fn on(http: &Arc<dyn ServiceHttp>, origin: &GatewayOrigin) -> Self {
        let keys = DeviceKeys::generate().expect("a device's keys");
        let signer = Arc::new(recording::Keyed {
            key: keys.authorisation.clone(),
            signer: ServiceRequestSigner::Installation,
        });
        let service = ManagedSyncService::new(origin.clone(), Arc::clone(http), signer as _);
        Self {
            keys,
            service: Arc::new(service),
        }
    }

    fn recipient(&self) -> CollectionRecipient {
        CollectionRecipient {
            authorisation: *self.keys.authorisation.public(),
            stored_envelope: *self.keys.stored_envelope.public(),
        }
    }
}

/// A device with no host to ask: enough for a collection of one.
#[derive(Debug)]
struct NoHosts;

impl DeviceDirectory for NoHosts {
    fn answers(&self) -> kr_client::services::ServiceFuture<'_, Option<HostAnswers>> {
        Box::pin(std::future::ready(Ok(None)))
    }
}

/* -------------------------------------------------------------------------- */
/* What a decoded answer is, in the words of the values the caller acts on     */
/* -------------------------------------------------------------------------- */

fn at(position: &SyncPosition) -> String {
    format!(
        "write {}{}",
        position.write_sequence,
        if position.revision.0.is_some() {
            ""
        } else {
            ", a removal"
        }
    )
}

fn shown(exchanged: &SyncExchanged) -> String {
    match exchanged {
        SyncExchanged::Applied { position } => format!("applied at {}", at(position)),
        SyncExchanged::Refused {
            retained, current, ..
        } => format!(
            "refused the comparison, copy kept {}, object {}",
            retained.is_some(),
            current.as_ref().map_or("never written".to_owned(), at)
        ),
        SyncExchanged::SignedBeforeCutoff => "signed before the cutoff".to_owned(),
    }
}

fn shown_keyed<T>(keyed: &Keyed<T>, show: impl FnOnce(&T) -> String) -> String {
    match keyed {
        Keyed::Answered { answer, head } => format!(
            "{}, collection {}",
            show(answer),
            head.map_or("unclaimed".to_owned(), |head| format!(
                "at epoch {} and record {}",
                head.epoch, head.revision
            ))
        ),
        Keyed::Retired { head } => format!(
            "retired, the collection is at epoch {} and record {}",
            head.epoch, head.revision
        ),
        Keyed::Absent => "the collection is absent".to_owned(),
    }
}

fn shown_status(status: &SyncRequestStatus) -> String {
    match status {
        SyncRequestStatus::Applied { position } => format!("applied at {}", at(position)),
        SyncRequestStatus::Refused { retained, .. } => {
            format!("refused, copy kept {}", retained.is_some())
        }
        SyncRequestStatus::Unknown { .. } => "unknown".to_owned(),
        SyncRequestStatus::Fenced { never_ran, .. } => format!("fenced, never ran {never_ran}"),
    }
}

fn shown_fence(fence: &SyncRequestFence) -> String {
    match fence {
        SyncRequestFence::Applied { position } => format!("applied at {}", at(position)),
        SyncRequestFence::Refused { retained, .. } => {
            format!("refused, copy kept {}", retained.is_some())
        }
        SyncRequestFence::Fenced { never_ran, .. } => format!("fenced, never ran {never_ran}"),
    }
}

fn shown_comparison(found: &SyncComparison) -> String {
    format!(
        "{} objects at {:?}, {} copies (more {}), stored {} objects, {} copies, {} bytes, \
         collection {}",
        found.objects.len(),
        found
            .objects
            .iter()
            .map(|object| object.position.write_sequence)
            .collect::<Vec<_>>(),
        found.copies.len(),
        found.more_copies,
        found.stored.objects.get(),
        found.stored.conflicts.get(),
        found.stored.bytes.get(),
        found.head.map_or("unclaimed".to_owned(), |head| format!(
            "at epoch {} and record {}",
            head.epoch, head.revision
        ))
    )
}

/* -------------------------------------------------------------------------- */
/* The script                                                                  */
/* -------------------------------------------------------------------------- */

/// How the script's first device comes to hold no settings-sync allowance.
///
/// A local Worker counts bytes against its free tier, so the allowance is spent by writing: through
/// a transport that keeps no record, because the writes are the arrangement and not what the
/// recording is of. The stand-in counts nothing and is told it is spent.
enum Spent<'a> {
    /// Write until the Worker refuses, over this transport.
    Written(&'a Arc<dyn ServiceHttp>),
    /// Tell the stand-in.
    Told(&'a ServiceWeb),
}

impl Spent<'_> {
    /// Leaves `device` with no room for an object the size of `smallest` and no room for anything
    /// larger.
    async fn spend(&self, device: &Device, origin: &GatewayOrigin, smallest: &[u8]) {
        let transport = match self {
            Self::Told(web) => {
                web.refuse_settings_writes(true);
                return;
            }
            Self::Written(transport) => transport,
        };
        let service = ManagedSyncService::new(
            origin.clone(),
            Arc::clone(transport),
            Arc::new(recording::Keyed {
                key: device.keys.authorisation.clone(),
                signer: ServiceRequestSigner::Installation,
            }) as _,
        );
        // The largest object first, then the smallest, so that nothing is left over to write.
        let largest = sealed(&vec![
            0x61;
            usize::try_from(MAX_SYNC_OBJECT_PLAINTEXT_BYTES - 1024)
                .expect("a size")
        ]);
        for object in [largest.as_slice(), smallest] {
            let mut written = 0_u32;
            loop {
                let collection =
                    sync_collection(SyncObjectKind::Settings, SyncObjectId::new(identity()));
                let answer = service
                    .compare_exchange(&collection, identity(), now_ms(), None, object)
                    .await;
                if !matches!(answer, Ok(SyncExchanged::Applied { .. })) {
                    break;
                }
                written += 1;
                assert!(
                    written < 4096,
                    "the Worker's allowance did not run out in {written} writes"
                );
            }
        }
    }
}

/// Runs the script against one service through `http`.
#[allow(clippy::too_many_lines)]
async fn run_the_script(
    http: &Arc<dyn ServiceHttp>,
    origin: &GatewayOrigin,
    journal: &Journal,
    spent: Spent<'_>,
) {
    let a = Device::on(http, origin);
    let b = Device::on(http, origin);

    // A device's own collection: one object, and the namespace of the device that signs.
    let object = identity();
    let collection = sync_collection(SyncObjectKind::Settings, SyncObjectId::new(object));
    let (mine, theirs, replacement) = (sealed(b"dark"), sealed(b"light"), sealed(b"system"));
    let (written, lost) = (identity(), identity());

    journal.step("write a new object against no revision");
    let first = a
        .service
        .compare_exchange(&collection, written, now_ms(), None, &mine)
        .await;
    let position = match &first {
        Ok(SyncExchanged::Applied { position }) => Some(*position),
        _ => None,
    };
    journal.decoded(decoded(&first, shown));

    journal.step("write the same request again");
    let answer = a
        .service
        .compare_exchange(&collection, written, now_ms(), None, &mine)
        .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("write other content under the same request identity");
    let answer = a
        .service
        .compare_exchange(&collection, written, now_ms(), None, &theirs)
        .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("write against no revision while the object is held");
    let stale = identity();
    let answer = a
        .service
        .compare_exchange(&collection, stale, now_ms(), None, &theirs)
        .await;
    let copy = match &answer {
        Ok(SyncExchanged::Refused { retained, .. }) => *retained,
        _ => None,
    };
    journal.decoded(decoded(&answer, shown));

    journal.step("read the collection with its copies");
    let answer = a.service.compare(&collection, true, None).await;
    journal.decoded(decoded(&answer, shown_comparison));

    journal.step("ask what became of the first write");
    let answer = a.service.request_status(&collection, written).await;
    journal.decoded(decoded(&answer, shown_status));

    journal.step("ask what became of the write that lost");
    let answer = a.service.request_status(&collection, stale).await;
    journal.decoded(decoded(&answer, shown_status));

    journal.step("ask about a request nothing was recorded for");
    let answer = a.service.request_status(&collection, lost).await;
    journal.decoded(decoded(&answer, shown_status));

    journal.step("fence a request nothing was recorded for");
    let signed = now_ms();
    let answer = a
        .service
        .fence_request(&collection, lost, signed, signed)
        .await;
    journal.decoded(decoded(&answer, shown_fence));

    journal.step("write under the fenced identity");
    let answer = a
        .service
        .compare_exchange(&collection, lost, now_ms(), position, &replacement)
        .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("fence a write the service applied");
    let answer = a
        .service
        .fence_request(&collection, written, signed, signed)
        .await;
    journal.decoded(decoded(&answer, shown_fence));

    journal.step("fence a request naming a time the service cannot keep a refusal for");
    let answer = a
        .service
        .fence_request(
            &collection,
            identity(),
            now_ms() + 40 * 86_400_000,
            now_ms() + 40 * 86_400_000,
        )
        .await;
    journal.decoded(decoded(&answer, shown_fence));

    journal.step("choose against the copy");
    if let Some(copy) = copy {
        let answer = a.service.resolve(&collection, copy).await;
        journal.decoded(decoded(&answer, debug));
        journal.step("choose against a copy nobody kept");
        let answer = a.service.resolve(&collection, copy).await;
        journal.decoded(decoded(&answer, debug));
    }

    journal.step("read the collection without its copies");
    let answer = a.service.compare(&collection, false, None).await;
    journal.decoded(decoded(&answer, shown_comparison));

    journal.step("replace the object against its revision");
    let answer = a
        .service
        .compare_exchange(&collection, identity(), now_ms(), position, &replacement)
        .await;
    journal.decoded(decoded(&answer, shown));

    journal.step("read naming an object the collection never held as held");
    let own = CollectionRef {
        home: kr_protocol::service::installation_id(a.keys.authorisation.public()),
        collection_id: SyncCollectionId::new(object),
    };
    let never = KnownRevision {
        object_id: SyncObjectId::new(identity()),
        revision: SyncRevision::new(identity()),
    };
    let answer = a.service.compare_shared(&own, &[never], false, None).await;
    journal.decoded(decoded(&answer, |found| {
        found
            .as_ref()
            .map_or("the collection is absent".to_owned(), |found| {
                format!(
                    "{}, {} removed, at {:?}",
                    shown_comparison(found),
                    found.removed.len(),
                    found
                        .removed
                        .iter()
                        .map(|removed| removed.position.map(|position| position.write_sequence))
                        .collect::<Vec<_>>()
                )
            })
    }));

    journal.step("read another device's collection");
    let others = CollectionRef {
        home: kr_protocol::service::installation_id(a.keys.authorisation.public()),
        collection_id: SyncCollectionId::new(object),
    };
    let answer = b.service.compare_shared(&others, &[], true, None).await;
    journal.decoded(decoded(&answer, |found| {
        found
            .as_ref()
            .map_or("the collection is absent".to_owned(), shown_comparison)
    }));

    // The copies an object keeps are bounded, and the write past them is refused.
    let crowded = sync_collection(SyncObjectKind::Settings, SyncObjectId::new(identity()));
    journal.step("write a new object to be crowded");
    let base = a
        .service
        .compare_exchange(&crowded, identity(), now_ms(), None, &sealed(b"base"))
        .await;
    journal.decoded(decoded(&base, shown));
    for turn in 0..=MAX_SYNC_CONFLICT_COPIES {
        journal.step(&format!("write against no revision, turn {turn}"));
        let answer = a
            .service
            .compare_exchange(
                &crowded,
                identity(),
                now_ms(),
                None,
                &sealed(format!("copy {turn}").as_bytes()),
            )
            .await;
        journal.decoded(decoded(&answer, shown));
    }
    journal.step("read the crowded collection with its copies");
    let answer = a.service.compare(&crowded, true, None).await;
    journal.decoded(decoded(&answer, shown_comparison));

    // A collection two devices share: claimed by its home's first record.
    let directory = tempfile::tempdir().expect("a directory");
    let secrets = StoredCollectionKeys::open(
        StoreSelection::File,
        "kalareach-settings-answers-test",
        &directory.path().join("secrets"),
        "test",
    )
    .expect("the file seam");
    let mut membership = SyncMembership::open(
        directory.path().join("membership"),
        &a.keys,
        secrets,
        Arc::clone(&a.service) as Arc<dyn KeyRecordService>,
        Arc::new(NoHosts),
    )
    .expect("a membership store");
    let shared_id = SyncCollectionId::new(identity());
    let now = || TimestampMs::new(now_ms());

    journal.step("read the records of a collection nothing has claimed");
    let unclaimed = CollectionRef {
        home: others.home,
        collection_id: shared_id,
    };
    let answer = a.service.records_after(&unclaimed, 0).await;
    journal.decoded(decoded(&answer, debug));

    journal.step("start a collection and send its claim");
    let started = membership.start(shared_id, now()).await;
    let steps = membership.reconcile(now()).await;
    journal.decoded(format!(
        "started {}, reconciled {}, publishes {:?}",
        started.is_ok(),
        steps.is_ok(),
        membership.publishes().ok()
    ));
    let shared = CollectionRef {
        home: others.home,
        collection_id: shared_id,
    };

    journal.step("read the key records");
    let answer = a.service.records_after(&shared, 0).await;
    let first_record = match &answer {
        Ok(KeyRecords::Records { records, .. }) => records.first().cloned(),
        _ => None,
    };
    journal.decoded(decoded(&answer, |records| match records {
        KeyRecords::Records { records, .. } => format!(
            "{} records, the newest at epoch {} and revision {}",
            records.len(),
            records
                .last()
                .map_or(0, |record| record.payload.key_epoch.get()),
            records
                .last()
                .map_or(0, |record| record.payload.revision.get()),
        ),
        KeyRecords::Absent => "absent".to_owned(),
    }));
    let Some(first_record) = first_record else {
        return;
    };
    let epoch = first_record.payload.key_epoch.get();

    journal.step("read the key records after the newest");
    let answer = a.service.records_after(&shared, 1).await;
    journal.decoded(decoded(&answer, |records| match records {
        KeyRecords::Records { records, .. } => format!("{} records", records.len()),
        KeyRecords::Absent => "absent".to_owned(),
    }));

    journal.step("list the collections the home is a member of");
    let answer = a.service.memberships().await;
    journal.decoded(decoded(&answer, |listed| {
        format!(
            "{} collections, the first at epoch {} and record {}",
            listed.len(),
            listed.first().map_or(0, |entry| entry.head.epoch),
            listed.first().map_or(0, |entry| entry.head.revision)
        )
    }));

    journal.step("list the collections a stranger is a member of");
    let answer = b.service.memberships().await;
    journal.decoded(decoded(&answer, |listed| {
        format!("{} collections", listed.len())
    }));

    let item = sync_collection(SyncObjectKind::Settings, SyncObjectId::new(identity()));
    let kept = sealed(b"shared");

    journal.step("write under an epoch the collection has never had");
    let answer = a
        .service
        .exchange_shared(&shared, &item, epoch + 1, identity(), now_ms(), None, &kept)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("write under the collection's epoch");
    let named = identity();
    let answer = a
        .service
        .exchange_shared(&shared, &item, epoch, named, now_ms(), None, &kept)
        .await;
    let held_at = match &answer {
        Ok(Keyed::Answered {
            answer: SyncExchanged::Applied { position },
            ..
        }) => Some(*position),
        _ => None,
    };
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("write the same request again");
    let answer = a
        .service
        .exchange_shared(&shared, &item, epoch, named, now_ms(), None, &kept)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("ask what became of the write");
    let answer = a.service.status_shared(&shared, named).await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown_status)));

    journal.step("read the collection as a member");
    let answer = a.service.compare_shared(&shared, &[], true, None).await;
    journal.decoded(decoded(&answer, |found| {
        found
            .as_ref()
            .map_or("the collection is absent".to_owned(), shown_comparison)
    }));

    journal.step("read the collection as a stranger");
    let answer = b.service.compare_shared(&shared, &[], true, None).await;
    journal.decoded(decoded(&answer, |found| {
        found
            .as_ref()
            .map_or("the collection is absent".to_owned(), shown_comparison)
    }));

    journal.step("write as a stranger");
    let answer = b
        .service
        .exchange_shared(&shared, &item, epoch, identity(), now_ms(), None, &kept)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("fence a request as a stranger");
    let answer = b
        .service
        .fence_shared(&shared, identity(), now_ms(), now_ms())
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown_fence)));

    journal.step("read the key records as a stranger");
    let answer = b.service.records_after(&shared, 0).await;
    journal.decoded(decoded(&answer, debug));

    // A removal is a compared write: it takes a place in the object's order, frees the object's
    // place in the collection, and one that loses its comparison keeps nothing.
    let gone_id = SyncObjectId::new(identity());
    let gone = draft_collection(DraftId::new(gone_id.get()));

    journal.step("write an object to be removed");
    let answer = a
        .service
        .exchange_shared(
            &shared,
            &gone,
            epoch,
            identity(),
            now_ms(),
            None,
            &sealed(b"to be removed"),
        )
        .await;
    let gone_at = match &answer {
        Ok(Keyed::Answered {
            answer: SyncExchanged::Applied { position },
            ..
        }) => Some(*position),
        _ => None,
    };
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("remove it against a revision that is not its own");
    let elsewhere = SyncPosition::at(1, SyncRevision::new(identity()), None);
    let answer = a
        .service
        .remove_shared(&shared, &gone, epoch, identity(), now_ms(), Some(elsewhere))
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("read the collection with the object still held");
    let answer = a.service.compare_shared(&shared, &[], true, None).await;
    journal.decoded(decoded(&answer, |found| {
        found
            .as_ref()
            .map_or("the collection is absent".to_owned(), shown_comparison)
    }));

    journal.step("remove it against its revision");
    let removal = identity();
    let answer = a
        .service
        .remove_shared(&shared, &gone, epoch, removal, now_ms(), gone_at)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("remove it again under the same request identity");
    let answer = a
        .service
        .remove_shared(&shared, &gone, epoch, removal, now_ms(), gone_at)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("ask what became of the removal");
    let answer = a.service.status_shared(&shared, removal).await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown_status)));

    journal.step("remove it again under a new request identity");
    let answer = a
        .service
        .remove_shared(&shared, &gone, epoch, identity(), now_ms(), gone_at)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("remove the object as a stranger");
    let answer = b
        .service
        .remove_shared(&shared, &gone, epoch, identity(), now_ms(), gone_at)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("read naming the removed object as held");
    let known = gone_at
        .and_then(|position| position.revision.0)
        .map(|revision| KnownRevision {
            object_id: gone_id,
            revision,
        });
    let answer = a
        .service
        .compare_shared(&shared, known.as_slice(), false, None)
        .await;
    journal.decoded(decoded(&answer, |found| {
        found
            .as_ref()
            .map_or("the collection is absent".to_owned(), |found| {
                format!(
                    "{}, {} removed, at {:?}",
                    shown_comparison(found),
                    found.removed.len(),
                    found
                        .removed
                        .iter()
                        .map(|removed| removed.position.map(|position| position.write_sequence))
                        .collect::<Vec<_>>()
                )
            })
    }));

    journal.step("write the removed object again against no revision");
    let answer = a
        .service
        .exchange_shared(
            &shared,
            &gone,
            epoch,
            identity(),
            now_ms(),
            None,
            &sealed(b"written again"),
        )
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("remove an object the collection never held");
    let never_held = draft_collection(DraftId::new(identity()));
    let answer = a
        .service
        .remove_shared(&shared, &never_held, epoch, identity(), now_ms(), None)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    // The next record moves the epoch on, keeping the one member.
    let rotation = |previous: &CollectionKeyRecord, key: u8| -> CollectionKeyRecord {
        let draft = CollectionRecordDraft {
            collection_id: shared_id,
            home: others.home,
            key_epoch: SyncKeyEpoch::new(previous.payload.key_epoch.get() + 1),
            revision: SyncKeyRecordRevision::new(previous.payload.revision.get() + 1),
            previous: Some(previous.digest().expect("a digest")),
            issued_at_ms: TimestampMs::new(now_ms()),
            members: vec![a.recipient()],
        };
        issue_collection_key_record(
            &a.keys.authorisation,
            &a.keys.stored_envelope,
            &draft,
            &SymmetricKey::from_bytes([key; 32]),
        )
        .expect("a record")
    };
    let next = rotation(&first_record, 0x21);
    let offered = identity();

    journal.step("offer the record that follows");
    let answer = a.service.rekey(&shared, offered, now_ms(), &next).await;
    journal.decoded(decoded(&answer, debug));

    journal.step("offer the same record again");
    let answer = a.service.rekey(&shared, offered, now_ms(), &next).await;
    journal.decoded(decoded(&answer, debug));

    journal.step("ask what became of the record");
    let answer = a.service.rekey_status(&shared, offered).await;
    journal.decoded(decoded(&answer, debug));

    journal.step("offer other content under the same request identity");
    let answer = a
        .service
        .rekey(&shared, offered, now_ms(), &rotation(&first_record, 0x22))
        .await;
    journal.decoded(decoded(&answer, debug));

    journal.step("offer a record that does not follow the newest");
    let answer = a
        .service
        .rekey(
            &shared,
            identity(),
            now_ms(),
            &rotation(&first_record, 0x23),
        )
        .await;
    journal.decoded(decoded(&answer, debug));

    journal.step("write under the epoch the collection has moved past");
    let retired = identity();
    let answer = a
        .service
        .exchange_shared(&shared, &item, epoch, retired, now_ms(), None, &kept)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("write the retired request again");
    let answer = a
        .service
        .exchange_shared(&shared, &item, epoch, retired, now_ms(), None, &kept)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("ask what became of the retired request");
    let answer = a.service.status_shared(&shared, retired).await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown_status)));

    journal.step("write under the new epoch");
    let answer = a
        .service
        .exchange_shared(
            &shared,
            &item,
            epoch + 1,
            identity(),
            now_ms(),
            held_at,
            &sealed(b"sealed again"),
        )
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("read the key records again");
    let answer = a.service.records_after(&shared, 0).await;
    journal.decoded(decoded(&answer, |records| match records {
        KeyRecords::Records { records, .. } => format!("{} records", records.len()),
        KeyRecords::Absent => "absent".to_owned(),
    }));

    // A collection that holds an object is not claimed.
    journal.step("claim a collection that holds an object");
    let held = CollectionRef {
        home: others.home,
        collection_id: SyncCollectionId::new(object),
    };
    let genesis = issue_collection_key_record(
        &a.keys.authorisation,
        &a.keys.stored_envelope,
        &CollectionRecordDraft {
            collection_id: held.collection_id,
            home: held.home,
            key_epoch: first_record.payload.key_epoch,
            revision: SyncKeyRecordRevision::new(1),
            previous: None,
            issued_at_ms: TimestampMs::new(now_ms()),
            members: vec![a.recipient()],
        },
        &SymmetricKey::from_bytes([0x31; 32]),
    )
    .expect("a record");
    let answer = a.service.rekey(&held, identity(), now_ms(), &genesis).await;
    journal.decoded(decoded(&answer, debug));

    journal.step("fence a record offer nothing was recorded for");
    let answer = a
        .service
        .rekey_fence(&shared, identity(), now_ms(), now_ms())
        .await;
    journal.decoded(decoded(&answer, debug));

    // A removal stores nothing, so it takes no hold against the allowance: a principal that can no
    // longer write an object can still remove one.
    let late_id = SyncObjectId::new(identity());
    let late = draft_collection(DraftId::new(late_id.get()));
    let small = sealed(b"to be removed late");

    journal.step("write an object to be removed once the allowance is spent");
    let answer = a
        .service
        .exchange_shared(
            &shared,
            &late,
            epoch + 1,
            identity(),
            now_ms(),
            None,
            &small,
        )
        .await;
    let late_at = match &answer {
        Ok(Keyed::Answered {
            answer: SyncExchanged::Applied { position },
            ..
        }) => Some(*position),
        _ => None,
    };
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    spent.spend(&a, origin, &small).await;

    journal.step("write an object when the allowance is spent");
    let answer = a
        .service
        .exchange_shared(
            &shared,
            &draft_collection(DraftId::new(identity())),
            epoch + 1,
            identity(),
            now_ms(),
            None,
            &small,
        )
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("remove an object when the allowance is spent");
    let removal = identity();
    let answer = a
        .service
        .remove_shared(&shared, &late, epoch + 1, removal, now_ms(), late_at)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));

    journal.step("remove it against a revision that is not its own when the allowance is spent");
    let answer = a
        .service
        .remove_shared(&shared, &late, epoch + 1, identity(), now_ms(), late_at)
        .await;
    journal.decoded(decoded(&answer, |keyed| shown_keyed(keyed, shown)));
}

/* -------------------------------------------------------------------------- */
/* The runs                                                                    */
/* -------------------------------------------------------------------------- */

/// The stand-in answers the script as the Worker did.
#[tokio::test]
async fn the_stand_in_answers_as_the_worker_did() {
    let held: serde_json::Value = serde_json::from_str(FIXTURE).expect("the recording");
    let web = Arc::new(ServiceWeb::new());
    let origin = GatewayOrigin::new(web.origin()).expect("an origin");
    let journal = Arc::new(Journal::default());
    let http: Arc<dyn ServiceHttp> = Arc::new(Recording {
        inner: Arc::clone(&web) as _,
        origin: web.origin().to_owned(),
        journal: Arc::clone(&journal),
    });
    run_the_script(&http, &origin, &journal, Spent::Told(&web)).await;
    let ran = recorded(&journal, "");

    let mut differing = exchange_differences(&held, &ran);
    differing.extend(differences(&held_outcomes(&held), &journal.outcomes()));
    assert!(
        differing.is_empty(),
        "the stand-in differs from the recording:\n{}",
        differing.join("\n")
    );
}

/// Runs the script against a local Worker and writes what it answered.
///
/// It is ignored unless it is asked for, and then it needs the Worker to ask, so an ordinary run
/// of this workspace asks nothing of any service.
#[tokio::test]
#[ignore = "runs only against a Worker on this machine named by KR_DEPLOYED_ORIGIN and \
            KR_RECORD_SETTINGS_ANSWERS"]
async fn record_a_local_workers_answers() {
    let (Some(path), Some(origin)) = (
        std::env::var_os("KR_RECORD_SETTINGS_ANSWERS"),
        std::env::var("KR_DEPLOYED_ORIGIN").ok(),
    ) else {
        panic!("KR_RECORD_SETTINGS_ANSWERS and KR_DEPLOYED_ORIGIN name what to record");
    };
    let gateway = GatewayOrigin::new(origin.clone()).expect("an origin");
    let transport: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::with(
            gateway.clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .expect("a transport"),
    );
    let journal = Arc::new(Journal::default());
    let http: Arc<dyn ServiceHttp> = Arc::new(Recording {
        inner: Arc::clone(&transport),
        origin,
        journal: Arc::clone(&journal),
    });
    run_the_script(&http, &gateway, &journal, Spent::Written(&transport)).await;
    let commit = std::env::var("KR_WEB_COMMIT").unwrap_or_else(|_| "not stated".to_owned());
    let mut text = serde_json::to_string_pretty(&recorded(&journal, &commit)).expect("a recording");
    text.push('\n');
    std::fs::write(path, text).expect("the recording is written");
}
