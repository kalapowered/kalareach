//! Privacy mode enabled while a settings write and a draft publication are at the service.
//!
//! Section 24: enabling privacy mode fences content-bearing outboxes at once, cancels undispatched
//! sync work, removes retained local content, and reconciles the work in flight before it reports
//! complete; no late result of the old generation is published; pinned labels stay on the device
//! and out of sync while private, and a person's drafts stay theirs; what had already left is shown
//! rather than erased; and disabling privacy mode starts retention again from that point, bringing
//! back nothing it omitted. This leg holds the client to each of those against the web service.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.27, client side of sync and settings backup | `kr_req_24_28_privacy_enabled_while_a_settings_write_and_a_draft_publication_are_in_flight` |
//! | KR-REQ-24.28, client side, sync upload in flight | the same leg |
//! | KR-REQ-24.29, sync's own retained artifacts | the same leg: the writes that left are listed, and the copy the service kept goes only when asked |
//!
//! # Two devices, one installation
//!
//! The service derives every collection from the installation key that signed, so the other device
//! whose writes this leg meets is a second store under the same run key: its own record of what
//! left and its own notes, and the same collections on the service.
//!
//! # In flight, on purpose
//!
//! A write in flight is one the service has committed and answered while the answer has not reached
//! the device. The leg's transport holds that answer until the leg releases it, so the case happens
//! every time and at the step it is meant to, and never because a clock ran one way.

use std::future::Future;
use std::sync::Arc;

use kr_client::drafts::{
    DraftSealer, DraftStore, DraftSync, DraftTarget, Published as DraftPublished, draft_collection,
};
use kr_client::recovery::{RecoveryError, export_settings};
use kr_client::services::relay::{ServiceHttp, ServiceSigner};
use kr_client::services::sync::ManagedSyncService;
use kr_client::services::{SyncBackupService, SyncExchanged};
use kr_client::sync::{
    CollectionSealer, MemoryCollectionKeys, Published, SettingValue, SyncBody, SyncClient,
    SyncError, SyncObject, SyncSettings, SyncStore, fresh_object_id, fresh_revision,
    sync_collection,
};
use kr_privacy_integration::giveback::give_back;
use kr_privacy_integration::held::{Held, Holding};
use kr_privacy_integration::{Deployment, RunKey, fresh_uuid, not_given_back, now_ms, proved};
use kr_protocol::ids::{DeviceId, DraftRevision, SessionId, SyncObjectId};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::sync::SyncObjectKind;

/* -------------------------------------------------------------------------- */
/* One run                                                                     */
/* -------------------------------------------------------------------------- */

/// One run's installation, the service client it signs through, and where its devices keep their
/// stores.
struct Run {
    deployment: Deployment,
    key: Arc<RunKey>,
    held: Arc<Held>,
    service: Arc<ManagedSyncService>,
    /// The collection key the leg's objects are sealed under: drawn for the run, held in memory.
    sealer: Arc<CollectionSealer>,
    directory: tempfile::TempDir,
}

impl Run {
    /// The run's installation, or nothing when this run was given no deployment.
    fn open() -> Option<Self> {
        let deployment = Deployment::from_environment()?;
        let key = RunKey::installation();
        let held = Held::over(deployment.transport());
        let service = Arc::new(ManagedSyncService::new(
            deployment.origin().clone(),
            Arc::clone(&held) as Arc<dyn ServiceHttp>,
            Arc::clone(&key) as Arc<dyn ServiceSigner>,
        ));
        let keys = Arc::new(MemoryCollectionKeys::new());
        let key_name = fresh_uuid().to_string();
        keys.draw(&key_name, 1)
            .expect("a collection key for the run");
        Some(Self {
            sealer: Arc::new(CollectionSealer::new(keys, &key_name, 1)),
            deployment,
            key,
            held,
            service,
            directory: tempfile::tempdir().expect("a directory for the devices' stores"),
        })
    }

    fn store(&self, name: &str) -> SyncStore {
        SyncStore::open(self.directory.path().join(name)).expect("a device's store")
    }

    /// One device's settings client over its store.
    fn settings(&self, name: &str) -> Arc<SyncClient> {
        Arc::new(SyncClient::new(
            Arc::clone(&self.service) as Arc<dyn SyncBackupService>,
            Arc::clone(&self.sealer) as Arc<dyn DraftSealer>,
            self.store(name),
        ))
    }

    /// The synchronised half of one device's drafts, over the same store its settings client uses.
    fn drafts(&self, name: &str) -> Arc<DraftSync> {
        Arc::new(DraftSync::new(
            Arc::clone(&self.service) as Arc<dyn SyncBackupService>,
            Arc::clone(&self.sealer) as Arc<dyn DraftSealer>,
            self.store(name),
        ))
    }

    /// Opens a settings object the service holds.
    fn opened(&self, ciphertext: &[u8]) -> SyncObject {
        let plaintext = self
            .sealer
            .open(ciphertext)
            .expect("sealed under the run's key");
        kr_cbor::from_canonical_slice(&plaintext, &kr_cbor::Limits::DEFAULT)
            .expect("a synchronised object")
    }

    /// Opens a draft the service holds.
    fn opened_draft(&self, ciphertext: &[u8]) -> kr_client::drafts::Draft {
        DraftStore::decode_payload(
            &self
                .sealer
                .open(ciphertext)
                .expect("sealed under the run's key"),
        )
        .expect("a draft")
    }

    /// What the service holds in one collection: the objects, the copies it kept, and a count.
    async fn held_in(&self, collection: &str) -> kr_client::services::sync::SyncComparison {
        self.service
            .compare(collection, true, None)
            .await
            .expect("the collection was read")
    }
}

/// Runs the leg and gives back what it took, whether it passed or failed.
///
/// The work runs as a task of its own, so a failed assertion ends that task rather than this one:
/// what the leg wrote is removed either way and the failure is raised again afterwards.
async fn leg<Body, Work>(body: Body)
where
    Body: FnOnce(Arc<Run>) -> Work + Send + 'static,
    Work: Future<Output = String> + Send + 'static,
{
    let Some(run) = Run::open() else {
        return;
    };
    let run = Arc::new(run);
    let outcome = tokio::spawn(body(Arc::clone(&run))).await;
    let left = give_back(&run.deployment, &run.key, &run.held.reached()).await;
    for what in &left {
        println!("{}", not_given_back(what));
    }
    match outcome {
        Ok(what) => {
            assert!(
                left.is_empty(),
                "this leg did not give back what it took: {left:?}"
            );
            proved("sync", &run.deployment, &what);
        }
        Err(failed) => std::panic::resume_unwind(failed.into_panic()),
    }
}

/* -------------------------------------------------------------------------- */
/* What the leg writes                                                         */
/* -------------------------------------------------------------------------- */

fn device(byte: u8) -> DeviceId {
    DeviceId::new(Uuid::from_bytes([byte; 16]))
}

fn now() -> TimestampMs {
    TimestampMs::new(now_ms())
}

fn settings(pairs: &[(&str, &str)], pinned: &[&str]) -> SyncSettings {
    SyncSettings {
        values: pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), SettingValue::Text((*value).to_owned())))
            .collect(),
        pinned_labels: pinned.iter().map(|label| (*label).to_owned()).collect(),
    }
}

fn settings_object(object_id: SyncObjectId, by: u8, body: SyncSettings) -> SyncObject {
    SyncObject {
        object_id,
        revision: fresh_revision().expect("a revision"),
        device_id: device(by),
        updated_at_ms: now(),
        body: SyncBody::Settings(body),
    }
}

fn pinned(object: &SyncObject) -> Vec<String> {
    let SyncBody::Settings(held) = &object.body else {
        panic!("a settings object");
    };
    held.pinned_labels.iter().cloned().collect()
}

/// A settings publication whose answer the transport holds once the service has committed it.
async fn held_settings(
    run: &Run,
    client: &Arc<SyncClient>,
    object_id: SyncObjectId,
) -> (
    Holding,
    tokio::task::JoinHandle<kr_client::sync::Result<Published>>,
) {
    let mut holding = run.held.hold_the_next_exchange(object_id.get());
    let publishing = tokio::spawn({
        let client = Arc::clone(client);
        async move { client.publish(object_id, now()).await }
    });
    holding.answered().await;
    (holding, publishing)
}

/// A draft publication whose answer the transport holds once the service has committed it.
async fn held_draft(
    run: &Run,
    sync: &Arc<DraftSync>,
    drafts: &DraftStore,
    draft: &kr_client::drafts::Draft,
) -> (
    Holding,
    tokio::task::JoinHandle<kr_client::sync::Result<DraftPublished>>,
) {
    let mut holding = run.held.hold_the_next_exchange(draft.draft_id.get());
    let publishing = tokio::spawn({
        let (sync, drafts, draft_id, revision) = (
            Arc::clone(sync),
            drafts.clone(),
            draft.draft_id,
            draft.revision,
        );
        async move { sync.publish(&drafts, draft_id, revision, now()).await }
    });
    holding.answered().await;
    (holding, publishing)
}

/* -------------------------------------------------------------------------- */
/* The leg                                                                     */
/* -------------------------------------------------------------------------- */

/// KR-REQ-24.27 and KR-REQ-24.28, the client's side: privacy mode is enabled while a settings write
/// and a draft publication are at the service with their answers on the way back.
#[tokio::test(flavor = "multi_thread")]
async fn kr_req_24_28_privacy_enabled_while_a_settings_write_and_a_draft_publication_are_in_flight()
{
    leg(|run| async move {
        let one = run.settings("one");
        let one_drafts = run.drafts("one");
        let two = run.settings("two");
        let drafts =
            DraftStore::open(run.directory.path().join("drafts"), device(1)).expect("drafts");
        let target = DraftTarget::session(SessionId::new(fresh_uuid()));
        let labelled = settings(&[("theme", "dark")], &["deploys", "reviews"]);

        // 1. The control, with privacy mode off: the same hold, released, publishes.
        let c = fresh_object_id().expect("an identity");
        one.store()
            .put_object(&settings_object(c, 1, labelled.clone()))
            .expect("stored");
        let (holding, publishing) = held_settings(&run, &one, c).await;
        holding.release();
        assert!(matches!(
            publishing.await.expect("the task").expect("answered"),
            Published::Accepted { .. }
        ));
        assert!(one.store().checkpoint(c).expect("a note").is_some());
        let control = run
            .held_in(&sync_collection(SyncObjectKind::Settings, c))
            .await;
        assert_eq!(control.objects.len(), 1);
        assert_eq!(
            pinned(&run.opened(&control.objects[0].ciphertext)),
            vec!["deploys".to_owned(), "reviews".to_owned()],
            "with privacy mode off, the labels travel with the settings"
        );
        let e = drafts
            .create(target.clone(), "a draft for the control".to_owned(), now())
            .expect("a draft");
        let (holding, publishing) = held_draft(&run, &one_drafts, &drafts, &e).await;
        holding.release();
        assert!(matches!(
            publishing.await.expect("the task").expect("answered"),
            DraftPublished::Accepted { .. }
        ));
        assert!(drafts.checkpoint(e.draft_id).expect("a note").is_some());

        // 2. Before privacy mode: a settings copy and a draft copy on this device, and a copy the
        // service kept of a refused write.
        let s = fresh_object_id().expect("an identity");
        let s_collection = sync_collection(SyncObjectKind::Settings, s);
        two.store()
            .put_object(&settings_object(s, 2, settings(&[("theme", "light")], &[])))
            .expect("stored");
        assert!(matches!(
            two.publish(s, now()).await.expect("published"),
            Published::Accepted { .. }
        ));
        one.store()
            .put_object(&settings_object(s, 1, settings(&[("theme", "dark")], &[])))
            .expect("stored");
        assert!(matches!(
            one.publish(s, now()).await.expect("answered"),
            Published::Conflicted { .. }
        ));
        let copies = one.store().conflicts(s).expect("copies").items;
        assert_eq!(
            copies.len(),
            1,
            "the other device's settings, kept beside this device's"
        );
        let kept_by_the_service = *copies[0]
            .retained
            .as_ref()
            .expect("the service kept a copy of the refused write");
        assert_eq!(
            one.store()
                .checkpoint(s)
                .expect("a note")
                .expect("held")
                .position
                .write_sequence,
            1
        );

        let d = drafts
            .create(target.clone(), "a prompt not yet sent".to_owned(), now())
            .expect("a draft");
        let d_collection = draft_collection(d.draft_id);
        assert!(matches!(
            one_drafts
                .publish(&drafts, d.draft_id, d.revision, now())
                .await
                .expect("published"),
            DraftPublished::Accepted { .. }
        ));
        let theirs = kr_client::drafts::Draft {
            device_id: device(9),
            revision: DraftRevision::new(d.revision.get().saturating_add(5)),
            text: "what the other device had".to_owned(),
            ..d.clone()
        };
        let sealed = run
            .sealer
            .seal(&DraftStore::encode_payload(&theirs).expect("canonical bytes"))
            .expect("sealed");
        let written = run
            .service
            .compare_exchange(
                &d_collection,
                fresh_uuid(),
                now_ms(),
                Some(
                    drafts
                        .checkpoint(d.draft_id)
                        .expect("a note")
                        .expect("held")
                        .position,
                ),
                &sealed,
            )
            .await
            .expect("the other device's write");
        assert!(matches!(written, SyncExchanged::Applied { .. }));
        let fetched = one_drafts
            .fetch_beside(&drafts, d.draft_id, now())
            .await
            .expect("fetched");
        assert_eq!(fetched.copy.conflict_of.as_ref().copied(), Some(d.draft_id));
        let d_note = drafts
            .checkpoint(d.draft_id)
            .expect("a note")
            .expect("held");
        assert_eq!(d_note.position.write_sequence, 2);

        one.store().pin_label("deploys", now()).expect("pinned");
        let edited_s = settings_object(
            s,
            1,
            settings(&[("theme", "dark"), ("font", "mono")], &["deploys"]),
        );
        one.store().put_object(&edited_s).expect("stored");
        let edited_d = drafts
            .update(
                &kr_client::drafts::Draft {
                    text: "a prompt, edited".to_owned(),
                    ..drafts.load(d.draft_id).expect("the draft")
                },
                now(),
            )
            .expect("edited");

        // 3. In flight: both at the service, committed, their answers held; and a third write
        // admitted and never sent.
        let (s_holding, s_publishing) = held_settings(&run, &one, s).await;
        let (d_holding, d_publishing) = held_draft(&run, &one_drafts, &drafts, &edited_d).await;
        let u = fresh_object_id().expect("an identity");
        let u_collection = sync_collection(SyncObjectKind::Settings, u);
        one.store()
            .put_object(&settings_object(
                u,
                1,
                settings(&[("editor", "plain")], &[]),
            ))
            .expect("stored");
        let sealer = Arc::clone(&run.sealer);
        one.store()
            .admit(u, |object| {
                Ok(sealer.seal(&kr_cbor::to_canonical_vec(object)?)?)
            })
            .expect("admitted");
        assert_eq!(
            one.outstanding().expect("a count"),
            2,
            "two writes have left"
        );

        // 4. Privacy mode, generation 1.
        let fenced = one.fence(1).expect("fenced");
        assert_eq!(
            (fenced.queues, fenced.items),
            (1, 1),
            "one outbox, one admitted write"
        );
        let sent = run.held.sent();
        assert!(matches!(
            one.publish(c, now()).await,
            Err(SyncError::Fenced { generation: 1 })
        ));
        assert!(matches!(
            one.fetch(SyncObjectKind::Settings, c, now()).await,
            Err(SyncError::Fenced { generation: 1 })
        ));
        assert!(matches!(
            one_drafts
                .publish(&drafts, e.draft_id, e.revision, now())
                .await,
            Err(SyncError::Fenced { generation: 1 })
        ));
        assert!(matches!(
            one_drafts.fetch_beside(&drafts, e.draft_id, now()).await,
            Err(SyncError::Fenced { generation: 1 })
        ));
        assert_eq!(
            run.held.sent(),
            sent,
            "nothing left the device once the fence was up"
        );
        assert!(
            one.settings_to_publish(&labelled)
                .expect("a filter")
                .pinned_labels
                .is_empty(),
            "while private, pinned labels are left out of what would be published"
        );
        assert!(matches!(
            export_settings(one.store(), c),
            Err(RecoveryError::Sync(SyncError::Fenced { generation: 1 }))
        ));

        let cancelled = one.cancel_undispatched(1, now()).await.expect("cancelled");
        assert_eq!(
            cancelled.undispatched, 1,
            "the write that never left is taken back"
        );
        assert_eq!(cancelled.in_flight, 2);
        assert_eq!(
            cancelled.reconciled.unresolved, 2,
            "a call still out is counted, not decided about"
        );
        let requests = one.store().requests().expect("requests").items;
        assert!(requests.iter().all(|record| record.object_id != u));
        let in_flight = |object_id: SyncObjectId| {
            one.store()
                .requests()
                .expect("requests")
                .items
                .into_iter()
                .filter(|record| record.object_id == object_id && record.dispatched())
                .count()
        };
        let d_object = SyncObjectId::new(d.draft_id.get());
        assert_eq!((in_flight(s), in_flight(d_object)), (1, 1));
        assert_eq!(
            one.outstanding().expect("a count"),
            2,
            "not complete while both are out"
        );

        let removed = one.remove_retained(1, now()).await.expect("removed");
        assert!(removed.records > 0 && removed.bytes > 0);
        assert!(one.store().checkpoint(s).expect("a note").is_none());
        assert!(one.store().conflicts(s).expect("copies").items.is_empty());
        assert!(
            one.store()
                .requests()
                .expect("requests")
                .items
                .iter()
                .filter(|record| record.dispatched())
                .all(|record| record.ciphertext().is_some()),
            "what was sent keeps its record until it is settled"
        );
        assert_eq!((in_flight(s), in_flight(d_object)), (1, 1));
        assert_eq!(drafts.load(d.draft_id).expect("the draft"), edited_d);
        assert_eq!(
            drafts.checkpoint(d.draft_id).expect("a note"),
            Some(d_note),
            "a draft's note stays on the device"
        );
        assert!(
            drafts
                .list()
                .expect("a listing")
                .drafts
                .iter()
                .any(|draft| draft.conflict_of.as_ref().copied() == Some(d.draft_id)),
            "the copy kept beside a draft stays on the device"
        );
        assert!(
            one.store()
                .pinned_labels()
                .expect("labels")
                .iter()
                .any(|label| label.label == "deploys"),
            "a pinned label stays until the person clears it"
        );
        assert_eq!(
            pinned(&one.store().object(s).expect("read").expect("held")),
            vec!["deploys".to_owned()]
        );
        assert_eq!(one.outstanding().expect("a count"), 2);

        // 5. The answers arrive, for work admitted under the generation before.
        s_holding.release();
        assert_eq!(
            s_publishing.await.expect("the task").expect("answered"),
            Published::Discarded {
                produced_under: 0,
                current: 1
            }
        );
        d_holding.release();
        assert_eq!(
            d_publishing.await.expect("the task").expect("answered"),
            DraftPublished::Discarded {
                produced_under: 0,
                current: 1
            }
        );
        assert_eq!((in_flight(s), in_flight(d_object)), (0, 0));
        assert_eq!(one.outstanding().expect("a count"), 0, "complete only now");
        assert!(one.store().checkpoint(s).expect("a note").is_none());
        assert_eq!(drafts.checkpoint(d.draft_id).expect("a note"), Some(d_note));

        let exported = one.exported().expect("exported");
        let about = |collection: &str| {
            exported
                .iter()
                .filter(|entry| entry.reference.starts_with(collection))
                .map(|entry| (entry.kind.clone(), entry.deletable, entry.reference.clone()))
                .collect::<Vec<_>>()
        };
        let s_left = about(&s_collection);
        assert_eq!(s_left.len(), 2, "{s_left:?}");
        assert!(
            s_left.iter().any(
                |(kind, deletable, reference)| kind == "synchronised settings"
                    && !deletable
                    && reference.contains("write 2")
            ),
            "{s_left:?}"
        );
        assert!(
            s_left.iter().any(|(kind, deletable, _)| kind
                .ends_with("kept as a copy by the service")
                && *deletable),
            "{s_left:?}"
        );
        let d_left = about(&d_collection);
        assert_eq!(d_left.len(), 1, "{d_left:?}");
        assert!(
            d_left[0].0 == "synchronised draft" && !d_left[0].1 && d_left[0].2.contains("write 3"),
            "{d_left:?}"
        );

        let at_s = run.held_in(&s_collection).await;
        assert_eq!(at_s.objects.len(), 1);
        assert_eq!(at_s.objects[0].position.write_sequence, 2);
        assert_eq!(
            run.opened(&at_s.objects[0].ciphertext).revision,
            edited_s.revision
        );
        assert!(
            at_s.copies
                .iter()
                .any(|copy| copy.conflict_id == kept_by_the_service),
            "what left before privacy mode is not erased"
        );
        let at_d = run.held_in(&d_collection).await;
        assert_eq!(at_d.objects.len(), 1);
        assert_eq!(at_d.objects[0].position.write_sequence, 3);
        assert_eq!(
            run.opened_draft(&at_d.objects[0].ciphertext).text,
            edited_d.text
        );
        let at_u = run.held_in(&u_collection).await;
        assert!(at_u.objects.is_empty() && at_u.copies.is_empty());
        assert_eq!(
            at_u.stored.objects.get(),
            0,
            "the write that never left is not there"
        );

        // The kept copy goes when the person asks for exactly that, privacy mode or not.
        let dropped = one
            .drop_kept_copy(kept_by_the_service)
            .await
            .expect("asked")
            .expect("this device holds that refusal");
        assert_eq!((dropped.dropped, dropped.pending), (1, 0));
        assert!(run.held_in(&s_collection).await.copies.is_empty());
        assert!(
            !one.exported()
                .expect("exported")
                .iter()
                .any(|entry| entry.deletable),
            "nothing deletable is left to show"
        );

        // 6. Privacy mode off, generation 2: retention starts again, and nothing comes back.
        assert_eq!(one.resume(2).expect("resumed").generation, 2);
        assert!(!one.is_fenced().expect("a record"));
        assert!(!one.accepts_result(1).expect("a record"));
        assert!(one.accepts_result(2).expect("a record"));
        assert!(one.store().checkpoint(s).expect("a note").is_none());
        assert!(one.store().conflicts(s).expect("copies").items.is_empty());
        assert_eq!(one.outstanding().expect("a count"), 0);
        assert!(export_settings(one.store(), c).is_ok());
        let n = fresh_object_id().expect("an identity");
        let publishable = one.settings_to_publish(&labelled).expect("a filter");
        assert_eq!(publishable.pinned_labels.len(), 2);
        one.store()
            .put_object(&settings_object(n, 1, publishable))
            .expect("stored");
        assert!(matches!(
            one.publish(n, now()).await.expect("published"),
            Published::Accepted { .. }
        ));
        let at_n = run
            .held_in(&sync_collection(SyncObjectKind::Settings, n))
            .await;
        assert_eq!(
            pinned(&run.opened(&at_n.objects[0].ciphertext)),
            vec!["deploys".to_owned(), "reviews".to_owned()]
        );

        "a settings write and a draft publication committed while their answers were held: \
         privacy mode fenced the client at once, took back the write that never left, removed \
         the settings note and copy and kept the draft, its copy, its note and the pinned labels, \
         reported complete only once both answers came back and were discarded, listed what had \
         left, dropped the copy the service kept only when asked, and on disabling brought back \
         nothing while new settings published with their labels; the same hold with privacy mode \
         off published"
            .to_owned()
    })
    .await;
}
